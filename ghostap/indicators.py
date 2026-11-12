"""Evil Twin indicators.

Each indicator looks at one access point (an SSID + BSSID pair) and returns an
IndicatorResult with a value in [0, 1] (0 = nothing suspicious, 1 = strongly
suspicious) and a human-readable reason.

What counts as "normal" for an SSID is learned from the first N minutes of the
capture (the baseline). Every indicator has the same signature:

    indicator(ap: APStats, base: SSIDBaseline | None, siblings: dict[str, APStats])

where `siblings` are the other BSSIDs advertising the same SSID.

Run against a database:
    python -m ghostap.indicators --db data/ghostap.db --baseline-minutes 2
"""
from __future__ import annotations

import argparse
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .parser import HIDDEN_SSID, security_rank
from .storage import Store

DEFAULT_BASELINE_MINUTES = 2.0
SEQ_MOD = 4096


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class IndicatorResult:
    name: str
    value: float
    reason: str

    def __post_init__(self):
        self.value = round(max(0.0, min(1.0, float(self.value))), 3)


@dataclass
class APStats:
    """Summary of the observations of one (ssid, bssid) pair."""
    ssid: str
    bssid: str
    oui: str
    obs: List[dict]
    first_seen: float
    last_seen: float
    channels: Counter
    securities: Set[str]
    rssi_mean: Optional[float]
    rssi_std: float
    beacon_interval: Optional[int]

    @classmethod
    def from_obs(cls, obs: Sequence[dict]) -> "APStats":
        obs = sorted(obs, key=lambda o: o["ts"])
        rssis = [o["rssi"] for o in obs if o.get("rssi") is not None]
        bis = Counter(o["beacon_interval"] for o in obs if o.get("beacon_interval"))
        return cls(
            ssid=obs[0]["ssid"],
            bssid=obs[0]["bssid"],
            oui=obs[0]["oui"],
            obs=list(obs),
            first_seen=obs[0]["ts"],
            last_seen=obs[-1]["ts"],
            channels=Counter(o["channel"] for o in obs if o.get("channel") is not None),
            securities={o["security"] for o in obs if o.get("security")},
            rssi_mean=statistics.fmean(rssis) if rssis else None,
            rssi_std=statistics.pstdev(rssis) if len(rssis) > 1 else 0.0,
            beacon_interval=bis.most_common(1)[0][0] if bis else None,
        )

    @property
    def weakest_security(self) -> Optional[str]:
        known = [s for s in self.securities if security_rank(s) <= 4]
        return max(known, key=security_rank) if known else None

    def boot_time(self) -> Optional[float]:
        """Wall-clock time the AP's TSF counter was 0 (median estimate)."""
        boots = [o["ts"] - o["tsf"] / 1e6 for o in self.obs if o.get("tsf") is not None]
        return statistics.median(boots) if boots else None


@dataclass
class SSIDBaseline:
    """What one SSID looked like during the baseline window."""
    ssid: str
    bssids: Set[str] = field(default_factory=set)
    ouis: Set[str] = field(default_factory=set)
    channels: Set[int] = field(default_factory=set)
    bssid_channels: Dict[str, Set[int]] = field(default_factory=dict)
    bssid_rssi: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    security: Optional[str] = None          # strongest security seen
    rssi_ref: Optional[float] = None        # mean RSSI of the strongest baseline AP
    beacon_interval: Optional[int] = None   # most common interval


class Baseline:
    """Per-SSID baseline learned from the first `minutes` of the capture."""

    def __init__(self, observations: Sequence[dict], minutes: float = DEFAULT_BASELINE_MINUTES):
        self.minutes = minutes
        self.start = observations[0]["ts"] if observations else 0.0
        self.end = self.start + minutes * 60
        self.ssids: Dict[str, SSIDBaseline] = {}

        groups: Dict[str, Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))
        for o in observations:
            if o["ts"] >= self.end:
                break
            groups[o["ssid"]][o["bssid"]].append(o)

        for ssid, by_bssid in groups.items():
            b = SSIDBaseline(ssid)
            securities: Set[str] = set()
            bis: Counter = Counter()
            for bssid, obs in by_bssid.items():
                ap = APStats.from_obs(obs)
                b.bssids.add(bssid)
                b.ouis.add(ap.oui)
                b.channels |= set(ap.channels)
                b.bssid_channels[bssid] = set(ap.channels)
                if ap.rssi_mean is not None:
                    b.bssid_rssi[bssid] = (ap.rssi_mean, ap.rssi_std)
                securities |= ap.securities
                if ap.beacon_interval:
                    bis[ap.beacon_interval] += len(obs)
            known = [s for s in securities if security_rank(s) <= 4]
            b.security = min(known, key=security_rank) if known else None
            if b.bssid_rssi:
                b.rssi_ref = max(m for m, _ in b.bssid_rssi.values())
            b.beacon_interval = bis.most_common(1)[0][0] if bis else None
            self.ssids[ssid] = b

    def get(self, ssid: str) -> Optional[SSIDBaseline]:
        return self.ssids.get(ssid)


def _fmt_secs(s: float) -> str:
    if s < 1:
        return "{:.0f} ms".format(s * 1000)
    if s < 120:
        return "{:.0f} s".format(s)
    if s < 7200:
        return "{:.0f} min".format(s / 60)
    if s < 172800:
        return "{:.1f} h".format(s / 3600)
    return "{:.1f} days".format(s / 86400)


def _chans(chs) -> str:
    return ", ".join(str(c) for c in sorted(chs)) or "none"


# --------------------------------------------------------------------------- #
# Indicators
# --------------------------------------------------------------------------- #

def security_downgrade(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """Weaker security than the SSID used during the baseline (e.g. WPA2 -> open)."""
    name = "security_downgrade"
    if base is None or base.security is None:
        return IndicatorResult(name, 0, "no baseline security for SSID '{}'".format(ap.ssid))
    weakest = ap.weakest_security
    if weakest is None:
        return IndicatorResult(name, 0, "security unknown")
    diff = security_rank(weakest) - security_rank(base.security)
    if diff <= 0:
        return IndicatorResult(name, 0, "{} matches baseline {}".format(weakest, base.security))
    # WPA2 -> WPA = 0.5, WPA2 -> WEP/OPN = 1.0
    return IndicatorResult(
        name, diff / 2,
        "advertises {} but '{}' used {} during the baseline (security downgrade)".format(
            weakest, ap.ssid, base.security))


def new_bssid_oui(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """A BSSID not seen during the baseline, especially from a different vendor (OUI)."""
    name = "new_bssid_oui"
    if base is None:
        return IndicatorResult(name, 0, "no baseline for SSID '{}'".format(ap.ssid))
    if ap.bssid in base.bssids:
        return IndicatorResult(name, 0, "BSSID known from baseline")
    locally_admin = bool(int(ap.bssid[:2], 16) & 0x02)
    la_note = " (locally administered / randomised MAC)" if locally_admin else ""
    if ap.oui in base.ouis and not locally_admin:
        return IndicatorResult(
            name, 0.3,
            "new BSSID {} for '{}', same vendor OUI as baseline APs (could be an added AP)".format(
                ap.bssid, ap.ssid))
    return IndicatorResult(
        name, 1.0,
        "new BSSID {} for '{}' with unfamiliar OUI {}{}; baseline OUIs: {}".format(
            ap.bssid, ap.ssid, ap.oui, la_note, ", ".join(sorted(base.ouis))))


def channel_deviation(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """Operating on a channel the SSID did not use during the baseline."""
    name = "channel_deviation"
    if base is None:
        return IndicatorResult(name, 0, "no baseline for SSID '{}'".format(ap.ssid))
    chans = set(ap.channels)
    if not chans:
        return IndicatorResult(name, 0, "channel unknown")
    if ap.bssid in base.bssid_channels:
        moved = chans - base.bssid_channels[ap.bssid]
        if moved:
            return IndicatorResult(
                name, 0.5,
                "known BSSID moved from channel {} to {} (could be auto channel selection)".format(
                    _chans(base.bssid_channels[ap.bssid]), _chans(moved)))
        return IndicatorResult(name, 0, "same channel as baseline ({})".format(_chans(chans)))
    unseen = chans - base.channels
    if unseen:
        return IndicatorResult(
            name, 1.0,
            "on channel {}, which '{}' never used during the baseline (used: {})".format(
                _chans(unseen), ap.ssid, _chans(base.channels)))
    return IndicatorResult(name, 0, "channel {} already used by '{}'".format(_chans(chans), ap.ssid))


def rssi_jump(ap: APStats, base: Optional[SSIDBaseline], siblings,
              baseline_end: Optional[float] = None) -> IndicatorResult:
    """Signal much stronger than the learned baseline (attacker sitting close by)."""
    name = "rssi_jump"
    if base is None or base.rssi_ref is None:
        return IndicatorResult(name, 0, "no RSSI baseline for SSID '{}'".format(ap.ssid))
    if ap.rssi_mean is None:
        return IndicatorResult(name, 0, "no RSSI available")

    if ap.bssid in base.bssid_rssi:
        ref, ref_std = base.bssid_rssi[ap.bssid]
        recent = [o["rssi"] for o in ap.obs
                  if o.get("rssi") is not None and (baseline_end is None or o["ts"] >= baseline_end)]
        if not recent:
            return IndicatorResult(name, 0, "no frames after the baseline yet")
        now = statistics.fmean(recent)
        margin = max(6.0, 3 * ref_std)
        delta = now - ref
        what = "its own baseline"
    else:
        ref, now, margin = base.rssi_ref, ap.rssi_mean, 6.0
        delta = now - ref
        what = "the strongest baseline AP of '{}'".format(ap.ssid)

    # 0 below +margin dB, rising to 1 at +margin+10 dB
    value = (delta - margin) / 10.0
    if value <= 0:
        return IndicatorResult(
            name, 0, "{:.0f} dBm, within normal range of {} ({:.0f} dBm)".format(now, what, ref))
    return IndicatorResult(
        name, value,
        "{:.0f} dBm is {:+.0f} dB stronger than {} ({:.0f} dBm)".format(now, delta, what, ref))


def tsf_anomaly(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """TSF (uptime) far below sibling APs, or the TSF counter reset."""
    name = "tsf_anomaly"
    tsf_obs = [o for o in ap.obs if o.get("tsf") is not None]
    if not tsf_obs:
        return IndicatorResult(name, 0, "no TSF available")

    # 1) TSF reset: counter jumps backwards by more than 1 s.
    resets = sum(1 for a, b in zip(tsf_obs, tsf_obs[1:]) if b["tsf"] < a["tsf"] - 1_000_000)
    if resets:
        return IndicatorResult(
            name, 1.0, "TSF counter reset {} time(s) - AP rebooted or a second device is "
                       "using this BSSID".format(resets))

    # 2) Uptime when first seen vs. the longest-running sibling at that moment.
    ap_up = tsf_obs[0]["tsf"] / 1e6
    sib_ups = []
    for sib in siblings.values():
        boot = sib.boot_time()
        if boot is not None and ap.first_seen - boot > 0:
            sib_ups.append(ap.first_seen - boot)
    if not sib_ups:
        return IndicatorResult(name, 0, "uptime {}; no sibling APs to compare".format(_fmt_secs(ap_up)))
    sib_up = max(sib_ups)
    if ap_up >= sib_up:
        return IndicatorResult(
            name, 0, "uptime {} is not below siblings ({})".format(_fmt_secs(ap_up), _fmt_secs(sib_up)))
    # log-scale ratio: 1 s vs 3 h -> ~0.9; 2 h vs 2.5 h -> ~0.02
    value = 1 - math.log10(ap_up + 1) / math.log10(sib_up + 1)
    note = " (freshly booted device)" if value >= 0.5 else " (similar order of magnitude - normal)"
    return IndicatorResult(
        name, value,
        "uptime was {} when first seen, while sibling AP(s) of '{}' had been up {}{}".format(
            _fmt_secs(ap_up), ap.ssid, _fmt_secs(sib_up), note))


def bssid_conflict(ap: APStats, base: Optional[SSIDBaseline], siblings,
                   window: float = 5.0) -> IndicatorResult:
    """Same BSSID on two channels at once, or its sequence numbers jump backwards."""
    name = "bssid_conflict"
    obs = ap.obs

    # 1) Two channels at the same time: frames keep alternating between channels
    #    within `window` seconds. A single switch is just a channel change.
    chan_obs = [o for o in obs if o.get("channel") is not None]
    flips = [(a, b) for a, b in zip(chan_obs, chan_obs[1:])
             if a["channel"] != b["channel"] and b["ts"] - a["ts"] <= window]
    if len(flips) >= 2:
        chans = sorted({o["channel"] for pair in flips for o in pair})
        return IndicatorResult(
            name, 1.0,
            "same BSSID alternates between channels {} ({} switches within {:g} s) - "
            "cloned BSSID?".format(_chans(chans), len(flips), window))

    # 2) Sequence numbers going backwards (two transmitters sharing a BSSID).
    seq_obs = [o for o in obs if o.get("seq") is not None]
    if len(seq_obs) < 2:
        return IndicatorResult(name, 0, "not enough frames")
    back = sum(1 for a, b in zip(seq_obs, seq_obs[1:])
               if (b["seq"] - a["seq"]) % SEQ_MOD > SEQ_MOD // 2)
    ratio = back / (len(seq_obs) - 1)
    if back < 3:
        return IndicatorResult(name, 0, "sequence numbers consistent")
    return IndicatorResult(
        name, ratio * 5,  # 20% backwards steps -> 1.0
        "sequence number went backwards {} times ({:.0%} of frames) - two transmitters "
        "may share this BSSID".format(back, ratio))


def beacon_interval_mismatch(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """Beacon interval differs from what the SSID used during the baseline."""
    name = "beacon_interval_mismatch"
    if base is None or base.beacon_interval is None:
        return IndicatorResult(name, 0, "no beacon interval baseline for SSID '{}'".format(ap.ssid))
    if ap.beacon_interval is None:
        return IndicatorResult(name, 0, "beacon interval unknown")
    if ap.beacon_interval == base.beacon_interval:
        return IndicatorResult(name, 0, "beacon interval {} TU matches baseline".format(ap.beacon_interval))
    return IndicatorResult(
        name, 1.0, "beacon interval {} TU, but '{}' used {} TU during the baseline".format(
            ap.beacon_interval, ap.ssid, base.beacon_interval))


INDICATORS: Tuple[Callable[..., IndicatorResult], ...] = (
    security_downgrade,
    new_bssid_oui,
    channel_deviation,
    rssi_jump,
    tsf_anomaly,
    bssid_conflict,
    beacon_interval_mismatch,
)
INDICATOR_NAMES = tuple(f.__name__ for f in INDICATORS)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #

class Analyzer:
    """Evaluates every indicator for every AP, optionally up to a point in time."""

    def __init__(self, observations: Sequence[dict],
                 baseline_minutes: float = DEFAULT_BASELINE_MINUTES):
        self.obs = sorted(observations, key=lambda o: o["ts"])
        self.baseline = Baseline(self.obs, baseline_minutes)
        self._by_ap: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        for o in self.obs:
            self._by_ap[(o["ssid"], o["bssid"])].append(o)

    @classmethod
    def from_db(cls, db_path: str, baseline_minutes: float = DEFAULT_BASELINE_MINUTES) -> "Analyzer":
        with Store(db_path) as store:
            return cls(store.observations(), baseline_minutes)

    def aps(self) -> List[Tuple[str, str]]:
        return sorted(self._by_ap)

    def _stats(self, ssid: str, bssid: str, until: Optional[float],
               since: Optional[float] = None) -> Optional[APStats]:
        obs = self._by_ap.get((ssid, bssid), [])
        if until is not None or since is not None:
            obs = [o for o in obs
                   if (until is None or o["ts"] <= until) and (since is None or o["ts"] > since)]
        return APStats.from_obs(obs) if obs else None

    def evaluate(self, ssid: str, bssid: str, until: Optional[float] = None,
                 window: Optional[float] = None) -> Optional[List[IndicatorResult]]:
        """All indicator results for one AP using data up to `until`.

        With `window` (seconds, needs `until`), indicators look only at the AP's
        frames in (until - window, until], so a single odd frame drops out again.
        tsf_anomaly always uses the AP's full history, because "uptime when first
        seen" is a property of the whole sighting. Returns None if the AP has no
        frames in the range.
        """
        full = self._stats(ssid, bssid, until)
        if full is None:
            return None
        ap = full
        if window is not None and until is not None:
            ap = self._stats(ssid, bssid, until, since=until - window)
            if ap is None:
                return None
        if ssid == HIDDEN_SSID:
            return [IndicatorResult(n, 0, "hidden SSID - not compared with other networks")
                    for n in INDICATOR_NAMES]
        siblings = {}
        for (s, b) in self._by_ap:
            if s == ssid and b != bssid:
                st = self._stats(s, b, until)
                if st is not None:
                    siblings[b] = st
        base = self.baseline.get(ssid)
        results = []
        for fn in INDICATORS:
            if fn is rssi_jump:
                results.append(fn(ap, base, siblings, baseline_end=self.baseline.end))
            elif fn is tsf_anomaly:
                results.append(fn(full, base, siblings))
            else:
                results.append(fn(ap, base, siblings))
        return results

    def evaluate_all(self, until: Optional[float] = None) -> Dict[Tuple[str, str], List[IndicatorResult]]:
        out = {}
        for ssid, bssid in self.aps():
            res = self.evaluate(ssid, bssid, until)
            if res is not None:
                out[(ssid, bssid)] = res
        return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

SHORT = {
    "security_downgrade": "SEC",
    "new_bssid_oui": "OUI",
    "channel_deviation": "CH",
    "rssi_jump": "RSSI",
    "tsf_anomaly": "TSF",
    "bssid_conflict": "CLONE",
    "beacon_interval_mismatch": "BI",
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.indicators",
                                 description="Show Evil Twin indicator values per AP.")
    ap.add_argument("--db", default="data/ghostap.db")
    ap.add_argument("--baseline-minutes", type=float, default=DEFAULT_BASELINE_MINUTES)
    args = ap.parse_args(argv)

    an = Analyzer.from_db(args.db, args.baseline_minutes)
    if not an.obs:
        print("[!] no observations in {} - run the collector first".format(args.db), file=sys.stderr)
        return 1
    results = an.evaluate_all()
    print("[+] baseline: first {:g} min ({} SSIDs)\n".format(args.baseline_minutes, len(an.baseline.ssids)))

    cols = [SHORT[n] for n in INDICATOR_NAMES]
    hdr = "{:<11} {:<18} ".format("SSID", "BSSID") + " ".join("{:>5}".format(c) for c in cols)
    print(hdr)
    print("-" * len(hdr))
    for (ssid, bssid), res in results.items():
        print("{:<11} {:<18} ".format(ssid[:11], bssid) +
              " ".join("{:>5.2f}".format(r.value) for r in res))

    print("\nReasons (non-zero indicators):")
    for (ssid, bssid), res in results.items():
        hits = [r for r in res if r.value > 0]
        if hits:
            print("  {} {}".format(ssid, bssid))
            for r in hits:
                print("    {:<5} {:.2f}  {}".format(SHORT[r.name], r.value, r.reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
