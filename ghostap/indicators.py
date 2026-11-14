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
import bisect
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .parser import (CIPHER_RANK, HIDDEN_SSID, akm_class, band_of, channel_from_freq, rsn_fields,
                     security_rank)
from .signatures import SIGNATURE_NAMES, karma_value, lookalike_target, match_tool
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
    fingerprints: Set[str] = field(default_factory=set)
    tsf_resets: Optional[int] = None   # precomputed by Analyzer over the full history
    rsn: Set[str] = field(default_factory=set)        # RSN detail strings seen (F004)
    skew_ppm: Optional[Tuple[float, float]] = None   # (drift, std error) in ppm, set by Analyzer (F007)

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
            fingerprints={o["fingerprint"] for o in obs
                          if o.get("fingerprint") and o.get("frame_type", "beacon") == "beacon"},
            rsn={o["rsn"] for o in obs if o.get("rsn")},
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
    fingerprints: Set[str] = field(default_factory=set)              # beacon structures seen
    bssid_fingerprints: Dict[str, Set[str]] = field(default_factory=dict)
    allowlist: Set[str] = field(default_factory=set)                 # admin-approved BSSIDs
    saved: bool = False                     # loaded from a saved baseline (F014), not learned
    rsn_best: Optional[dict] = None         # strongest {pmf, cipher, akm} ranks seen (F004)
    bssid_skew: Dict[str, Tuple[float, float]] = field(default_factory=dict)   # (ppm, se) per AP (F007)

    def to_dict(self) -> dict:
        """JSON-friendly form for data/monitored.json."""
        return {
            "bssids": sorted(self.bssids), "ouis": sorted(self.ouis),
            "channels": sorted(self.channels),
            "bssid_channels": {b: sorted(c) for b, c in sorted(self.bssid_channels.items())},
            "bssid_rssi": {b: [round(m, 2), round(s, 2)] for b, (m, s) in sorted(self.bssid_rssi.items())},
            "security": self.security, "rssi_ref": self.rssi_ref,
            "beacon_interval": self.beacon_interval,
            "fingerprints": sorted(self.fingerprints),
            "bssid_fingerprints": {b: sorted(f) for b, f in sorted(self.bssid_fingerprints.items())},
            "rsn_best": self.rsn_best,
            "bssid_skew": {b: [round(v[0], 2), round(v[1], 2)] for b, v in sorted(self.bssid_skew.items())},
            "bssid_skew_kind": "relative",
        }

    @classmethod
    def from_dict(cls, ssid: str, d: dict, allowlist: Iterable[str] = ()) -> "SSIDBaseline":
        return cls(
            ssid=ssid,
            bssids={b.lower() for b in d.get("bssids", [])},
            ouis=set(d.get("ouis", [])),
            channels={int(c) for c in d.get("channels", [])},
            bssid_channels={b.lower(): {int(c) for c in cs} for b, cs in d.get("bssid_channels", {}).items()},
            bssid_rssi={b.lower(): (float(v[0]), float(v[1])) for b, v in d.get("bssid_rssi", {}).items()},
            security=d.get("security"), rssi_ref=d.get("rssi_ref"),
            beacon_interval=d.get("beacon_interval"),
            fingerprints=set(d.get("fingerprints", [])),
            bssid_fingerprints={b.lower(): set(f) for b, f in d.get("bssid_fingerprints", {}).items()},
            allowlist={b.lower() for b in allowlist}, saved=True,
            rsn_best=d.get("rsn_best"),
            # files saved before the clock fix hold drifts against the sensor clock: not comparable
            bssid_skew={b.lower(): (float(v[0]), float(v[1])) for b, v in d.get("bssid_skew", {}).items()}
            if d.get("bssid_skew_kind") == "relative" else {})


class Baseline:
    """Per-SSID baseline learned from the first `minutes` of the capture."""

    def __init__(self, observations: Sequence[dict], minutes: float = DEFAULT_BASELINE_MINUTES,
                 allowlist: Iterable[str] = (), saved: Optional[Dict[str, SSIDBaseline]] = None):
        """`saved`: networks from a saved baseline (F014). They replace whatever would be
        learned for those SSIDs; every other SSID is still learned from the first minutes."""
        self.minutes = minutes
        self.allowlist = {b.lower() for b in allowlist}
        self.saved = dict(saved or {})
        self.start = observations[0]["ts"] if observations else 0.0
        self.end = self.start + minutes * 60
        self.ssids: Dict[str, SSIDBaseline] = {}

        groups: Dict[str, Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))
        radios: Dict[str, List[dict]] = defaultdict(list)       # per BSSID, any SSID (clock refs)
        for o in observations:
            if o["ts"] >= self.end:
                break
            groups[o["ssid"]][o["bssid"]].append(o)
            radios[o["bssid"]].append(o)

        for ssid, by_bssid in groups.items():
            b = SSIDBaseline(ssid, allowlist=self.allowlist)
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
                b.fingerprints |= ap.fingerprints
                b.bssid_fingerprints[bssid] = set(ap.fingerprints)
                strength = rsn_strength(ap.rsn)
                if strength:
                    b.rsn_best = strength if b.rsn_best is None else {
                        k: max(b.rsn_best.get(k, strength[k]), strength[k]) for k in strength}
                skew = relative_clock_skew_ppm(obs, _busiest(radios, bssid))
                if skew is not None:
                    b.bssid_skew[bssid] = skew
                if ap.beacon_interval:
                    bis[ap.beacon_interval] += len(obs)
            known = [s for s in securities if security_rank(s) <= 4]
            b.security = min(known, key=security_rank) if known else None
            if b.bssid_rssi:
                b.rssi_ref = max(m for m, _ in b.bssid_rssi.values())
            b.beacon_interval = bis.most_common(1)[0][0] if bis else None
            self.ssids[ssid] = b

        for ssid, b in self.saved.items():
            b.allowlist = self.allowlist
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

_PMF_RANK = {"none": 0, "capable": 1, "required": 2}


def rsn_strength(rsn_strings: Iterable[str]) -> Optional[dict]:
    """Weakest option an AP offers, as ranks: pmf (0-2), cipher (0-3, pairwise), group
    (0-3, broadcast cipher; same as cipher when not sent), akm class (0-3, OWE 0.5)."""
    out = None
    for r in rsn_strings or ():
        f = rsn_fields(r)
        if not f["akm"] and not f["pw"]:
            continue
        s = {"pmf": _PMF_RANK.get(f["pmf"] or "none", 0),
             "cipher": min((CIPHER_RANK.get(c, 0) for c in f["pw"]), default=0),
             "group": CIPHER_RANK.get(f["grp"], 0) if f["grp"] else min(
                 (CIPHER_RANK.get(c, 0) for c in f["pw"]), default=0),
             "akm": min((akm_class(a) for a in f["akm"]), default=0)}
        out = s if out is None else {k: min(out[k], s[k]) for k in s}
    return out


def clock_skew_ppm(obs: Sequence[dict], max_points: int = 600) -> Optional[Tuple[float, float]]:
    """F007: (drift, standard error) of the AP's TSF clock against the capture clock, in
    parts per million. Needs >= 10 frames over >= 30 s without a TSF reset; uses the last
    `max_points`. Capture timestamps jitter, so the standard error matters: two drifts are
    only "different" when the gap is large compared with their combined uncertainty."""
    pts = [(o["ts"], o["tsf"] / 1e6) for o in obs if o.get("tsf") is not None][-max_points:]
    if len(pts) < 10 or pts[-1][0] - pts[0][0] < 30:
        return None
    if any(b[1] < a[1] for a, b in zip(pts, pts[1:])):
        return None                                   # reset inside the sample
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    if sxx == 0:
        return None
    slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / sxx
    resid = sum((p[1] - my - slope * (p[0] - mx)) ** 2 for p in pts)
    se = math.sqrt(resid / (n - 2) / sxx) if n > 2 else float("inf")
    return (slope - 1.0) * 1e6, se * 1e6


SKEW_MIN_REFS = 3        # other APs needed to compare clocks with
SKEW_MAX_REFS = 15       # the busiest ones are used
SKEW_MAX_POINTS = 120    # frames of the AP itself that are compared
SKEW_MAX_GAP = 5.0       # s: a reference's clock is interpolated only between frames this close


def _tsf_points(obs: Sequence[dict]) -> Optional[List[Tuple[float, float]]]:
    """(capture time, TSF in s) for frames with a TSF, or None if the clock reset inside."""
    pts = [(o["ts"], o["tsf"] / 1e6) for o in obs if o.get("tsf") is not None]
    if any(b[1] < a[1] for a, b in zip(pts, pts[1:])):
        return None
    return pts


def relative_clock_skew_ppm(obs: Sequence[dict], refs: Iterable[Sequence[dict]]
                            ) -> Optional[Tuple[float, float]]:
    """F007: (drift, standard error) in ppm of an AP's TSF clock against the clocks of
    other APs heard over the same time, not against the sensor's clock.

    The sensor's clock is not a stable reference: NTP, systemd-timesyncd or VM tools
    slew it by hundreds of ppm (seen live on a Kali VM: every AP "drifted" +250 ppm
    during the learning period and -110 ppm a few minutes later). Each of the AP's
    frames is paired with every reference AP's TSF interpolated to the same capture
    moment, so any error of the capture clock cancels; the slope of TSF against
    reference TSF is the drift between the two crystals. The median over the
    references is returned (a twin among the references cannot move it). Needs
    >= 10 frames over >= 30 s and SKEW_MIN_REFS usable references, else None.
    """
    pts = _tsf_points(obs)
    if not pts or len(pts) < 10 or pts[-1][0] - pts[0][0] < 30:
        return None
    pts = pts[::max(1, len(pts) // SKEW_MAX_POINTS)]
    found = []
    for ref in refs:
        rp = _tsf_points(ref)
        if not rp or len(rp) < 2:
            continue
        r_ts = [p[0] for p in rp]
        xs, ys = [], []
        for ts, tsf in pts:
            k = bisect.bisect_left(r_ts, ts)
            if 0 < k < len(rp) and r_ts[k] - r_ts[k - 1] <= SKEW_MAX_GAP:
                (t0, f0), (t1, f1) = rp[k - 1], rp[k]
                xs.append(f0 + (f1 - f0) * ((ts - t0) / (t1 - t0) if t1 > t0 else 0.0))
                ys.append(tsf)
        if len(xs) < 10 or xs[-1] - xs[0] < 30:
            continue
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        sxx = sum((x - mx) ** 2 for x in xs)
        if sxx == 0:
            continue
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
        resid = sum((y - my - slope * (x - mx)) ** 2 for x, y in zip(xs, ys))
        found.append(((slope - 1.0) * 1e6, math.sqrt(resid / (n - 2) / sxx) * 1e6))
    if len(found) < SKEW_MIN_REFS:
        return None
    return (statistics.median(v[0] for v in found), statistics.median(v[1] for v in found))


def _busiest(groups: Dict[str, Sequence[dict]], exclude: str) -> List[Sequence[dict]]:
    """Reference APs for relative_clock_skew_ppm: the busiest other radios."""
    keys = sorted((b for b in groups if b != exclude), key=lambda b: (-len(groups[b]), b))
    return [groups[b] for b in keys[:SKEW_MAX_REFS]]


def _detail_downgrade(ap: APStats, base: SSIDBaseline):
    """F004: (value, reason) for weaker RSN details than the network normally uses."""
    if not base.rsn_best or not ap.rsn:
        return 0.0, None
    s, b = rsn_strength(ap.rsn), base.rsn_best
    if s is None:
        return 0.0, None
    found = []
    if b["akm"] == 3 and s["akm"] < 3:
        found.append((1.0, "offers a shared-password login while the network uses enterprise (802.1X) logins"))
    elif b["akm"] == 2 and s["akm"] == 1:
        found.append((0.8, "also offers WPA2 password login (WPA3 transition) while the network used WPA3 only"))
    elif b["akm"] >= 1 and s["akm"] == 0.5:
        found.append((0.9, "uses OWE (encrypted, but no password or login, so anyone can run it) while the "
                           "network required a password or login"))
    if s["cipher"] <= 1 < b["cipher"]:
        found.append((1.0, "allows the broken TKIP/WEP cipher, which the network does not use"))
    elif s.get("group", s["cipher"]) <= 1 < b.get("group", b["cipher"]):
        found.append((0.8, "uses the broken TKIP/WEP cipher for broadcast traffic (group cipher), "
                           "which the network does not"))
    if b["pmf"] == 2 and s["pmf"] < 2:
        found.append((0.8 if s["pmf"] == 0 else 0.4,
                      "does not require protected management frames, which the network requires"))
    elif b["pmf"] == 1 and s["pmf"] == 0:
        found.append((0.4, "has protected management frames switched off"))
    if not found:
        return 0.0, None
    return max(v for v, _ in found), "; ".join(r for _, r in found)


def security_downgrade(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """Weaker security than the SSID used during the baseline: WPA2 -> open, and (F004)
    weaker details such as enterprise -> password, WPA3 -> transition, TKIP, PMF off."""
    name = "security_downgrade"
    if base is None or base.security is None:
        return IndicatorResult(name, 0, "no baseline security for SSID '{}'".format(ap.ssid))
    weakest = ap.weakest_security
    if weakest is None:
        return IndicatorResult(name, 0, "security unknown")
    diff = security_rank(weakest) - security_rank(base.security)
    family_v = diff / 2 if diff > 0 else 0.0           # WPA2 -> WPA = 0.5, -> WEP/OPN = 1.0
    detail_v, detail_reason = _detail_downgrade(ap, base) if diff <= 0 else (0.0, None)
    if family_v <= 0 and detail_v <= 0:
        return IndicatorResult(name, 0, "{} matches baseline {}".format(weakest, base.security))
    if family_v >= detail_v:
        return IndicatorResult(
            name, family_v,
            "advertises {} but '{}' used {} during the baseline (security downgrade)".format(
                weakest, ap.ssid, base.security))
    return IndicatorResult(name, detail_v, "{} (security downgrade)".format(detail_reason))


def new_bssid_oui(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """A BSSID not seen during the baseline, especially from a different vendor (OUI)."""
    name = "new_bssid_oui"
    if base is None:
        return IndicatorResult(name, 0, "no baseline for SSID '{}'".format(ap.ssid))
    if ap.bssid in base.bssids:
        return IndicatorResult(name, 0, "BSSID known from baseline")
    if ap.bssid in base.allowlist:
        return IndicatorResult(name, 0, "BSSID is on the administrator's allow-list")
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
    if ap.bssid in base.allowlist:
        return IndicatorResult(name, 0, "allow-listed BSSID on channel {}".format(_chans(chans)))
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


def tsf_anomaly(ap: APStats, base: Optional[SSIDBaseline], siblings,
                skew_tolerance_ppm: float = 10.0) -> IndicatorResult:
    """TSF (uptime) far below sibling APs, or the TSF counter reset."""
    name = "tsf_anomaly"
    tsf_obs = [o for o in ap.obs if o.get("tsf") is not None]
    if not tsf_obs:
        return IndicatorResult(name, 0, "no TSF available")

    # 1) TSF reset: counter jumps backwards by more than 1 s.
    resets = ap.tsf_resets
    if resets is None:
        resets = sum(1 for a, b in zip(tsf_obs, tsf_obs[1:]) if b["tsf"] < a["tsf"] - 1_000_000)
    if resets:
        return IndicatorResult(
            name, 1.0, "TSF counter reset {} time(s) - AP rebooted or a second device is "
                       "using this BSSID".format(resets))

    # 1b) F007: a known BSSID whose clock now drifts differently = different hardware.
    if base is not None and ap.skew_ppm is not None and ap.bssid in base.bssid_skew:
        now_ppm, now_se = ap.skew_ppm
        was_ppm, was_se = base.bssid_skew[ap.bssid]
        delta = abs(now_ppm - was_ppm)
        margin = skew_tolerance_ppm + 3 * math.sqrt(now_se ** 2 + was_se ** 2)
        if delta > margin:
            return IndicatorResult(
                name, min(1.0, (delta - margin) / margin + 0.5),
                "clock drift {:+.1f} ppm, but this BSSID drifted {:+.1f} ppm while GhostAP learned it "
                "(different hardware using this address?)".format(now_ppm, was_ppm))

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


def _heard_on_channel(o: dict) -> bool:
    """Was this frame received while the sensor was tuned to (or, on 2.4 GHz, within two
    channels of) the channel the AP advertises? A channel-hopping sensor also hears a
    strong nearby AP faintly while tuned several channels away (seen live: -8 dBm on
    channels 1-4 and -50 dBm on channels 7-10 from one phone hotspot on channel 2).
    Frames without the tuned frequency (older pcaps, synthetic data) count as on-channel."""
    tuned = channel_from_freq(o.get("freq"))
    if tuned is None or o.get("channel") is None:
        return True
    if band_of(o.get("freq")) == "2.4":
        return abs(tuned - o["channel"]) <= 2
    return tuned == o["channel"]


def _signal_tracks(obs: Sequence[dict], gap_db: float):
    """F006: two clearly separated signal levels that keep alternating = two transmitters.
    Only frames heard on the AP's own channel are compared (see _heard_on_channel)."""
    pts = [(o["ts"], o["rssi"]) for o in obs if o.get("rssi") is not None and _heard_on_channel(o)]
    if len(pts) < 10:
        return None
    vals = sorted(r for _, r in pts)
    gaps = [(vals[i + 1] - vals[i], i) for i in range(len(vals) - 1)]
    gap, i = max(gaps)
    if gap < gap_db:
        return None
    cut = (vals[i] + vals[i + 1]) / 2
    low = [r for r in vals if r < cut]
    high = [r for r in vals if r >= cut]
    if min(len(low), len(high)) < 0.2 * len(vals):
        return None
    sides = [r >= cut for _, r in sorted(pts)]
    switches = sum(1 for a, b in zip(sides, sides[1:]) if a != b)
    if switches < 3:
        return None
    return sum(low) / len(low), sum(high) / len(high), switches


def bssid_conflict(ap: APStats, base: Optional[SSIDBaseline], siblings,
                   window: float = 5.0, gap_db: float = 12.0) -> IndicatorResult:
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

    # 1b) F006: the same address heard at two separate signal levels at the same time.
    tracks = _signal_tracks(obs, gap_db)
    if tracks:
        lo, hi, switches = tracks
        return IndicatorResult(
            name, 1.0,
            "same BSSID heard at two signal levels, about {:.0f} and {:.0f} dBm, alternating {} times "
            "- two transmitters share this address".format(lo, hi, switches))

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


def beacon_interval_mismatch(ap: APStats, base: Optional[SSIDBaseline], siblings,
                             rate_tolerance: float = 0.5) -> IndicatorResult:
    """Beacon interval differs from what the SSID used during the baseline, or (F008) the AP
    beacons much faster than its own advertised interval allows (beacon flood / fake-AP tool)."""
    name = "beacon_interval_mismatch"
    beacons = [o["ts"] for o in ap.obs if o.get("frame_type", "beacon") == "beacon"]
    if ap.beacon_interval and len(beacons) >= 10 and beacons[-1] > beacons[0]:
        rate = (len(beacons) - 1) / (beacons[-1] - beacons[0])
        expected = 1.0 / (ap.beacon_interval * 0.001024)
        ratio = rate / expected
        if ratio > 1 + rate_tolerance:
            return IndicatorResult(
                name, min(1.0, (ratio - 1 - rate_tolerance) / (1 + rate_tolerance)),
                "beaconing {:.1f} times per second, {:.1f}x what its {} TU interval allows "
                "(beacon flood or fake-AP tool?)".format(rate, ratio, ap.beacon_interval))
    if base is None or base.beacon_interval is None:
        return IndicatorResult(name, 0, "no beacon interval baseline for SSID '{}'".format(ap.ssid))
    if ap.beacon_interval is None:
        return IndicatorResult(name, 0, "beacon interval unknown")
    if ap.beacon_interval == base.beacon_interval:
        return IndicatorResult(name, 0, "beacon interval {} TU matches baseline".format(ap.beacon_interval))
    return IndicatorResult(
        name, 1.0, "beacon interval {} TU, but '{}' used {} TU during the baseline".format(
            ap.beacon_interval, ap.ssid, base.beacon_interval))


def ie_fingerprint(ap: APStats, base: Optional[SSIDBaseline], siblings) -> IndicatorResult:
    """Beacon *structure* (element order, rates, capabilities, vendor elements) unlike
    any AP of this SSID in the baseline, i.e. different hardware or AP software."""
    name = "ie_fingerprint"
    if base is None or not base.fingerprints:
        return IndicatorResult(name, 0, "no beacon fingerprint baseline for SSID '{}'".format(ap.ssid))
    fps = ap.fingerprints
    if not fps:
        return IndicatorResult(name, 0, "no beacon fingerprint (no beacons in range)")
    known = base.bssid_fingerprints.get(ap.bssid)
    if known is not None:
        if not fps - known:
            return IndicatorResult(name, 0, "beacon structure unchanged since the baseline")
        return IndicatorResult(
            name, 0.6, "beacon structure of this BSSID changed ({} new variant(s)): firmware or "
                       "configuration change, or a second device using this BSSID".format(len(fps - known)))
    if fps & base.fingerprints:
        return IndicatorResult(
            name, 0,
            "beacon structure matches existing AP(s) of '{}' (same model / software)".format(ap.ssid))
    return IndicatorResult(
        name, 1.0, "beacon structure {} matches none of the {} fingerprint(s) seen for '{}' in the "
                   "baseline (different hardware or AP software)".format(
                       ",".join(sorted(fps)), len(base.fingerprints), ap.ssid))


INDICATORS: Tuple[Callable[..., IndicatorResult], ...] = (
    security_downgrade,
    new_bssid_oui,
    channel_deviation,
    rssi_jump,
    tsf_anomaly,
    ie_fingerprint,
    bssid_conflict,
    beacon_interval_mismatch,
)
INDICATOR_NAMES = tuple(f.__name__ for f in INDICATORS)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #

class Analyzer:
    """Evaluates every indicator for every AP, optionally up to a point in time.

    Observations can be added incrementally (`add`), which is what the live
    dashboard does. Per-AP time indexes make each windowed evaluation cost
    O(log n + window) instead of a scan of the AP's whole history.
    """

    HEAD = 50   # frames used to estimate an AP's boot time / first uptime

    def __init__(self, observations: Sequence[dict] = (),
                 baseline_minutes: float = DEFAULT_BASELINE_MINUTES,
                 allowlist: Iterable[str] = (),
                 monitored: Optional[Dict[str, SSIDBaseline]] = None,
                 library: Optional[List[dict]] = None, detection: Optional[dict] = None,
                 network_settings: Optional[Dict[str, dict]] = None):
        """monitored: saved baselines (F014). With them, scoring starts at the first frame
        instead of after the learning period, and a twin already on the air is caught.
        library: attack-tool fingerprints (F003). detection: thresholds from config.yaml.
        network_settings: per-network switches from the monitored-networks file (F011)."""
        self.baseline_minutes = baseline_minutes
        self.allowlist = {b.lower() for b in allowlist}
        self.monitored = dict(monitored or {})
        self.library = list(library or [])
        self.detection = dict(detection or {})
        self.network_settings = dict(network_settings or {})
        self._reset_state()
        self.add(observations)

    def _reset_state(self) -> None:
        self.obs: List[dict] = []
        self._by_ap: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        self._ts: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._resets: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._last_tsf: Dict[Tuple[str, str], int] = {}
        self._by_ssid: Dict[str, Set[str]] = defaultdict(set)
        # every network name each radio has used, with when it was first heard (F001, F010)
        self._bssid_ssids: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.baseline = Baseline([], self.baseline_minutes, self.allowlist, self.monitored)
        self._baseline_frozen = False
        self._pruned = False
        self._pruned_before: Optional[float] = None

    @classmethod
    def from_db(cls, db_path: str, baseline_minutes: float = DEFAULT_BASELINE_MINUTES,
                allowlist: Iterable[str] = ()) -> "Analyzer":
        with Store(db_path) as store:
            return cls(store.observations(), baseline_minutes, allowlist)

    def add(self, observations: Iterable[dict]) -> None:
        """Append observations (any order within the batch)."""
        new = sorted(observations, key=lambda o: o["ts"])
        if not new:
            return
        if self.obs and new[0]["ts"] < self.obs[-1]["ts"]:
            if self._pruned:
                # after pruning a rebuild would relearn from partial history: insert the late
                # frames in place instead (any frame older than the pruned span is dropped)
                self._insert_late([o for o in new if o["ts"] < self.obs[-1]["ts"]])
                new = [o for o in new if o["ts"] >= self.obs[-1]["ts"]]
                if not new:
                    return
            else:
                # rare: a frame older than what we have. Rebuild in time order.
                merged = sorted(self.obs + new, key=lambda o: o["ts"])
                self._reset_state()
                new = merged
        for o in new:
            if o["ssid"] == HIDDEN_SSID:
                names = self._bssid_ssids.get(o["bssid"])
                if names and len(names) == 1:          # F010: this hidden radio's name is known
                    o = dict(o, ssid=next(iter(names)), decloaked=True)
            else:
                first = o["bssid"] not in self._bssid_ssids or o["ssid"] not in self._bssid_ssids[o["bssid"]]
                self._bssid_ssids[o["bssid"]].setdefault(o["ssid"], o["ts"])
                if first and len(self._bssid_ssids[o["bssid"]]) == 1:
                    self._decloak(o["bssid"], o["ssid"])
            key = (o["ssid"], o["bssid"])
            self.obs.append(o)
            self._by_ap[key].append(o)
            self._ts[key].append(o["ts"])
            self._by_ssid[o["ssid"]].add(o["bssid"])
            tsf = o.get("tsf")
            if tsf is not None:
                prev = self._last_tsf.get(key)
                if prev is not None and tsf < prev - 1_000_000:
                    self._resets[key].append(o["ts"])
                self._last_tsf[key] = tsf
        if not self._baseline_frozen:
            self.baseline = Baseline(self.obs, self.baseline_minutes, self.allowlist, self.monitored)
            # all frames of the baseline window are in once we are past its end
            self._baseline_frozen = self.obs[-1]["ts"] >= self.baseline.end

    def _insert_late(self, late: List[dict]) -> None:
        """Late frames after pruning: insert by time into the per-AP lists (no rebuild)."""
        for o in late:
            if self._pruned_before is not None and o["ts"] < self._pruned_before:
                continue                                    # older than what memory keeps
            key = (o["ssid"], o["bssid"])
            if key not in self._ts:
                continue                                    # unknown AP this late: skip it
            i = bisect.bisect_right(self._ts[key], o["ts"])
            self._ts[key].insert(i, o["ts"])
            self._by_ap[key].insert(i, o)
            self.obs.insert(bisect.bisect_right([x["ts"] for x in self.obs], o["ts"]), o)

    def _decloak(self, bssid: str, ssid: str) -> None:
        """F010: frames from a hidden radio heard before its name was known move to that name."""
        hk = (HIDDEN_SSID, bssid)
        if hk not in self._by_ap:
            return
        moved = [dict(o, ssid=ssid, decloaked=True) for o in self._by_ap.pop(hk)]
        self._ts.pop(hk, None)
        self._by_ssid[HIDDEN_SSID].discard(bssid)
        key = (ssid, bssid)
        merged = sorted(self._by_ap.get(key, []) + moved, key=lambda o: o["ts"])
        self._by_ap[key] = merged
        self._ts[key] = [o["ts"] for o in merged]
        self._by_ssid[ssid].add(bssid)
        self._resets[key] = sorted(self._resets.get(key, []) + self._resets.pop(hk, []))
        self.obs = sorted([o for o in self.obs if not (o["ssid"] == HIDDEN_SSID and o["bssid"] == bssid)]
                          + moved, key=lambda o: o["ts"])

    def names_of(self, bssid: str, until: Optional[float] = None) -> List[str]:
        """Network names this radio has used (up to `until`)."""
        return sorted(s for s, t in self._bssid_ssids.get(bssid, {}).items() if until is None or t <= until)

    @property
    def scoring_start(self) -> float:
        """When risk scoring may begin: immediately with a saved baseline, otherwise
        after the learning period."""
        return self.baseline.start if self.monitored else self.baseline.end

    def prune(self, before_ts: float) -> int:
        """F070: forget frames older than `before_ts` (keeping each AP's first HEAD frames
        and every TSF reset, which indicators need). Only after the baseline is frozen."""
        if not self._baseline_frozen or not self.obs:
            return 0
        removed = 0
        for key in list(self._by_ap):
            obs = self._by_ap[key]
            keep = obs[:self.HEAD] + [o for o in obs[self.HEAD:] if o["ts"] >= before_ts]
            removed += len(obs) - len(keep)
            self._by_ap[key] = keep
            self._ts[key] = [o["ts"] for o in keep]
        if removed:
            heads = {id(o) for obs in self._by_ap.values() for o in obs}
            self.obs = [o for o in self.obs if id(o) in heads]
            self._pruned = True
            self._pruned_before = max(self._pruned_before or before_ts, before_ts)
        return removed

    def aps(self) -> List[Tuple[str, str]]:
        return sorted(self._by_ap)

    def first_seen(self, ssid: str, bssid: str) -> Optional[float]:
        ts = self._ts.get((ssid, bssid))
        return ts[0] if ts else None

    def _slice(self, key, since: Optional[float], until: Optional[float]) -> List[dict]:
        ts = self._ts.get(key)
        if not ts:
            return []
        lo = bisect.bisect_right(ts, since) if since is not None else 0
        hi = bisect.bisect_right(ts, until) if until is not None else len(ts)
        return self._by_ap[key][lo:hi]

    def _stats(self, ssid: str, bssid: str, until: Optional[float],
               since: Optional[float] = None) -> Optional[APStats]:
        obs = self._slice((ssid, bssid), since, until)
        return APStats.from_obs(obs) if obs else None

    def _head(self, key, until: Optional[float]) -> Optional[APStats]:
        """First frames of an AP (for 'uptime when first seen') + TSF resets up to `until`."""
        ts = self._ts.get(key)
        if not ts:
            return None
        hi = bisect.bisect_right(ts, until) if until is not None else len(ts)
        if hi == 0:
            return None
        st = APStats.from_obs(self._by_ap[key][:min(self.HEAD, hi)])
        resets = self._resets.get(key, [])
        st.tsf_resets = bisect.bisect_right(resets, until) if until is not None else len(resets)
        return st

    def _sibling_at(self, key, moment: float, until: Optional[float]) -> Optional[APStats]:
        """A sibling's frames around `moment`, to estimate its boot time at that point."""
        ts = self._ts.get(key)
        if not ts:
            return None
        limit = bisect.bisect_right(ts, until) if until is not None else len(ts)
        hi = min(bisect.bisect_right(ts, moment), limit)
        obs = self._by_ap[key]
        chunk = obs[max(0, hi - self.HEAD):hi] if hi else obs[:min(self.HEAD, limit)]
        return APStats.from_obs(chunk) if chunk else None

    def _relative_skew(self, key, until: Optional[float]) -> Optional[Tuple[float, float]]:
        """F007: this AP's clock drift against the other radios over the same span."""
        obs = self._slice(key, None, until)[-600:]
        if len(obs) < 10:
            return None
        lo = obs[0]["ts"]
        radios: Dict[str, List[dict]] = {}
        for k in self._by_ap:
            if k[1] == key[1] or k[1] in radios:
                continue
            ref = self._slice(k, lo, until)
            if len(ref) >= 10:
                radios[k[1]] = ref
        return relative_clock_skew_ppm(obs, _busiest(radios, key[1]))

    def evaluate(self, ssid: str, bssid: str, until: Optional[float] = None,
                 window: Optional[float] = None) -> Optional[List[IndicatorResult]]:
        """All indicator results for one AP using data up to `until`.

        With `window` (seconds, needs `until`), indicators look only at the AP's
        frames in (until - window, until], so a single odd frame drops out again.
        tsf_anomaly always uses the AP's first frames and its full reset history,
        because "uptime when first seen" is a property of the whole sighting.
        Returns None if the AP has no frames in the range.
        """
        key = (ssid, bssid)
        head = self._head(key, until)
        if head is None:
            return None
        if window is not None and until is not None:
            ap = self._stats(ssid, bssid, until, since=until - window)
        else:
            ap = self._stats(ssid, bssid, until)
        if ap is None:
            return None
        det = self.detection
        if ssid == HIDDEN_SSID:
            return [IndicatorResult(n, 0, "hidden SSID - not compared with other networks")
                    for n in INDICATOR_NAMES + SIGNATURE_NAMES]

        # ---- signatures (F001-F003)
        sig = {}
        names = self.names_of(bssid, until)
        n_min = int(det.get("karma_min_ssids", 3))
        kv = karma_value(len(names), n_min)
        sig["karma"] = IndicatorResult(
            "karma", kv,
            "this radio answers for {} different network names ({}) - KARMA/MANA rogue-AP behaviour".format(
                len(names), ", ".join(names[:6]) + (" ..." if len(names) > 6 else ""))
            if kv else "uses {} network name{}".format(len(names), "" if len(names) == 1 else "s"))
        base = self.baseline.get(ssid)
        compared_with = ssid
        target = lookalike_target(ssid, [k for k in self.baseline.ssids if k != ssid],
                                  int(det.get("lookalike_max_distance", 2)))
        if target:
            identical = target[1].startswith("identical")
            sig["lookalike_ssid"] = IndicatorResult(
                "lookalike_ssid", 1.0 if identical else (0.6 if target[1].startswith("1 ") else 0.4),
                "name '{}' imitates the known network '{}' ({})".format(ssid, target[0], target[1]))
            if base is None and identical:          # judge it against the network it imitates
                base, compared_with = self.baseline.get(target[0]), target[0]
        else:
            sig["lookalike_ssid"] = IndicatorResult("lookalike_ssid", 0, "name does not imitate another known network")
        tool = match_tool(ap.fingerprints | head.fingerprints, ap.oui, self.library) if self.library else None
        sig["known_tool"] = IndicatorResult(
            "known_tool", 1.0 if tool else 0,
            "matches the {} of '{}'{}".format(tool["matched"], tool["name"],
                                              " (synthetic example signature)" if tool.get("example") else "")
            if tool else "no match in the attack-tool library ({} entries)".format(len(self.library)))

        # ---- the eight weighted indicators
        siblings = {}
        for b in self._by_ssid.get(compared_with, ()):
            if b != bssid:
                st = self._sibling_at((compared_with, b), head.first_seen, until)
                if st is not None:
                    siblings[b] = st
        if base is not None and bssid in base.bssid_skew:
            head.skew_ppm = self._relative_skew(key, until)
        settings = self.network_settings.get(compared_with) or {}
        enabled = settings.get("enabled") or {}
        results = []
        for fn in INDICATORS:
            if enabled.get(fn.__name__) is False:
                results.append(IndicatorResult(fn.__name__, 0, "turned off for this network"))
            elif fn is rssi_jump:
                results.append(fn(ap, base, siblings, baseline_end=self.baseline.end))
            elif fn is tsf_anomaly:
                results.append(fn(head, base, siblings,
                                  skew_tolerance_ppm=float(det.get("clock_skew_tolerance_ppm", 10.0))))
            elif fn is bssid_conflict:
                results.append(fn(ap, base, siblings, gap_db=float(det.get("signal_track_gap_db", 12.0))))
            elif fn is beacon_interval_mismatch:
                results.append(fn(ap, base, siblings,
                                  rate_tolerance=float(det.get("beacon_rate_tolerance", 0.5))))
            else:
                results.append(fn(ap, base, siblings))
        if compared_with != ssid:
            results = [IndicatorResult(r.name, r.value, r.reason + " [compared with '{}']".format(compared_with))
                       if r.value > 0 else r for r in results]
        for n in SIGNATURE_NAMES:
            r = sig[n]
            results.append(IndicatorResult(n, 0, "turned off for this network")
                           if enabled.get(n) is False else r)
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
    "ie_fingerprint": "FP",
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
