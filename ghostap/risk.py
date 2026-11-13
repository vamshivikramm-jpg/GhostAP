"""Phase 4: weighted risk score, temporal smoothing, alerts, and a baseline detector.

Risk score of one AP at one point in time:

    R = sum(w_i * x_i) / sum(w_i) * 100

where x_i are the indicator values (0-1) from ghostap.indicators and w_i the
weights from config.yaml. Every `step_seconds` of capture time, each AP is
scored using only its frames from the last `window_seconds`. The smoothed
score is the mean of the last `smoothing_steps` raw scores (0 while the AP is
not seen), so one odd frame cannot raise an alert on its own.

Levels on the smoothed score: LOW < medium <= MEDIUM < high <= HIGH.
An alert is raised when an AP reaches MEDIUM.

Run:
    python -m ghostap.risk --db data/ghostap.db --config config.yaml
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .config import DEFAULT_CONFIG, ConfigError, load_config  # noqa: F401 (re-exported)
from .indicators import Analyzer, IndicatorResult
from .parser import HIDDEN_SSID
from .storage import Store

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
_LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

# Innocent explanations an analyst should rule out before acting on an alert.
BENIGN_CAUSES = {
    "security_downgrade": [
        "The network owner changed the security settings (e.g. opened a guest network)",
        "WPA3/WPA2 transition mode advertising a weaker option alongside the stronger one",
    ],
    "new_bssid_oui": [
        "IT installed or replaced an access point (possibly a different vendor)",
        "Mesh node or range extender from another manufacturer",
    ],
    "channel_deviation": [
        "Automatic channel selection or a DFS radar event moved the AP",
        "A newly installed AP was planned on a different channel",
    ],
    "rssi_jump": [
        "The monitoring device was moved closer to the AP",
        "The AP's transmit power was increased or an obstruction was removed",
    ],
    "tsf_anomaly": [
        "The AP was rebooted, power-cycled or had a firmware update",
        "A brand-new AP was just switched on",
    ],
    "ie_fingerprint": [
        "A new AP of a different model or vendor was added to the network",
        "Firmware update or configuration change (e.g. 802.11r / WMM / band settings)",
    ],
    "bssid_conflict": [
        "Capture artefacts such as frames reordered by the driver",
        "Multi-radio AP sharing one BSSID across bands (unusual)",
    ],
    "beacon_interval_mismatch": [
        "A different AP model or configuration profile in the same network",
    ],
    "duplicate_ssid": [
        "Enterprise / campus networks use many APs with the same SSID",
        "Mesh systems and range extenders repeat the SSID",
    ],
    "karma": [
        "Hotspot-portal equipment that deliberately answers for several of its own network names",
    ],
    "lookalike_ssid": [
        "A legitimate second network with a deliberately similar name (e.g. a band or guest suffix)",
    ],
    "known_tool": [
        "Your own lab equipment or a teammate's test setup",
        "A legitimate device built on the same hardware or software as the listed tool",
    ],
    "deauth_flood": [
        "The AP kicking clients during a configuration change, reboot or band steering",
        "Clients leaving normally (a few deauthentications are routine; a burst is not)",
    ],
    "beacon_flood": [
        "Arriving at a very busy place (conference, stadium) where many networks appear at once",
        "Switching channel-hopping on, which suddenly reveals networks on other channels",
    ],
}


# --------------------------------------------------------------------------- #
# Config and scoring
# --------------------------------------------------------------------------- #

def risk_score(results: Sequence[IndicatorResult], weights: Dict[str, float],
               floors: Optional[Dict[str, float]] = None) -> Tuple[float, List[dict]]:
    """R = sum(w_i x_i) / sum(w_i) * 100 over the weighted indicators, plus each one's share.

    Attack signatures (F001-F003) carry no weight; when one matches, the score is raised to
    at least floors[name] x value, and that signature's contribution is the amount it added.
    """
    floors = floors or {}
    weighted = [r for r in results if r.name in weights]
    total_w = sum(weights[r.name] for r in weighted)
    contributions = []
    for r in weighted:
        w = weights[r.name]
        contributions.append({
            "name": r.name,
            "value": r.value,
            "weight": w,
            "contribution": round(w * r.value / total_w * 100, 2) if total_w else 0.0,
            "reason": r.reason,
        })
    score = round(sum(c["contribution"] for c in contributions), 2)
    sigs = [r for r in results if r.name not in weights]
    best = max(sigs, key=lambda r: floors.get(r.name, 0.0) * r.value, default=None)
    floor = round(floors.get(best.name, 0.0) * best.value, 2) if best is not None else 0.0
    for r in sigs:
        added = round(floor - score, 2) if (r is best and floor > score) else 0.0
        contributions.append({
            "name": r.name, "value": r.value, "weight": 0.0, "contribution": added,
            "reason": r.reason + (" - raises the score to {:.0f}".format(floor) if added else ""),
            "signature": True})
    if floor > score:
        score = floor
    return score, contributions


def analyzer_for(cfg: dict, observations: Iterable[dict] = (), monitored: Optional[dict] = None,
                 network_settings: Optional[dict] = None) -> Analyzer:
    """The one place an Analyzer is configured: allow-list, saved baselines, attack-tool
    library, detection thresholds and per-network switches all come from here."""
    from .signatures import library_for
    return Analyzer(observations, cfg["baseline_minutes"], cfg.get("known_bssids") or (),
                    monitored=monitored, library=library_for(cfg), detection=cfg.get("detection"),
                    network_settings=network_settings)


def level_for(score: float, thresholds: Dict[str, float]) -> str:
    if score >= thresholds["high"]:
        return HIGH
    if score >= thresholds["medium"]:
        return MEDIUM
    return LOW


def _summarise(contributions: List[dict]) -> Tuple[str, List[str]]:
    hits = sorted((c for c in contributions if c["contribution"] > 0),
                  key=lambda c: -c["contribution"])
    reasons = "; ".join("{} (+{:.0f}): {}".format(c["name"], c["contribution"], c["reason"])
                        for c in hits)
    benign: List[str] = []
    for c in hits:
        for cause in BENIGN_CAUSES.get(c["name"], []):
            if cause not in benign:
                benign.append(cause)
    return reasons, benign


# --------------------------------------------------------------------------- #
# GhostAP risk engine
# --------------------------------------------------------------------------- #

@dataclass
class RiskReport:
    timeline: List[dict] = field(default_factory=list)
    alerts: List[dict] = field(default_factory=list)
    latest: List[dict] = field(default_factory=list)   # newest score + breakdown per AP


class RiskEngine:
    def __init__(self, analyzer: Analyzer, config: Optional[dict] = None):
        self.an = analyzer
        self.cfg = config or load_config(None)
        t = self.cfg["temporal"]
        self.step = float(t["step_seconds"])
        self.window = float(t["window_seconds"])
        self.n = int(t["smoothing_steps"])
        self.weights = self.cfg["weights"]
        self.thresholds = self.cfg["thresholds"]
        self.floors = self.cfg.get("signatures") or {}
        # state kept between run() calls, so the live pipeline only scores new steps
        self._history: Dict[Tuple[str, str], deque] = {}
        self._alerts: Dict[Tuple[str, str], dict] = {}
        self._next_grid: Optional[float] = None   # next regular evaluation time
        self._last_t: Optional[float] = None      # last evaluated time (grid or final)
        self.latest: Dict[Tuple[str, str], dict] = {}

    @classmethod
    def from_db(cls, db_path: str, config: Optional[dict] = None) -> "RiskEngine":
        cfg = config or load_config(None)
        with Store(db_path) as s:
            obs = s.observations()
        return cls(analyzer_for(cfg, obs), cfg)

    def thresholds_for(self, ssid: str) -> Dict[str, float]:
        """F011: a monitored network may set its own MEDIUM threshold."""
        s = self.an.network_settings.get(ssid) or {}
        med = s.get("threshold_medium")
        if med is None:
            return self.thresholds
        return {"medium": float(med), "high": max(float(med) + 1, self.thresholds["high"])}

    def _schedule(self, final: bool) -> Tuple[List[float], Optional[float]]:
        """(regular steps not yet evaluated, optional final partial step)."""
        if not self.an.obs:
            return [], None
        start, end = self.an.scoring_start, self.an.obs[-1]["ts"]
        if end <= start:
            return [], None               # still learning the baseline
        t = self._next_grid if self._next_grid is not None else start + self.step
        grid = []
        while t <= end:
            grid.append(t)
            t += self.step
        last = grid[-1] if grid else self._last_t
        partial = end if final and (last is None or end > last) else None
        return grid, partial

    def steps(self, final: bool = True) -> List[float]:
        """Evaluation times still to run: every `step` s after the baseline (+ the end)."""
        grid, partial = self._schedule(final)
        return grid + ([partial] if partial is not None else [])

    def run(self, final: bool = True) -> RiskReport:
        """Score every step not scored by an earlier call.

        Returns the new timeline rows and all alerts so far. `final=False` skips the
        partial step at the end of the data (the live pipeline uses this while frames
        are still arriving, so that step is scored once it is complete).
        """
        report = RiskReport()
        history, alerts = self._history, self._alerts
        grid, partial = self._schedule(final)
        if grid:
            self._next_grid = grid[-1] + self.step
        elif self._next_grid is None and self.an.obs and self.an.obs[-1]["ts"] > self.an.scoring_start:
            self._next_grid = self.an.scoring_start + self.step

        touched = set()
        for t in grid + ([partial] if partial is not None else []):
            self._last_t = t
            for key in self.an.aps():
                if self.an.first_seen(*key) > t:
                    continue                      # not on air yet
                res = self.an.evaluate(*key, until=t, window=self.window)
                if res is None:
                    raw, contrib = 0.0, None      # seen before, silent in this window
                else:
                    raw, contrib = risk_score(res, self.weights, self.floors)
                h = history.setdefault(key, deque(maxlen=self.n))
                h.append(raw)
                smoothed = round(sum(h) / self.n, 2)
                level = level_for(smoothed, self.thresholds_for(key[0]))
                report.timeline.append({"ts": t, "ssid": key[0], "bssid": key[1],
                                        "raw_score": raw, "score": smoothed, "level": level})
                prev = self.latest.get(key)
                self.latest[key] = {"ts": t, "ssid": key[0], "bssid": key[1], "raw_score": raw,
                                    "score": smoothed, "level": level,
                                    "indicators": contrib or (prev["indicators"] if prev else [])}
                touched.add(key)
                if level != LOW:
                    self._update_alert(alerts, key, t, smoothed, level, contrib)

        report.alerts = sorted(alerts.values(), key=lambda a: (-a["score"], a["first_ts"]))
        report.latest = [self.latest[k] for k in sorted(touched)]
        return report

    @staticmethod
    def _update_alert(alerts, key, t, score, level, contrib):
        a = alerts.get(key)
        if a is None:
            a = alerts[key] = {"ssid": key[0], "bssid": key[1], "level": level, "score": score,
                               "first_ts": t, "high_ts": None, "peak_ts": t, "last_ts": t,
                               "indicators": contrib or [], "reasons": "", "benign_causes": []}
        if level == HIGH and a["high_ts"] is None:
            a["high_ts"] = t
        if _LEVEL_ORDER[level] > _LEVEL_ORDER[a["level"]]:
            a["level"] = level
        # first time the peak is reached (ties keep the earlier time); fill the breakdown
        # if the alert started in a window where the AP was silent
        if contrib and (score > a["score"] or not a["indicators"]):
            a["score"], a["peak_ts"], a["indicators"] = score, t, contrib
        a["last_ts"] = t
        a["reasons"], a["benign_causes"] = _summarise(a["indicators"])


# --------------------------------------------------------------------------- #
# Baseline detector: flag every BSSID whose SSID is advertised by >1 BSSID
# --------------------------------------------------------------------------- #

class DuplicateSSIDDetector:
    """Incremental version: feed observations in time order with update()."""

    def __init__(self):
        self.seen: Dict[str, List[str]] = defaultdict(list)
        self.first: Dict[Tuple[str, str], float] = {}
        self.last: Dict[Tuple[str, str], float] = {}

    def update(self, observations: Iterable[dict]) -> None:
        for o in sorted(observations, key=lambda o: o["ts"]):
            ssid, bssid = o["ssid"], o["bssid"]
            if ssid == HIDDEN_SSID:
                continue
            if bssid not in self.seen[ssid]:
                self.seen[ssid].append(bssid)
            self.last[(ssid, bssid)] = o["ts"]
            if len(self.seen[ssid]) > 1:
                for b in self.seen[ssid]:
                    self.first.setdefault((ssid, b), o["ts"])

    def alerts(self) -> List[dict]:
        out = []
        for (ssid, bssid), ts in self.first.items():
            others = [b for b in self.seen[ssid] if b != bssid]
            reason = "SSID '{}' is advertised by {} BSSIDs (also {})".format(
                ssid, len(self.seen[ssid]), ", ".join(others))
            out.append({
                "ssid": ssid, "bssid": bssid, "level": HIGH, "score": 100.0,
                "first_ts": ts, "high_ts": ts, "peak_ts": ts, "last_ts": self.last[(ssid, bssid)],
                "indicators": [{"name": "duplicate_ssid", "value": 1.0, "weight": 1.0,
                                "contribution": 100.0, "reason": reason}],
                "reasons": reason,
                "benign_causes": list(BENIGN_CAUSES["duplicate_ssid"]),
            })
        return sorted(out, key=lambda a: (a["first_ts"], a["ssid"], a["bssid"]))


def duplicate_ssid_detector(observations: Iterable[dict]) -> List[dict]:
    """Baseline detector: flag every BSSID whose SSID is advertised by more than one BSSID."""
    det = DuplicateSSIDDetector()
    det.update(observations)
    return det.alerts()


# --------------------------------------------------------------------------- #
# F005 deauthentication floods and F008 beacon floods: attacks *on* a network
# --------------------------------------------------------------------------- #

class DeauthDetector:
    """Counts deauthentication / disassociation frames per AP in a sliding window."""

    def __init__(self, detection: Optional[dict] = None):
        d = detection or {}
        self.window = float(d.get("deauth_window_seconds", 10.0))
        self.medium = int(d.get("deauth_medium", 10))
        self.high = int(d.get("deauth_high", 30))
        self._recent: Dict[str, deque] = defaultdict(deque)
        self._state: Dict[str, dict] = {}

    def update(self, events: Iterable[dict]) -> None:
        for e in sorted(events, key=lambda e: e["ts"]):
            q = self._recent[e["bssid"]]
            q.append(e)
            while q and q[0]["ts"] < e["ts"] - self.window:
                q.popleft()
            n = len(q)
            if n < self.medium:
                continue
            level = HIGH if n >= self.high else MEDIUM
            st = self._state.setdefault(e["bssid"], {
                "first_ts": e["ts"], "high_ts": None, "peak": 0, "peak_ts": e["ts"], "frames": 0,
                "broadcast": 0, "reasons": defaultdict(int), "level": level})
            st["last_ts"] = e["ts"]
            st["frames"] += 1
            st["broadcast"] += int(bool(e.get("broadcast")))
            if e.get("reason") is not None:
                st["reasons"][int(e["reason"])] += 1
            if level == HIGH and st["high_ts"] is None:
                st["high_ts"] = e["ts"]
            if _LEVEL_ORDER[level] > _LEVEL_ORDER[st["level"]]:
                st["level"] = level
            if n > st["peak"]:
                st["peak"], st["peak_ts"] = n, e["ts"]

    def alerts(self, names_of=lambda b: []) -> List[dict]:
        out = []
        for bssid, st in self._state.items():
            names = names_of(bssid)
            reason = ("{} deauthentication/disassociation frames within {:g} s against this AP "
                      "(peak), {:.0%} sent to everyone; often used to push clients onto an evil twin").format(
                st["peak"], self.window, st["broadcast"] / max(1, st["frames"]))
            score = min(100.0, 50.0 + 30.0 * min(1.0, st["peak"] / max(1, self.high)))
            ind = [{"name": "deauth_flood", "value": 1.0, "weight": 0.0, "contribution": score,
                    "reason": reason, "signature": True}]
            out.append({"ssid": names[0] if names else "<unknown>", "bssid": bssid, "level": st["level"],
                        "score": round(score, 1), "first_ts": st["first_ts"], "high_ts": st["high_ts"],
                        "peak_ts": st["peak_ts"], "last_ts": st["last_ts"], "indicators": ind,
                        "reasons": "deauth_flood (+{:.0f}): {}".format(score, reason),
                        "benign_causes": list(BENIGN_CAUSES["deauth_flood"])})
        return sorted(out, key=lambda a: -a["score"])


class FloodDetector:
    """F008: many radios appearing within one minute (beacon-flood tools such as mdk)."""

    def __init__(self, detection: Optional[dict] = None, warmup: float = 0.0):
        self.limit = int((detection or {}).get("flood_new_aps_per_minute", 30))
        self.warmup = warmup              # ignore the first minutes, when everything is new
        self._seen: set = set()
        self._new: deque = deque()
        self._t0: Optional[float] = None
        self.alert: Optional[dict] = None

    def update(self, observations: Iterable[dict]) -> None:
        for o in sorted(observations, key=lambda o: o["ts"]):
            if self._t0 is None:
                self._t0 = o["ts"]
            if o["bssid"] in self._seen:
                continue
            self._seen.add(o["bssid"])
            if o["ts"] - self._t0 < self.warmup:
                continue
            self._new.append(o["ts"])
            while self._new and self._new[0] < o["ts"] - 60:
                self._new.popleft()
            n = len(self._new)
            if self.limit and n >= self.limit:
                a = self.alert
                if a is None:
                    reason = "{} new radios appeared within one minute (beacon flood / fake-AP generator?)".format(n)
                    self.alert = a = {
                        "ssid": "*", "bssid": "*", "level": HIGH, "score": 75.0, "first_ts": o["ts"],
                        "high_ts": o["ts"], "peak_ts": o["ts"], "last_ts": o["ts"], "peak": n,
                        "indicators": [{"name": "beacon_flood", "value": 1.0, "weight": 0.0,
                                        "contribution": 75.0, "reason": reason, "signature": True}],
                        "reasons": "beacon_flood (+75): " + reason,
                        "benign_causes": list(BENIGN_CAUSES["beacon_flood"])}
                a["last_ts"] = o["ts"]
                if n > a["peak"]:
                    a["peak"], a["peak_ts"] = n, o["ts"]

    def alerts(self) -> List[dict]:
        return [self.alert] if self.alert else []


# --------------------------------------------------------------------------- #
# F012 incidents: related alerts grouped into one story
# --------------------------------------------------------------------------- #

def build_incidents(alerts: List[dict], gap_seconds: float = 300.0) -> List[dict]:
    """Group GhostAP, deauth and flood alerts that concern the same network and happen
    within `gap_seconds` of each other into incidents with a plain-language story."""
    rows = [a for a in alerts if a.get("detector") in ("ghostap", "deauth", "flood")
            and a.get("triage_status") != "false_positive"]
    rows.sort(key=lambda a: a["first_ts"])
    incidents: List[dict] = []
    for a in rows:
        net = a["ssid"]
        inc = next((i for i in incidents
                    if (i["network"] == net or a["ssid"] == "*" or i["network"] == "*")
                    and a["first_ts"] - i["last_ts"] <= gap_seconds), None)
        if inc is None:
            inc = {"network": net, "first_ts": a["first_ts"], "last_ts": a.get("last_ts") or a["first_ts"],
                   "level": a["level"], "score": a["score"], "alerts": []}
            incidents.append(inc)
        inc["alerts"].append(a)
        inc["last_ts"] = max(inc["last_ts"], a.get("last_ts") or a["first_ts"])
        inc["score"] = max(inc["score"], a["score"])
        if _LEVEL_ORDER[a["level"]] > _LEVEL_ORDER[inc["level"]]:
            inc["level"] = a["level"]
    for n, inc in enumerate(sorted(incidents, key=lambda i: -i["score"]), start=1):
        inc["id"] = n
        steps = []
        for a in sorted(inc["alerts"], key=lambda a: a["first_ts"]):
            what = {"deauth": "deauthentication burst against {}".format(a["bssid"]),
                    "flood": "beacon flood: many new radios at once"}.get(
                a["detector"], "suspicious access point {} on '{}' ({})".format(a["bssid"], a["ssid"], a["level"]))
            steps.append({"ts": a["first_ts"], "text": what, "alert_id": a.get("id"),
                          "detector": a["detector"]})
            if a.get("high_ts") and a["high_ts"] != a["first_ts"]:
                steps.append({"ts": a["high_ts"], "text": "{} reached HIGH".format(a["bssid"]),
                              "alert_id": a.get("id"), "detector": a["detector"]})
        inc["story"] = sorted(steps, key=lambda s: s["ts"])
        kinds = {a["detector"] for a in inc["alerts"]}
        inc["summary"] = (("Deauthentication attack and suspicious access point" if {"deauth", "ghostap"} <= kinds
                           else "Deauthentication attack" if kinds == {"deauth"}
                           else "Beacon flood" if kinds == {"flood"}
                           else "Suspicious access point") + " on '{}'".format(inc["network"]))
    return sorted(incidents, key=lambda i: (-i["score"], i["first_ts"]))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.risk",
                                 description="Score APs, raise alerts and run the baseline detector.")
    ap.add_argument("--db", default="data/ghostap.db")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    engine = RiskEngine.from_db(args.db, cfg)
    if not engine.an.obs:
        print("[!] no observations in {} - run the collector first".format(args.db), file=sys.stderr)
        return 1
    report = engine.run()
    base_alerts = duplicate_ssid_detector(engine.an.obs)

    with Store(args.db) as store:
        store.save_timeline(report.timeline)
        store.save_alerts("ghostap", report.alerts)
        store.save_alerts("baseline", base_alerts)

    t0 = engine.an.obs[0]["ts"]
    rel = lambda ts: "-" if ts is None else "t+{:.0f}s".format(ts - t0)  # noqa: E731
    th = cfg["thresholds"]
    print("[+] {} evaluation steps every {:g}s after a {:g}-min baseline; "
          "MEDIUM >= {:g}, HIGH >= {:g}\n".format(len({r["ts"] for r in report.timeline}), engine.step,
                                                  cfg["baseline_minutes"], th["medium"], th["high"]))

    print("GhostAP alerts ({}):".format(len(report.alerts)))
    if not report.alerts:
        print("  none")
    for a in report.alerts:
        print("  [{:<6}] {:>5.1f}  {} {}  first {}  high {}".format(
            a["level"], a["score"], a["ssid"], a["bssid"], rel(a["first_ts"]), rel(a["high_ts"])))
        for c in sorted(a["indicators"], key=lambda c: -c["contribution"]):
            if c["contribution"] > 0:
                print("      +{:>5.1f}  {:<24} {}".format(c["contribution"], c["name"], c["reason"]))
        print("      possible benign causes:")
        for cause in a["benign_causes"]:
            print("        - " + cause)

    print("\nBaseline (duplicate-SSID) alerts ({}):".format(len(base_alerts)))
    for a in base_alerts:
        print("  [HIGH  ] {} {}  first {}".format(a["ssid"], a["bssid"], rel(a["first_ts"])))
    print("\n[+] saved alerts and risk timeline to {}".format(args.db))
    return 0


if __name__ == "__main__":
    sys.exit(main())
