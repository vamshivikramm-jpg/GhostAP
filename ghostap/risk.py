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
import copy
import os
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .indicators import Analyzer, IndicatorResult
from .parser import HIDDEN_SSID
from .storage import Store

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
_LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

DEFAULT_CONFIG = {
    "baseline_minutes": 2.0,
    "weights": {
        "security_downgrade": 3.0,
        "new_bssid_oui": 2.0,
        "tsf_anomaly": 2.0,
        "bssid_conflict": 2.5,
        "rssi_jump": 1.5,
        "channel_deviation": 1.0,
        "beacon_interval_mismatch": 1.0,
    },
    "thresholds": {"medium": 30.0, "high": 60.0},
    "temporal": {"step_seconds": 10.0, "window_seconds": 10.0, "smoothing_steps": 3},
}

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
}


# --------------------------------------------------------------------------- #
# Config and scoring
# --------------------------------------------------------------------------- #

def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = "config.yaml") -> dict:
    """Read config.yaml (if it exists) on top of the built-in defaults."""
    if path and os.path.exists(path):
        import yaml
        with open(path) as f:
            return _merge(DEFAULT_CONFIG, yaml.safe_load(f) or {})
    return copy.deepcopy(DEFAULT_CONFIG)


def risk_score(results: Sequence[IndicatorResult], weights: Dict[str, float]) -> Tuple[float, List[dict]]:
    """R = sum(w_i x_i) / sum(w_i) * 100, plus each indicator's share of R."""
    total_w = sum(weights.get(r.name, 0.0) for r in results)
    contributions = []
    for r in results:
        w = weights.get(r.name, 0.0)
        contributions.append({
            "name": r.name,
            "value": r.value,
            "weight": w,
            "contribution": round(w * r.value / total_w * 100, 2) if total_w else 0.0,
            "reason": r.reason,
        })
    score = round(sum(c["contribution"] for c in contributions), 2)
    return score, contributions


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

    @classmethod
    def from_db(cls, db_path: str, config: Optional[dict] = None) -> "RiskEngine":
        cfg = config or load_config(None)
        return cls(Analyzer.from_db(db_path, cfg["baseline_minutes"]), cfg)

    def steps(self) -> List[float]:
        """Evaluation times: every `step` seconds from the end of the baseline."""
        if not self.an.obs:
            return []
        start, end = self.an.baseline.end, self.an.obs[-1]["ts"]
        out, t = [], start + self.step
        while t <= end:
            out.append(t)
            t += self.step
        if not out or out[-1] < end:
            out.append(end)
        return out

    def run(self) -> RiskReport:
        report = RiskReport()
        history: Dict[Tuple[str, str], deque] = {}
        alerts: Dict[Tuple[str, str], dict] = {}
        first_seen = {ap: obs[0]["ts"] for ap, obs in self.an._by_ap.items()}

        for t in self.steps():
            for key in self.an.aps():
                if first_seen[key] > t:
                    continue                      # not on air yet
                res = self.an.evaluate(*key, until=t, window=self.window)
                if res is None:
                    raw, contrib = 0.0, None      # seen before, silent in this window
                else:
                    raw, contrib = risk_score(res, self.weights)
                h = history.setdefault(key, deque(maxlen=self.n))
                h.append(raw)
                smoothed = round(sum(h) / self.n, 2)
                level = level_for(smoothed, self.thresholds)
                report.timeline.append({"ts": t, "ssid": key[0], "bssid": key[1],
                                        "raw_score": raw, "score": smoothed, "level": level})
                if level != LOW:
                    self._update_alert(alerts, key, t, smoothed, level, contrib)

        report.alerts = sorted(alerts.values(), key=lambda a: (-a["score"], a["first_ts"]))
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
        if score >= a["score"] and contrib:
            a["score"], a["peak_ts"], a["indicators"] = score, t, contrib
        a["last_ts"] = t
        a["reasons"], a["benign_causes"] = _summarise(a["indicators"])


# --------------------------------------------------------------------------- #
# Baseline detector: flag every BSSID whose SSID is advertised by >1 BSSID
# --------------------------------------------------------------------------- #

def duplicate_ssid_detector(observations: Iterable[dict]) -> List[dict]:
    seen: Dict[str, List[str]] = defaultdict(list)
    first: Dict[Tuple[str, str], float] = {}
    last: Dict[Tuple[str, str], float] = {}
    for o in sorted(observations, key=lambda o: o["ts"]):
        ssid, bssid = o["ssid"], o["bssid"]
        if ssid == HIDDEN_SSID:
            continue
        if bssid not in seen[ssid]:
            seen[ssid].append(bssid)
        last[(ssid, bssid)] = o["ts"]
        if len(seen[ssid]) > 1:
            for b in seen[ssid]:
                first.setdefault((ssid, b), o["ts"])

    alerts = []
    for (ssid, bssid), ts in first.items():
        others = [b for b in seen[ssid] if b != bssid]
        reason = "SSID '{}' is advertised by {} BSSIDs (also {})".format(
            ssid, len(seen[ssid]), ", ".join(others))
        alerts.append({
            "ssid": ssid, "bssid": bssid, "level": HIGH, "score": 100.0,
            "first_ts": ts, "high_ts": ts, "peak_ts": ts, "last_ts": last[(ssid, bssid)],
            "indicators": [{"name": "duplicate_ssid", "value": 1.0, "weight": 1.0,
                            "contribution": 100.0, "reason": reason}],
            "reasons": reason,
            "benign_causes": list(BENIGN_CAUSES["duplicate_ssid"]),
        })
    return sorted(alerts, key=lambda a: (a["first_ts"], a["ssid"], a["bssid"]))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.risk",
                                 description="Score APs, raise alerts and run the baseline detector.")
    ap.add_argument("--db", default="data/ghostap.db")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
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
          "MEDIUM >= {:g}, HIGH >= {:g}\n".format(len(engine.steps()), engine.step,
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
