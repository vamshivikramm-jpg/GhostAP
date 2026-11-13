"""What-if weights (F031): re-score a session with other weights and thresholds.

The indicators are evaluated once (the slow part) and kept as compact value tuples;
re-scoring with new weights then takes milliseconds. Nothing stored is changed: the
result is only shown, and the configured weights stay as they are.

The rule from CLAUDE.md still applies: do not pick weights or thresholds by looking at
the results on the data you report. This tool is for understanding the score, not for
tuning it.
"""
from __future__ import annotations

from collections import deque, namedtuple
from typing import Dict, List, Optional, Tuple

from .indicators import INDICATOR_NAMES
from .risk import HIGH, LOW, MEDIUM, RiskEngine, analyzer_for, level_for, risk_score
from .signatures import SIGNATURE_NAMES

MAX_EVALUATIONS = 200_000          # (access point, step) pairs kept in memory
_R = namedtuple("_R", "name value reason")
_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


class TooLarge(Exception):
    pass


class Recording:
    """Every (step, access point) indicator result of one session, compactly."""

    def __init__(self, cfg: dict, observations: List[dict], monitored: Optional[dict] = None,
                 network_settings: Optional[dict] = None):
        an = analyzer_for(cfg, observations, monitored, network_settings)
        eng = RiskEngine(an, cfg)
        n_aps = len(an.aps())
        if n_aps * len(eng.steps()) > MAX_EVALUATIONS:
            raise TooLarge("{} access points x {} steps is more than this page re-scores ({}); "
                           "use evaluate.py on an exported capture instead".format(
                               n_aps, len(eng.steps()), MAX_EVALUATIONS))
        eng.record = []
        eng.run()
        self.names: Optional[Tuple[str, ...]] = None
        self.rows: List[tuple] = []
        for t, key, res in eng.record:
            if res is None:
                self.rows.append((t, key, None))
                continue
            names = tuple(r.name for r in res)
            if self.names is None:
                self.names = names
            if names != self.names:            # never expected; keep the names if it happens
                self.rows.append((t, key, tuple((r.name, r.value) for r in res)))
            else:
                self.rows.append((t, key, tuple(r.value for r in res)))
        self.network_settings = network_settings or {}
        self.n = int(cfg["temporal"]["smoothing_steps"])

    def _results(self, vals):
        if vals and isinstance(vals[0], tuple):
            return [_R(n, v, "") for n, v in vals]
        return [_R(n, v, "") for n, v in zip(self.names, vals)]

    def rescore(self, weights: Dict[str, float], floors: Dict[str, float],
                thresholds: Dict[str, float]) -> Dict[Tuple[str, str], dict]:
        def thr(ssid):
            med = (self.network_settings.get(ssid) or {}).get("threshold_medium")
            if med is None:
                return thresholds
            return {"medium": float(med), "high": max(float(med) + 1, thresholds["high"])}
        hist: Dict[tuple, deque] = {}
        out: Dict[tuple, dict] = {}
        for t, key, vals in self.rows:
            raw = 0.0 if vals is None else risk_score(self._results(vals), weights, floors)[0]
            h = hist.setdefault(key, deque(maxlen=self.n))
            h.append(raw)
            sm = round(sum(h) / self.n, 2)
            lvl = level_for(sm, thr(key[0]))
            o = out.setdefault(key, {"peak": 0.0, "level": LOW, "first_alert": None})
            o["peak"] = max(o["peak"], sm)
            if _ORDER[lvl] > _ORDER[o["level"]]:
                o["level"] = lvl
            if lvl != LOW and o["first_alert"] is None:
                o["first_alert"] = t
        return out


def validate(body: dict, cfg: dict) -> Tuple[dict, dict, dict]:
    """Weights, signature floors and thresholds from a request, defaulting to the config."""
    weights = dict(cfg["weights"])
    for k, v in (body.get("weights") or {}).items():
        if k not in INDICATOR_NAMES or isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 10:
            raise ValueError("weight {!r} must be a number from 0 to 10".format(k))
        weights[k] = float(v)
    if sum(weights.values()) <= 0:
        raise ValueError("at least one weight must be above 0")
    floors = dict(cfg.get("signatures") or {})
    for k, v in (body.get("signatures") or {}).items():
        if k not in SIGNATURE_NAMES or isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 100:
            raise ValueError("signature {!r} must be a number from 0 to 100".format(k))
        floors[k] = float(v)
    th = dict(cfg["thresholds"])
    for k, v in (body.get("thresholds") or {}).items():
        if k not in ("medium", "high") or isinstance(v, bool) or not isinstance(v, (int, float)) or not 1 <= v <= 100:
            raise ValueError("threshold {!r} must be a number from 1 to 100".format(k))
        th[k] = float(v)
    if th["medium"] >= th["high"]:
        raise ValueError("MEDIUM must be below HIGH")
    return weights, floors, th


def compare(before: dict, after: dict) -> dict:
    """Which access points would alert, stop alerting or change level."""
    rows = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key) or {"peak": 0.0, "level": LOW}, after.get(key) or {"peak": 0.0, "level": LOW}
        change = ("new_alert" if b["level"] == LOW and a["level"] != LOW else
                  "no_longer" if b["level"] != LOW and a["level"] == LOW else
                  "level" if b["level"] != a["level"] else "same")
        rows.append({"ssid": key[0], "bssid": key[1], "peak_now": b["peak"], "level_now": b["level"],
                     "peak_whatif": a["peak"], "level_whatif": a["level"],
                     "first_alert_whatif": a.get("first_alert"), "change": change})
    rows.sort(key=lambda r: (r["change"] == "same", -r["peak_whatif"]))
    count = lambda lv, k: sum(r[k] != LOW for r in rows) if lv is None else sum(r[k] == lv for r in rows)  # noqa: E731
    return {"rows": rows,
            "summary": {"alerts_now": count(None, "level_now"), "alerts_whatif": count(None, "level_whatif"),
                        "high_now": count(HIGH, "level_now"), "high_whatif": count(HIGH, "level_whatif"),
                        "new_alerts": sum(r["change"] == "new_alert" for r in rows),
                        "no_longer": sum(r["change"] == "no_longer" for r in rows)}}
