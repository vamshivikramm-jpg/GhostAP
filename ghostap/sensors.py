"""Several sensors (F044) and rough location (F045).

Each sensor is a normal GhostAP (its own capture, baseline and scores). With
sensors.report_to set, it sends a compact report to a central GhostAP every few seconds:
its health, the access points it hears (with their signal over the last minute) and its
open alerts. Raw frames stay on the sensor. The central dashboard's Sensors page shows
every sensor, which sensors hear each access point, and, when at least three sensors with
known positions hear it, a rough position.

Location uses the log-distance path-loss model
    rssi = P0 - 10 n log10(d)        (P0 = signal at 1 m, n = path-loss exponent)
to turn each sensor's signal into a distance, then least squares for the point that best
fits all distances. Walls, bodies and antennas make this rough: expect errors of several
metres indoors. Calibrate P0 and n with an access point at a known spot.

Sensor side (in config.yaml or on the command line):
    sensors: {name: lab-1, report_to: https://central.local:8050, report_ca: data/central-cert.pem}
    export GHOSTAP_REPORT_KEY=gk_...            # a write API key created on the central server
"""
from __future__ import annotations

import json
import math
import os
import re
import ssl
import threading
import time
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .logs import get_logger
from .storage import Store

log = get_logger("sensors")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAX_APS = 300
ONLINE_S = 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS sensors (
    name       TEXT PRIMARY KEY,
    last_seen  REAL,
    address    TEXT,
    version    TEXT,
    status     TEXT,            -- JSON: state, frames, frames_last_minute, alerts
    x          REAL,            -- position in metres on your floor plan (set on the Sensors page)
    y          REAL
);
CREATE TABLE IF NOT EXISTS sensor_aps (
    sensor   TEXT NOT NULL,
    ssid     TEXT NOT NULL,
    bssid    TEXT NOT NULL,
    rssi     REAL,
    channel  TEXT,
    level    TEXT,
    score    REAL,
    ts       REAL,
    PRIMARY KEY (sensor, ssid, bssid)
);
"""


class ReportError(ValueError):
    pass


# --------------------------------------------------------------------------- sensor side
def build_report(name: str, db: str, status: dict) -> dict:
    """What a sensor sends: health, APs heard in the last minute (with signal), open alerts."""
    with Store(db) as s:
        last = s.conn.execute("SELECT MAX(ts) FROM observations").fetchone()[0]
        recent = {}
        if last is not None:
            for r in s.conn.execute("SELECT ssid, bssid, AVG(rssi), GROUP_CONCAT(DISTINCT channel), COUNT(*) "
                                    "FROM observations WHERE ts > ? GROUP BY ssid, bssid", (last - 60,)):
                recent[(r[0], r[1])] = (r[2], r[3], r[4])
        latest = s.latest()
        alerts = [a for a in s.alerts("ghostap,deauth,flood") if a.get("triage_status") != "false_positive"]
    aps = []
    for (ssid, bssid), (rssi, ch, _n) in sorted(recent.items(), key=lambda kv: -kv[1][2])[:MAX_APS]:
        cur = latest.get((ssid, bssid)) or {}
        aps.append({"ssid": ssid[:64], "bssid": bssid, "rssi": None if rssi is None else round(rssi, 1),
                    "channel": ch, "level": cur.get("level"), "score": cur.get("score")})
    return {"sensor": name, "version": __version__, "sent_at": time.time(),
            "status": {"state": status.get("state"), "mode": status.get("mode"), "frames": status.get("frames"),
                       "frames_last_minute": sum(v[2] for v in recent.values()),
                       "alerts": [{"ssid": a["ssid"][:64], "bssid": a["bssid"], "level": a["level"],
                                   "score": a["score"], "detector": a.get("detector")} for a in alerts[:20]]},
            "aps": aps}


class Reporter(threading.Thread):
    """Sends build_report() to the central server every `every` seconds."""

    def __init__(self, ctx, cfg: dict, key: str):
        super().__init__(name="ghostap-reporter", daemon=True)
        sc = cfg["sensors"]
        self.ctx, self.name, self.key = ctx, sc["name"], key
        self.url = sc["report_to"].rstrip("/") + "/api/sensors/report"
        self.every = float(sc["every_seconds"])
        self.ssl = ssl.create_default_context(cafile=sc["report_ca"] or None) if self.url.startswith("https") else None
        self.stop_event = threading.Event()
        self.last_ok: Optional[float] = None
        self.last_error: Optional[str] = None

    def send_once(self) -> None:
        body = json.dumps(build_report(self.name, self.ctx.db, self.ctx.status_now())).encode()
        while len(body) > 60_000:                         # the central server accepts 64 KB
            rep = json.loads(body)
            rep["aps"] = rep["aps"][: max(1, len(rep["aps"]) * 3 // 4)]
            body = json.dumps(rep).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",  # noqa: S310 - http(s) checked
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.key,
                                              "User-Agent": "GhostAP-sensor/" + __version__})
        with urllib.request.urlopen(req, timeout=10, context=self.ssl) as r:  # noqa: S310
            if r.status != 200:
                raise OSError("HTTP {}".format(r.status))

    def run(self):
        while not self.stop_event.wait(self.every):
            try:
                self.send_once()
                self.last_ok, self.last_error = time.time(), None
            except Exception as e:  # network down, wrong key: keep trying, show it
                if self.last_error is None:
                    log.warning("sensor report to %s failed: %s", self.url, e)
                self.last_error = "{}: {}".format(type(e).__name__, e)


# --------------------------------------------------------------------------- central side
def ensure_schema(admin_db: str) -> None:
    with Store(admin_db) as s:
        s.conn.executescript(SCHEMA)


def record_report(admin_db: str, rep: dict, address: str) -> int:
    """Validate and store one report; returns the number of access points stored."""
    if not isinstance(rep, dict) or not NAME_RE.match(str(rep.get("sensor", ""))):
        raise ReportError("sensor must be a name of 1-40 letters, digits, . _ -")
    aps = rep.get("aps")
    if not isinstance(aps, list) or len(aps) > MAX_APS:
        raise ReportError("aps must be a list of at most {}".format(MAX_APS))
    clean = []
    for a in aps:
        if not isinstance(a, dict) or not isinstance(a.get("ssid"), str) or not MAC_RE.match(str(a.get("bssid", ""))):
            raise ReportError("every access point needs ssid and bssid")
        rssi = a.get("rssi")
        if rssi is not None and (isinstance(rssi, bool) or not isinstance(rssi, (int, float)) or not -120 <= rssi <= 0):
            raise ReportError("rssi must be a number from -120 to 0")
        score = a.get("score")
        if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float))):
            raise ReportError("score must be a number")
        level = a.get("level") if a.get("level") in ("LOW", "MEDIUM", "HIGH") else None
        clean.append((a["ssid"][:64], a["bssid"], rssi, str(a.get("channel") or "")[:40], level, score))
    status = rep.get("status") if isinstance(rep.get("status"), dict) else {}
    now = time.time()
    with Store(admin_db) as s:
        s.conn.execute("INSERT INTO sensors (name, last_seen, address, version, status) VALUES (?, ?, ?, ?, ?) "
                       "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, address=excluded.address, "
                       "version=excluded.version, status=excluded.status",
                       (rep["sensor"], now, address[:64], str(rep.get("version", ""))[:20], json.dumps(status)[:20000]))
        s.conn.execute("DELETE FROM sensor_aps WHERE sensor = ?", (rep["sensor"],))
        s.conn.executemany("INSERT OR REPLACE INTO sensor_aps VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           [(rep["sensor"],) + c + (now,) for c in clean])
        s.conn.commit()
    return len(clean)


def fleet(admin_db: str) -> List[dict]:
    with Store(admin_db) as s:
        rows = [dict(r) for r in s.conn.execute("SELECT * FROM sensors ORDER BY name")]
        counts = dict(s.conn.execute("SELECT sensor, COUNT(*) FROM sensor_aps GROUP BY sensor").fetchall())
    for r in rows:
        r["status"] = json.loads(r["status"] or "{}")
        r["online"] = r["last_seen"] is not None and time.time() - r["last_seen"] < ONLINE_S
        r["aps"] = counts.get(r["name"], 0)
    return rows


# --------------------------------------------------------------------------- F045 location
def distance(rssi: float, p0: float, n: float) -> float:
    return 10 ** ((p0 - rssi) / (10 * n))


def locate(points: Sequence[Tuple[float, float, float]], p0: float = -40.0, n: float = 3.0) -> Optional[dict]:
    """points: (x, y, rssi) for each sensor that hears the AP. Returns the estimate with an
    uncertainty radius, or the nearest sensor when fewer than three sensors hear it."""
    pts = [(float(x), float(y), distance(r, p0, n)) for x, y, r in points if r is not None]
    if not pts:
        return None
    if len(pts) < 3:
        x, y, d = min(pts, key=lambda p: p[2])
        return {"x": x, "y": y, "radius": d, "method": "nearest sensor ({} heard it)".format(len(pts)),
                "sensors": len(pts)}
    # start at the signal-weighted centre, then Gauss-Newton on Σ w (|p - s| - d)^2
    w = [1 / max(d, 0.5) ** 2 for _, _, d in pts]
    px = sum(wi * x for wi, (x, _, _) in zip(w, pts)) / sum(w)
    py = sum(wi * y for wi, (_, y, _) in zip(w, pts)) / sum(w)
    for _ in range(50):
        jtj = [[0.0, 0.0], [0.0, 0.0]]
        jtr = [0.0, 0.0]
        for wi, (x, y, d) in zip(w, pts):
            dist = math.hypot(px - x, py - y) or 1e-6
            jx, jy, res = (px - x) / dist, (py - y) / dist, dist - d
            jtj[0][0] += wi * jx * jx
            jtj[0][1] += wi * jx * jy
            jtj[1][1] += wi * jy * jy
            jtr[0] += wi * jx * res
            jtr[1] += wi * jy * res
        jtj[1][0] = jtj[0][1]
        det = jtj[0][0] * jtj[1][1] - jtj[0][1] ** 2
        if abs(det) < 1e-12:
            break
        dx = (jtj[1][1] * jtr[0] - jtj[0][1] * jtr[1]) / det
        dy = (jtj[0][0] * jtr[1] - jtj[1][0] * jtr[0]) / det
        px, py = px - dx, py - dy
        if math.hypot(dx, dy) < 1e-4:
            break
    rms = math.sqrt(sum((math.hypot(px - x, py - y) - d) ** 2 for x, y, d in pts) / len(pts))
    return {"x": round(px, 2), "y": round(py, 2), "radius": round(max(rms, 1.0), 2),
            "method": "trilateration from {} sensors".format(len(pts)), "sensors": len(pts)}


def merged(admin_db: str, p0: float, n: float) -> List[dict]:
    """Every access point heard by any online sensor, with per-sensor signal and a position."""
    sensors = {s["name"]: s for s in fleet(admin_db) if s["online"]}
    with Store(admin_db) as s:
        rows = [dict(r) for r in s.conn.execute("SELECT * FROM sensor_aps")]
    by: Dict[Tuple[str, str], List[dict]] = {}
    for r in rows:
        if r["sensor"] in sensors:
            by.setdefault((r["ssid"], r["bssid"]), []).append(r)
    order = {"HIGH": 2, "MEDIUM": 1}
    out = []
    for (ssid, bssid), hs in by.items():
        placed = [(sensors[h["sensor"]]["x"], sensors[h["sensor"]]["y"], h["rssi"]) for h in hs
                  if sensors[h["sensor"]]["x"] is not None and h["rssi"] is not None]
        lv = max((h["level"] for h in hs if h["level"]), key=lambda v: order.get(v, 0), default=None)
        out.append({"ssid": ssid, "bssid": bssid, "level": lv, "score": max((h["score"] or 0) for h in hs),
                    "heard_by": [{"sensor": h["sensor"], "rssi": h["rssi"], "level": h["level"]} for h in hs],
                    "location": locate(placed, p0, n) if placed else None})
    out.sort(key=lambda a: (-order.get(a["level"] or "", 0), -a["score"], a["ssid"]))
    return out


def report_key(cfg: dict) -> Optional[str]:
    return os.environ.get(cfg["sensors"]["report_key_env"] or "") or None
