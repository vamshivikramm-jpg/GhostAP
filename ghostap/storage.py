"""SQLite storage for raw observations and per-AP profiles."""
from __future__ import annotations

import json
import os
import sqlite3
from typing import List, Optional, Tuple

OBS_FIELDS = (
    "ts", "frame_type", "ssid", "bssid", "oui", "channel",
    "security", "rssi", "beacon_interval", "tsf", "seq", "fingerprint",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    frame_type      TEXT    NOT NULL,
    ssid            TEXT    NOT NULL,
    bssid           TEXT    NOT NULL,
    oui             TEXT,
    channel         INTEGER,
    security        TEXT,
    rssi            INTEGER,
    beacon_interval INTEGER,
    tsf             INTEGER,
    seq             INTEGER,
    fingerprint     TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ssid  ON observations(ssid);
CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observations(bssid);

CREATE TABLE IF NOT EXISTS ap_profiles (
    ssid        TEXT    NOT NULL,
    bssid       TEXT    NOT NULL,
    first_seen  REAL,
    last_seen   REAL,
    frames      INTEGER,
    channels    TEXT,
    securities  TEXT,
    rssi_min    INTEGER,
    rssi_max    INTEGER,
    rssi_avg    REAL,
    PRIMARY KEY (ssid, bssid)
);

-- Phase 4: one alert per (detector, ssid, bssid); updated as it escalates.
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detector      TEXT    NOT NULL,          -- 'ghostap' or 'baseline'
    ssid          TEXT    NOT NULL,
    bssid         TEXT    NOT NULL,
    level         TEXT    NOT NULL,          -- highest level reached: MEDIUM / HIGH
    score         REAL    NOT NULL,          -- peak smoothed risk score (0-100)
    first_ts      REAL    NOT NULL,          -- first time the alert fired
    high_ts       REAL,                      -- first time it reached HIGH
    peak_ts       REAL,                      -- time of the peak score
    last_ts       REAL,                      -- last time it was at MEDIUM or above
    indicators    TEXT,                      -- JSON: [{name, value, weight, contribution, reason}]
    reasons       TEXT,                      -- human-readable summary
    benign_causes TEXT,                      -- JSON: [str]
    triage_status TEXT DEFAULT 'new',        -- analyst: new / investigating / confirmed / false_positive
    triage_note   TEXT,
    triage_ts     REAL,
    UNIQUE (detector, ssid, bssid)
);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score);

-- Latest score and indicator breakdown of every AP (for the dashboard's AP view).
CREATE TABLE IF NOT EXISTS ap_latest (
    ssid        TEXT NOT NULL,
    bssid       TEXT NOT NULL,
    ts          REAL NOT NULL,
    raw_score   REAL NOT NULL,
    score       REAL NOT NULL,
    level       TEXT NOT NULL,
    indicators  TEXT,                         -- JSON, same shape as alerts.indicators
    PRIMARY KEY (ssid, bssid)
);

-- Phase 4: risk score of every AP at every evaluation step.
CREATE TABLE IF NOT EXISTS risk_timeline (
    ts          REAL NOT NULL,
    ssid        TEXT NOT NULL,
    bssid       TEXT NOT NULL,
    raw_score   REAL NOT NULL,
    score       REAL NOT NULL,                -- smoothed
    level       TEXT NOT NULL,
    PRIMARY KEY (ts, ssid, bssid)
);
"""

ALERT_FIELDS = (
    "detector", "ssid", "bssid", "level", "score", "first_ts", "high_ts",
    "peak_ts", "last_ts", "indicators", "reasons", "benign_causes",
)
_JSON_ALERT_FIELDS = ("indicators", "benign_causes")

_INSERT = "INSERT INTO observations ({}) VALUES ({})".format(
    ", ".join(OBS_FIELDS), ", ".join("?" for _ in OBS_FIELDS)
)

_REBUILD = """
INSERT INTO ap_profiles
    (ssid, bssid, first_seen, last_seen, frames, channels, securities,
     rssi_min, rssi_max, rssi_avg)
SELECT ssid, bssid, MIN(ts), MAX(ts), COUNT(*),
       GROUP_CONCAT(DISTINCT channel), GROUP_CONCAT(DISTINCT security),
       MIN(rssi), MAX(rssi), AVG(rssi)
FROM observations
GROUP BY ssid, bssid
"""


class Store:
    BATCH_SIZE = 200

    def __init__(self, path: str = "data/ghostap.db"):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        # WAL lets the dashboard read while a replay / live capture writes.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self._pending = 0

    def _migrate(self) -> None:
        """Add columns introduced after a database was created (older GhostAP versions)."""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(observations)")}
        if "fingerprint" not in cols:
            self.conn.execute("ALTER TABLE observations ADD COLUMN fingerprint TEXT")
        acols = {r[1] for r in self.conn.execute("PRAGMA table_info(alerts)")}
        for col, decl in (("triage_status", "TEXT DEFAULT 'new'"), ("triage_note", "TEXT"),
                          ("triage_ts", "REAL")):
            if col not in acols:
                self.conn.execute("ALTER TABLE alerts ADD COLUMN {} {}".format(col, decl))
        self.conn.commit()

    def add(self, obs: dict) -> None:
        self.conn.execute(_INSERT, tuple(obs.get(f) for f in OBS_FIELDS))
        self._pending += 1
        if self._pending >= self.BATCH_SIZE:
            self.commit()

    def commit(self) -> None:
        self.conn.commit()
        self._pending = 0

    def rebuild_profiles(self) -> None:
        self.commit()
        with self.conn:
            self.conn.execute("DELETE FROM ap_profiles")
            self.conn.execute(_REBUILD)

    def reset(self) -> None:
        with self.conn:
            for table in ("observations", "ap_profiles", "alerts", "risk_timeline", "ap_latest"):
                self.conn.execute("DELETE FROM {}".format(table))

    def profiles(self) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM ap_profiles ORDER BY ssid, bssid"
        ).fetchall()
        return [dict(r) for r in rows]

    def observations(self, until: Optional[float] = None) -> List[dict]:
        """All observations in time order, optionally only those with ts <= until."""
        sql = "SELECT {} FROM observations".format(", ".join(OBS_FIELDS))
        params: tuple = ()
        if until is not None:
            sql += " WHERE ts <= ?"
            params = (until,)
        sql += " ORDER BY ts, id"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def observations_after(self, last_id: int = 0) -> Tuple[List[dict], int]:
        """Observations with id > last_id (arrival order) and the new highest id."""
        rows = self.conn.execute(
            "SELECT id, {} FROM observations WHERE id > ? ORDER BY id".format(", ".join(OBS_FIELDS)),
            (last_id,)).fetchall()
        if not rows:
            return [], last_id
        out = []
        for r in rows:
            d = dict(r)
            d.pop("id")
            out.append(d)
        return out, rows[-1]["id"]

    # ---- Phase 4: alerts and risk timeline ------------------------------- #

    def save_alerts(self, detector: str, alerts: List[dict]) -> None:
        """Make the stored alerts of one detector equal to `alerts`.

        Existing rows are updated in place (upsert on detector+ssid+bssid), so an
        alert keeps its id while it is rescored; alerts that disappeared are removed.
        """
        cols = ", ".join(ALERT_FIELDS)
        updates = ", ".join("{0}=excluded.{0}".format(f) for f in ALERT_FIELDS
                            if f not in ("detector", "ssid", "bssid"))
        sql = ("INSERT INTO alerts ({}) VALUES ({}) "
               "ON CONFLICT(detector, ssid, bssid) DO UPDATE SET {}").format(
            cols, ", ".join("?" for _ in ALERT_FIELDS), updates)
        keep = {(a["ssid"], a["bssid"]) for a in alerts}
        with self.conn:
            for a in alerts:
                row = dict(a, detector=detector)
                for f in _JSON_ALERT_FIELDS:
                    row[f] = json.dumps(row.get(f) or [])
                self.conn.execute(sql, tuple(row.get(f) for f in ALERT_FIELDS))
            for r in self.conn.execute(
                    "SELECT id, ssid, bssid FROM alerts WHERE detector = ?", (detector,)).fetchall():
                if (r["ssid"], r["bssid"]) not in keep:
                    self.conn.execute("DELETE FROM alerts WHERE id = ?", (r["id"],))

    def alert(self, alert_id: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        for f in _JSON_ALERT_FIELDS:
            d[f] = json.loads(d[f]) if d[f] else []
        return d

    def alerts(self, detector: Optional[str] = None) -> List[dict]:
        """Alerts ordered by risk (highest first)."""
        sql = "SELECT * FROM alerts"
        params: tuple = ()
        if detector:
            sql += " WHERE detector = ?"
            params = (detector,)
        sql += " ORDER BY score DESC, first_ts"
        out = []
        for r in self.conn.execute(sql, params).fetchall():
            d = dict(r)
            for f in _JSON_ALERT_FIELDS:
                d[f] = json.loads(d[f]) if d[f] else []
            out.append(d)
        return out

    def save_timeline(self, rows: List[dict]) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM risk_timeline")
            self.conn.executemany(
                "INSERT INTO risk_timeline (ts, ssid, bssid, raw_score, score, level) "
                "VALUES (:ts, :ssid, :bssid, :raw_score, :score, :level)", rows)

    def append_timeline(self, rows: List[dict]) -> None:
        """Add (or overwrite) risk-timeline rows without touching older ones."""
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO risk_timeline (ts, ssid, bssid, raw_score, score, level) "
                "VALUES (:ts, :ssid, :bssid, :raw_score, :score, :level)", rows)

    def timeline(self, ssid: Optional[str] = None, bssid: Optional[str] = None) -> List[dict]:
        sql, params = "SELECT * FROM risk_timeline WHERE 1=1", []
        if ssid is not None:
            sql += " AND ssid = ?"
            params.append(ssid)
        if bssid is not None:
            sql += " AND bssid = ?"
            params.append(bssid)
        sql += " ORDER BY ts, ssid, bssid"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    # ---- dashboard: latest per-AP breakdown and analyst triage ---------------- #

    TRIAGE_STATES = ("new", "investigating", "confirmed", "false_positive")

    def save_latest(self, rows: List[dict]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO ap_latest (ssid, bssid, ts, raw_score, score, level, indicators) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(r["ssid"], r["bssid"], r["ts"], r["raw_score"], r["score"], r["level"],
                  json.dumps(r.get("indicators") or [])) for r in rows])

    def latest(self) -> dict:
        """{(ssid, bssid): latest score row with decoded indicators}"""
        out = {}
        for r in self.conn.execute("SELECT * FROM ap_latest").fetchall():
            d = dict(r)
            d["indicators"] = json.loads(d["indicators"]) if d["indicators"] else []
            out[(d["ssid"], d["bssid"])] = d
        return out

    def set_triage(self, alert_id: int, status: str, note: Optional[str], ts: float) -> bool:
        if status not in self.TRIAGE_STATES:
            raise ValueError("unknown triage status: {}".format(status))
        with self.conn:
            cur = self.conn.execute(
                "UPDATE alerts SET triage_status = ?, triage_note = ?, triage_ts = ? WHERE id = ?",
                (status, (note or "")[:2000], ts, alert_id))
        return cur.rowcount > 0

    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
