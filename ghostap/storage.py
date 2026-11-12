"""SQLite storage for raw observations and per-AP profiles."""
from __future__ import annotations

import os
import sqlite3
from typing import List, Optional

OBS_FIELDS = (
    "ts", "frame_type", "ssid", "bssid", "oui", "channel",
    "security", "rssi", "beacon_interval", "tsf", "seq",
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
    seq             INTEGER
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
"""

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
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._pending = 0

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
            self.conn.execute("DELETE FROM observations")
            self.conn.execute("DELETE FROM ap_profiles")

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

    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
