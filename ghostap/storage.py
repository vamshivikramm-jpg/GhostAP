"""SQLite storage for raw observations and per-AP profiles."""
from __future__ import annotations

import json
import os
import sqlite3
from typing import List, Optional, Tuple

OBS_FIELDS = (
    "ts", "frame_type", "ssid", "bssid", "oui", "channel",
    "security", "rssi", "beacon_interval", "tsf", "seq", "fingerprint", "rsn", "freq",
)
EVENT_FIELDS = ("ts", "kind", "bssid", "broadcast", "reason", "rssi", "freq")

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
    fingerprint     TEXT,
    rsn             TEXT,             -- 'pw=CCMP;akm=PSK;pmf=none' (F004)
    freq            INTEGER           -- MHz from the radio header (F009)
);

-- F028: what each beacon fingerprint is made of (one row per distinct fingerprint)
CREATE TABLE IF NOT EXISTS layouts (
    fingerprint TEXT PRIMARY KEY,
    layout      TEXT NOT NULL,        -- JSON list, see parser.beacon_layout
    first_ts    REAL,
    ssid        TEXT,
    bssid       TEXT
);

-- F037: analyst notes on the timeline ("plugged in the hotspot", "attack started")
CREATE TABLE IF NOT EXISTS annotations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL    NOT NULL,        -- capture time the note refers to
    text     TEXT    NOT NULL,
    actor    TEXT,
    created  REAL
);

-- F005: deauthentication / disassociation frames (AP address only, no client addresses)
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    kind       TEXT    NOT NULL,      -- deauth | disassoc
    bssid      TEXT    NOT NULL,
    broadcast  INTEGER,
    reason     INTEGER,
    rssi       INTEGER,
    freq       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_bssid ON events(bssid, ts);
CREATE INDEX IF NOT EXISTS idx_obs_ssid  ON observations(ssid);
CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observations(bssid);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);

-- F026: mute an access point or a whole network for a while (kept in the admin database)
CREATE TABLE IF NOT EXISTS mutes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,          -- bssid | ssid
    value      TEXT NOT NULL,
    until_ts   REAL NOT NULL,
    created_ts REAL NOT NULL,
    actor      TEXT,
    note       TEXT
);

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
    rssi_n      INTEGER,                      -- frames with an RSSI (for incremental averages)
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

-- F069: permanent record of analyst and admin actions.
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    actor   TEXT NOT NULL,             -- account name, "token", "local" or "system"
    action  TEXT NOT NULL,             -- e.g. triage, baseline.save, settings.save
    target  TEXT,
    detail  TEXT                       -- JSON
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

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
     rssi_min, rssi_max, rssi_avg, rssi_n)
SELECT ssid, bssid, MIN(ts), MAX(ts), COUNT(*),
       GROUP_CONCAT(DISTINCT channel), GROUP_CONCAT(DISTINCT security),
       MIN(rssi), MAX(rssi), AVG(rssi), COUNT(rssi)
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
        new_file = not os.path.exists(path)
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        if new_file:
            # lets retention (F070) give pruned space back with PRAGMA incremental_vacuum
            self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        # WAL lets the dashboard read while a replay / live capture writes.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self._pending = 0
        self._layouts_seen: set = set()

    def _migrate(self) -> None:
        """Add columns introduced after a database was created (older GhostAP versions)."""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(observations)")}
        for col, decl in (("fingerprint", "TEXT"), ("rsn", "TEXT"), ("freq", "INTEGER")):
            if col not in cols:
                self.conn.execute("ALTER TABLE observations ADD COLUMN {} {}".format(col, decl))
        pcols = {r[1] for r in self.conn.execute("PRAGMA table_info(ap_profiles)")}
        if "rssi_n" not in pcols:
            self.conn.execute("ALTER TABLE ap_profiles ADD COLUMN rssi_n INTEGER")
        acols = {r[1] for r in self.conn.execute("PRAGMA table_info(alerts)")}
        for col, decl in (("triage_status", "TEXT DEFAULT 'new'"), ("triage_note", "TEXT"),
                          ("triage_ts", "REAL")):
            if col not in acols:
                self.conn.execute("ALTER TABLE alerts ADD COLUMN {} {}".format(col, decl))
        self.conn.commit()

    def add(self, obs: dict) -> None:
        self.conn.execute(_INSERT, tuple(obs.get(f) for f in OBS_FIELDS))
        fp = obs.get("fingerprint")
        if fp and obs.get("layout") and fp not in self._layouts_seen:
            self._layouts_seen.add(fp)
            self.conn.execute("INSERT OR IGNORE INTO layouts VALUES (?, ?, ?, ?, ?)",
                              (fp, json.dumps(obs["layout"]), obs.get("ts"), obs.get("ssid"), obs.get("bssid")))
        self._pending += 1
        if self._pending >= self.BATCH_SIZE:
            self.commit()

    # ---- F037 annotations ---------------------------------------------------- #
    def add_annotation(self, ts: float, text: str, actor: str, created: float) -> int:
        cur = self.conn.execute("INSERT INTO annotations (ts, text, actor, created) VALUES (?, ?, ?, ?)",
                                (ts, text, actor, created))
        self.conn.commit()
        return cur.lastrowid

    def annotations(self) -> List[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM annotations ORDER BY ts, id")]

    def delete_annotation(self, ann_id: int) -> bool:
        n = self.conn.execute("DELETE FROM annotations WHERE id = ?", (ann_id,)).rowcount
        self.conn.commit()
        return n > 0

    def add_event(self, ev: dict) -> None:
        """F005: one deauthentication / disassociation frame."""
        self.conn.execute(
            "INSERT INTO events ({}) VALUES ({})".format(
                ", ".join(EVENT_FIELDS), ", ".join("?" for _ in EVENT_FIELDS)),
            tuple(int(ev[f]) if f == "broadcast" else ev.get(f) for f in EVENT_FIELDS))
        self._pending += 1
        if self._pending >= self.BATCH_SIZE:
            self.commit()

    def events_after(self, last_id: int = 0) -> Tuple[List[dict], int]:
        rows = self.conn.execute(
            "SELECT id, {} FROM events WHERE id > ? ORDER BY id".format(", ".join(EVENT_FIELDS)),
            (last_id,)).fetchall()
        if not rows:
            return [], last_id
        return [{k: r[k] for k in EVENT_FIELDS} for r in rows], rows[-1]["id"]

    def commit(self) -> None:
        self.conn.commit()
        self._pending = 0

    def rebuild_profiles(self) -> None:
        self.commit()
        with self.conn:
            self.conn.execute("DELETE FROM ap_profiles")
            self.conn.execute(_REBUILD)

    def clear_profiles(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM ap_profiles")

    def update_profiles(self, observations: List[dict]) -> int:
        """Merge new observations into ap_profiles without rescanning old ones.

        Gives the same result as rebuild_profiles() over all observations, at a cost
        proportional to the new data only (the live dashboard calls this every round).
        Returns the number of APs touched.
        """
        agg: dict = {}
        for o in observations:
            a = agg.get((o["ssid"], o["bssid"]))
            if a is None:
                a = agg[(o["ssid"], o["bssid"])] = {
                    "first": o["ts"], "last": o["ts"], "frames": 0, "channels": set(),
                    "securities": set(), "rmin": None, "rmax": None, "rsum": 0, "rn": 0}
            a["first"], a["last"] = min(a["first"], o["ts"]), max(a["last"], o["ts"])
            a["frames"] += 1
            if o.get("channel") is not None:
                a["channels"].add(int(o["channel"]))
            if o.get("security"):
                a["securities"].add(o["security"])
            r = o.get("rssi")
            if r is not None:
                a["rmin"] = r if a["rmin"] is None else min(a["rmin"], r)
                a["rmax"] = r if a["rmax"] is None else max(a["rmax"], r)
                a["rsum"] += r
                a["rn"] += 1
        if not agg:
            return 0
        self.commit()
        with self.conn:
            for (ssid, bssid), a in agg.items():
                old = self.conn.execute(
                    "SELECT * FROM ap_profiles WHERE ssid = ? AND bssid = ?", (ssid, bssid)).fetchone()
                chans, secs = set(a["channels"]), set(a["securities"])
                first, last, frames = a["first"], a["last"], a["frames"]
                rmin, rmax, rsum, rn = a["rmin"], a["rmax"], a["rsum"], a["rn"]
                if old is not None:
                    chans |= {int(c) for c in (old["channels"] or "").split(",") if c}
                    secs |= {x for x in (old["securities"] or "").split(",") if x}
                    first, last = min(first, old["first_seen"]), max(last, old["last_seen"])
                    frames += old["frames"] or 0
                    old_n = old["rssi_n"] if old["rssi_n"] is not None else (old["frames"] or 0)
                    if old["rssi_avg"] is not None and old_n:
                        rsum += old["rssi_avg"] * old_n
                        rn += old_n
                        rmin = old["rssi_min"] if rmin is None else min(rmin, old["rssi_min"])
                        rmax = old["rssi_max"] if rmax is None else max(rmax, old["rssi_max"])
                self.conn.execute(
                    "INSERT OR REPLACE INTO ap_profiles (ssid, bssid, first_seen, last_seen, frames, "
                    "channels, securities, rssi_min, rssi_max, rssi_avg, rssi_n) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ssid, bssid, first, last, frames, ",".join(str(c) for c in sorted(chans)) or None,
                     ",".join(sorted(secs)) or None, rmin, rmax, (rsum / rn) if rn else None, rn))
        return len(agg)

    def reset(self) -> None:
        with self.conn:
            for table in ("observations", "ap_profiles", "alerts", "risk_timeline", "ap_latest", "events"):
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
            names = [d for d in detector.split(",") if d]
            sql += " WHERE detector IN ({})".format(", ".join("?" for _ in names))
            params = tuple(names)
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

    # ---- F026 mutes --------------------------------------------------------------- #

    def add_mute(self, kind: str, value: str, until_ts: float, actor: str, note: str = "") -> int:
        import time as _time
        if kind not in ("bssid", "ssid"):
            raise ValueError("kind must be bssid or ssid")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO mutes (kind, value, until_ts, created_ts, actor, note) VALUES (?, ?, ?, ?, ?, ?)",
                (kind, value.lower() if kind == "bssid" else value, until_ts, _time.time(), actor, note[:500]))
        return cur.lastrowid

    def active_mutes(self, now: float) -> List[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM mutes WHERE until_ts > ? ORDER BY until_ts", (now,)).fetchall()]

    def delete_mute(self, mute_id: int) -> bool:
        with self.conn:
            return self.conn.execute("DELETE FROM mutes WHERE id = ?", (mute_id,)).rowcount > 0

    # ---- F069 audit log -------------------------------------------------------- #

    def audit(self, actor: str, action: str, target: Optional[str] = None,
              detail: Optional[dict] = None, ts: Optional[float] = None) -> None:
        import time as _time
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
                (ts if ts is not None else _time.time(), actor, action, target,
                 json.dumps(detail or {})))

    def audit_log(self, limit: int = 200, action: Optional[str] = None) -> List[dict]:
        sql, params = "SELECT * FROM audit", []
        if action:
            sql += " WHERE action = ?"
            params.append(action)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(int(limit))
        out = []
        for r in self.conn.execute(sql, params).fetchall():
            d = dict(r)
            d["detail"] = json.loads(d["detail"]) if d["detail"] else {}
            out.append(d)
        return out

    # ---- F070 retention ---------------------------------------------------------- #

    def prune_observations(self, before_ts: float, keep_head: int = 50) -> int:
        """Delete raw frames older than `before_ts`, keeping each AP's first `keep_head`
        frames (GhostAP needs them for 'uptime when first seen'). AP profiles, alerts and
        the risk timeline are unaffected. Returns the number of rows deleted."""
        self.commit()
        with self.conn:
            cur = self.conn.execute(
                "DELETE FROM observations WHERE ts < ? AND id NOT IN ("
                " SELECT id FROM (SELECT id, ROW_NUMBER() OVER ("
                "   PARTITION BY ssid, bssid ORDER BY ts, id) AS rn FROM observations) WHERE rn <= ?)",
                (before_ts, keep_head))
        deleted = cur.rowcount
        if deleted:
            self.conn.execute("PRAGMA incremental_vacuum")
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted

    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
