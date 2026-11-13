"""Sessions (F040): every replay or live run is kept in its own folder.

    data/sessions/<id>/
        session.db     observations, alerts, timeline ... (storage.Store)
        meta.json      name, mode, source, start / end times
        capture.pcap   live runs: the recorded beacons (evidence, Phase 2 labelling)

Session ids are generated here and validated strictly on every lookup, so an id coming
from a URL can never point outside the sessions directory.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from typing import List, Optional

_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}(-[0-9]+)?-[a-z0-9-]{1,40}$")


class SessionError(ValueError):
    pass


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s or "session")[:40].strip("-") or "session"


@dataclass
class Session:
    id: str
    path: str

    @property
    def db(self) -> str:
        return os.path.join(self.path, "session.db")

    @property
    def pcap(self) -> str:
        return os.path.join(self.path, "capture.pcap")

    @property
    def meta_path(self) -> str:
        return os.path.join(self.path, "meta.json")

    def meta(self) -> dict:
        try:
            with open(self.meta_path) as f:
                m = json.load(f)
        except (OSError, ValueError):
            m = {}
        m.setdefault("id", self.id)
        m.setdefault("name", self.id)
        return m

    def update_meta(self, **changes) -> dict:
        m = self.meta()
        m.update(changes)
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(m, f, indent=2)
        os.replace(tmp, self.meta_path)
        return m


class SessionStore:
    def __init__(self, root: str = "data/sessions"):
        self.root = root

    def _path(self, sid: str) -> str:
        if not isinstance(sid, str) or not _ID_RE.match(sid):
            raise SessionError("invalid session id")
        path = os.path.realpath(os.path.join(self.root, sid))
        if os.path.dirname(path) != os.path.realpath(self.root):
            raise SessionError("invalid session id")
        return path

    def create(self, name: str, mode: str, source: str = "", now: Optional[float] = None) -> Session:
        now = time.time() if now is None else now
        os.makedirs(self.root, exist_ok=True)
        base = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
        slug = _slug(name)
        sid, n = "{}-{}".format(base, slug), 1
        while os.path.exists(os.path.join(self.root, sid)):
            n += 1
            sid = "{}-{}-{}".format(base, n, slug)
        s = Session(sid, os.path.join(self.root, sid))
        os.makedirs(s.path)
        s.update_meta(id=sid, name=name or slug, mode=mode, source=source,
                      started_at=now, ended_at=None)
        return s

    def get(self, sid: str) -> Session:
        path = self._path(sid)
        if not os.path.isfile(os.path.join(path, "session.db")) and \
                not os.path.isfile(os.path.join(path, "meta.json")):
            raise SessionError("no such session")
        return Session(sid, path)

    def list(self) -> List[dict]:
        """Newest first, with sizes and headline numbers read from each database."""
        if not os.path.isdir(self.root):
            return []
        out = []
        for sid in os.listdir(self.root):
            if not _ID_RE.match(sid):
                continue
            s = Session(sid, os.path.join(self.root, sid))
            m = s.meta()
            m["size_bytes"] = sum(os.path.getsize(os.path.join(s.path, f))
                                  for f in os.listdir(s.path) if os.path.isfile(os.path.join(s.path, f)))
            m["has_pcap"] = os.path.isfile(s.pcap)
            m.update(_headline(s.db))
            out.append(m)
        out.sort(key=lambda m: (m.get("started_at") or 0, m["id"]), reverse=True)
        return out

    def latest(self) -> Optional[Session]:
        items = self.list()
        return self.get(items[0]["id"]) if items else None

    def rename(self, sid: str, name: str) -> dict:
        name = (name or "").strip()
        if not name or len(name) > 120:
            raise SessionError("name must be 1-120 characters")
        return self.get(sid).update_meta(name=name)

    def delete(self, sid: str) -> None:
        s = self.get(sid)
        shutil.rmtree(s.path)


def _headline(db: str) -> dict:
    """Frames / APs / alerts for the sessions list, without opening a Store (no migrations)."""
    import sqlite3
    if not os.path.isfile(db):
        return {"frames": 0, "aps": 0, "alerts_high": 0, "alerts_medium": 0}
    try:
        conn = sqlite3.connect("file:{}?mode=ro".format(db), uri=True, timeout=5)
        try:
            frames, aps, t0, t1 = conn.execute(
                "SELECT COALESCE(SUM(frames),0), COUNT(*), MIN(first_seen), MAX(last_seen) "
                "FROM ap_profiles").fetchone()
            levels = dict(conn.execute(
                "SELECT level, COUNT(*) FROM alerts WHERE detector='ghostap' GROUP BY level").fetchall())
        finally:
            conn.close()
    except sqlite3.Error:
        return {"frames": 0, "aps": 0, "alerts_high": 0, "alerts_medium": 0}
    return {"frames": frames, "aps": aps, "capture_start": t0, "capture_end": t1,
            "alerts_high": levels.get("HIGH", 0), "alerts_medium": levels.get("MEDIUM", 0)}
