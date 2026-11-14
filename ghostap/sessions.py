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


_PCAP_MAGIC = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
               b"\x0a\x0d\x0d\x0a")                     # pcap (us / ns, both byte orders), pcapng


def is_pcap(path: str) -> bool:
    """True for an existing pcap / pcapng file (checked by its first bytes, not its name)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) in _PCAP_MAGIC
    except OSError:
        return False


def recording_of(session: "Session") -> "str | None":
    """The pcap behind a session: its own capture.pcap, else the file a replay read.

    The replayed path comes from meta.json, which GhostAP writes itself. Imported bundles
    have their source removed (import_bundle), and the file must really be a pcap, so a
    session can never be made to point evidence or label exports at another file."""
    if is_pcap(session.pcap):
        return session.pcap
    m = session.meta()
    src = m.get("source")
    if m.get("mode") == "replay" and not m.get("imported_from") and src and is_pcap(src):
        return src
    return None


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


# --------------------------------------------------------------------------- F054 bundles
BUNDLE_FILES = ("session.db", "meta.json", "capture.pcap", "labels.json")
MAX_BUNDLE_BYTES = 2 * 1024 ** 3


def export_bundle(session: Session, dest) -> dict:
    """Write a zip of the session to `dest` (path or file object): a consistent copy of the
    database (SQLite backup API, safe while capturing), meta, pcap and labels, plus
    manifest.json with a SHA-256 of every file."""
    import hashlib
    import sqlite3
    import tempfile
    import zipfile
    manifest = {"format": "ghostap-session-bundle", "version": 1, "session": session.id,
                "created_at": time.time(), "files": {}}
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "session.db")
        if os.path.isfile(session.db):
            src = sqlite3.connect("file:{}?mode=ro".format(session.db), uri=True)
            dst = sqlite3.connect(snap)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name in BUNDLE_FILES:
                path = snap if name == "session.db" else os.path.join(session.path, name)
                if not os.path.isfile(path):
                    continue
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                manifest["files"][name] = {"sha256": h.hexdigest(), "bytes": os.path.getsize(path)}
                z.write(path, arcname=name)
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
    return manifest


def import_bundle(store: "SessionStore", path: str) -> Session:
    """Unpack a bundle as a new session. Only the known file names are accepted (no paths,
    so nothing can be written outside the new folder) and every checksum must match."""
    import hashlib
    import zipfile
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        if "manifest.json" not in names or "session.db" not in names:
            raise SessionError("not a GhostAP session bundle (manifest.json or session.db missing)")
        extra = names - set(BUNDLE_FILES) - {"manifest.json"}
        if extra:
            raise SessionError("unexpected files in the bundle: " + ", ".join(sorted(extra))[:200])
        if sum(i.file_size for i in z.infolist()) > MAX_BUNDLE_BYTES:
            raise SessionError("the bundle is larger than 2 GB")
        manifest = json.loads(z.read("manifest.json"))
        if manifest.get("format") != "ghostap-session-bundle":
            raise SessionError("not a GhostAP session bundle")
        try:
            meta = json.loads(z.read("meta.json")) if "meta.json" in names else {}
        except ValueError:
            meta = {}
        # the source path is NOT kept: it named a file on the machine that made the bundle, and
        # trusting it would let a crafted bundle point exports at any file here
        s = store.create("{} (imported)".format(str(meta.get("name") or manifest.get("session") or "bundle")[:100]),
                         "imported", "")
        try:
            for name in BUNDLE_FILES:
                if name not in names or name == "meta.json":
                    continue
                want = (manifest.get("files") or {}).get(name, {}).get("sha256")
                h = hashlib.sha256()
                with z.open(name) as src, open(os.path.join(s.path, name), "wb") as dst:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        h.update(chunk)
                        dst.write(chunk)
                if not want or h.hexdigest() != want:
                    raise SessionError("{} does not match its checksum: the bundle is damaged".format(name))
        except Exception:
            shutil.rmtree(s.path, ignore_errors=True)
            raise
        keep = {k: meta[k] for k in ("started_at", "ended_at", "frames", "state") if k in meta}
        s.update_meta(imported_from=manifest.get("session"), imported_at=time.time(), **keep)
        return s


def main(argv=None) -> int:
    import argparse
    import sys
    from .config import ConfigError, load_config
    ap = argparse.ArgumentParser(prog="python -m ghostap.sessions", description="List, export or import sessions.")
    ap.add_argument("--config", default="config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    e = sub.add_parser("export")
    e.add_argument("id")
    e.add_argument("out", help="zip file to write")
    i = sub.add_parser("import")
    i.add_argument("bundle")
    args = ap.parse_args(argv)
    try:
        store = SessionStore(load_config(args.config)["sessions_dir"])
    except ConfigError as err:
        print("[!] settings problem: {}".format(err), file=sys.stderr)
        return 2
    try:
        if args.cmd == "list":
            for m in store.list():
                print("{:<48} {:<8} {:>8} frames  {} HIGH / {} MEDIUM".format(
                    m["id"], m.get("mode", ""), m.get("frames", 0), m.get("alerts_high", 0), m.get("alerts_medium", 0)))
        elif args.cmd == "export":
            man = export_bundle(store.get(args.id), args.out)
            print("[+] wrote {} ({})".format(args.out, ", ".join(man["files"])))
        else:
            s = import_bundle(store, args.bundle)
            print("[+] imported as session {}".format(s.id))
    except (SessionError, OSError, ValueError) as err:
        print("[!] {}".format(err), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(main())
