"""Dashboard API: sessions (F040), system health (F068) and audit log (F069)."""
from __future__ import annotations

import os
import platform
import shutil
import sys
import time

from flask import abort, jsonify, request

from . import __version__
from .sessions import SessionError
from .storage import Store


def _size(path: str) -> int:
    return sum(os.path.getsize(path + ext) for ext in ("", "-wal", "-shm") if os.path.exists(path + ext))


def register(app, ctx) -> None:

    # ---------------------------------------------------------------- sessions
    @app.get("/api/sessions")
    def sessions_list():
        items = ctx.sessions.list() if ctx.sessions else []
        for m in items:
            m["current"] = m["id"] == ctx.current_session
        return jsonify({"current": ctx.current_session, "sessions": items})

    def _session_or_404(sid):
        if not ctx.sessions:
            abort(404)
        try:
            return ctx.sessions.get(sid)
        except SessionError:
            abort(404)

    @app.post("/api/sessions/<sid>/rename")
    def session_rename(sid):
        body, err = ctx.json_body()
        if err:
            return err
        _session_or_404(sid)
        try:
            meta = ctx.sessions.rename(sid, body.get("name") if isinstance(body.get("name"), str) else "")
        except SessionError as e:
            return jsonify({"error": str(e)}), 400
        ctx.audit("session.rename", sid, {"name": meta["name"]})
        return jsonify(meta)

    @app.post("/api/sessions/<sid>/delete")
    def session_delete(sid):
        body, err = ctx.json_body()
        if err:
            return err
        _session_or_404(sid)
        if sid == ctx.current_session:
            return jsonify({"error": "the running session cannot be deleted"}), 409
        if body.get("confirm") != sid:            # the page asks the user to confirm first
            return jsonify({"error": "confirmation missing"}), 400
        name = ctx.sessions.get(sid).meta().get("name")
        ctx.sessions.delete(sid)
        ctx.audit("session.delete", sid, {"name": name})
        return jsonify({"deleted": sid})

    # ---------------------------------------------------------------- health
    @app.get("/api/health")
    def health():
        st = ctx.status()
        db = ctx.db_path()
        with Store(db) as s:
            last = s.conn.execute("SELECT MAX(ts) FROM observations").fetchone()[0]
            recent = s.conn.execute("SELECT COUNT(*) FROM observations WHERE ts > ?",
                                    ((last or 0) - 60,)).fetchone()[0] if last else 0
            n_obs = s.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        disk = shutil.disk_usage(os.path.dirname(os.path.abspath(db)))
        sessions_bytes = sum(m.get("size_bytes", 0) for m in ctx.sessions.list()) if ctx.sessions else None
        ret = ctx.cfg.get("retention", {})
        return jsonify({
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(terse=True),
            "server_uptime_s": round(time.time() - ctx.started, 1),
            "status": st,
            "database": {"path": db, "bytes": _size(db), "raw_frames": n_obs},
            "frames_last_minute": recent,
            "last_frame_age_s": (round(time.time() - st["last_frame_ts"], 1)
                                 if st.get("last_frame_ts") and st.get("mode") == "live" else None),
            "disk": {"free_bytes": disk.free, "total_bytes": disk.total},
            "sessions_bytes": sessions_bytes,
            "retention": {"raw_hours": ret.get("raw_hours"), "pruned_frames": st.get("pruned_frames", 0)},
        })

    # ---------------------------------------------------------------- audit
    @app.get("/api/audit")
    def audit_log():
        try:
            limit = max(1, min(1000, int(request.args.get("limit", 200))))
        except ValueError:
            limit = 200
        with Store(ctx.admin_db) as s:
            return jsonify(s.audit_log(limit, request.args.get("action") or None))
