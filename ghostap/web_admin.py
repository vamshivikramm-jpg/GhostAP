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
    @app.get("/api/sensor/capabilities")
    def sensor_capabilities():
        """PLAN_3.0 O18: what the capture adapter can and cannot observe (read-only `iw phy`)."""
        from . import hwcaps
        st = ctx.status()
        if st.get("mode") != "live" or not st.get("source"):
            return jsonify({"available": False, "reason": "No live capture: this session comes from a file, "
                                                          "so there is no adapter to describe"})
        return jsonify(hwcaps.cached(st["source"]))

    @app.get("/api/health")
    def health():
        st = ctx.status()
        db = ctx.db_path()
        with Store(db) as s:
            last = s.conn.execute("SELECT MAX(ts) FROM observations").fetchone()[0]
            recent = s.conn.execute("SELECT COUNT(*) FROM observations WHERE ts > ?",
                                    ((last or 0) - 60,)).fetchone()[0] if last else 0
            n_obs = s.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            schema = s.schema_version()
        disk = shutil.disk_usage(os.path.dirname(os.path.abspath(db)))
        sessions_bytes = sum(m.get("size_bytes", 0) for m in ctx.sessions.list()) if ctx.sessions else None
        ret = ctx.cfg.get("retention", {})
        return jsonify({
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(terse=True),
            "server_uptime_s": round(time.time() - ctx.started, 1),
            "status": st,
            "database": {"path": db, "bytes": _size(db), "raw_frames": n_obs, "schema_version": schema},
            "frames_last_minute": recent,
            "last_frame_age_s": (round(time.time() - st["last_frame_ts"], 1)
                                 if st.get("last_frame_ts") and st.get("mode") == "live" else None),
            "disk": {"free_bytes": disk.free, "total_bytes": disk.total},
            "sessions_bytes": sessions_bytes,
            "retention": {"raw_hours": ret.get("raw_hours"), "pruned_frames": st.get("pruned_frames", 0)},
        })

    # ---------------------------------------------------------------- F042 capture quality
    @app.get("/api/quality")
    def quality():
        """Per channel: frames and radios in the last minute of capture. Per AP: how many
        of its expected beacons were actually heard (low = weak signal or hopping away)."""
        st = ctx.status()
        with Store(ctx.db_path()) as s:
            last = s.conn.execute("SELECT MAX(ts) FROM observations").fetchone()[0]
            channels = [dict(r) for r in s.conn.execute(
                "SELECT channel, COUNT(*) AS frames, COUNT(DISTINCT bssid) AS aps FROM observations "
                "WHERE ts > ? AND channel IS NOT NULL GROUP BY channel ORDER BY channel",
                ((last or 0) - 60,)).fetchall()] if last else []
            rows = s.conn.execute(
                "SELECT p.ssid, p.bssid, p.frames, p.first_seen, p.last_seen, "
                "(SELECT MAX(beacon_interval) FROM observations o WHERE o.bssid = p.bssid AND o.ssid = p.ssid) "
                "AS bi FROM ap_profiles p").fetchall()
            events = s.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        aps = []
        for r in rows:
            span = (r["last_seen"] or 0) - (r["first_seen"] or 0)
            expected = span / (r["bi"] * 0.001024) if r["bi"] and span > 0 else None
            aps.append({"ssid": r["ssid"], "bssid": r["bssid"], "frames": r["frames"],
                        "heard_ratio": round(min(1.0, r["frames"] / expected), 4) if expected else None})
        aps.sort(key=lambda a: (a["heard_ratio"] is None, a["heard_ratio"] or 0))
        return jsonify({"window_seconds": 60, "channels": channels, "aps": aps,
                        "damaged_frames": st.get("rejected") or {}, "hopping": st.get("hopping"),
                        "deauth_events": events})

    # ---------------------------------------------------------------- F026 mutes
    @app.get("/api/mutes")
    def mutes_list():
        return jsonify(ctx.active_mutes())

    @app.post("/api/mutes")
    def mutes_add():
        body, err = ctx.json_body()
        if err:
            return err
        kind, value, hours = body.get("kind"), body.get("value"), body.get("hours")
        if kind not in ("bssid", "ssid") or not isinstance(value, str) or not value:
            return jsonify({"error": "mute an access point (bssid) or a network (ssid)"}), 400
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 0 < hours <= 24 * 30:
            return jsonify({"error": "hours must be between 0 and 720"}), 400
        note = body.get("note") if isinstance(body.get("note"), str) else ""
        with Store(ctx.admin_db) as s:
            mid = s.add_mute(kind, value, time.time() + hours * 3600, ctx.actor(), note)
        ctx.audit("mute.add", "{} {}".format(kind, value), {"hours": hours, "note": note})
        return jsonify({"id": mid})

    @app.post("/api/mutes/<int:mute_id>/delete")
    def mutes_delete(mute_id):
        with Store(ctx.admin_db) as s:
            if not s.delete_mute(mute_id):
                abort(404)
        ctx.audit("mute.remove", str(mute_id))
        return jsonify({"deleted": mute_id})

    # ---------------------------------------------------------------- F025 bulk triage, F027 history
    @app.post("/api/alerts/triage_bulk")
    def triage_bulk():
        body, err = ctx.json_body()
        if err:
            return err
        ids, status_ = body.get("ids"), body.get("status")
        if (not isinstance(ids, list) or not ids or len(ids) > 500
                or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids)):
            return jsonify({"error": "ids must be a list of alert numbers"}), 400
        if status_ not in Store.TRIAGE_STATES:
            return jsonify({"error": "status must be one of " + ", ".join(Store.TRIAGE_STATES)}), 400
        done = []
        with ctx.store() as s:
            for i in ids:
                a = s.alert(i)
                if a and s.set_triage(i, status_, a.get("triage_note"), time.time()):
                    done.append(i)
        ctx.audit("triage.bulk", "{} alerts".format(len(done)),
                  {"alerts": done, "to": status_, "session": ctx.viewed_session() or ctx.current_session})
        return jsonify({"updated": done})

    @app.get("/api/alerts/<int:alert_id>/history")
    def triage_history(alert_id):
        sess = ctx.viewed_session() or ctx.current_session
        with Store(ctx.admin_db) as s:
            rows = s.audit_log(2000)
        out = [r for r in rows if r["action"] in ("triage", "triage.bulk")
               and (r["detail"].get("alert") == alert_id or alert_id in (r["detail"].get("alerts") or []))
               and r["detail"].get("session") == sess]
        return jsonify(out)

    # ---------------------------------------------------------------- F012 incidents
    @app.get("/api/incidents")
    def incidents():
        from .risk import build_incidents
        with ctx.store() as s:
            return jsonify(build_incidents(s.alerts()))

    # ---------------------------------------------------------------- audit
    @app.get("/api/audit")
    def audit_log():
        try:
            limit = max(1, min(1000, int(request.args.get("limit", 200))))
        except ValueError:
            limit = 200
        with Store(ctx.admin_db) as s:
            return jsonify(s.audit_log(limit, request.args.get("action") or None))
