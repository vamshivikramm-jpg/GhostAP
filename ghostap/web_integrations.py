"""Integrations API: notifications (F013, F055-F059), Prometheus metrics (F060), API keys and
the OpenAPI description (F061)."""
from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from flask import Response, abort, jsonify, request

from . import __version__, apikeys
from .notify import Notifier, NotifierThread, Webhook
from .storage import Store


def _redact(url: str) -> str:
    """Show where a webhook goes without its secret path or token."""
    p = urlsplit(url or "")
    return "{}://{}/…".format(p.scheme, p.hostname) if p.hostname else "(not set)"


def _metric_label(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def register(app, ctx) -> None:
    n = ctx.cfg["notifications"]
    ctx.notifier = Notifier(ctx.cfg, ctx.admin_db) if n["enabled"] else None
    ctx.notifier_thread = None
    if ctx.notifier is not None and ctx.notifier.channels and app.config.get("GHOSTAP_START_NOTIFIER", True):
        ctx.notifier_thread = NotifierThread(ctx.notifier, ctx)
        ctx.notifier_thread.start()

    # ---------------------------------------------------------------- F013, F055-F059
    @app.get("/api/notifications")
    def notifications_status():
        chans = []
        if ctx.notifier is not None:
            for c in ctx.notifier.channels:
                target = _redact(c.url) if isinstance(c, Webhook) else \
                    ", ".join(n["email"]["to"]) if c.name == "email" else \
                    "{}:{} ({})".format(n["syslog"]["host"], n["syslog"]["port"], n["syslog"]["protocol"]) \
                    if c.name == "syslog" else n["jsonl"]["path"]
                chans.append({"name": c.name, "min_level": c.min_level, "target": target})
        with Store(ctx.admin_db) as s:
            logrows = s.notification_log(50)
        return jsonify({"enabled": n["enabled"], "channels": chans,
                        "problems": ctx.notifier.problems if ctx.notifier else [],
                        "rules": {k: n[k] for k in ("min_level", "realert_minutes", "max_per_minute")},
                        "running": bool(ctx.notifier_thread and ctx.notifier_thread.is_alive()),
                        "log": logrows})

    @app.post("/api/notifications/test")
    def notifications_test():
        if ctx.notifier is None or not ctx.notifier.channels:
            return jsonify({"error": "no notification channel is configured (notifications in config.yaml)"}), 400
        res = ctx.notifier.test(ctx.current_session or "dashboard")
        ctx.audit("notifications.test", None, {"results": res})
        return jsonify({"results": res})

    # ---------------------------------------------------------------- F060 metrics
    @app.get("/metrics")
    def metrics():
        if not ctx.cfg["api"]["metrics"]:
            abort(404)
        st = ctx.status()
        with ctx.store() as s:
            row = s.conn.execute("SELECT COUNT(*), COUNT(DISTINCT ssid), COALESCE(SUM(frames), 0), MAX(last_seen) "
                                 "FROM ap_profiles").fetchone()
            alerts = s.alerts("ghostap,deauth,flood")
            recent = s.conn.execute("SELECT COUNT(*) FROM observations WHERE ts > ?",
                                    ((row[3] or 0) - 60,)).fetchone()[0] if row[3] else 0
        mutes = ctx.active_mutes()
        from .web import is_muted
        out = ["# HELP ghostap_info GhostAP version and capture mode.", "# TYPE ghostap_info gauge",
               'ghostap_info{{version="{}",mode="{}",state="{}"}} 1'.format(
                   _metric_label(__version__), _metric_label(st.get("mode")), _metric_label(st.get("state")))]

        def gauge(name, help_, value, labels=None):
            out.append("# HELP {} {}".format(name, help_))
            out.append("# TYPE {} gauge".format(name))
            for lab, v in (labels or [(None, value)]):
                lbl = "" if lab is None else "{" + ",".join('{}="{}"'.format(k, _metric_label(x)) for k, x in lab) + "}"
                out.append("{}{} {}".format(name, lbl, v))
        gauge("ghostap_access_points", "Access points heard in this session.", row[0])
        gauge("ghostap_networks", "Distinct network names heard.", row[1])
        gauge("ghostap_beacons", "Beacons stored for this session.", row[2])
        gauge("ghostap_beacons_last_minute", "Beacons in the last minute of capture time.", recent)
        open_ = [a for a in alerts if a.get("triage_status") != "false_positive" and not is_muted(a, mutes)]
        gauge("ghostap_open_alerts", "Open alerts (not dismissed or muted) by level.", None,
              [((("level", lv),), sum(a["level"] == lv for a in open_)) for lv in ("HIGH", "MEDIUM")])
        gauge("ghostap_alerts", "All alerts by detector.", None,
              [((("detector", d),), sum((a.get("detector") or "ghostap") == d for a in alerts))
               for d in ("ghostap", "deauth", "flood")])
        if st.get("score_seconds") is not None:
            gauge("ghostap_score_round_seconds", "Time of the last scoring round.", st["score_seconds"])
        if st.get("last_frame_ts"):
            gauge("ghostap_last_frame_age_seconds", "Seconds since the last frame (live capture).",
                  round(time.time() - st["last_frame_ts"], 1))
        rej = st.get("rejected") or {}
        if rej:
            gauge("ghostap_damaged_frames", "Damaged frames skipped, by reason.", None,
                  [((("reason", k),), v) for k, v in sorted(rej.items())])
        return Response("\n".join(out) + "\n", mimetype="text/plain; version=0.0.4")

    # ---------------------------------------------------------------- F061 API keys
    def no_key():
        if request.environ.get("ghostap.api_key"):
            abort(Response('{"error": "API keys cannot manage API keys"}', 403, mimetype="application/json"))

    @app.get("/api/keys")
    def keys_list():
        no_key()
        with Store(ctx.admin_db) as s:
            return jsonify(s.api_keys())

    @app.post("/api/keys")
    def keys_create():
        no_key()
        body, err = ctx.json_body()
        if err:
            return err
        try:
            kid, key = apikeys.create(ctx.admin_db, body.get("name"), body.get("scope", "read"))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        ctx.audit("apikey.create", str(kid), {"name": body.get("name"), "scope": body.get("scope", "read")})
        return jsonify({"id": kid, "key": key, "note": "Shown once. Send it as: Authorization: Bearer <key>"})

    @app.post("/api/keys/<int:key_id>/revoke")
    def keys_revoke(key_id):
        no_key()
        with Store(ctx.admin_db) as s:
            if not s.revoke_api_key(key_id, time.time()):
                abort(404)
        ctx.audit("apikey.revoke", str(key_id))
        return jsonify({"revoked": key_id})

    # ---------------------------------------------------------------- F061 OpenAPI
    @app.get("/api/openapi.json")
    def openapi():
        """Generated from the routes, so it never falls behind the code."""
        paths: dict = {}
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            if not (rule.rule.startswith("/api/") or rule.rule == "/metrics"):
                continue
            path = re.sub(r"<(?:[a-z]+:)?([a-z_]+)>", r"{\1}", rule.rule)
            doc = (app.view_functions[rule.endpoint].__doc__ or rule.endpoint.replace("_", " ")).strip()
            for m in sorted((rule.methods or set()) - {"HEAD", "OPTIONS"}):
                op = {"summary": doc.splitlines()[0], "operationId": "{}_{}".format(m.lower(), rule.endpoint),
                      "responses": {"200": {"description": "OK"}, "401": {"description": "sign-in or API key needed"}}}
                params = [{"name": p, "in": "path", "required": True, "schema": {"type": "string"}}
                          for p in re.findall(r"{([a-z_]+)}", path)]
                if path.startswith("/api/") and m == "GET":
                    params.append({"name": "session", "in": "query", "required": False,
                                   "schema": {"type": "string"}, "description": "a past session's id"})
                if params:
                    op["parameters"] = params
                if m == "POST":
                    op["requestBody"] = {"required": False,
                                         "content": {"application/json": {"schema": {"type": "object"}}}}
                    op["responses"]["415"] = {"description": "the body must be JSON"}
                paths.setdefault(path, {})[m.lower()] = op
        return jsonify({"openapi": "3.0.3",
                        "info": {"title": "GhostAP API", "version": __version__,
                                 "description": "Passive evil twin detector. See docs/API.md for examples."},
                        "components": {"securitySchemes": {"apiKey": {
                            "type": "http", "scheme": "bearer", "description": "gk_... API key or the login token"}}},
                        "security": [{"apiKey": []}], "paths": paths})
