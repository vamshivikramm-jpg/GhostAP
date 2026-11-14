"""Capture control (F041), several sensors (F044) and rough location (F045) API."""
from __future__ import annotations

import time

from flask import Response, abort, jsonify, request

from . import sensors as S
from .hopper import parse_channels


def register(app, ctx) -> None:
    S.ensure_schema(ctx.admin_db)
    ctx.status_now = lambda: ctx.pipeline.snapshot() if ctx.pipeline is not None else {"mode": "database"}
    ctx.reporter = None
    sc = ctx.cfg["sensors"]
    if sc["report_to"] and app.config.get("GHOSTAP_START_REPORTER", True):
        key = S.report_key(ctx.cfg)
        if key:
            ctx.reporter = S.Reporter(ctx, ctx.cfg, key)
            ctx.reporter.start()
        else:
            S.log.warning("sensors.report_to is set but %s is empty: not reporting", sc["report_key_env"])

    # ---------------------------------------------------------------- F041 capture control
    def control():
        p = ctx.pipeline
        if ctx.viewed_session() is not None or p is None or p.status.get("mode") != "live":
            abort(Response('{"error": "only a running live capture can be controlled"}', 409,
                           mimetype="application/json"))
        return p.control

    @app.get("/api/capture")
    def capture_get():
        p = ctx.pipeline
        live = p is not None and p.status.get("mode") == "live" and ctx.viewed_session() is None
        return jsonify({"live": live, "state": p.status.get("state") if p else None,
                        **(p.control.snapshot() if live else {})})

    @app.post("/api/capture")
    def capture_set():
        body, err = ctx.json_body()
        if err:
            return err
        c = control()
        action = body.get("action")
        if action in ("pause", "resume"):
            changed = c.pause() if action == "pause" else c.resume()
            if changed:
                with ctx.store() as s:                 # the gap in the data gets an explanation
                    s.add_annotation(time.time(), "capture {} from the dashboard".format(
                        "paused" if action == "pause" else "resumed"), ctx.actor(), time.time())
                ctx.audit("capture." + action, None, {})
            return jsonify(c.snapshot())
        if action == "hop":
            try:
                chans = parse_channels(str(body.get("channels") or ""))
                desc = c.set_hop(chans, float(body.get("dwell", 0.25)))
            except (ValueError, TypeError) as e:
                return jsonify({"error": str(e)}), 400
            except RuntimeError as e:
                return jsonify({"error": str(e)}), 409
            ctx.audit("capture.hop", body.get("channels"), {"dwell": body.get("dwell", 0.25)})
            return jsonify(dict(c.snapshot(), hopping=desc))
        return jsonify({"error": "action must be pause, resume or hop"}), 400

    # ---------------------------------------------------------------- F044 sensors
    @app.post("/api/sensors/report")
    def sensors_report():
        """A sensor's report (send it with a write API key)."""
        body, err = ctx.json_body()
        if err:
            return err
        try:
            n = S.record_report(ctx.admin_db, body, request.remote_addr or "")
        except S.ReportError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"stored": n})

    @app.get("/api/sensors")
    def sensors_list():
        r = ctx.reporter
        return jsonify({"sensors": S.fleet(ctx.admin_db),
                        "this_sensor": {"name": sc["name"] or None, "reports_to": sc["report_to"] or None,
                                        "last_ok": r.last_ok if r else None, "last_error": r.last_error if r else None},
                        "model": {"p0": sc["path_loss_p0"], "n": sc["path_loss_n"]}})

    @app.get("/api/sensors/aps")
    def sensors_aps():
        return jsonify(S.merged(ctx.admin_db, sc["path_loss_p0"], sc["path_loss_n"]))

    @app.post("/api/sensors/<name>/position")
    def sensors_position(name):
        body, err = ctx.json_body()
        if err:
            return err
        x, y = body.get("x"), body.get("y")
        if (x is None) != (y is None) or any(v is not None and (isinstance(v, bool) or not isinstance(v, (int, float))
                                                               or abs(v) > 10000) for v in (x, y)):
            return jsonify({"error": "x and y are metres on your floor plan (or both empty)"}), 400
        with S.Store(ctx.admin_db) as s:
            n = s.conn.execute("UPDATE sensors SET x = ?, y = ? WHERE name = ?", (x, y, name)).rowcount
            s.conn.commit()
        if not n:
            abort(404)
        ctx.audit("sensor.position", name, {"x": x, "y": y})
        return jsonify({"name": name, "x": x, "y": y})

    @app.post("/api/sensors/<name>/delete")
    def sensors_delete(name):
        with S.Store(ctx.admin_db) as s:
            n = s.conn.execute("DELETE FROM sensors WHERE name = ?", (name,)).rowcount
            s.conn.execute("DELETE FROM sensor_aps WHERE sensor = ?", (name,))
            s.conn.commit()
        if not n:
            abort(404)
        ctx.audit("sensor.delete", name, {})
        return jsonify({"deleted": name})
