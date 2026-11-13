"""Analyst tools API: what-if weights (F031) and timeline annotations (F037)."""
from __future__ import annotations

import os
import threading
import time

from flask import abort, jsonify

from . import whatif
from .storage import Store

MAX_NOTE = 300


def register(app, ctx) -> None:
    job: dict = {}                    # one recording at a time: they can be large
    lock = threading.Lock()

    def recording():
        """(Recording or None, state dict). Builds it in a background thread the first time,
        because evaluating every indicator of a long session can take a minute."""
        path = ctx.db_path()
        live = ctx.viewed_session() is None and ctx.pipeline is not None
        version = ctx.pipeline.status.get("data_version") if live else os.path.getmtime(path)
        key = (path, version)
        with lock:
            if job.get("key") == key:
                return job.get("rec"), job
            if job.get("thread") is not None and job["thread"].is_alive():
                return None, job              # still busy with older data; ask again shortly
            mon, nets = (ctx.pipeline.monitored, ctx.pipeline.network_settings) if live else (None, None)
            job.clear()
            job.update(key=key, started=time.time(), rec=None, error=None)

            def build():
                try:
                    with Store(path) as s:
                        obs = s.observations()
                    rec = whatif.Recording(ctx.cfg, obs, mon, nets)
                    with lock:
                        if job.get("key") == key:
                            job["rec"] = rec
                except whatif.TooLarge as e:
                    with lock:
                        job["error"] = (str(e), 413)
                except Exception as e:  # reported to the page, not hidden
                    with lock:
                        job["error"] = ("could not prepare the what-if: {}".format(e), 500)

            job["thread"] = threading.Thread(target=build, name="ghostap-whatif", daemon=True)
            job["thread"].start()
        job["thread"].join(timeout=3)         # small sessions are ready almost at once
        with lock:
            return job.get("rec"), job

    # ---------------------------------------------------------------- F031
    @app.post("/api/whatif")
    def whatif_run():
        body, err = ctx.json_body()
        if err:
            return err
        try:
            weights, floors, th = whatif.validate(body, ctx.cfg)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        t0 = time.perf_counter()
        rec, state = recording()
        if state.get("error"):
            msg, code = state["error"]
            return jsonify({"error": msg}), code
        if rec is None:
            return jsonify({"preparing": True, "elapsed_s": round(time.time() - state.get("started", time.time()), 1),
                            "message": "Evaluating every indicator of this session once; re-scoring is instant "
                                       "after that."}), 202
        before = rec.rescore(ctx.cfg["weights"], ctx.cfg.get("signatures") or {}, ctx.cfg["thresholds"])
        after = rec.rescore(weights, floors, th)
        out = whatif.compare(before, after)
        out.update(weights=weights, signatures=floors, thresholds=th,
                   configured={"weights": ctx.cfg["weights"], "signatures": ctx.cfg.get("signatures") or {},
                               "thresholds": ctx.cfg["thresholds"]},
                   seconds=round(time.perf_counter() - t0, 3), evaluations=len(rec.rows))
        return jsonify(out)

    # ---------------------------------------------------------------- F037
    @app.get("/api/annotations")
    def annotations_list():
        with ctx.store() as s:
            return jsonify(s.annotations())

    @app.post("/api/annotations")
    def annotations_add():
        body, err = ctx.json_body()
        if err:
            return err
        ts, text = body.get("ts"), body.get("text")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            return jsonify({"error": "ts must be a capture time (seconds since 1970)"}), 400
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_NOTE:
            return jsonify({"error": "a note needs 1 to {} characters".format(MAX_NOTE)}), 400
        with ctx.store() as s:
            span = s.conn.execute("SELECT MIN(ts), MAX(ts) FROM observations").fetchone()
            if span[0] is None or not span[0] - 3600 <= ts <= span[1] + 3600:
                return jsonify({"error": "that time is outside this capture"}), 400
            aid = s.add_annotation(float(ts), text.strip(), ctx.actor(), time.time())
        ctx.audit("annotation.add", str(aid), {"ts": ts, "text": text.strip(),
                                               "session": ctx.viewed_session() or ctx.current_session})
        return jsonify({"id": aid})

    @app.post("/api/annotations/<int:ann_id>/delete")
    def annotations_delete(ann_id):
        with ctx.store() as s:
            if not s.delete_annotation(ann_id):
                abort(404)
        ctx.audit("annotation.remove", str(ann_id), {"session": ctx.viewed_session() or ctx.current_session})
        return jsonify({"deleted": ann_id})
