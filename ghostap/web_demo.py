"""Demo button (F089): replay the bundled synthetic test capture as a new session.

The test capture (tools/make_test_pcap.py) is SYNTHETIC: one network with two real access
points and an evil twin that appears after three minutes. The demo refuses to run while a
live capture is in progress, so it can never interrupt real monitoring.
"""
from __future__ import annotations

import importlib.util
import os
import time

from flask import jsonify

from .pipeline import Pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_PCAP = os.path.join("data", "test_capture.pcap")


def demo_pcap() -> str:
    """The synthetic test capture, generated on first use (data/ is not in git)."""
    if not os.path.exists(DEMO_PCAP):
        spec = importlib.util.spec_from_file_location(
            "make_test_pcap", os.path.join(ROOT, "tools", "make_test_pcap.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.generate(os.path.dirname(DEMO_PCAP) or ".")
    return DEMO_PCAP


def register(app, ctx) -> None:

    @app.post("/api/demo/start")
    def demo_start():
        body, err = ctx.json_body()
        if err:
            return err
        speed = body.get("speed", 10)
        if isinstance(speed, bool) or not isinstance(speed, (int, float)) or not 1 <= speed <= 100:
            return jsonify({"error": "speed must be between 1 and 100"}), 400
        cur = ctx.pipeline
        if cur is not None and cur.status.get("mode") == "live" and cur.status.get("state") in ("starting", "running"):
            return jsonify({"error": "a live capture is running; stop it before starting the demo"}), 409
        if ctx.sessions is None:
            return jsonify({"error": "the demo needs session storage (start the dashboard without --db)"}), 400
        try:
            pcap = demo_pcap()
        except Exception as e:  # reported, not hidden
            return jsonify({"error": "could not create the demo capture: {}".format(e)}), 500
        session = ctx.sessions.create("demo (synthetic test capture)", "replay", pcap)

        def finished(st):
            session.update_meta(ended_at=time.time(), frames=st.get("frames"), state=st.get("state"))

        new = Pipeline(session.db, ctx.cfg, pcap=pcap, speed=float(speed), on_finish=finished).start()
        ctx.pipeline, ctx.db, ctx.current_session = new, session.db, session.id
        if cur is not None:
            cur.stop()
        ctx.audit("demo.start", session.id, {"speed": speed})
        return jsonify({"session": session.id, "speed": speed, "pcap": pcap,
                        "note": "synthetic test capture: the twin appears about 3 minutes in "
                                "(~18 s at 10x)"})
