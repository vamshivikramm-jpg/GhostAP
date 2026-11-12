"""Phase 5: Flask API + Plotly dashboard.

    # dashboard over an existing database (after collector + risk)
    python -m ghostap.web --db data/ghostap.db

    # replay a pcap into a fresh database at 10x speed, scoring as it goes
    python -m ghostap.web --pcap data/test_capture.pcap --speed 10 --db data/replay.db

    # live capture (Linux, root, monitor mode)
    sudo .venv/bin/python -m ghostap.web --iface wlan0 --db data/live.db

Then open http://127.0.0.1:8050
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from typing import Optional

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from .pipeline import Pipeline
from .risk import load_config
from .storage import Store

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def _plotly_js() -> Optional[str]:
    """plotly.min.js ships inside the plotly Python package - no CDN needed."""
    try:
        import plotly
        path = os.path.join(os.path.dirname(plotly.__file__), "package_data", "plotly.min.js")
        return path if os.path.exists(path) else None
    except ImportError:
        return None


def create_app(db: str, config: Optional[dict] = None,
               pipeline: Optional[Pipeline] = None) -> Flask:
    cfg = config or load_config(None)
    app = Flask(__name__, static_folder=None)
    app.config["JSON_SORT_KEYS"] = False

    def store() -> Store:
        return Store(db)

    def status() -> dict:
        if pipeline is not None:
            return pipeline.snapshot()
        return {"mode": "database", "source": db, "state": "done", "frames": None,
                "message": "", "speed": None}

    # -- pages -------------------------------------------------------------- #

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    @app.get("/vendor/plotly.min.js")
    def plotly_js():
        path = _plotly_js()
        if not path:
            abort(404)
        return send_file(path, mimetype="application/javascript", max_age=86400)

    # -- API ---------------------------------------------------------------- #

    @app.get("/api/summary")
    def summary():
        with store() as s:
            row = s.conn.execute(
                "SELECT COUNT(*) AS n, MIN(ts) AS t0, MAX(ts) AS t1 FROM observations").fetchone()
            n_aps = s.conn.execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ssid, bssid FROM observations)").fetchone()[0]
            levels = dict(s.conn.execute(
                "SELECT level, COUNT(*) FROM alerts WHERE detector='ghostap' GROUP BY level").fetchall())
            n_base = s.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector='baseline'").fetchone()[0]
        t0 = row["t0"]
        baseline_s = cfg["baseline_minutes"] * 60
        return jsonify({
            "status": status(),
            "frames": row["n"],
            "aps": n_aps,
            "capture_start": t0,
            "capture_end": row["t1"],
            "baseline_seconds": baseline_s,
            "baseline_end": (t0 + baseline_s) if t0 is not None else None,
            "baseline_complete": t0 is not None and row["t1"] >= t0 + baseline_s,
            "alerts": {"HIGH": levels.get("HIGH", 0), "MEDIUM": levels.get("MEDIUM", 0)},
            "baseline_alerts": n_base,
            "thresholds": cfg["thresholds"],
            "weights": cfg["weights"],
        })

    @app.get("/api/aps")
    def aps():
        with store() as s:
            profiles = s.profiles()
            latest = {(r["ssid"], r["bssid"]): r for r in s.conn.execute(
                "SELECT t.* FROM risk_timeline t JOIN (SELECT ssid, bssid, MAX(ts) AS ts "
                "FROM risk_timeline GROUP BY ssid, bssid) m "
                "ON t.ssid=m.ssid AND t.bssid=m.bssid AND t.ts=m.ts").fetchall()}
            peak = {(r[0], r[1]): r[2] for r in s.conn.execute(
                "SELECT ssid, bssid, MAX(score) FROM risk_timeline GROUP BY ssid, bssid").fetchall()}
            alert_ids = {(r[0], r[1]): r[2] for r in s.conn.execute(
                "SELECT ssid, bssid, id FROM alerts WHERE detector='ghostap'").fetchall()}
        out = []
        for p in profiles:
            key = (p["ssid"], p["bssid"])
            cur = latest.get(key)
            out.append(dict(p,
                            score=cur["score"] if cur else None,
                            level=cur["level"] if cur else None,
                            peak_score=peak.get(key),
                            alert_id=alert_ids.get(key)))
        out.sort(key=lambda a: (-(a["peak_score"] or 0), a["ssid"], a["bssid"]))
        return jsonify(out)

    @app.get("/api/alerts")
    def alerts():
        detector = request.args.get("detector", "ghostap")
        with store() as s:
            return jsonify(s.alerts(None if detector == "all" else detector))

    @app.get("/api/alerts/<int:alert_id>")
    def alert_detail(alert_id: int):
        with store() as s:
            a = s.alert(alert_id)
            if a is None:
                abort(404)
            a["timeline"] = s.timeline(a["ssid"], a["bssid"])
            prof = [p for p in s.profiles() if p["ssid"] == a["ssid"] and p["bssid"] == a["bssid"]]
        a["profile"] = prof[0] if prof else None
        return jsonify(a)

    @app.get("/api/timeline")
    def timeline():
        series = defaultdict(lambda: {"ts": [], "score": [], "raw": [], "level": []})
        with store() as s:
            for r in s.timeline():
                d = series[(r["ssid"], r["bssid"])]
                d["ts"].append(r["ts"])
                d["score"].append(r["score"])
                d["raw"].append(r["raw_score"])
                d["level"].append(r["level"])
        return jsonify([dict(ssid=k[0], bssid=k[1], peak=max(v["score"]), **v)
                        for k, v in series.items()])

    @app.get("/api/events")
    def events():
        ev = []
        with store() as s:
            for p in s.profiles():
                ev.append({"ts": p["first_seen"], "type": "ap_seen", "level": None,
                           "ssid": p["ssid"], "bssid": p["bssid"], "alert_id": None,
                           "text": "AP first seen on channel {} ({})".format(
                               p["channels"], p["securities"])})
            for a in s.alerts():
                if a["detector"] == "baseline":
                    ev.append({"ts": a["first_ts"], "type": "baseline_alert", "level": "HIGH",
                               "ssid": a["ssid"], "bssid": a["bssid"], "alert_id": a["id"],
                               "text": "Baseline detector: duplicate SSID"})
                    continue
                ev.append({"ts": a["first_ts"], "type": "alert", "level": "MEDIUM",
                           "ssid": a["ssid"], "bssid": a["bssid"], "alert_id": a["id"],
                           "text": "GhostAP alert raised"})
                if a["high_ts"] is not None:
                    ev.append({"ts": a["high_ts"], "type": "escalated", "level": "HIGH",
                               "ssid": a["ssid"], "bssid": a["bssid"], "alert_id": a["id"],
                               "text": "Escalated to HIGH"})
        ev.sort(key=lambda e: (e["ts"], e["type"]))
        return jsonify(ev)

    return app


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.web",
                                 description="GhostAP dashboard (Flask + Plotly).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pcap", help="replay a pcap into --db while the dashboard runs")
    src.add_argument("--iface", help="live capture on a monitor-mode interface (Linux, root)")
    ap.add_argument("--db", default=None,
                    help="SQLite database (default: data/ghostap.db, data/replay.db for "
                         "--pcap, data/live.db for --iface)")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--speed", type=float, default=10.0,
                    help="replay speed multiplier; 0 = as fast as possible (default 10)")
    ap.add_argument("--duration", type=float, default=None, help="stop live capture after N seconds")
    ap.add_argument("--hop", metavar="CHANNELS",
                    help="live: hop channels, e.g. 1,6,11 or 1-13 or 2.4 or 5 or all")
    ap.add_argument("--dwell", type=float, default=0.25, help="live: seconds per channel (default 0.25)")
    ap.add_argument("--save-pcap", metavar="FILE",
                    help="live: also save captured beacons / probe responses to a pcap")
    ap.add_argument("--keep", action="store_true",
                    help="keep existing data in --db instead of starting fresh (replay/live)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8050)
    args = ap.parse_args(argv)

    db = args.db or ("data/replay.db" if args.pcap else "data/live.db" if args.iface
                     else "data/ghostap.db")
    if args.pcap and not os.path.exists(args.pcap):
        print("[!] pcap not found: {}".format(args.pcap), file=sys.stderr)
        return 1
    hop = None
    if args.hop:
        from .hopper import parse_channels
        try:
            hop = parse_channels(args.hop)
        except ValueError as e:
            ap.error(str(e))
    if (args.hop or args.save_pcap) and not args.iface:
        ap.error("--hop and --save-pcap only apply to live capture (--iface)")
    cfg = load_config(args.config)
    pipe = Pipeline(db, cfg, pcap=args.pcap, iface=args.iface, speed=args.speed,
                    duration=args.duration, reset=not args.keep, hop=hop, dwell=args.dwell,
                    save_pcap=args.save_pcap).start()
    app = create_app(db, cfg, pipe)
    mode = pipe.status["mode"]
    print("[+] GhostAP dashboard ({}: {}) -> http://{}:{}".format(
        mode, pipe.status["source"], args.host, args.port))
    try:
        app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)
    finally:
        pipe.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
