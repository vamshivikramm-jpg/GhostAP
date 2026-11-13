"""Phase 5: Flask API + Plotly dashboard.

    # dashboard over an existing database (after collector + risk)
    python -m ghostap.web --db data/ghostap.db

    # replay a pcap into a fresh database at 10x speed, scoring as it goes
    python -m ghostap.web --pcap data/test_capture.pcap --speed 10 --db data/replay.db

    # live capture (Linux, root, monitor mode)
    sudo .venv/bin/python -m ghostap.web --iface wlan0 --db data/live.db

Then open http://127.0.0.1:8050

Security model
  * Bound to localhost (default): only requests addressed to localhost / 127.0.0.1 are
    served, which blocks DNS-rebinding attacks from web pages you visit.
  * Bound to anything else (--host 0.0.0.0, e.g. Kali in a VM): an access token is
    required. One is generated at start-up and printed as a ready-to-open link; it is
    exchanged for an HttpOnly, SameSite=Strict cookie. Set your own with GHOSTAP_TOKEN.
  * Every response carries a strict Content-Security-Policy and anti-framing headers.
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import os
import secrets
import sys
import time
from collections import defaultdict
from typing import List, Optional

from flask import Flask, Response, abort, jsonify, redirect, request, send_file, send_from_directory

from .pipeline import Pipeline
from .risk import load_config
from .storage import Store

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
TOKEN_COOKIE = "ghostap_token"  # noqa: S105 - the cookie's name, not a secret
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
LOGIN_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>GhostAP: sign in</title>
<body style="font:15px/1.5 system-ui,sans-serif;max-width:560px;margin:12vh auto;padding:0 16px;color:#222">
<h1 style="font-size:20px">GhostAP dashboard</h1>
<p>This dashboard is reachable from the network, so it needs its access link.</p>
<p>Open the link that GhostAP printed in the terminal when it started; it ends in
<code>/?token=...</code>.</p></body></html>"""


def is_loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _request_hostname() -> str:
    """Host header without the port (handles [IPv6]:port)."""
    host = (request.host or "").lower()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0]


def _plotly_js() -> Optional[str]:
    """plotly.min.js ships inside the plotly Python package - no CDN needed."""
    try:
        import plotly
        path = os.path.join(os.path.dirname(plotly.__file__), "package_data", "plotly.min.js")
        return path if os.path.exists(path) else None
    except ImportError:
        return None


def create_app(db: str, config: Optional[dict] = None,
               pipeline: Optional[Pipeline] = None, token: Optional[str] = None,
               local_only: bool = True) -> Flask:
    """Build the Flask app.

    local_only: refuse requests whose Host header is not a loopback name/address
                (DNS-rebinding protection). Use with the default 127.0.0.1 binding.
    token:      if set, every request needs it (cookie, `Authorization: Bearer`, or a
                one-time `/?token=` link that sets the cookie).
    """
    cfg = config or load_config(None)
    app = Flask(__name__, static_folder=None)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024          # only small JSON bodies are accepted

    def token_ok(value: Optional[str]) -> bool:
        return bool(value) and hmac.compare_digest(value.encode(), token.encode())

    @app.before_request
    def guard():
        if local_only and not is_loopback(_request_hostname()):
            return Response("GhostAP only answers requests addressed to localhost.\n",
                            status=403, mimetype="text/plain")
        if token:
            if request.path == "/" and token_ok(request.args.get("token")):
                resp = redirect("/", code=303)                 # drop the token from the URL bar
                resp.set_cookie(TOKEN_COOKIE, token, httponly=True, samesite="Strict",
                                max_age=12 * 3600, secure=request.is_secure)
                return resp
            auth = request.headers.get("Authorization", "")
            supplied = auth[7:] if auth.startswith("Bearer ") else request.cookies.get(TOKEN_COOKIE)
            if not token_ok(supplied):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "authentication required"}), 401
                return Response(LOGIN_PAGE, status=401, mimetype="text/html")
        return None

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def store() -> Store:
        return Store(db)

    def status() -> dict:
        if pipeline is not None:
            return pipeline.snapshot()
        return {"mode": "database", "source": db, "state": "done", "frames": None,
                "message": "", "speed": None, "data_version": 0}

    # -- pages -------------------------------------------------------------- #

    # max_age=0: browsers revalidate (cheap 304s), so an updated dashboard is never stale
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html", max_age=0)

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name, max_age=0)

    @app.get("/vendor/plotly.min.js")
    def plotly_js():
        path = _plotly_js()
        if not path:
            abort(404)
        return send_file(path, mimetype="application/javascript", max_age=86400)

    # -- API ---------------------------------------------------------------- #

    @app.get("/api/summary")
    def summary():
        """Small and cheap: the dashboard polls it every 2 s. Counts come from ap_profiles
        (maintained incrementally), not from scanning every observation."""
        with store() as s:
            row = s.conn.execute(
                "SELECT COUNT(*) AS aps, COUNT(DISTINCT ssid) AS ssids, COALESCE(SUM(frames), 0) AS n, "
                "MIN(first_seen) AS t0, MAX(last_seen) AS t1 FROM ap_profiles").fetchone()
            open_levels = dict(s.conn.execute(
                "SELECT level, COUNT(*) FROM alerts WHERE detector='ghostap' "
                "AND COALESCE(triage_status, 'new') != 'false_positive' GROUP BY level").fetchall())
            dismissed = s.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector='ghostap' AND triage_status='false_positive'"
            ).fetchone()[0]
            n_base = s.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector='baseline'").fetchone()[0]
            triage_v = s.conn.execute(
                "SELECT COALESCE(MAX(triage_ts), 0), COUNT(*) FROM alerts").fetchone()
            top = [a for a in s.alerts("ghostap") if a.get("triage_status") != "false_positive"][:1]
        st = status()
        t0 = row["t0"]
        baseline_s = cfg["baseline_minutes"] * 60
        return jsonify({
            "status": st,
            # changes whenever scores, alerts or triage change: the page refetches only then
            "data_version": "{}-{}-{}-{}".format(st.get("data_version", 0), triage_v[0], triage_v[1],
                                                 row["aps"]),
            "frames": row["n"],
            "aps": row["aps"],
            "networks": row["ssids"],
            "capture_start": t0,
            "capture_end": row["t1"],
            "baseline_seconds": baseline_s,
            "baseline_end": (t0 + baseline_s) if t0 is not None else None,
            "baseline_complete": t0 is not None and row["t1"] >= t0 + baseline_s,
            "alerts": {"HIGH": open_levels.get("HIGH", 0), "MEDIUM": open_levels.get("MEDIUM", 0)},
            "dismissed_alerts": dismissed,
            "baseline_alerts": n_base,
            "top_alert": ({k: top[0][k] for k in ("id", "ssid", "bssid", "level", "score",
                                                  "first_ts", "reasons", "triage_status")}
                          if top else None),
            "thresholds": cfg["thresholds"],
            "weights": cfg["weights"],
        })

    def baseline_end(s: Store) -> Optional[float]:
        t0 = s.conn.execute("SELECT MIN(ts) FROM observations").fetchone()[0]
        return None if t0 is None else t0 + cfg["baseline_minutes"] * 60

    def ap_facts(s: Store, profile: dict, b_end: Optional[float]) -> dict:
        """Everything the comparison view shows about one AP."""
        q = (profile["ssid"], profile["bssid"])
        first = s.conn.execute(
            "SELECT ts, tsf FROM observations WHERE ssid=? AND bssid=? AND tsf IS NOT NULL "
            "ORDER BY ts LIMIT 1", q).fetchone()
        last = s.conn.execute(
            "SELECT ts, tsf FROM observations WHERE ssid=? AND bssid=? AND tsf IS NOT NULL "
            "ORDER BY ts DESC LIMIT 1", q).fetchone()
        fps = [r[0] for r in s.conn.execute(
            "SELECT DISTINCT fingerprint FROM observations WHERE ssid=? AND bssid=? "
            "AND frame_type='beacon' AND fingerprint IS NOT NULL", q).fetchall()]
        bi = s.conn.execute(
            "SELECT beacon_interval, COUNT(*) c FROM observations WHERE ssid=? AND bssid=? "
            "AND beacon_interval IS NOT NULL GROUP BY beacon_interval ORDER BY c DESC LIMIT 1",
            q).fetchone()
        return dict(profile,
                    oui=profile["bssid"][:8],
                    uptime_first_seen=(first["tsf"] / 1e6) if first else None,
                    uptime_now=(last["tsf"] / 1e6) if last else None,
                    fingerprints=fps,
                    beacon_interval=bi[0] if bi else None,
                    in_baseline=b_end is not None and profile["first_seen"] < b_end,
                    allowlisted=profile["bssid"] in {b.lower() for b in cfg.get("known_bssids") or []})

    def ap_rows(s: Store) -> List[dict]:
        latest = s.latest()
        peak = {(r[0], r[1]): r[2] for r in s.conn.execute(
            "SELECT ssid, bssid, MAX(score) FROM risk_timeline GROUP BY ssid, bssid").fetchall()}
        alerts_by = {(r["ssid"], r["bssid"]): r for r in s.conn.execute(
            "SELECT id, ssid, bssid, level, triage_status FROM alerts WHERE detector='ghostap'").fetchall()}
        dup = {(r[0], r[1]) for r in s.conn.execute(
            "SELECT ssid, bssid FROM alerts WHERE detector='baseline'").fetchall()}
        b_end = baseline_end(s)
        out = []
        for p in s.profiles():
            key = (p["ssid"], p["bssid"])
            cur, al = latest.get(key), alerts_by.get(key)
            out.append(dict(p,
                            score=cur["score"] if cur else None,
                            level=cur["level"] if cur else None,
                            peak_score=peak.get(key),
                            alert_id=al["id"] if al else None,
                            alert_level=al["level"] if al else None,
                            triage_status=al["triage_status"] if al else None,
                            duplicate_flag=key in dup,
                            in_baseline=b_end is not None and p["first_seen"] < b_end))
        out.sort(key=lambda a: (-(a["peak_score"] or 0), a["ssid"], a["bssid"]))
        return out

    @app.get("/api/aps")
    def aps():
        with store() as s:
            return jsonify(ap_rows(s))

    @app.get("/api/networks")
    def networks():
        """APs grouped by SSID, most suspicious network first."""
        with store() as s:
            rows = ap_rows(s)
        groups: dict = {}
        for r in rows:
            g = groups.setdefault(r["ssid"], {"ssid": r["ssid"], "aps": [], "peak": 0.0})
            g["aps"].append(r)
            g["peak"] = max(g["peak"], r["peak_score"] or 0.0)
        out = sorted(groups.values(), key=lambda g: (-g["peak"], g["ssid"]))
        for g in out:
            g["securities"] = sorted({x for a in g["aps"] for x in (a["securities"] or "").split(",") if x})
            g["channels"] = sorted({int(x) for a in g["aps"] for x in (a["channels"] or "").split(",") if x})
        return jsonify(out)

    @app.get("/api/ap")
    def ap_detail():
        ssid, bssid = request.args.get("ssid"), (request.args.get("bssid") or "").lower()
        with store() as s:
            profiles = [p for p in s.profiles() if p["ssid"] == ssid]
            me = next((p for p in profiles if p["bssid"] == bssid), None)
            if me is None:
                abort(404)
            b_end = baseline_end(s)
            latest = s.latest().get((ssid, bssid))
            alert = next((a for a in s.alerts("ghostap") if a["bssid"] == bssid and a["ssid"] == ssid), None)
            dup = next((a for a in s.alerts("baseline") if a["bssid"] == bssid and a["ssid"] == ssid), None)
            out = {
                "ap": ap_facts(s, me, b_end),
                "siblings": [ap_facts(s, p, b_end) for p in profiles if p["bssid"] != bssid],
                "latest": latest,
                "alert": alert,
                "baseline_alert": dup,
                "timeline": s.timeline(ssid, bssid),
                "baseline_end": b_end,
            }
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

    @app.post("/api/alerts/<int:alert_id>/triage")
    def triage(alert_id: int):
        # JSON only: a cross-site form post cannot send application/json without a CORS
        # preflight, which this server never approves.
        body = request.get_json(silent=True)
        if not request.is_json or not isinstance(body, dict):
            return jsonify({"error": "expected a JSON body"}), 415
        status_ = body.get("status")
        note = body.get("note")
        if status_ not in Store.TRIAGE_STATES or (note is not None and not isinstance(note, str)):
            return jsonify({"error": "status must be one of " + ", ".join(Store.TRIAGE_STATES)}), 400
        with store() as s:
            if not s.set_triage(alert_id, status_, note, time.time()):
                abort(404)
            return jsonify(s.alert(alert_id))

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
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to listen on (default 127.0.0.1). Anything else, e.g. 0.0.0.0 "
                         "to reach Kali in a VM from the host, turns on token login")
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
    local = is_loopback(args.host)
    token = None if local else (os.environ.get("GHOSTAP_TOKEN") or secrets.token_urlsafe(24))
    app = create_app(db, cfg, pipe, token=token, local_only=local)
    mode = pipe.status["mode"]
    if local:
        print("[+] GhostAP dashboard ({}: {}) -> http://{}:{}".format(
            mode, pipe.status["source"], "127.0.0.1" if args.host in ("localhost", "::1") else args.host,
            args.port))
    else:
        wildcard = args.host in ("0.0.0.0", "::")  # noqa: S104 - checking, not binding
        shown = "<this-machine-ip>" if wildcard else args.host
        print("[+] GhostAP dashboard ({}: {}) is reachable from the network.".format(
            mode, pipe.status["source"]))
        print("[+] Open this link (keep it private, it is the login):")
        print("      http://{}:{}/?token={}".format(shown, args.port, token))
        print("[i] Anyone with the link can see the dashboard. Use it only on a private or lab network.")
    try:
        serve(app, args.host, args.port)
    except OSError as e:
        print("[!] could not listen on {}:{}: {} (port in use? try --port 8051)".format(
            args.host, args.port, e), file=sys.stderr)
        return 1
    finally:
        pipe.stop()
    return 0


def serve(app: Flask, host: str, port: int) -> None:
    """Production WSGI server (waitress) when installed, else Flask's built-in server."""
    try:
        from waitress import serve as waitress_serve
    except ImportError:
        print("[i] waitress not installed; using Flask's development server "
              "(pip install -r requirements.txt)")
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
        return
    waitress_serve(app, host=host, port=port, threads=8, ident="GhostAP")


if __name__ == "__main__":
    sys.exit(main())
