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
from types import SimpleNamespace
from typing import List, Optional

from flask import Flask, Response, abort, jsonify, redirect, request, send_file, send_from_directory

from .pipeline import Pipeline
from .sessions import SessionError, SessionStore
from .config import ConfigError, load_config
from .storage import Store
from . import vendors

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ATTACK_DETECTORS = "ghostap,deauth,flood"


def is_muted(alert: dict, mutes: List[dict]) -> bool:
    """F026: an alert is muted while a rule for its AP or its network is active."""
    return any((m["kind"] == "bssid" and m["value"] == alert.get("bssid"))
               or (m["kind"] == "ssid" and m["value"] == alert.get("ssid")) for m in mutes)
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


def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except ValueError:
        return default


def _downsample(series: dict, points: int) -> dict:
    """At most `points` points per line; each bucket keeps its highest score."""
    n = len(series["ts"])
    if n <= points:
        return series
    out = dict(series, ts=[], score=[], raw=[], level=[])
    step = n / points
    for b in range(points):
        lo, hi = int(b * step), max(int((b + 1) * step), int(b * step) + 1)
        i = max(range(lo, min(hi, n)), key=lambda j: series["score"][j])
        for k in ("ts", "score", "raw", "level"):
            out[k].append(series[k][i])
    out["downsampled_from"] = n
    return out


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
               local_only: bool = True, sessions: Optional[SessionStore] = None,
               current_session: Optional[str] = None, admin_db: Optional[str] = None,
               config_path: Optional[str] = "config.yaml", monitored_path: Optional[str] = None) -> Flask:
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

    started = time.time()

    def viewed_session() -> Optional[str]:
        """?session=<id> selects a past session; absent = the current one."""
        sid = request.args.get("session") or None
        return None if sid in (None, current_session) else sid

    def db_path() -> str:
        sid = viewed_session()
        if sid is None:
            return db
        if sessions is None:
            abort(404)
        try:
            return sessions.get(sid).db
        except SessionError:
            abort(404)

    def store() -> Store:
        return Store(db_path())

    def status() -> dict:
        sid = viewed_session()
        if sid is not None:
            meta = sessions.get(sid).meta()
            return {"mode": "session", "source": meta.get("name", sid), "state": "done", "frames": None,
                    "message": "", "speed": None, "data_version": 0, "session": sid}
        st = pipeline.snapshot() if pipeline is not None else {
            "mode": "database", "source": db, "state": "done", "frames": None,
            "message": "", "speed": None, "data_version": 0}
        st["session"] = current_session
        return st

    def actor() -> str:
        return "token" if token else "local"

    def json_body():
        """The request's JSON object, or a (response, status) tuple to return."""
        body = request.get_json(silent=True)
        if not request.is_json or not isinstance(body, dict):
            return None, (jsonify({"error": "expected a JSON body"}), 415)
        return body, None

    def active_mutes() -> List[dict]:
        with Store(admin_db or db) as s:
            return s.active_mutes(time.time())

    def audit(action: str, target: Optional[str] = None, detail: Optional[dict] = None) -> None:
        with Store(admin_db or db) as s:
            s.audit(actor(), action, target, detail)

    ctx = SimpleNamespace(cfg=cfg, db=db, pipeline=pipeline, sessions=sessions, started=started,
                          current_session=current_session, admin_db=admin_db or db,
                          store=store, status=status, db_path=db_path, actor=actor,
                          json_body=json_body, audit=audit, viewed_session=viewed_session,
                          active_mutes=active_mutes,
                          config_path=config_path,
                          monitored_path=monitored_path or cfg.get("monitored_networks") or "data/monitored.json")
    app.extensions["ghostap"] = ctx

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
            attacks = s.alerts(ATTACK_DETECTORS)
            t1 = row["t1"]
            recent = s.conn.execute("SELECT COUNT(*) FROM observations WHERE ts > ?",
                                    ((t1 or 0) - 60,)).fetchone()[0] if t1 else 0
            n_base = s.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector='baseline'").fetchone()[0]
            triage_v = s.conn.execute(
                "SELECT COALESCE(MAX(triage_ts), 0), COUNT(*) FROM alerts").fetchone()
        mutes = active_mutes()
        open_alerts = [a for a in attacks if a.get("triage_status") != "false_positive" and not is_muted(a, mutes)]
        open_levels = {}
        for a in open_alerts:
            open_levels[a["level"]] = open_levels.get(a["level"], 0) + 1
        dismissed = sum(1 for a in attacks if a.get("triage_status") == "false_positive")
        top = open_alerts[:1]
        st = status()
        t0 = row["t0"]
        baseline_s = cfg["baseline_minutes"] * 60
        return jsonify({
            "status": st,
            # changes whenever scores, alerts or triage change: the page refetches only then
            "data_version": "{}-{}-{}-{}-{}".format(st.get("data_version", 0), triage_v[0], triage_v[1],
                                                    row["aps"], ",".join(str(m["id"]) for m in mutes)),
            "heartbeat": {"frames_last_minute": recent,                       # F021
                          "last_frame_age_s": (round(time.time() - st["last_frame_ts"], 1)
                                               if st.get("mode") == "live" and st.get("last_frame_ts") else None)},
            "muted_alerts": sum(1 for a in attacks if is_muted(a, mutes)),
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
            "top_alert": ({k: top[0][k] for k in ("id", "ssid", "bssid", "level", "score", "detector",
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
                    vendor=vendors.lookup(profile["bssid"]),
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
                            vendor=vendors.name(p["bssid"]),
                            local_mac=vendors.is_local(p["bssid"]),
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
            rows = s.alerts(None if detector == "all" else detector)
        mutes = active_mutes()
        for a in rows:
            a["muted"] = is_muted(a, mutes)
        return jsonify(rows)

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
            before = s.alert(alert_id)
            if before is None or not s.set_triage(alert_id, status_, note, time.time()):
                abort(404)
            after = s.alert(alert_id)
        audit("triage", "{} {}".format(after["ssid"], after["bssid"]),
              {"alert": alert_id, "session": viewed_session() or current_session,
               "from": before.get("triage_status") or "new", "to": status_,
               "note_changed": (before.get("triage_note") or "") != (note or "")})
        return jsonify(after)

    from . import web_admin
    web_admin.register(app, ctx)
    from . import web_monitored
    web_monitored.register(app, ctx)
    from . import web_ap
    web_ap.register(app, ctx)
    from . import web_tools
    web_tools.register(app, ctx)

    @app.get("/api/timeline")
    def timeline():
        """Risk lines for the timeline chart (F038: bounded for large sites).

        Every access point that reached MEDIUM, then the highest-scoring others up to `top`
        lines, are sent in full; the rest are folded into one line holding their highest
        score at each step. Each line is cut to at most `points` points, keeping the
        highest score of every bucket so that no peak disappears."""
        top = _int_arg("top", 30, 1, 500)
        points = _int_arg("points", 800, 50, 20000)
        series = defaultdict(lambda: {"ts": [], "score": [], "raw": [], "level": []})
        with store() as s:
            for r in s.conn.execute("SELECT ts, ssid, bssid, score, raw_score, level FROM risk_timeline "
                                    "ORDER BY ssid, bssid, ts"):
                d = series[(r[1], r[2])]
                d["ts"].append(r[0])
                d["score"].append(r[3])
                d["raw"].append(r[4])
                d["level"].append(r[5])
        rows = [dict(ssid=k[0], bssid=k[1], peak=max(v["score"]), **v) for k, v in series.items()]
        rows.sort(key=lambda r: -r["peak"])
        med = cfg["thresholds"]["medium"]
        keep = [r for r in rows if r["peak"] >= med]
        keep += [r for r in rows if r["peak"] < med][:max(0, top - len(keep))]
        kept = {(r["ssid"], r["bssid"]) for r in keep}
        rest = [r for r in rows if (r["ssid"], r["bssid"]) not in kept]
        out = [_downsample(r, points) for r in keep]
        if rest:
            env: dict = {}
            for r in rest:
                for t, sc, raw in zip(r["ts"], r["score"], r["raw"]):
                    e = env.get(t)
                    env[t] = (max(e[0], sc), max(e[1], raw)) if e else (sc, raw)
            ts = sorted(env)
            agg = {"ssid": "", "bssid": "", "aggregate": len(rest), "peak": max(v[0] for v in env.values()),
                   "ts": ts, "score": [env[t][0] for t in ts], "raw": [env[t][1] for t in ts],
                   "level": [None] * len(ts)}
            out.append(_downsample(agg, points))
        resp = jsonify(out)
        resp.headers["X-GhostAP-Lines"] = "{} of {}".format(len(keep), len(rows))
        return resp

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
    src.add_argument("--pcap", help="replay a pcap (a new session is created)")
    src.add_argument("--iface", help="live capture on a monitor-mode interface (Linux, root)")
    ap.add_argument("--name", help="name for the new session (default: from the pcap / interface)")
    ap.add_argument("--db", default=None,
                    help="use this database instead of a session (older behaviour)")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--speed", type=float, default=10.0,
                    help="replay speed multiplier; 0 = as fast as possible (default 10)")
    ap.add_argument("--duration", type=float, default=None, help="stop live capture after N seconds")
    ap.add_argument("--hop", metavar="CHANNELS",
                    help="live: hop channels, e.g. 1,6,11 or 1-13 or 2.4 or 5 or all")
    ap.add_argument("--dwell", type=float, default=0.25, help="live: seconds per channel (default 0.25)")
    ap.add_argument("--save-pcap", metavar="FILE",
                    help="live: record to this pcap (default: capture.pcap in the session folder)")
    ap.add_argument("--no-record", action="store_true", help="live: do not record a pcap")
    mon = ap.add_mutually_exclusive_group()
    mon.add_argument("--monitored", metavar="FILE",
                     help="use this saved baseline (default for live capture: config monitored_networks)")
    mon.add_argument("--no-monitored", action="store_true", help="ignore saved baselines; learn everything")
    ap.add_argument("--keep", action="store_true",
                    help="with --db: keep existing data instead of starting fresh")
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to listen on (default 127.0.0.1). Anything else, e.g. 0.0.0.0 "
                         "to reach Kali in a VM from the host, turns on token login")
    ap.add_argument("--port", type=int, default=8050)
    args = ap.parse_args(argv)

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
    if (args.hop or args.save_pcap or args.no_record) and not args.iface:
        ap.error("--hop, --save-pcap and --no-record only apply to live capture (--iface)")
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    from .logs import setup_logging
    log = setup_logging(cfg)

    # ---- where the data goes: a new session per run (F040), or an explicit --db
    sessions = SessionStore(cfg["sessions_dir"])
    session = None
    if args.db:
        db = args.db
    elif args.pcap or args.iface:
        mode = "replay" if args.pcap else "live"
        default_name = (os.path.splitext(os.path.basename(args.pcap))[0] if args.pcap
                        else "live {}".format(args.iface))
        session = sessions.create(args.name or default_name, mode, args.pcap or args.iface)
        db = session.db
    else:
        session = sessions.latest()
        db = session.db if session else "data/ghostap.db"
    save_pcap = args.save_pcap
    if args.iface and not save_pcap and not args.no_record:
        save_pcap = session.pcap if session else None

    # ---- saved baseline (F014): live uses it by default, replays only on request
    monitored = None
    network_settings = None
    mon_path = None if args.no_monitored else (
        args.monitored or (cfg["monitored_networks"] if args.iface else None))
    if mon_path and os.path.exists(mon_path):
        from . import monitored as monitored_mod
        try:
            mdata = monitored_mod.load(mon_path)
            monitored = monitored_mod.baselines(mdata, cfg["known_bssids"]) or None
            network_settings = {s: n.get("settings") or {} for s, n in mdata["networks"].items()}
        except (ValueError, OSError) as e:
            print("[!] cannot use saved baseline {}: {}".format(mon_path, e), file=sys.stderr)
            return 2
    elif args.monitored:
        print("[!] saved baseline not found: {}".format(args.monitored), file=sys.stderr)
        return 1

    def finished(st):
        if session is not None:
            session.update_meta(ended_at=time.time(), frames=st.get("frames"), state=st.get("state"))

    pipe = Pipeline(db, cfg, pcap=args.pcap, iface=args.iface, speed=args.speed,
                    duration=args.duration, reset=not args.keep if args.db else True, hop=hop,
                    dwell=args.dwell, save_pcap=save_pcap, monitored=monitored,
                    network_settings=network_settings, on_finish=finished,
                    hop_focus=({c: 3.0 for b in monitored.values() for c in b.channels}
                               if monitored and hop else None)).start()
    local = is_loopback(args.host)
    token = None if local else (os.environ.get("GHOSTAP_TOKEN") or secrets.token_urlsafe(24))
    admin_db = os.path.join(os.path.dirname(cfg["sessions_dir"].rstrip("/")) or ".", "admin.db")
    app = create_app(db, cfg, pipe, token=token, local_only=local, sessions=sessions,
                     current_session=session.id if session else None, admin_db=admin_db,
                     config_path=args.config, monitored_path=args.monitored or cfg["monitored_networks"])
    mode = pipe.status["mode"]
    log.info("dashboard start: mode=%s source=%s session=%s monitored=%s host=%s port=%s",
             mode, pipe.status["source"], session.id if session else db,
             len(monitored) if monitored else 0, args.host, args.port)
    if session is not None:
        print("[+] session: {}".format(session.path))
    if monitored:
        print("[+] using saved baseline for {} network(s): scoring starts immediately".format(len(monitored)))
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
