"""Lab and evaluation API (Phase G): session report (F052), session bundle (F054),
labelling with suggestions (F046, F088) and the evaluation runner (F047)."""
from __future__ import annotations

import base64
import html
import io
import json
import os
import re
import shutil
import threading
import time
from typing import Optional

from flask import Response, abort, jsonify, request

from .sessions import SessionError, export_bundle, recording_of

LABELS = {
    "security_downgrade": "Security downgrade", "new_bssid_oui": "New radio / vendor",
    "channel_deviation": "Unusual channel", "rssi_jump": "Signal jump", "tsf_anomaly": "Freshly booted",
    "ie_fingerprint": "Beacon fingerprint", "bssid_conflict": "Cloned address",
    "beacon_interval_mismatch": "Beacon timing", "karma": "KARMA / MANA", "lookalike_ssid": "Look-alike name",
    "known_tool": "Known attack tool", "deauth_flood": "Deauthentication flood", "beacon_flood": "Beacon flood",
}
TRIAGE = {"new": "New", "investigating": "Investigating", "confirmed": "Confirmed attack",
          "false_positive": "False positive"}
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,60}$")
DATASETS = (("eval", "Standard synthetic set (tools/make_eval_set.py)"),
            ("eval_custom", "Custom synthetic scenarios (tools/build_scenario.py)"),
            ("lab", "Your labelled lab captures (Phase 2)"))


def _session(ctx):
    """(Session, meta) for the viewed session; 400 when GhostAP runs without sessions."""
    sid = ctx.viewed_session() or ctx.current_session
    if not ctx.sessions or not sid:
        abort(Response('{"error": "this needs sessions (start the dashboard without --db)"}', 400,
                       mimetype="application/json"))
    try:
        s = ctx.sessions.get(sid)
    except SessionError:
        abort(404)
    return s, s.meta()


def _source_pcap(s, meta=None) -> Optional[str]:
    return recording_of(s)


def _t(ts, t0):
    return "–" if ts is None else "t+{:.0f} s ({})".format(ts - t0, time.strftime("%H:%M:%S", time.localtime(ts)))


# --------------------------------------------------------------------------- F088 suggestions
def suggest(profile: dict, alert: Optional[dict], baseline_end: Optional[float]) -> dict:
    """A label suggestion with a reason. The analyst decides; nothing is saved by itself."""
    early = baseline_end is not None and profile["first_seen"] < baseline_end
    inds = {i["name"]: i for i in (alert or {}).get("indicators") or []}
    if alert and inds.get("bssid_conflict", {}).get("value", 0) > 0:
        return {"label": "evil_twin", "confidence": "high",
                "why": "two radios transmit with this address (cloned BSSID); the address belongs to the twin's label"}
    if alert and not early and alert["level"] == "HIGH":
        return {"label": "evil_twin", "confidence": "high",
                "why": "appeared after the learning period and reached HIGH ({:.0f})".format(alert["score"])}
    if alert and not early:
        return {"label": "evil_twin", "confidence": "low",
                "why": "appeared after the learning period and reached MEDIUM ({:.0f}): check it".format(
                    alert["score"])}
    if early and alert:
        return {"label": "legit", "confidence": "low",
                "why": "present while GhostAP learned, but alerted later ({:.0f}): check for a reboot or change".format(
                    alert["score"])}
    if early:
        return {"label": "legit", "confidence": "high", "why": "present while GhostAP learned the network"}
    return {"label": "legit", "confidence": "medium", "why": "new access point that matches its network (no alert)"}


def register(app, ctx) -> None:
    eval_job: dict = {"state": "idle"}
    lock = threading.Lock()

    # ---------------------------------------------------------------- F052 session report
    @app.get("/api/report.html")
    def session_report():
        """A printable incident report of the viewed session (save as PDF from the browser)."""
        with ctx.store() as s:
            prof = s.profiles()
            alerts = s.alerts("ghostap,deauth,flood")
            base = s.conn.execute("SELECT COUNT(*) FROM alerts WHERE detector='baseline'").fetchone()[0]
            notes = s.annotations()
            t0, t1, frames = s.conn.execute("SELECT MIN(first_seen), MAX(last_seen), COALESCE(SUM(frames), 0) "
                                            "FROM ap_profiles").fetchone()
            tl = s.timeline()
        from .risk import build_incidents
        incidents = build_incidents(alerts)
        sid = ctx.viewed_session() or ctx.current_session
        meta = ctx.sessions.get(sid).meta() if ctx.sessions and sid else {"name": os.path.basename(ctx.db)}
        if t0 is None:
            return Response("<p>No data in this session yet.</p>", mimetype="text/html")
        e = html.escape
        chart = _report_chart(tl, alerts, t0, ctx.cfg["thresholds"])
        nets = len({p["ssid"] for p in prof})
        hi = sum(a["level"] == "HIGH" for a in alerts)
        md = sum(a["level"] == "MEDIUM" for a in alerts)
        synthetic = "test_capture" in str(meta.get("source", "")) or "synthetic" in str(meta.get("name", ""))
        rows = []
        for a in alerts:
            top = sorted([i for i in a.get("indicators") or [] if i.get("contribution", 0) > 0],
                         key=lambda i: -i["contribution"])[:4]
            rows.append("<tr><td>{}</td><td>{}</td><td class=mono>{}</td><td class=num>{:.0f}</td><td>{}</td>"
                        "<td>{}</td><td>{}</td></tr>".format(
                            e(a["level"]), e(a["ssid"]), e(a["bssid"]), a["score"], e(_t(a["first_ts"], t0)),
                            "<br>".join("{} +{:.0f}".format(e(LABELS.get(i["name"], i["name"])), i["contribution"])
                                        for i in top) or e(a.get("detector") or ""),
                            e(TRIAGE.get(a.get("triage_status") or "new", "")) +
                            ("<br><i>{}</i>".format(e(a["triage_note"])) if a.get("triage_note") else "")))
        story = "".join("<li><b>{}</b><ol>{}</ol></li>".format(
            e(i["summary"]), "".join("<li>{}: {}</li>".format(e(_t(st["ts"], t0)), e(st["text"])) for st in i["story"]))
            for i in incidents)
        page = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>GhostAP report: {name}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#111}}
h1{{font-size:22px;margin:0}}h2{{font-size:17px;margin-top:26px;border-bottom:1px solid #ddd;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #e3e3e3;padding:5px 6px;
text-align:left;vertical-align:top}}.mono{{font-family:ui-monospace,monospace}}.num{{text-align:right}}
.muted{{color:#555}}.box{{border:1px solid #e0c060;background:#fff8e0;padding:8px 12px;border-radius:6px}}
img{{max-width:100%}}@media print{{body{{margin:0}}}}</style></head><body>
<h1>GhostAP incident report</h1><p class=muted>Session “{name}” · {mode} · generated {now}</p>
{synth}
<h2>Summary</h2><p>Capture from {start} to {end} ({dur:.0f} min): {aps} access points on {nets} networks,
{frames:,} beacons. <b>{hi} HIGH and {md} MEDIUM alerts.</b> A check that only looks for duplicated network names
would have raised {base} alarms on the same capture.</p>
<h2>Incidents</h2>{incidents}
<h2>Alerts</h2>{alerts}
<h2>Risk over time</h2>{chart}
<h2>Analyst notes</h2>{notes}
<h2>How to read this</h2><p class=muted>GhostAP is passive: it only listened to Wi-Fi beacons and never transmitted.
Each access point's risk score (0–100) is the weighted share of eight indicators that differ from what was learned
about its network in the first {bm:g} minutes, averaged over 30 s. MEDIUM from {med:g}, HIGH from {high:g}. An alert
is evidence to check, not proof: the “why” column lists the strongest reasons, and the triage column what an
analyst concluded.</p></body></html>""".format(
            name=e(str(meta.get("name", ""))), mode=e(str(meta.get("mode", ""))),
            now=e(time.strftime("%Y-%m-%d %H:%M")),
            synth='<p class=box>This session replays the <b>synthetic</b> test capture: it demonstrates the method, '
                  'it is not a field result.</p>' if synthetic else "",
            start=e(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t0))),
            end=e(time.strftime("%H:%M:%S", time.localtime(t1))), dur=(t1 - t0) / 60, aps=len(prof), nets=nets,
            frames=frames, hi=hi, md=md, base=base,
            incidents="<ol>{}</ol>".format(story) if story else "<p>No incidents.</p>",
            alerts=("<table><tr><th>Level</th><th>Network</th><th>BSSID</th><th>Peak</th><th>First alert</th>"
                    "<th>Why</th><th>Triage</th></tr>{}</table>".format("".join(rows)) if rows
                    else "<p>No alerts: every access point matched what was learned.</p>"),
            chart='<img alt="Risk score of each access point over time" src="data:image/png;base64,{}">'.format(chart)
            if chart else "<p>No timeline yet.</p>",
            notes="<ul>{}</ul>".format("".join("<li>{}: {} <span class=muted>({})</span></li>".format(
                e(_t(n["ts"], t0)), e(n["text"]), e(n["actor"] or "")) for n in notes)) if notes else "<p>None.</p>",
            bm=ctx.cfg["baseline_minutes"], med=ctx.cfg["thresholds"]["medium"], high=ctx.cfg["thresholds"]["high"])
        ctx.audit("report.view", sid, {})
        return Response(page, mimetype="text/html")

    # ---------------------------------------------------------------- F054 bundle
    @app.get("/api/sessions/<sid>/bundle.zip")
    def session_bundle(sid):
        try:
            s = ctx.sessions.get(sid) if ctx.sessions else None
        except SessionError:
            abort(404)
        if s is None:
            abort(404)
        buf = io.BytesIO()
        man = export_bundle(s, buf)
        ctx.audit("session.bundle", sid, {"files": list(man["files"])})
        return Response(buf.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="ghostap_{}.zip"'.format(sid)})

    # ---------------------------------------------------------------- F046 / F088 labelling
    @app.get("/api/labels")
    def labels_get():
        s, meta = _session(ctx)
        saved = {}
        path = os.path.join(s.path, "labels.json")
        if os.path.isfile(path):
            with open(path) as f:
                saved = json.load(f)
        with ctx.store() as st:
            prof = st.profiles()
            alerts = {(a["ssid"], a["bssid"]): a for a in st.alerts("ghostap")}
            t0 = st.conn.execute("SELECT MIN(first_seen) FROM ap_profiles").fetchone()[0]
        b_end = None if t0 is None else t0 + ctx.cfg["baseline_minutes"] * 60
        aps = []
        for p in sorted(prof, key=lambda p: p["first_seen"]):
            a = alerts.get((p["ssid"], p["bssid"]))
            sug = suggest(p, a, b_end)
            mine = (saved.get("aps") or {}).get(p["bssid"])
            start = None
            if sug["label"] == "evil_twin":
                start = p["first_seen"] if (b_end is None or p["first_seen"] >= b_end) else (a or {}).get("first_ts")
            aps.append({"ssid": p["ssid"], "bssid": p["bssid"], "first_seen": p["first_seen"],
                        "in_baseline": b_end is not None and p["first_seen"] < b_end,
                        "level": a["level"] if a else None, "score": a["score"] if a else None,
                        "suggestion": dict(sug, attack_start=start),
                        "label": mine if isinstance(mine, dict) else ({"label": mine} if mine else None)})
        return jsonify({"session": s.id, "capture_start": t0, "aps": aps, "saved_at": saved.get("labelled_at"),
                        "has_pcap": _source_pcap(s, meta) is not None})

    @app.post("/api/labels")
    def labels_save():
        s, meta = _session(ctx)
        body, err = ctx.json_body()
        if err:
            return err
        aps = body.get("aps")
        if not isinstance(aps, dict) or not aps:
            return jsonify({"error": "label at least one access point"}), 400
        clean = {}
        for b, v in aps.items():
            if not isinstance(b, str) or not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", b.lower()):
                return jsonify({"error": "{!r} is not a BSSID".format(b)}), 400
            if not isinstance(v, dict) or v.get("label") not in ("legit", "evil_twin"):
                return jsonify({"error": "labels are legit or evil_twin"}), 400
            entry = {"label": v["label"]}
            if v["label"] == "evil_twin":
                st = v.get("attack_start")
                if isinstance(st, bool) or not isinstance(st, (int, float)):
                    return jsonify({"error": "an evil twin needs attack_start (capture time)"}), 400
                entry["attack_start"] = float(st)
            clean[b.lower()] = entry
        with ctx.store() as st:
            t0 = st.conn.execute("SELECT MIN(first_seen) FROM ap_profiles").fetchone()[0]
        doc = {"session": s.id, "description": str(body.get("description") or meta.get("name") or "")[:300],
               "synthetic": bool(body.get("synthetic")), "capture_start": t0, "labelled_by": ctx.actor(),
               "labelled_at": time.time(), "aps": clean}
        tmp = os.path.join(s.path, "labels.json.tmp")
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=2)
        os.replace(tmp, os.path.join(s.path, "labels.json"))
        twins = sum(v["label"] == "evil_twin" for v in clean.values())
        ctx.audit("labels.save", s.id, {"aps": len(clean), "twins": twins})
        return jsonify({"saved": len(clean)})

    @app.post("/api/labels/export")
    def labels_export():
        """Copy the session's capture and labels into data/lab/ for `evaluate.py --dataset data/lab`."""
        s, meta = _session(ctx)
        body, err = ctx.json_body()
        if err:
            return err
        name = str(body.get("name") or "")
        if not NAME_RE.match(name):
            return jsonify({"error": "name: 1-60 letters, digits, _ or -"}), 400
        src = _source_pcap(s, meta)
        lab = os.path.join(s.path, "labels.json")
        if not src or not os.path.isfile(lab):
            return jsonify({"error": "this session needs a recording and saved labels first"}), 400
        out = os.path.join("data", "lab")
        os.makedirs(out, exist_ok=True)
        dest = os.path.join(out, name + ".pcap")
        if os.path.exists(dest) and not body.get("overwrite"):
            return jsonify({"error": "data/lab/{}.pcap exists; choose another name".format(name), "exists": True}), 409
        shutil.copyfile(src, dest)
        shutil.copyfile(lab, os.path.join(out, name + ".labels.json"))
        ctx.audit("labels.export", s.id, {"to": dest})
        return jsonify({"pcap": dest, "labels": os.path.join(out, name + ".labels.json")})

    # ---------------------------------------------------------------- F047 evaluation page
    def _dataset_dir(name):
        return os.path.join("data", name)

    def _out_dir(name):
        return "results" if name == "eval" else os.path.join("results", name)

    @app.get("/api/evaluation/datasets")
    def eval_datasets():
        from .evaluate import find_dataset
        out = []
        for name, desc in DATASETS:
            d = _dataset_dir(name)
            pairs = find_dataset(d) if os.path.isdir(d) else []
            res = os.path.join(_out_dir(name), "metrics.csv")
            out.append({"name": name, "description": desc, "captures": len(pairs), "dir": d,
                        "results_at": os.path.getmtime(res) if os.path.exists(res) else None})
        return jsonify(out)

    @app.post("/api/evaluation/run")
    def eval_run():
        body, err = ctx.json_body()
        if err:
            return err
        name = body.get("dataset")
        if name not in dict(DATASETS):
            return jsonify({"error": "unknown dataset"}), 400
        with lock:
            if eval_job.get("state") == "running":
                return jsonify({"error": "an evaluation is already running"}), 409
            eval_job.clear()
            eval_job.update(state="running", dataset=name, started=time.time(), progress="starting")

        def work():
            from .evaluate import evaluate, find_dataset, write_results
            from .evaluate_extended import extended
            try:
                if name == "eval" and not os.path.isdir(_dataset_dir(name)):
                    import importlib.util
                    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    spec = importlib.util.spec_from_file_location(
                        "make_eval_set", os.path.join(root, "tools", "make_eval_set.py"))
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    mod.generate(_dataset_dir(name))
                pairs = find_dataset(_dataset_dir(name))
                if not pairs:
                    raise ValueError("no labelled captures in {}".format(_dataset_dir(name)))
                eval_job["progress"] = "scoring {} captures".format(len(pairs))
                rows, metrics, sweep, scen = evaluate(pairs, ctx.cfg)
                eval_job["progress"] = "writing results"
                write_results(_out_dir(name), rows, metrics, sweep, scen, ctx.cfg, charts=True)
                ext = extended(rows, ctx.cfg, _out_dir(name), charts=True)
                with lock:
                    eval_job.update(state="done", finished=time.time(), progress="done")
                ctx.audit_as("evaluation", "evaluation.run", name,
                             {"captures": len(pairs), "headline": ext["headline"]})
            except Exception as ex:  # shown on the page, not hidden
                with lock:
                    eval_job.update(state="error", error="{}: {}".format(type(ex).__name__, ex), finished=time.time())

        threading.Thread(target=work, name="ghostap-evaluation", daemon=True).start()
        ctx.audit("evaluation.start", name, {})
        return jsonify({"started": True})

    @app.get("/api/evaluation/status")
    def eval_status():
        with lock:
            return jsonify({k: v for k, v in eval_job.items()})

    @app.get("/api/evaluation/result")
    def eval_result():
        import csv
        name = request.args.get("dataset", "eval")
        if name not in dict(DATASETS):
            abort(404)
        out = _out_dir(name)
        if not os.path.exists(os.path.join(out, "metrics.csv")):
            return jsonify({"available": False})

        def rows(fn):
            p = os.path.join(out, fn)
            if not os.path.exists(p):
                return []
            with open(p) as f:
                return list(csv.DictReader(f))
        ext = None
        if os.path.exists(os.path.join(out, "extended.json")):
            with open(os.path.join(out, "extended.json")) as f:
                ext = json.load(f)
        return jsonify({"available": True, "dataset": name, "metrics": rows("metrics.csv"),
                        "per_scenario": rows("per_scenario.csv"), "per_ap": rows("per_ap.csv"), "extended": ext,
                        "written_at": os.path.getmtime(os.path.join(out, "metrics.csv"))})


def _report_chart(tl, alerts, t0, th) -> Optional[str]:
    if not tl:
        return None
    from matplotlib.figure import Figure             # object API: safe in request threads (pyplot is not)
    alerting = {(a["ssid"], a["bssid"]) for a in alerts}
    series = {}
    for r in tl:
        series.setdefault((r["ssid"], r["bssid"]), []).append((r["ts"] - t0, r["score"]))
    fig = Figure(figsize=(9, 3.2))
    ax = fig.subplots()
    for key, pts in sorted(series.items(), key=lambda kv: (kv[0] in alerting, kv[0])):
        hot = key in alerting
        ax.plot([p[0] for p in pts], [p[1] for p in pts], lw=2 if hot else 1, alpha=1 if hot else .45,
                color=None if hot else "#9a9890", label="{} {}".format(*key) if hot else None)
    ax.axhline(th["medium"], ls="--", lw=1, color="#cf5f30")
    ax.axhline(th["high"], ls="--", lw=1, color="#d03b3b")
    ax.set(ylim=(0, 100), xlabel="capture time (s)", ylabel="risk")
    if alerting:
        ax.legend(fontsize=8, loc="upper left")
    ax.grid(alpha=.3)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    return base64.b64encode(buf.getvalue()).decode()
