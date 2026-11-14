"""Access-point detail API (F028 beacon diff, F030 signal/uptime series, F032 evidence pcap,
F033 related access points). Vendor names (F029) are added to the AP rows in web.py.
"""
from __future__ import annotations

import io
import json
import os
import re
import time
from difflib import SequenceMatcher

from flask import Response, abort, jsonify, request

from . import beacons

MAX_EVIDENCE_FRAMES = 50_000
EVIDENCE_PAD_S = 30


def _args():
    ssid, bssid = request.args.get("ssid"), (request.args.get("bssid") or "").lower()
    if not ssid or not bssid:
        abort(400)
    return ssid, bssid


def related_reasons(me: dict, other: dict, fps_me: set, fps_other: set, b_end) -> list:
    """Why `other` may belong to the same device or attack as `me` (F033)."""
    why = []
    a, b = me["bssid"], other["bssid"]
    try:
        ia, ib = int(a.replace(":", ""), 16), int(b.replace(":", ""), 16)
    except ValueError:
        return why
    if a[:14] == b[:14] and abs(ia - ib) <= 15:
        why.append(("neighbour", 3, "consecutive address: multi-network radios number their networks this way"))
    elif (ia ^ ib) == 0x02 << 40:
        why.append(("neighbour", 3,
                    "same address with the 'locally administered' bit set: same device, second network"))
    if (b_end is not None and me["first_seen"] >= b_end and other["first_seen"] >= b_end
            and abs(me["first_seen"] - other["first_seen"]) <= 15):
        why.append(("together", 2, "appeared within {:.0f} s of it, after the learning period".format(
            abs(me["first_seen"] - other["first_seen"]))))
    if other["ssid"] != me["ssid"] and fps_me & fps_other:
        why.append(("fingerprint", 1, "same beacon structure under another name (same hardware or AP software)"))
    if why and me["rssi_avg"] is not None and other["rssi_avg"] is not None \
            and abs(me["rssi_avg"] - other["rssi_avg"]) <= 3 and me["channels"] == other["channels"]:
        why.append(("signal", 1, "same channel and signal within 3 dB: probably the same spot"))
    return why


def register(app, ctx) -> None:

    # ---------------------------------------------------------------- F028
    @app.get("/api/ap/beacon_diff")
    def beacon_diff():
        ssid, bssid = _args()
        with ctx.store() as s:
            rows = s.conn.execute(
                "SELECT o.bssid, o.fingerprint, MIN(o.ts) AS first, COUNT(*) AS n, MIN(o.ts) < ? AS early "
                "FROM observations o WHERE o.ssid=? AND o.frame_type='beacon' AND o.fingerprint IS NOT NULL "
                "GROUP BY o.bssid, o.fingerprint",
                (_baseline_end(s) or 0, ssid)).fetchall()
            layouts = {r["fingerprint"]: json.loads(r["layout"]) for r in s.conn.execute(
                "SELECT fingerprint, layout FROM layouts WHERE fingerprint IN ({})".format(
                    ",".join("?" * len({r["fingerprint"] for r in rows}))),
                tuple({r["fingerprint"] for r in rows})).fetchall()} if rows else {}
        mine = sorted((r for r in rows if r["bssid"] == bssid), key=lambda r: -r["n"])
        if not mine:
            return jsonify({"available": False, "reason": "this access point sent no beacons with a fingerprint"})
        others = [r for r in rows if r["bssid"] != bssid]
        known = [r for r in others if r["early"]] or others
        if not known:
            return jsonify({"available": False, "reason": "no other access point of this network to compare with"})
        mfp = mine[0]["fingerprint"]
        if mfp not in layouts:
            return jsonify({"available": False,
                            "reason": "this session was recorded before GhostAP kept beacon layouts"})
        cands = [r for r in known if r["fingerprint"] in layouts]
        if not cands:
            return jsonify({"available": False, "reason": "the known access points' layouts were not kept"})
        best = max(cands, key=lambda r: (SequenceMatcher(a=layouts[r["fingerprint"]], b=layouts[mfp],
                                                         autojunk=False).ratio(), r["n"]))
        diff = beacons.diff(layouts[mfp], layouts[best["fingerprint"]])
        return jsonify({"available": True, "fingerprint": mfp,
                        "other_fingerprints": [r["fingerprint"] for r in mine[1:]],
                        "known": {"bssid": best["bssid"], "fingerprint": best["fingerprint"],
                                  "in_baseline": bool(best["early"])},
                        "rows": diff, "summary": beacons.summary(diff)})

    # ---------------------------------------------------------------- F030
    @app.get("/api/ap/series")
    def ap_series():
        ssid, bssid = _args()
        with ctx.store() as s:
            span = s.conn.execute("SELECT MIN(ts), MAX(ts) FROM observations WHERE ssid=?", (ssid,)).fetchone()
            if span[0] is None:
                abort(404)
            step = max(float(ctx.cfg["temporal"]["step_seconds"]), (span[1] - span[0]) / 1500 or 1)
            rows = s.conn.execute(
                "SELECT bssid, CAST((ts - ?) / ? AS INTEGER) AS b, AVG(rssi) AS rssi, COUNT(*) AS frames, "
                "MAX(tsf) AS tsf FROM observations WHERE ssid=? GROUP BY bssid, b ORDER BY bssid, b",
                (span[0], step, ssid)).fetchall()
        series = {}
        for r in rows:
            series.setdefault(r["bssid"], []).append(
                [span[0] + (r["b"] + 0.5) * step, None if r["rssi"] is None else round(r["rssi"], 1),
                 round(r["frames"] / step, 2), None if r["tsf"] is None else round(r["tsf"] / 1e6, 1)])
        if bssid not in series:
            abort(404)
        return jsonify({"step": step, "t0": span[0], "focus": bssid,
                        "series": [{"bssid": b, "points": p} for b, p in sorted(series.items(),
                                                                               key=lambda kv: kv[0] != bssid)]})

    # ---------------------------------------------------------------- Live radar
    @app.get("/api/live")
    def live():
        """Access points heard in the last `seconds` (capture time), for the live radar:
        signal now (last 10 s), 5-second signal buckets for trails, channel, band, risk.
        "Now" is the newest frame, so replays and past sessions work the same way."""
        try:
            seconds = max(10, min(600, int(request.args.get("seconds", 60))))
        except ValueError:
            seconds = 60
        from . import vendors
        from .parser import band_of
        with ctx.store() as s:
            now = s.conn.execute("SELECT MAX(last_seen) FROM ap_profiles").fetchone()[0]
            if now is None:
                return jsonify({"now": None, "seconds": seconds, "aps": []})
            rows = s.conn.execute(
                "SELECT ssid, bssid, CAST((ts - ?) / 5 AS INTEGER) AS b, AVG(rssi) AS rssi, COUNT(*) AS n, "
                "MAX(ts) AS last, MAX(channel) AS ch, MAX(freq) AS freq "
                "FROM observations WHERE ts > ? GROUP BY ssid, bssid, b ORDER BY ssid, bssid, b",
                (now - seconds, now - seconds)).fetchall()
            prof = {(p["ssid"], p["bssid"]): p for p in s.profiles()}
            latest = s.latest()
            t0 = s.conn.execute("SELECT MIN(first_seen) FROM ap_profiles").fetchone()[0]
        b_end = t0 + ctx.cfg["baseline_minutes"] * 60
        aps: dict = {}
        for r in rows:
            key = (r["ssid"], r["bssid"])
            a = aps.setdefault(key, {"trail": [], "frames": 0, "last": 0.0, "ch": None, "freq": None})
            if r["rssi"] is not None:
                a["trail"].append([min(now, round(now - seconds + (r["b"] + 1) * 5, 1)), round(r["rssi"], 1)])
            a["frames"] += r["n"]
            a["last"] = max(a["last"], r["last"])
            a["ch"] = r["ch"] if r["ch"] is not None else a["ch"]
            a["freq"] = r["freq"] if r["freq"] is not None else a["freq"]
        out = []
        for (ssid, bssid), a in aps.items():
            p = prof.get((ssid, bssid)) or {}
            cur = latest.get((ssid, bssid)) or {}
            recent = [v for t, v in a["trail"] if t > now - 10] or [v for _, v in a["trail"][-2:]]
            out.append({
                "ssid": ssid, "bssid": bssid, "vendor": vendors.name(bssid),
                "rssi": round(sum(recent) / len(recent), 1) if recent else None,
                "trail": a["trail"], "frames_per_s": round(a["frames"] / seconds, 2),
                "channel": a["ch"], "band": band_of(a["freq"]) or ("5" if (a["ch"] or 0) > 14 else "2.4"),
                "security": p.get("securities"), "first_seen": p.get("first_seen"),
                "silent_s": round(now - a["last"], 1), "new": (p.get("first_seen") or 0) > now - seconds,
                "known": (p.get("first_seen") or now) < b_end,
                "level": cur.get("level"), "score": cur.get("score"),
            })
        out.sort(key=lambda x: (x["ssid"], x["bssid"]))
        sn = ctx.cfg["sensors"]
        return jsonify({"now": now, "seconds": seconds, "aps": out,
                        "model": {"p0": sn["path_loss_p0"], "n": sn["path_loss_n"]}})

    # ---------------------------------------------------------------- F033
    @app.get("/api/ap/related")
    def ap_related():
        ssid, bssid = _args()
        with ctx.store() as s:
            profiles = s.profiles()
            fps = {}
            for r in s.conn.execute("SELECT DISTINCT ssid, bssid, fingerprint FROM observations "
                                    "WHERE frame_type='beacon' AND fingerprint IS NOT NULL"):
                fps.setdefault((r[0], r[1]), set()).add(r[2])
            b_end = _baseline_end(s)
        me = next((p for p in profiles if p["ssid"] == ssid and p["bssid"] == bssid), None)
        if me is None:
            abort(404)
        out = []
        for p in profiles:
            if p is me:
                continue
            why = related_reasons(me, p, fps.get((ssid, bssid), set()), fps.get((p["ssid"], p["bssid"]), set()), b_end)
            if why:
                out.append({"ssid": p["ssid"], "bssid": p["bssid"], "score": sum(w[1] for w in why),
                            "reasons": [{"kind": k, "text": t} for k, _, t in why]})
        out.sort(key=lambda r: (-r["score"], r["ssid"], r["bssid"]))
        return jsonify(out[:20])

    # ---------------------------------------------------------------- F032
    @app.get("/api/ap/evidence.pcap")
    def evidence_pcap():
        from scapy.layers.dot11 import Dot11, Dot11Beacon
        from scapy.utils import PcapReader, PcapWriter
        ssid, bssid = _args()
        src = _session_pcap(ctx)
        if not src:
            return jsonify({"error": "this session has no recording (start live capture without --no-record, "
                                     "or replay a pcap)"}), 404
        with ctx.store() as s:
            alert = next((a for a in s.alerts("ghostap") if a["ssid"] == ssid and a["bssid"] == bssid), None)
            prof = next((p for p in s.profiles() if p["ssid"] == ssid and p["bssid"] == bssid), None)
        if prof is None:
            abort(404)
        start = (alert["first_ts"] if alert else prof["first_seen"]) - EVIDENCE_PAD_S
        end = (alert["last_ts"] if alert else prof["last_seen"]) + EVIDENCE_PAD_S
        buf, n = io.BytesIO(), 0
        writer = None
        with PcapReader(src) as reader:
            for pkt in reader:
                t = float(pkt.time)
                if t < start:
                    continue
                if t > end or n >= MAX_EVIDENCE_FRAMES:
                    break
                # beacons only: probe responses and deauthentication frames carry client addresses
                if not pkt.haslayer(Dot11Beacon):
                    continue
                d = pkt[Dot11]
                if (d.addr3 or d.addr2 or "").lower() != bssid:
                    continue
                if writer is None:
                    writer = PcapWriter(buf, linktype=getattr(reader, "linktype", None))
                writer.write(pkt)
                n += 1
        if writer is None:
            return jsonify({"error": "no beacons from this access point in the recording for that time"}), 404
        writer.flush()
        data = buf.getvalue()
        ctx.audit("evidence.export", "{} {}".format(ssid, bssid), {"frames": n, "from": start, "to": end})
        name = "evidence_{}_{}.pcap".format(re.sub(r"[^A-Za-z0-9_-]", "_", ssid)[:40], bssid.replace(":", ""))
        return Response(data, mimetype="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": 'attachment; filename="{}"'.format(name),
                                 "X-GhostAP-Frames": str(n), "X-GhostAP-Generated": str(int(time.time()))})

    def _baseline_end(s):
        t0 = s.conn.execute("SELECT MIN(ts) FROM observations").fetchone()[0]
        return None if t0 is None else t0 + ctx.cfg["baseline_minutes"] * 60


def _session_pcap(ctx):
    """The recording behind the viewed session: its capture.pcap, or the replayed file."""
    sid = ctx.viewed_session()
    if sid is not None:
        from .sessions import recording_of
        return recording_of(ctx.sessions.get(sid)) if ctx.sessions else None
    pipe = ctx.pipeline
    for p in (getattr(pipe, "pcap", None), getattr(pipe, "save_pcap", None)):
        if p and os.path.isfile(p):
            return p
    if ctx.sessions and ctx.current_session:
        p = ctx.sessions.get(ctx.current_session).pcap
        if os.path.isfile(p):
            return p
    return None
