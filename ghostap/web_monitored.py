"""Dashboard API for monitored networks (F014-F019, F034, F035).

Everything here edits data/monitored.json (the saved baseline) or the allow-list in the
settings overlay. Changes are validated, written atomically, recorded in the audit log
and applied to a running capture immediately.

Baseline changes go through baselines.py: each applied change is a signed, numbered version;
changes that need approval (analyst, two-person rule, contamination found while learning) are
stored as proposals until an admin approves them (/api/baselines/...).
"""
from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request

from . import baselines as B
from . import monitored as mon
from .config import ConfigError, load_config, save_overlay
from .parser import HIDDEN_SSID
from .storage import Store

_MAC_CHARS = set("0123456789abcdef:")


def _is_mac(s) -> bool:
    return isinstance(s, str) and len(s) == 17 and set(s.lower()) <= _MAC_CHARS and s.count(":") == 5


def register(app, ctx) -> None:

    @app.errorhandler(B.IntegrityError)
    def integrity_failed(e):
        return jsonify({"error": str(e), "integrity": False}), 409

    def load():
        return mon.load(ctx.monitored_path)

    def role():
        p = request.environ.get("ghostap.principal")
        return p.get("role") if p else None                    # None: local mode, acts as admin

    def admins() -> int:
        try:
            with Store(ctx.admin_db) as s:
                return s.conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND NOT disabled").fetchone()[0]
        except sqlite3.OperationalError:                       # no accounts table yet
            return 0

    def apply(data, action, target, detail, checks, proposer, approver, base, vid=None) -> int:
        version = mon.save(ctx.monitored_path, data, version=base + 1)
        with Store(ctx.admin_db) as s:
            if vid is None:
                B.record(s.conn, status="trusted", content=B.content_of(data), base_version=base, actor=proposer,
                         action=action, target=target, detail=detail, checks=checks, version=version,
                         approved_by=approver)
            else:
                B.approve(s.conn, vid, version, approver)
        ctx.audit(action, target, dict(detail or {}, version=version, **({"proposal": vid} if vid else {})))
        if ctx.pipeline is not None:
            ctx.pipeline.update_monitored(
                mon.baselines(data, ctx.cfg.get("known_bssids") or ()) or None,
                {s: n.get("settings") or {} for s, n in data["networks"].items()})
        return version

    def commit(data, action, target, detail=None, checks=(), ok=None):
        """Apply a baseline change now, or store it as a proposal (HTTP 202) when it needs approval."""
        checks = list(checks)
        base = mon.signed_version(load())
        why = B.approval_needed(role(), admins(), checks)
        if why:
            with Store(ctx.admin_db) as s:
                vid = B.record(s.conn, status="pending", content=B.content_of(data), base_version=base,
                               actor=ctx.actor(), action=action, target=target, detail=detail, checks=checks)
            ctx.audit("baseline.propose", target, {"action": action, "proposal": vid, "checks": len(checks)})
            return jsonify({"pending": vid, "message": why, "checks": checks}), 202
        version = apply(data, action, target, detail, checks, ctx.actor(), ctx.actor(), base)
        return jsonify(dict(ok or {}, version=version))

    def session_profiles():
        with ctx.store() as s:
            profiles = s.profiles()
            last = s.conn.execute("SELECT MAX(ts) FROM observations").fetchone()[0]
            latest = s.latest()
            tl = s.conn.execute(
                "SELECT ts, ssid, MAX(score) AS score FROM risk_timeline GROUP BY ts, ssid ORDER BY ts"
            ).fetchall()
        return profiles, last, latest, tl

    # ---------------------------------------------------------------- overview
    @app.get("/api/monitored")
    def monitored_overview():
        data = load()
        profiles, last, latest, tl = session_profiles()
        by_ssid = {}
        for p in profiles:
            by_ssid.setdefault(p["ssid"], []).append(p)
        trend = {}
        for r in tl:
            trend.setdefault(r["ssid"], []).append([r["ts"], r["score"]])
        nets = []
        for ssid, net in sorted(data["networks"].items()):
            heard = by_ssid.get(ssid, [])
            recent = {p["bssid"] for p in heard if last and p["last_seen"] >= last - 60}
            expected = set(net["bssids"])
            risks = [latest[(ssid, b)]["score"] for b in {p["bssid"] for p in heard} if (ssid, b) in latest]
            nets.append({
                "ssid": ssid, "baseline": {k: v for k, v in net.items() if k != "settings"},
                "settings": net.get("settings") or mon.default_settings(),
                "health": {                                               # F034
                    "expected": sorted(expected),
                    "heard_now": sorted(expected & recent),
                    "missing": sorted(expected - recent) if last else [],
                    "unexpected": [{"bssid": p["bssid"], "channels": p["channels"], "securities": p["securities"],
                                    "rssi_avg": p["rssi_avg"], "first_seen": p["first_seen"]}
                                   for p in sorted(heard, key=lambda p: p["first_seen"]) if p["bssid"] not in expected],
                    "channels_heard": sorted({int(c) for p in heard for c in (p["channels"] or "").split(",") if c}),
                },
                "risk_now": max(risks) if risks else None,                # F035
                "trend": trend.get(ssid, [])[-60:],
            })
        seen = sorted({p["ssid"] for p in profiles if p["ssid"] != HIDDEN_SSID})
        inv = data.get("inventory", {})
        def secs(s):
            return sorted({x for p in by_ssid.get(s, []) for x in (p["securities"] or "").split(",") if x})

        inbox = [{"ssid": s, "aps": len(by_ssid.get(s, [])), "securities": secs(s),
                  "decision": (inv.get(s) or {}).get("decision")}
                 for s in seen if s not in data["networks"]]
        return jsonify({"file": ctx.monitored_path, "updated_at": data.get("updated_at"),
                        "applies_live": ctx.pipeline is not None and ctx.pipeline.status.get("mode") == "live",
                        "networks": nets, "inbox": inbox,
                        "allowlist": ctx.cfg.get("known_bssids") or [], "capture_end": last})

    # ---------------------------------------------------------------- F016 wizard
    @app.post("/api/monitored/learn")
    def monitored_learn():
        body, err = ctx.json_body()
        if err:
            return err
        ssids = body.get("ssids")
        if not isinstance(ssids, list) or not ssids or not all(isinstance(s, str) for s in ssids):
            return jsonify({"error": "choose at least one network"}), 400
        with ctx.store() as s:
            obs = s.observations()
        learned = mon.learn(obs, ctx.cfg["baseline_minutes"], ssids, whole_capture=bool(body.get("whole")))
        if not learned:
            return jsonify({"error": "none of those networks were heard in this session"}), 400
        checks = B.contamination(obs, ctx.cfg["baseline_minutes"], ssids, whole_capture=bool(body.get("whole")))
        data = load()
        names = mon.upsert(data, learned)
        for n in names:
            mon.set_decision(data, n, None)
        return commit(data, "baseline.learn", ", ".join(names),
                      {"session": ctx.viewed_session() or ctx.current_session, "whole": bool(body.get("whole"))},
                      checks=checks, ok={"saved": names, "checks": checks})

    # ---------------------------------------------------------------- F011 settings
    @app.post("/api/monitored/settings")
    def monitored_settings():
        body, err = ctx.json_body()
        if err:
            return err
        data = load()
        ssid = body.get("ssid")
        if ssid not in data["networks"]:
            return jsonify({"error": "not a monitored network"}), 404
        try:
            settings = mon.validate_settings(body.get("settings") or {})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        data["networks"][ssid]["settings"] = settings
        off = sorted(k for k, v in settings["enabled"].items() if not v)
        return commit(data, "baseline.settings", ssid, {"off": off, "threshold_medium": settings["threshold_medium"]},
                      ok=settings)

    # ---------------------------------------------------------------- F017 accept / remove AP
    @app.post("/api/monitored/accept")
    def monitored_accept():
        body, err = ctx.json_body()
        if err:
            return err
        ssid, bssid = body.get("ssid"), (body.get("bssid") or "").lower()
        if not isinstance(ssid, str) or not ssid or ssid == HIDDEN_SSID or not _is_mac(bssid):
            return jsonify({"error": "need a network name and an access point address"}), 400
        with ctx.store() as s:
            prof = next((p for p in s.profiles() if p["ssid"] == ssid and p["bssid"] == bssid), None)
            fps = [r[0] for r in s.conn.execute(
                "SELECT DISTINCT fingerprint FROM observations WHERE ssid=? AND bssid=? AND frame_type='beacon' "
                "AND fingerprint IS NOT NULL", (ssid, bssid)).fetchall()]
        if prof is None:
            return jsonify({"error": "that access point was not heard in this session"}), 404
        data = load()
        mon.add_ap(data, ssid, {"bssid": bssid, "security": (prof["securities"] or "").split(",")[0] or None,
                                "channels": [int(c) for c in (prof["channels"] or "").split(",") if c],
                                "fingerprints": fps, "rssi_avg": prof["rssi_avg"]})
        return commit(data, "baseline.accept_ap", "{} {}".format(ssid, bssid), {"note": body.get("note") or ""},
                      ok={"accepted": bssid, "network": ssid})

    @app.post("/api/monitored/remove_ap")
    def monitored_remove_ap():
        body, err = ctx.json_body()
        if err:
            return err
        data = load()
        if not mon.remove_ap(data, body.get("ssid"), body.get("bssid") or ""):
            return jsonify({"error": "not in that network's baseline"}), 404
        return commit(data, "baseline.remove_ap", "{} {}".format(body["ssid"], body["bssid"]),
                      ok={"removed": body["bssid"]})

    @app.post("/api/monitored/remove")
    def monitored_remove():
        body, err = ctx.json_body()
        if err:
            return err
        data = load()
        ssid = body.get("ssid")
        if ssid not in data["networks"]:
            return jsonify({"error": "not a monitored network"}), 404
        if body.get("confirm") != ssid:
            return jsonify({"error": "confirmation missing"}), 400
        del data["networks"][ssid]
        return commit(data, "baseline.remove_network", ssid, ok={"removed": ssid})

    # ---------------------------------------------------------------- F018 inbox
    @app.post("/api/monitored/inbox")
    def monitored_inbox():
        body, err = ctx.json_body()
        if err:
            return err
        ssid, decision = body.get("ssid"), body.get("decision")
        if not isinstance(ssid, str) or not ssid:
            return jsonify({"error": "missing network name"}), 400
        data = load()
        try:
            mon.set_decision(data, ssid, None if decision == "reset" else decision)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return commit(data, "inventory." + str(decision), ssid,
                      ok={"ssid": ssid, "decision": None if decision == "reset" else decision})

    # ---------------------------------------------------------------- versions and approvals
    @app.get("/api/baselines/versions")
    def baseline_versions():
        data = load()
        with Store(ctx.admin_db) as s:
            rows = B.versions(s.conn)
        n_admins, me, my_role = admins(), ctx.actor(), role()
        for r in rows:
            if r["status"] == "pending":
                r["approve_error"] = B.approval_error(my_role, me, r["proposed_by"], n_admins)
        return jsonify({"current_version": mon.signed_version(data), "signed": bool(data.get("integrity")),
                        "sha256": (data.get("integrity") or {}).get("sha256"), "key_file": B.key_path(),
                        "admins": n_admins, "two_person": n_admins >= 2,
                        "you": {"name": me, "role": my_role or "admin"}, "versions": rows})

    @app.get("/api/baselines/versions/<int:vid>")
    def baseline_version(vid):
        with Store(ctx.admin_db) as s:
            v = B.get(s.conn, vid)
        if v is None:
            return jsonify({"error": "no such version"}), 404
        v["diff"] = B.diff(B.content_of(load()), v["content"])
        return jsonify(v)

    def pending_or_error(vid):
        with Store(ctx.admin_db) as s:
            v = B.get(s.conn, vid)
        if v is None:
            return None, (jsonify({"error": "no such proposal"}), 404)
        if v["status"] != "pending":
            return None, (jsonify({"error": "this change is already {}".format(v["status"])}), 409)
        return v, None

    @app.post("/api/baselines/versions/<int:vid>/approve")
    def baseline_approve(vid):
        _, err = ctx.json_body()
        if err:
            return err
        v, err = pending_or_error(vid)
        if err:
            return err
        why = B.approval_error(role(), ctx.actor(), v["proposed_by"], admins())
        if why:
            return jsonify({"error": why}), 403
        data = load()
        base = mon.signed_version(data)
        if v["base_version"] != base:
            return jsonify({"error": "the baseline changed since this was proposed (version {} is now {}); "
                                     "reject it and propose the change again".format(v["base_version"], base)}), 409
        data["networks"], data["inventory"] = v["content"]["networks"], v["content"]["inventory"]
        version = apply(data, v["action"], v["target"], v["detail"], v["checks"], v["proposed_by"],
                        ctx.actor(), base, vid=vid)
        ctx.audit("baseline.approve", v["target"], {"proposal": vid, "version": version, "by": v["proposed_by"]})
        return jsonify({"approved": vid, "version": version})

    @app.post("/api/baselines/versions/<int:vid>/reject")
    def baseline_reject(vid):
        body, err = ctx.json_body()
        if err:
            return err
        v, err = pending_or_error(vid)
        if err:
            return err
        reason = str(body.get("reason") or "")[:500]
        with Store(ctx.admin_db) as s:
            B.reject(s.conn, vid, ctx.actor(), reason)
        ctx.audit("baseline.reject", v["target"], {"proposal": vid, "reason": reason})
        return jsonify({"rejected": vid})

    @app.post("/api/baselines/versions/<int:vid>/rollback")
    def baseline_rollback(vid):
        _, err = ctx.json_body()
        if err:
            return err
        with Store(ctx.admin_db) as s:
            v = B.get(s.conn, vid)
        if v is None or v["status"] not in ("trusted", "superseded") or v["version"] is None:
            return jsonify({"error": "only an applied version can be restored"}), 404
        data = load()
        if B.content_of(data) == v["content"]:
            return jsonify({"error": "that version is already the current baseline"}), 409
        data["networks"], data["inventory"] = v["content"]["networks"], v["content"]["inventory"]
        return commit(data, "baseline.rollback", "to version {}".format(v["version"]), {"from_id": vid},
                      ok={"restored": v["version"]})

    # ---------------------------------------------------------------- F019 allow-list
    @app.post("/api/allowlist")
    def allowlist_edit():
        body, err = ctx.json_body()
        if err:
            return err
        add, remove = body.get("add"), body.get("remove")
        current = list(ctx.cfg.get("known_bssids") or [])
        if add is not None:
            if not _is_mac(add):
                return jsonify({"error": "'{}' is not an address like a4:2b:b0:11:22:33".format(add)}), 400
            if add.lower() not in current:
                current.append(add.lower())
        if remove is not None:
            current = [b for b in current if b != str(remove).lower()]
        try:
            new_cfg = save_overlay({"known_bssids": current}, base_path=ctx.config_path)
        except ConfigError as e:
            return jsonify({"error": str(e)}), 400
        ctx.cfg["known_bssids"] = new_cfg["known_bssids"]
        if ctx.pipeline is not None:
            ctx.pipeline.update_allowlist(new_cfg["known_bssids"])
        ctx.audit("allowlist." + ("add" if add is not None else "remove"), add or remove)
        return jsonify({"allowlist": new_cfg["known_bssids"]})

    @app.get("/api/settings/effective")
    def settings_effective():
        """The configuration currently in force (config.yaml + overlay), for the Settings page."""
        try:
            cfg = load_config(ctx.config_path)
        except ConfigError as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"config": cfg, "loaded_at": time.time(), "config_path": ctx.config_path,
                        "running": {k: ctx.cfg.get(k) for k in ("thresholds", "weights", "temporal")},
                        "restart_needed_for": ["baseline_minutes", "temporal", "weights", "thresholds"]})

