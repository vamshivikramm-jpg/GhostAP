"""Settings page API (F075). Admins only (see web_auth.ADMIN_ONLY).

Changes are validated with the same rules as config.yaml and written to the settings
overlay (data/settings.yaml); config.yaml itself is never rewritten. A few settings apply
at once; the rest take effect when GhostAP restarts, because changing how scores are
computed in the middle of a session would make its timeline inconsistent.
"""
from __future__ import annotations

import copy
import json
import logging

from flask import jsonify

from . import config as config_mod
from .config import ConfigError, load_config, reset_overlay, save_overlay
from .logs import LOGGER_NAME

LIVE = ("retention", "logging.level", "api.metrics")


def _f(key, label, kind, help_="", lo=None, hi=None, step=None, choices=None):
    return {"key": key, "label": label, "type": kind, "help": help_, "min": lo, "max": hi, "step": step,
            "choices": choices, "live": any(key == k or key.startswith(k + ".") for k in LIVE)}


SECTIONS = [
    ("Learning and alert levels", [
        _f("baseline_minutes", "Learning period (minutes)", "number",
           "how long GhostAP learns each network before scoring", 0.5, 60, 0.5),
        _f("thresholds.medium", "MEDIUM from", "number", "smoothed score that raises an alert", 1, 99, 1),
        _f("thresholds.high", "HIGH from", "number", "", 2, 100, 1),
    ]),
    ("Indicator weights", [_f("weights." + k, k.replace("_", " "), "number", "", 0, 10, 0.5)
                           for k in config_mod.DEFAULT_CONFIG["weights"]]),
    ("Attack signatures (minimum score when matched)", [
        _f("signatures." + k, k.replace("_", " "), "number", "", 0, 100, 5)
        for k in config_mod.DEFAULT_CONFIG["signatures"]]),
    ("Detection details", [
        _f("detection.karma_min_ssids", "KARMA: names per radio", "number", "", 2, 50, 1),
        _f("detection.lookalike_max_distance", "Look-alike names: edits allowed", "number", "", 0, 4, 1),
        _f("detection.signal_track_gap_db", "Two transmitters: signal gap (dB)", "number", "", 3, 40, 1),
        _f("detection.beacon_rate_tolerance", "Beacon rate tolerance", "number", "", 0.1, 5, 0.1),
        _f("detection.clock_skew_tolerance_ppm", "Clock skew tolerance (ppm)", "number", "", 1, 500, 1),
        _f("detection.deauth_window_seconds", "Deauth window (s)", "number", "", 1, 120, 1),
        _f("detection.deauth_medium", "Deauth frames for MEDIUM", "number", "", 1, 10000, 1),
        _f("detection.deauth_high", "Deauth frames for HIGH", "number", "", 1, 10000, 1),
        _f("detection.flood_new_aps_per_minute", "Beacon flood: new APs per minute", "number", "", 1, 10000, 1),
        _f("detection.use_example_signatures", "Use the synthetic example tool signatures", "bool",
           "only for demos: they are made up"),
    ]),
    ("Timing", [
        _f("temporal.step_seconds", "Score every (s)", "number", "", 1, 120, 1),
        _f("temporal.window_seconds", "Frames per score (s)", "number", "", 1, 120, 1),
        _f("temporal.smoothing_steps", "Smoothing (steps)", "number", "", 1, 20, 1),
    ]),
    ("Storage and logs", [
        _f("retention.raw_hours", "Keep raw frames (hours, 0 = all)", "number",
           "older frames are deleted during live capture", 0, 24 * 365, 1),
        _f("retention.check_minutes", "Check every (minutes)", "number", "", 1, 1440, 1),
        _f("logging.level", "Log level", "select", "data/logs/ghostap.log",
           choices=["DEBUG", "INFO", "WARNING", "ERROR"]),
    ]),
    ("Notifications", [
        _f("notifications.enabled", "Send notifications", "bool"),
        _f("notifications.min_level", "From level", "select", "", choices=["MEDIUM", "HIGH"]),
        _f("notifications.realert_minutes", "Remind every (minutes, 0 = never)", "number", "", 0, 1440, 5),
        _f("notifications.max_per_minute", "At most per channel per minute", "number", "", 1, 120, 1),
        _f("notifications.dashboard_url", "Link to this dashboard", "text", "e.g. https://kali.local:8050"),
        _f("notifications.webhooks", "Webhooks (JSON list)", "json",
           'e.g. [{"name": "phone", "url_env": "GHOSTAP_NTFY_URL", "format": "ntfy"}]; secrets only via *_env'),
        _f("notifications.email.enabled", "E-mail", "bool"),
        _f("notifications.email.host", "SMTP server", "text"),
        _f("notifications.email.port", "SMTP port", "number", "", 1, 65535, 1),
        _f("notifications.email.username", "SMTP user", "text", "password from the environment variable below"),
        _f("notifications.email.password_env", "Password environment variable", "text"),
        _f("notifications.email.sender", "From", "text"),
        _f("notifications.email.to", "To (JSON list)", "json", '["you@example.org"]'),
        _f("notifications.syslog.enabled", "Syslog / SIEM", "bool"),
        _f("notifications.syslog.host", "Syslog host", "text"),
        _f("notifications.syslog.port", "Syslog port", "number", "", 1, 65535, 1),
        _f("notifications.syslog.protocol", "Protocol", "select", "", choices=["udp", "tcp"]),
        _f("notifications.syslog.format", "Format", "select", "", choices=["json", "cef"]),
        _f("notifications.jsonl.enabled", "JSON lines file", "bool"),
        _f("notifications.jsonl.path", "File", "text"),
    ]),
    ("API", [_f("api.metrics", "Prometheus /metrics endpoint", "bool")]),
]
FIELDS = {f["key"]: f for _, fs in SECTIONS for f in fs}


def _get(d, key):
    for part in key.split("."):
        d = d[part]
    return d


def _nest(flat: dict) -> dict:
    out: dict = {}
    for k, v in flat.items():
        cur = out
        parts = k.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def register(app, ctx) -> None:

    def overlay_path():
        return config_mod.SETTINGS_OVERLAY

    @app.get("/api/settings")
    def settings_get():
        """Every editable setting: config.yaml + saved changes, and what the running server uses."""
        try:
            saved = load_config(ctx.config_path)
            base = load_config(ctx.config_path, overlay=None)
        except ConfigError as e:
            return jsonify({"error": str(e)}), 500
        values = {k: {"saved": _get(saved, k), "file": _get(base, k), "running": _get(ctx.cfg, k)} for k in FIELDS}
        return jsonify({"sections": [{"title": t, "fields": fs} for t, fs in SECTIONS], "values": values,
                        "config_path": ctx.config_path, "overlay_path": overlay_path()})

    @app.post("/api/settings")
    def settings_save():
        body, err = ctx.json_body()
        if err:
            return err
        changes = body.get("changes")
        if not isinstance(changes, dict) or not changes:
            return jsonify({"error": "nothing to save"}), 400
        unknown = [k for k in changes if k not in FIELDS]
        if unknown:
            return jsonify({"error": "not editable here: " + ", ".join(sorted(unknown))}), 400
        try:
            new = save_overlay(_nest(changes), overlay=overlay_path(), base_path=ctx.config_path)
        except ConfigError as e:
            return jsonify({"error": str(e)}), 400
        live, restart = [], []
        for k in changes:
            if FIELDS[k]["live"]:
                parts = k.split(".")
                cur = ctx.cfg
                for p in parts[:-1]:
                    cur = cur[p]
                cur[parts[-1]] = copy.deepcopy(_get(new, k))
                live.append(k)
            elif _get(new, k) != _get(ctx.cfg, k):
                restart.append(k)
        if "logging.level" in live:
            logging.getLogger(LOGGER_NAME).setLevel(getattr(logging, str(new["logging"]["level"]).upper()))
        ctx.audit("settings.save", ", ".join(sorted(changes))[:200],
                  {"changes": json.loads(json.dumps(changes)), "live": live, "restart": restart})
        return jsonify({"saved": sorted(changes), "applied_now": live, "restart_needed": restart})

    @app.post("/api/settings/reset")
    def settings_reset():
        body, err = ctx.json_body()
        if err:
            return err
        if body.get("confirm") is not True:
            return jsonify({"error": "confirmation missing"}), 400
        reset_overlay(overlay_path())
        ctx.audit("settings.reset", None, {})
        return jsonify({"reset": True, "note": "restart GhostAP to run with config.yaml as it is"})
