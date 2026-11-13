"""Configuration: defaults, layered loading and validation (F072).

Load order (later wins):
  1. DEFAULT_CONFIG below
  2. config.yaml           (documented, kept in git; never rewritten by GhostAP)
  3. data/settings.yaml    (overrides saved by the dashboard's Settings page)

Every key is validated against the defaults: unknown keys get a "did you mean"
hint, wrong types and impossible values raise ConfigError with a readable message.
"""
from __future__ import annotations

import copy
import difflib
import os
from typing import Any, List, Optional

SETTINGS_OVERLAY = os.path.join("data", "settings.yaml")

DEFAULT_CONFIG: dict = {
    "baseline_minutes": 2.0,
    "weights": {
        "security_downgrade": 3.0,
        "new_bssid_oui": 2.0,
        "tsf_anomaly": 2.0,
        "ie_fingerprint": 2.5,
        "bssid_conflict": 2.5,
        "rssi_jump": 1.5,
        "channel_deviation": 1.0,
        "beacon_interval_mismatch": 1.0,
    },
    "thresholds": {"medium": 30.0, "high": 60.0},
    "temporal": {"step_seconds": 10.0, "window_seconds": 10.0, "smoothing_steps": 3},
    "known_bssids": [],
    # Saved "monitored networks" baseline (F014). Empty string = learn every session.
    "monitored_networks": "data/monitored.json",
    "sessions_dir": "data/sessions",
    "retention": {
        "raw_hours": 0.0,             # 0 = keep every frame; >0 = prune older raw frames
        "check_minutes": 10.0,        # how often pruning runs during a live session
    },
    "logging": {"file": "data/logs/ghostap.log", "level": "INFO"},
    # Attack signatures (F001-F003): a match raises the AP's score to at least this value.
    "signatures": {"karma": 70.0, "known_tool": 70.0, "lookalike_ssid": 40.0},
    "attack_tools_file": "data/attack_tools.json",   # your lab-recorded tool fingerprints
    "detection": {
        "karma_min_ssids": 3,              # one radio answering for this many names = KARMA
        "lookalike_max_distance": 2,       # edits allowed between look-alike names
        "signal_track_gap_db": 12.0,       # F006: two signal levels this far apart = 2 radios
        "beacon_rate_tolerance": 0.5,      # F008: flag beaconing > (1 + this) x advertised rate
        "clock_skew_tolerance_ppm": 10.0,  # F007: clock drift change that counts
        "deauth_window_seconds": 10.0,     # F005
        "deauth_medium": 10,               #   frames per window for MEDIUM
        "deauth_high": 30,                 #   ... and for HIGH
        "flood_new_aps_per_minute": 30,    # F008: many new radios at once = beacon flood
        "use_example_signatures": False,   # enable the synthetic example tool signatures
    },
    # F013, F055-F059: messages about alerts. Off until you configure a channel.
    # Secrets are never stored here: give the NAME of an environment variable instead.
    "notifications": {
        "enabled": False,
        "min_level": "MEDIUM",             # MEDIUM or HIGH
        "realert_minutes": 30.0,           # F013: remind about an alert still active this long (0 = never)
        "max_per_minute": 6,               # F013: per channel; extra messages are counted, not sent
        "dashboard_url": "",               # link added to messages, e.g. http://kali.local:8050
        "webhooks": [],                    # F056/F057: see config.yaml for the format
        "email": {                         # F058
            "enabled": False, "host": "", "port": 587, "starttls": True, "username": "",
            "password_env": "GHOSTAP_SMTP_PASSWORD", "sender": "", "to": [],
        },
        "syslog": {"enabled": False, "host": "127.0.0.1", "port": 514, "protocol": "udp", "format": "json"},  # F059
        "jsonl": {"enabled": False, "path": "data/alerts.jsonl"},                                            # F059
    },
    "api": {"metrics": True},              # F060: Prometheus /metrics endpoint
}

WEBHOOK_FORMATS = ("json", "ntfy", "telegram", "slack")
_WEBHOOK_KEYS = {"name", "url", "url_env", "format", "secret_env", "chat_id", "min_level"}

_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(ValueError):
    """config.yaml / settings overlay contains something GhostAP cannot use."""


def merge(base: dict, override: Optional[dict]) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


def _type_name(v: Any) -> str:
    return {bool: "true/false", int: "a number", float: "a number", str: "text",
            list: "a list", dict: "a section"}.get(type(v), type(v).__name__)


def _check_types(value: Any, default: Any, path: str, errors: List[str]) -> None:
    if isinstance(default, dict):
        if not isinstance(value, dict):
            errors.append("{} must be {}, not {!r}".format(path, _type_name(default), value))
            return
        for k, v in value.items():
            if k not in default:
                hint = difflib.get_close_matches(k, list(default), n=1)
                errors.append("unknown setting {}{}{}".format(
                    path + "." if path else "", k,
                    " (did you mean '{}'?)".format(hint[0]) if hint else ""))
                continue
            _check_types(v, default[k], (path + "." if path else "") + k, errors)
    elif isinstance(default, bool):
        if not isinstance(value, bool):
            errors.append("{} must be true or false, not {!r}".format(path, value))
    elif isinstance(default, (int, float)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append("{} must be a number, not {!r}".format(path, value))
    elif isinstance(default, str):
        if value is not None and not isinstance(value, str):
            errors.append("{} must be text, not {!r}".format(path, value))
    elif isinstance(default, list):
        if not isinstance(value, list):
            errors.append("{} must be a list, not {!r}".format(path, value))


def validate(cfg: dict) -> dict:
    """Raise ConfigError listing every problem; return cfg unchanged when valid."""
    errors: List[str] = []
    _check_types(cfg, DEFAULT_CONFIG, "", errors)
    if errors:
        raise ConfigError("; ".join(errors))

    def need(cond: bool, msg: str) -> None:
        if not cond:
            errors.append(msg)

    need(cfg["baseline_minutes"] > 0, "baseline_minutes must be greater than 0")
    w = cfg["weights"]
    need(all(v >= 0 for v in w.values()), "weights cannot be negative")
    need(sum(w.values()) > 0, "at least one weight must be greater than 0")
    th = cfg["thresholds"]
    need(0 < th["medium"] < th["high"] <= 100,
         "thresholds must satisfy 0 < medium < high <= 100 (got medium {}, high {})".format(
             th["medium"], th["high"]))
    t = cfg["temporal"]
    need(t["step_seconds"] > 0, "temporal.step_seconds must be greater than 0")
    need(t["window_seconds"] > 0, "temporal.window_seconds must be greater than 0")
    need(isinstance(t["smoothing_steps"], int) or float(t["smoothing_steps"]).is_integer(),
         "temporal.smoothing_steps must be a whole number")
    need(t["smoothing_steps"] >= 1, "temporal.smoothing_steps must be at least 1")
    for b in cfg["known_bssids"]:
        ok = isinstance(b, str) and len(b) == 17 and all(
            len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in b.split(":"))
        need(ok, "known_bssids: {!r} is not a MAC address like a4:2b:b0:11:22:33".format(b))
    for k, v in cfg["signatures"].items():
        need(0 <= v <= 100, "signatures.{} must be between 0 and 100".format(k))
    d = cfg["detection"]
    for k in ("karma_min_ssids", "deauth_medium", "deauth_high", "flood_new_aps_per_minute",
              "lookalike_max_distance"):
        need(d[k] >= 0, "detection.{} cannot be negative".format(k))
    need(d["karma_min_ssids"] >= 2, "detection.karma_min_ssids must be at least 2")
    need(d["deauth_medium"] <= d["deauth_high"], "detection.deauth_medium must not exceed deauth_high")
    for k in ("signal_track_gap_db", "beacon_rate_tolerance", "clock_skew_tolerance_ppm",
              "deauth_window_seconds"):
        need(d[k] > 0, "detection.{} must be greater than 0".format(k))
    r = cfg["retention"]
    need(r["raw_hours"] >= 0, "retention.raw_hours cannot be negative (0 keeps everything)")
    need(r["check_minutes"] > 0, "retention.check_minutes must be greater than 0")
    need(str(cfg["logging"]["level"]).upper() in _LEVELS,
         "logging.level must be one of " + ", ".join(_LEVELS))
    n = cfg["notifications"]
    need(n["min_level"] in ("MEDIUM", "HIGH"), "notifications.min_level must be MEDIUM or HIGH")
    need(n["realert_minutes"] >= 0, "notifications.realert_minutes cannot be negative (0 = never)")
    need(n["max_per_minute"] >= 1, "notifications.max_per_minute must be at least 1")
    need(not n["dashboard_url"] or str(n["dashboard_url"]).startswith(("http://", "https://")),
         "notifications.dashboard_url must start with http:// or https://")
    for i, h in enumerate(n["webhooks"]):
        where = "notifications.webhooks[{}]".format(i)
        if not isinstance(h, dict):
            errors.append(where + " must be a section with url (or url_env) and format")
            continue
        extra = set(h) - _WEBHOOK_KEYS
        need(not extra, "{}: unknown setting(s) {}".format(where, ", ".join(sorted(extra))))
        need(bool(h.get("url")) != bool(h.get("url_env")), where + " needs exactly one of url or url_env")
        need(not h.get("url") or str(h["url"]).startswith(("http://", "https://")),
             where + ".url must start with http:// or https://")
        need(h.get("format", "json") in WEBHOOK_FORMATS,
             "{}.format must be one of {}".format(where, ", ".join(WEBHOOK_FORMATS)))
        need(h.get("format") != "telegram" or bool(h.get("chat_id")), where + ": telegram needs chat_id")
        need(h.get("min_level", "MEDIUM") in ("MEDIUM", "HIGH"), where + ".min_level must be MEDIUM or HIGH")
    e = n["email"]
    if e["enabled"]:
        need(bool(e["host"]) and bool(e["sender"]) and bool(e["to"]),
             "notifications.email needs host, sender and at least one address in to")
    need(1 <= e["port"] <= 65535, "notifications.email.port must be 1-65535")
    sl = n["syslog"]
    need(sl["protocol"] in ("udp", "tcp"), "notifications.syslog.protocol must be udp or tcp")
    need(sl["format"] in ("json", "cef"), "notifications.syslog.format must be json or cef")
    need(1 <= sl["port"] <= 65535, "notifications.syslog.port must be 1-65535")
    need(not n["jsonl"]["enabled"] or bool(n["jsonl"]["path"]), "notifications.jsonl.path is empty")
    if errors:
        raise ConfigError("; ".join(errors))
    cfg["temporal"]["smoothing_steps"] = int(t["smoothing_steps"])
    cfg["known_bssids"] = [b.lower() for b in cfg["known_bssids"]]
    return cfg


def _read_yaml(path: str) -> dict:
    import yaml
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError("{} is not valid YAML: {}".format(path, e)) from None
    if not isinstance(data, dict):
        raise ConfigError("{} must contain settings (key: value), not {}".format(
            path, type(data).__name__))
    return data


_USE_DEFAULT = object()


def load_config(path: Optional[str] = "config.yaml", overlay=_USE_DEFAULT) -> dict:
    """Defaults <- config.yaml <- settings overlay, validated.

    `overlay` defaults to the module-level SETTINGS_OVERLAY (read at call time, so tests
    can redirect it); pass None to ignore the overlay."""
    if overlay is _USE_DEFAULT:
        overlay = SETTINGS_OVERLAY
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    sources = []
    if path and os.path.exists(path):
        cfg = merge(cfg, _read_yaml(path))
        sources.append(path)
    if path and overlay and os.path.exists(overlay):     # overlay only with a real config
        cfg = merge(cfg, _read_yaml(overlay))
        sources.append(overlay)
    try:
        return validate(cfg)
    except ConfigError as e:
        raise ConfigError("{} ({})".format(e, " + ".join(sources) or "defaults")) from None


def save_overlay(changes: dict, overlay: Optional[str] = None, base_path: str = "config.yaml") -> dict:
    """Validate `changes` on top of the current configuration, then write the overlay
    atomically. Returns the resulting configuration. Nothing is written if invalid."""
    import yaml
    overlay = overlay or SETTINGS_OVERLAY
    current = _read_yaml(overlay) if os.path.exists(overlay) else {}
    new_overlay = merge(current, changes)
    base = merge(copy.deepcopy(DEFAULT_CONFIG),
                 _read_yaml(base_path) if base_path and os.path.exists(base_path) else {})
    result = validate(merge(base, new_overlay))
    os.makedirs(os.path.dirname(overlay) or ".", exist_ok=True)
    tmp = overlay + ".tmp"
    with open(tmp, "w") as f:
        f.write("# Saved by the GhostAP Settings page. Overrides config.yaml.\n")
        yaml.safe_dump(new_overlay, f, sort_keys=True)
    os.replace(tmp, overlay)
    return result


def reset_overlay(overlay: Optional[str] = None) -> None:
    overlay = overlay or SETTINGS_OVERLAY
    if os.path.exists(overlay):
        os.remove(overlay)
