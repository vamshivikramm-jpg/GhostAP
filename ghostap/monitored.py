"""Monitored networks (F014): save what GhostAP learned and reuse it in later sessions.

File format (data/monitored.json):
    {"version": 1, "updated_at": <epoch>,
     "networks": {"<ssid>": {<SSIDBaseline.to_dict()>,
                             "settings": {"enabled": {<indicator>: bool, ...},
                                          "threshold_medium": null | number}}}}

CLI:
    python -m ghostap.monitored save --db data/sessions/<id>/session.db [--ssid X ...]
    python -m ghostap.monitored show
    python -m ghostap.monitored remove --ssid X
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, Iterable, List, Optional

from .indicators import INDICATOR_NAMES, Baseline, SSIDBaseline
from .parser import HIDDEN_SSID

VERSION = 1


def default_settings() -> dict:
    return {"enabled": {n: True for n in INDICATOR_NAMES}, "threshold_medium": None}


def empty() -> dict:
    return {"version": VERSION, "updated_at": None, "networks": {}}


def load(path: Optional[str]) -> dict:
    """The whole file (missing file = no monitored networks)."""
    if not path or not os.path.exists(path):
        return empty()
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("networks"), dict):
        raise ValueError("{} is not a GhostAP monitored-networks file".format(path))
    for net in data["networks"].values():
        s = net.setdefault("settings", default_settings())
        for n in INDICATOR_NAMES:                       # indicators added in later versions
            s.setdefault("enabled", {}).setdefault(n, True)
        s.setdefault("threshold_medium", None)
    return data


def save(path: str, data: dict) -> None:
    data["version"] = VERSION
    data["updated_at"] = time.time()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def baselines(data: dict, allowlist: Iterable[str] = ()) -> Dict[str, SSIDBaseline]:
    """SSIDBaseline objects for the Analyzer."""
    return {ssid: SSIDBaseline.from_dict(ssid, net, allowlist) for ssid, net in data["networks"].items()}


def learn(observations: List[dict], minutes: float, ssids: Optional[Iterable[str]] = None,
          whole_capture: bool = False) -> Dict[str, dict]:
    """Baselines learned from observations: the first `minutes` (or the whole capture)."""
    obs = sorted(observations, key=lambda o: o["ts"])
    if not obs:
        return {}
    if whole_capture:
        minutes = (obs[-1]["ts"] - obs[0]["ts"]) / 60 + 1
    b = Baseline(obs, minutes)
    wanted = set(ssids) if ssids else None
    return {s: sb.to_dict() for s, sb in b.ssids.items()
            if s != HIDDEN_SSID and (wanted is None or s in wanted)}


def upsert(data: dict, learned: Dict[str, dict]) -> List[str]:
    """Add or replace networks, keeping each network's existing settings."""
    for ssid, d in learned.items():
        old = data["networks"].get(ssid, {})
        data["networks"][ssid] = dict(d, settings=old.get("settings", default_settings()))
    return sorted(learned)


def add_ap(data: dict, ssid: str, ap: dict) -> None:
    """Accept one access point into a network's baseline (F017). `ap` has keys
    bssid, channels (list), security, fingerprints (list), rssi_avg."""
    net = data["networks"].setdefault(ssid, dict(SSIDBaseline(ssid).to_dict(), settings=default_settings()))
    b = ap["bssid"].lower()
    for key, val in (("bssids", b), ("ouis", b[:8])):
        if val not in net[key]:
            net[key] = sorted(set(net[key]) | {val})
    net["channels"] = sorted(set(net["channels"]) | set(ap.get("channels") or []))
    net["bssid_channels"][b] = sorted(set(net["bssid_channels"].get(b, [])) | set(ap.get("channels") or []))
    fps = set(ap.get("fingerprints") or [])
    net["fingerprints"] = sorted(set(net["fingerprints"]) | fps)
    net["bssid_fingerprints"][b] = sorted(set(net["bssid_fingerprints"].get(b, [])) | fps)
    if ap.get("rssi_avg") is not None:
        net["bssid_rssi"][b] = [round(float(ap["rssi_avg"]), 2), 3.0]
        net["rssi_ref"] = max([v[0] for v in net["bssid_rssi"].values()] + [net.get("rssi_ref") or -200])
    if not net.get("security") and ap.get("security"):
        net["security"] = ap["security"]


def remove_ap(data: dict, ssid: str, bssid: str) -> bool:
    """Take one access point out of a network's baseline."""
    net = data["networks"].get(ssid)
    b = bssid.lower()
    if not net or b not in net["bssids"]:
        return False
    net["bssids"] = [x for x in net["bssids"] if x != b]
    for key in ("bssid_channels", "bssid_rssi", "bssid_fingerprints", "bssid_skew"):
        net.get(key, {}).pop(b, None)
    net["ouis"] = sorted({x[:8] for x in net["bssids"]})
    net["channels"] = sorted({c for cs in net["bssid_channels"].values() for c in cs})
    net["fingerprints"] = sorted({f for fs in net["bssid_fingerprints"].values() for f in fs})
    rs = [v[0] for v in net["bssid_rssi"].values()]
    net["rssi_ref"] = max(rs) if rs else None
    return True


INBOX_DECISIONS = ("approved", "ignored")


def set_decision(data: dict, ssid: str, decision: Optional[str]) -> None:
    """F018: remember that a newly seen network was approved or ignored (None = undecided)."""
    inv = data.setdefault("inventory", {})
    if decision is None:
        inv.pop(ssid, None)
    elif decision in INBOX_DECISIONS:
        inv[ssid] = {"decision": decision, "at": time.time()}
    else:
        raise ValueError("decision must be one of " + ", ".join(INBOX_DECISIONS))


def validate_settings(settings: dict) -> dict:
    """F011 per-network settings coming from the dashboard."""
    from .signatures import SIGNATURE_NAMES
    out = default_settings()
    known = set(INDICATOR_NAMES) | set(SIGNATURE_NAMES)
    for name, on in (settings.get("enabled") or {}).items():
        if name not in known or not isinstance(on, bool):
            raise ValueError("unknown check or value: {!r}".format(name))
        out["enabled"][name] = on
    for n in SIGNATURE_NAMES:
        out["enabled"].setdefault(n, True)
    med = settings.get("threshold_medium")
    if med is not None:
        if isinstance(med, bool) or not isinstance(med, (int, float)) or not 1 <= med <= 99:
            raise ValueError("threshold_medium must be between 1 and 99, or empty")
        out["threshold_medium"] = float(med)
    return out


def main(argv=None) -> int:
    from .config import ConfigError, load_config
    from .storage import Store

    ap = argparse.ArgumentParser(prog="python -m ghostap.monitored",
                                 description="Save, show or remove monitored networks (saved baselines).")
    ap.add_argument("command", choices=("save", "show", "remove"))
    ap.add_argument("--db", help="session database to learn from (save)")
    ap.add_argument("--ssid", action="append", default=[], help="network name (repeatable)")
    ap.add_argument("--whole", action="store_true",
                    help="learn from the whole capture, not the first minutes")
    ap.add_argument("--file", help="monitored-networks file (default: config monitored_networks)")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    path = args.file or cfg["monitored_networks"]
    if not path:
        print("[!] monitored_networks is empty in config.yaml; pass --file", file=sys.stderr)
        return 2
    data = load(path)

    if args.command == "show":
        if not data["networks"]:
            print("[i] no monitored networks in {}".format(path))
        for ssid, net in sorted(data["networks"].items()):
            print("{:<24} {} AP(s)  ch {}  {}  fingerprints {}".format(
                ssid, len(net["bssids"]), ",".join(map(str, net["channels"])), net["security"],
                len(net["fingerprints"])))
            for b in net["bssids"]:
                print("    {}".format(b))
        return 0
    if args.command == "remove":
        if not args.ssid:
            ap.error("remove needs --ssid")
        for s in args.ssid:
            data["networks"].pop(s, None)
        save(path, data)
        print("[+] removed {} from {}".format(", ".join(args.ssid), path))
        return 0
    if not args.db or not os.path.exists(args.db):
        ap.error("save needs --db pointing to an existing session database")
    with Store(args.db) as st:
        obs = st.observations()
    learned = learn(obs, cfg["baseline_minutes"], args.ssid or None, args.whole)
    if not learned:
        print("[!] nothing to save (no matching networks in {})".format(args.db), file=sys.stderr)
        return 1
    names = upsert(data, learned)
    save(path, data)
    print("[+] saved {} network(s) to {}: {}".format(len(names), path, ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
