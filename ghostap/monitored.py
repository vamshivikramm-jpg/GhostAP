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
    python -m ghostap.monitored history                 # versions and approvals
    python -m ghostap.monitored trust --yes             # accept a file changed outside GhostAP

The file is signed (see baselines.py). The CLI is for the person at the machine (who can
edit the file anyway): its changes apply directly and are recorded as versions in admin.db.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, Iterable, List, Optional

from . import baselines as integrity
from .indicators import INDICATOR_NAMES, Baseline, SSIDBaseline
from .parser import HIDDEN_SSID

VERSION = 1


def default_settings() -> dict:
    return {"enabled": {n: True for n in INDICATOR_NAMES}, "threshold_medium": None}


def empty() -> dict:
    return {"version": VERSION, "updated_at": None, "networks": {}}


def load(path: Optional[str], verify: bool = True) -> dict:
    """The whole file (missing file = no monitored networks). A signed file whose content or
    signature does not match raises integrity.IntegrityError (a ValueError); see baselines.py."""
    if not path or not os.path.exists(path):
        return empty()
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("networks"), dict):
        raise ValueError("{} is not a GhostAP monitored-networks file".format(path))
    if verify:
        integrity.verify(data, path)
    for net in data["networks"].values():
        s = net.setdefault("settings", default_settings())
        for n in INDICATOR_NAMES:                       # indicators added in later versions
            s.setdefault("enabled", {}).setdefault(n, True)
        s.setdefault("threshold_medium", None)
    return data


def signed_version(data: dict) -> int:
    """Version number in the file's integrity block (0 = never signed)."""
    return int((data.get("integrity") or {}).get("version") or 0)


def save(path: str, data: dict, version: Optional[int] = None) -> int:
    """Write the file atomically and sign it as `version` (default: the next one). Returns it."""
    version = signed_version(data) + 1 if version is None else version
    data["version"] = VERSION
    data["updated_at"] = time.time()
    data["integrity"] = integrity.sign(data, version)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return version


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
    ap.add_argument("command", choices=("save", "show", "remove", "history", "trust"))
    ap.add_argument("--yes", action="store_true", help="trust: confirm after reviewing the file")
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
    admin_db = os.path.join(os.path.dirname(cfg["sessions_dir"].rstrip("/")) or ".", "admin.db")
    actor = "cli:" + (os.environ.get("SUDO_USER") or os.environ.get("USER") or "unknown")

    def recorded(version: int, action: str, target: str) -> None:
        with Store(admin_db) as st:
            integrity.record(st.conn, status="trusted", content=integrity.content_of(data), base_version=version - 1,
                             actor=actor, action=action, target=target, version=version, approved_by=actor)
            st.audit(actor, action, target, {"version": version})

    if args.command == "history":
        with Store(admin_db) as st:
            rows = integrity.versions(st.conn)
        if not rows:
            print("[i] no recorded versions yet")
        for r in rows:
            print("{:>4}  v{:<4} {:<10} {:<20} {:<24} by {}{}".format(
                r["id"], r["version"] if r["version"] is not None else "-", r["status"], r["action"],
                (r["target"] or "")[:24], r["proposed_by"],
                ", approved by " + r["approved_by"] if r["approved_by"] and r["status"] != "rejected" else ""))
        return 0
    if args.command == "trust":
        data = load(path, verify=False)
        try:
            integrity.verify(data, path)
            print("[i] {} is already correctly signed; nothing to do".format(path))
            return 0
        except integrity.IntegrityError as e:
            print("[!] " + str(e))
        print("[i] it holds {} network(s): {}".format(len(data["networks"]), ", ".join(sorted(data["networks"]))))
        if not args.yes:
            print("[i] review the file, then re-run with --yes to accept it as a new version", file=sys.stderr)
            return 1
        v = save(path, data)
        recorded(v, "baseline.trust", path)
        print("[+] accepted and signed as version {}".format(v))
        return 0
    try:
        data = load(path)
    except integrity.IntegrityError as e:
        print("[!] {}".format(e), file=sys.stderr)
        return 2

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
        recorded(save(path, data), "baseline.remove_network", ", ".join(args.ssid))
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
    recorded(save(path, data), "baseline.learn", ", ".join(names))
    print("[+] saved {} network(s) to {}: {}".format(len(names), path, ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
