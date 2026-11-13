#!/usr/bin/env python3
"""Scenario builder (F051): make your own SYNTHETIC labelled capture.

Describe the twin (or a benign change) and get <name>.pcap + <name>.labels.json, in the
same format as tools/make_eval_set.py, ready for `evaluate.py --dataset <dir>`. The labels
say "synthetic": true and "custom": true, and the description says what was built.

Quick form (a twin of MVSR_WiFi in the standard office environment):
    python tools/build_scenario.py my_twin --twin-of MVSR_WiFi --channel 11 --open \\
        --oui same --rssi -40 --profile phone --start 180

From a JSON spec (any number of access points, events, other environments):
    python tools/build_scenario.py --spec my_scenarios.json
    {"name": "...", "description": "...", "duration": 300, "seed": 1, "environment": "office",
     "aps": [{"ssid": "...", "bssid": "aa:bb:...", "channel": 6, "security": "wpa2" | "open",
              "rssi": -50, "uptime_s": 3600, "start": 0, "end": 300, "label": "legit" | "evil_twin",
              "profile": "enterprise" | "soho" | "hostapd" | "phone", "beacon_interval": 100,
              "events": [{"at": 200, "rssi": -40} | {"at": 200, "ch": 11} | {"at": 170, "reboot_gap": 20}]}]}

Default output directory: data/eval_custom (keep it apart from the standard set).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_eval_set import ATTACK, DURATION, ap, office, write_scenario  # noqa: E402
from make_test_pcap import PROFILES  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,60}$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
ENVIRONMENTS = {"office": office, "empty": lambda: []}


class SpecError(ValueError):
    pass


def _num(spec, key, lo, hi, default):
    v = spec.get(key, default)
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise SpecError("{} must be a number from {} to {}".format(key, lo, hi))
    return v


def build_aps(spec: dict) -> list:
    """Validated access-point list (the environment plus the spec's own APs)."""
    duration = _num(spec, "duration", 150, 3600, DURATION)
    env = spec.get("environment", "office")
    if env not in ENVIRONMENTS:
        raise SpecError("environment must be one of " + ", ".join(ENVIRONMENTS))
    aps = []
    for a in ENVIRONMENTS[env]():
        a["end"] = duration
        aps.append(a)
    own = spec.get("aps") or []
    if not isinstance(own, list) or not own and not aps:
        raise SpecError("aps must be a list with at least one access point")
    for i, a in enumerate(own):
        where = "aps[{}]".format(i)
        if not isinstance(a, dict):
            raise SpecError(where + " must be an object")
        bssid = str(a.get("bssid", "")).lower()
        if not MAC_RE.match(bssid):
            raise SpecError(where + ".bssid must look like 00:c0:ca:de:ad:01")
        ssid = a.get("ssid")
        if not isinstance(ssid, str) or not 0 < len(ssid.encode()) <= 32:
            raise SpecError(where + ".ssid must be 1 to 32 bytes")
        if a.get("security", "wpa2") not in ("wpa2", "open"):
            raise SpecError(where + ".security must be wpa2 or open")
        if a.get("label", "legit") not in ("legit", "evil_twin"):
            raise SpecError(where + ".label must be legit or evil_twin")
        if a.get("profile", "enterprise") not in PROFILES:
            raise SpecError(where + ".profile must be one of " + ", ".join(PROFILES))
        start = _num(a, "start", 0, duration - 10, 0)
        end = _num(a, "end", start + 10, duration, duration)
        events = a.get("events") or []
        for e in events:
            if not isinstance(e, dict) or not isinstance(e.get("at"), (int, float)) or not (
                    set(e) - {"at"}) <= {"rssi", "ch", "reboot_gap"}:
                raise SpecError(where + ".events: each event is {at, rssi | ch | reboot_gap}")
        aps.append(ap(ssid, bssid, int(_num(a, "channel", 1, 165, 6)), a.get("security", "wpa2") == "wpa2",
                      int(_num(a, "rssi", -95, -20, -60)),
                      int(_num(a, "uptime_s", 0, 10 ** 7, 3600) * 1_000_000) or 1_000,
                      start=start, end=end, label=a.get("label", "legit"),
                      bi=int(_num(a, "beacon_interval", 20, 1000, 100)), events=events,
                      profile=a.get("profile", "enterprise")))
    return aps


def build(spec: dict, out_dir: str) -> dict:
    name = spec.get("name", "")
    if not NAME_RE.match(str(name)):
        raise SpecError("name must be 1-60 letters, digits, _ or -")
    aps = build_aps(spec)
    desc = str(spec.get("description") or "Custom scenario")[:300] + " (built with tools/build_scenario.py)"
    n = write_scenario(out_dir, name, desc, aps, seed=int(_num(spec, "seed", 0, 2 ** 31, 1)),
                       extra_labels={"custom": True, "spec": spec})
    twins = sum(a["label"] == "evil_twin" for a in aps)
    return {"name": name, "frames": n, "aps": len({a["bssid"] for a in aps}), "twins": twins,
            "pcap": os.path.join(out_dir, name + ".pcap")}


def quick_spec(args) -> dict:
    env = {a["ssid"]: a for a in office()}
    if args.twin_of not in env:
        raise SpecError("--twin-of must be one of the office networks: " + ", ".join(sorted(env)))
    real = env[args.twin_of]
    oui = {"same": real["bssid"][:8], "alfa": "00:c0:ca", "random": "da:a1:19"}[args.oui]
    bssid = real["bssid"] if args.clone_bssid else oui + ":de:ad:" + "{:02x}".format(args.seed % 256)
    return {"name": args.name, "seed": args.seed, "duration": args.duration, "environment": "office",
            "description": "Twin of {}: {} {} on channel {}, signal {} dBm, {} beacon structure, from t={} s".format(
                args.twin_of, "cloned BSSID" if args.clone_bssid else "{} vendor prefix".format(args.oui),
                "open" if args.open else "WPA2", args.channel, args.rssi, args.profile, args.start),
            "aps": [{"ssid": args.twin_of, "bssid": bssid, "channel": args.channel,
                     "security": "open" if args.open else "wpa2", "rssi": args.rssi, "uptime_s": args.uptime,
                     "start": args.start, "label": "evil_twin", "profile": args.profile}]}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("name", nargs="?", help="scenario name (quick form)")
    p.add_argument("--spec", help="JSON file with one scenario or a list of scenarios")
    p.add_argument("--out", default=os.path.join("data", "eval_custom"))
    p.add_argument("--twin-of", default="MVSR_WiFi")
    p.add_argument("--channel", type=int, default=11)
    p.add_argument("--open", action="store_true", help="twin without encryption (default: WPA2)")
    p.add_argument("--oui", choices=("same", "alfa", "random"), default="alfa",
                   help="vendor prefix: copy the real one, an Alfa adapter's, or a random local one")
    p.add_argument("--clone-bssid", action="store_true", help="copy the real AP's whole BSSID")
    p.add_argument("--rssi", type=int, default=-40)
    p.add_argument("--uptime", type=float, default=0.001, help="seconds since the twin booted (TSF)")
    p.add_argument("--profile", choices=sorted(PROFILES), default="hostapd")
    p.add_argument("--start", type=int, default=ATTACK)
    p.add_argument("--duration", type=int, default=DURATION)
    p.add_argument("--seed", type=int, default=1)
    args = p.parse_args(argv)
    try:
        if args.spec:
            with open(args.spec) as f:
                data = json.load(f)
            specs = data if isinstance(data, list) else [data]
        elif args.name:
            specs = [quick_spec(args)]
        else:
            p.error("give a scenario name or --spec FILE")
        for spec in specs:
            r = build(spec, args.out)
            print("[+] {name}: {frames} frames, {aps} access points, {twins} evil twin(s) -> {pcap}".format(**r))
    except (SpecError, OSError, ValueError) as e:
        print("[!] {}".format(e), file=sys.stderr)
        return 1
    print("[i] synthetic. Evaluate with: python evaluate.py --dataset {} --out results/custom".format(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
