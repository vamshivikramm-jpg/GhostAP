#!/usr/bin/env python3
"""Label a real capture for evaluation (Phase 2).

Step 1: list the access points in the capture, to find your lab twin's BSSID
    python tools/label_capture.py lab1.pcap

Step 2: write lab1.labels.json next to the pcap
    python tools/label_capture.py lab1.pcap --evil 02:11:22:33:44:55
    python tools/label_capture.py lab1.pcap --evil 02:11:22:33:44:55 --attack-start +240
    python tools/label_capture.py lab0.pcap --no-twin     # a run without a twin (false positives)

--attack-start:
    auto      (default) the twin's first frame in the capture. Correct when the twin
              was switched on during the capture with its own BSSID.
    +SECONDS  offset from the start of the capture (use this for a cloned BSSID,
              whose first frame belongs to the real AP)
    EPOCH     absolute Unix time, e.g. what `date +%s` printed when you switched it on

Every other AP is labelled legit. Then evaluate with
    python evaluate.py --dataset <folder with the pcaps>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ghostap.parser import parse_frame  # noqa: E402


def scan(pcap: str):
    from scapy.utils import PcapReader

    aps = OrderedDict()
    t0 = None
    rejected: dict = {}
    with PcapReader(pcap) as reader:
        for pkt in reader:
            o = parse_frame(pkt, rejected)
            if not o:
                continue
            t0 = o["ts"] if t0 is None else min(t0, o["ts"])
            a = aps.setdefault(o["bssid"], {"ssids": set(), "first": o["ts"], "last": o["ts"],
                                            "frames": 0, "channels": set(), "security": set(),
                                            "rssi": []})
            a["ssids"].add(o["ssid"])
            a["first"], a["last"] = min(a["first"], o["ts"]), max(a["last"], o["ts"])
            a["frames"] += 1
            if o["channel"] is not None:
                a["channels"].add(o["channel"])
            a["security"].add(o["security"])
            if o["rssi"] is not None:
                a["rssi"].append(o["rssi"])
    bad = {k: v for k, v in rejected.items() if k != "not_beacon" and v}
    if bad:
        print("[i] skipped damaged frames: " + ", ".join("{} {}".format(v, k) for k, v in bad.items()))
    return t0, aps


def print_table(t0, aps):
    print("{:<20} {:<18} {:>9} {:>8} {:<8} {:<10} {:>6}".format(
        "SSID", "BSSID", "FIRST(s)", "FRAMES", "CH", "SECURITY", "RSSI"))
    for bssid, a in sorted(aps.items(), key=lambda kv: (sorted(kv[1]["ssids"]), kv[1]["first"])):
        rssi = sum(a["rssi"]) / len(a["rssi"]) if a["rssi"] else float("nan")
        print("{:<20} {:<18} {:>9.0f} {:>8} {:<8} {:<10} {:>6.0f}".format(
            ",".join(sorted(a["ssids"]))[:20], bssid, a["first"] - t0, a["frames"],
            ",".join(map(str, sorted(a["channels"]))), ",".join(sorted(a["security"]))[:10], rssi))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="List APs in a capture or write its labels file.")
    ap.add_argument("pcap")
    who = ap.add_mutually_exclusive_group()
    who.add_argument("--evil", action="append", default=[], metavar="BSSID",
                     help="BSSID of a lab evil twin (repeat for several)")
    who.add_argument("--no-twin", action="store_true",
                     help="no twin in this capture: label every AP legit (measures false positives)")
    ap.add_argument("--attack-start", default="auto", help="auto | +SECONDS | EPOCH (see --help)")
    ap.add_argument("--baseline-minutes", type=float, default=2.0,
                    help="warn if an attack starts inside the baseline (default 2)")
    ap.add_argument("--description", default="", help="free text stored in the labels file")
    ap.add_argument("--out", help="labels path (default: <pcap stem>.labels.json)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.pcap):
        print("[!] not found: {}".format(args.pcap), file=sys.stderr)
        return 1
    t0, aps = scan(args.pcap)
    if not aps:
        print("[!] no beacon / probe-response frames in {}".format(args.pcap), file=sys.stderr)
        return 1
    if not args.evil and not args.no_twin:
        print_table(t0, aps)
        print("\n[i] re-run with --evil <BSSID> to write the labels file")
        return 0

    evil = [b.lower() for b in args.evil]
    unknown = [b for b in evil if b not in aps]
    if unknown:
        print("[!] not in this capture: {}".format(", ".join(unknown)), file=sys.stderr)
        return 1

    labels = {}
    warnings = []
    for bssid, a in aps.items():
        entry = {"ssid": sorted(a["ssids"])[0], "label": "legit"}
        if bssid in evil:
            spec = args.attack_start
            if spec == "auto":
                start = a["first"]
            elif spec.startswith("+"):
                start = t0 + float(spec[1:])
            else:
                start = float(spec)
            entry.update(label="evil_twin", attack_start=start)
            if start - t0 < args.baseline_minutes * 60:
                warnings.append("{} starts {:.0f} s into the capture, inside the {:g}-min baseline: "
                                "the twin will be learned as normal".format(
                                    bssid, start - t0, args.baseline_minutes))
        labels[bssid] = entry

    out = args.out or os.path.splitext(args.pcap)[0] + ".labels.json"
    with open(out, "w") as f:
        json.dump({"scenario": os.path.splitext(os.path.basename(args.pcap))[0],
                   "description": args.description, "synthetic": False,
                   "capture_start": t0, "aps": labels}, f, indent=2)
    print("[+] wrote {} ({} APs, {} evil twin(s))".format(out, len(labels), len(evil)))
    for w in warnings:
        print("[!] " + w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
