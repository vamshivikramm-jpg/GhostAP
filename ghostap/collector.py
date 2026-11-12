"""GhostAP collector: passively read beacons / probe responses into SQLite.

Usage:
    python -m ghostap.collector --pcap data/test_capture.pcap
    sudo python -m ghostap.collector --iface wlan0 --duration 120
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .parser import parse_frame
from .storage import Store

LIVE_HELP = """\
[!] Live capture failed: {err}

Live capture needs:
  * Linux (macOS cannot put USB Wi-Fi adapters into monitor mode for Scapy)
  * root privileges            -> run with: sudo .venv/bin/python -m ghostap.collector --iface <iface>
  * an interface in monitor mode, e.g.:
        sudo ip link set wlan0 down
        sudo iw dev wlan0 set type monitor
        sudo ip link set wlan0 up
        sudo iw dev wlan0 set channel 6

On a Mac, use offline mode instead:  python -m ghostap.collector --pcap <file.pcap>
"""


def _is_beacon_or_probe_resp(pkt) -> bool:
    # Management frames (type 0) with subtype 8 (beacon) or 5 (probe response).
    return getattr(pkt, "type", None) == 0 and getattr(pkt, "subtype", None) in (8, 5)


def collect_pcap(path: str, store: Store) -> int:
    from scapy.utils import PcapReader

    n = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            obs = parse_frame(pkt)
            if obs:
                store.add(obs)
                n += 1
    store.commit()
    return n


def collect_live(iface: str, duration: int, store: Store) -> int:
    from scapy.sendrecv import sniff

    counter = {"n": 0}

    def handle(pkt):
        obs = parse_frame(pkt)
        if obs:
            store.add(obs)
            counter["n"] += 1

    sniff(iface=iface, prn=handle, lfilter=_is_beacon_or_probe_resp,
          store=False, timeout=duration)
    store.commit()
    return counter["n"]


def format_table(profiles: List[dict]) -> str:
    headers = ("SSID", "BSSID", "CH", "SECURITY", "RSSI avg", "FRAMES")
    rows = []
    for p in profiles:
        rssi = "-" if p["rssi_avg"] is None else "{:.1f}".format(p["rssi_avg"])
        rows.append((p["ssid"], p["bssid"], p["channels"] or "-",
                     p["securities"] or "-", rssi, str(p["frames"])))
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*r) for r in rows]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m ghostap.collector",
        description="Passively collect 802.11 beacons / probe responses.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="read frames from a pcap file (offline)")
    src.add_argument("--iface", help="sniff live on a monitor-mode interface")
    ap.add_argument("--duration", type=int, default=60,
                    help="live capture duration in seconds (default 60)")
    ap.add_argument("--db", default="data/ghostap.db",
                    help="SQLite database path (default data/ghostap.db)")
    ap.add_argument("--reset", action="store_true",
                    help="delete existing observations before collecting")
    args = ap.parse_args(argv)

    store = Store(args.db)
    if args.reset:
        store.reset()
    try:
        if args.pcap:
            try:
                n = collect_pcap(args.pcap, store)
            except FileNotFoundError:
                print("[!] pcap not found: {}".format(args.pcap), file=sys.stderr)
                return 1
            print("[+] Parsed {} beacon/probe-response frames from {}".format(n, args.pcap))
        else:
            try:
                n = collect_live(args.iface, args.duration, store)
            except (PermissionError, OSError) as e:
                print(LIVE_HELP.format(err=e), file=sys.stderr)
                return 2
            except Exception as e:  # Scapy_Exception etc.
                print(LIVE_HELP.format(err="{}: {}".format(type(e).__name__, e)),
                      file=sys.stderr)
                return 2
            print("[+] Captured {} beacon/probe-response frames on {} ({}s)".format(
                n, args.iface, args.duration))
        store.rebuild_profiles()
        profiles = store.profiles()
        print("[+] {} access point profiles in {}\n".format(len(profiles), args.db))
        print(format_table(profiles))
    except KeyboardInterrupt:
        store.rebuild_profiles()
        print("\n[!] Interrupted - partial data saved to {}".format(args.db))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
