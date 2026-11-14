"""GhostAP collector: passively read beacons / probe responses into SQLite.

Usage:
    python -m ghostap.collector --pcap data/test_capture.pcap
    sudo python -m ghostap.collector --iface wlan0 --duration 120
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from typing import Callable, List, Optional

from .parser import parse_event, parse_frame
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


WANTED_SUBTYPES = (8, 5, 12, 10)   # beacon, probe response, deauthentication, disassociation


def _is_beacon_or_probe_resp(pkt) -> bool:
    """Management frames GhostAP reads: beacons and probe responses (observations) plus
    deauthentication / disassociation frames (attack-activity events, F005)."""
    return getattr(pkt, "type", None) == 0 and getattr(pkt, "subtype", None) in WANTED_SUBTYPES


def _listen(iface: str):
    """One capture socket for the whole live run. Opening a socket per sniff() call (once a
    second) made the driver log "entered/left promiscuous mode" every second (about 10,000
    kernel log lines in a live test) and left a short receive gap at each reopen."""
    from scapy.config import conf
    return conf.L2listen(iface=iface)


def collect_pcap(path: str, store: Store, stats: Optional[dict] = None) -> int:
    """Parse every beacon / probe response in a pcap into `store`.

    `stats` (optional dict) receives counts of rejected frames by reason.
    """
    from scapy.utils import PcapReader

    n = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            obs = parse_frame(pkt, stats)
            if obs:
                store.add(obs)
                n += 1
                continue
            ev = parse_event(pkt, stats)
            if ev:
                store.add_event(ev)
                if stats is not None:
                    stats["events"] = stats.get("events", 0) + 1
    store.commit()
    return n


def collect_live(iface: str, duration: Optional[float], store: Store,
                 hop: Optional[List[int]] = None, dwell: float = 0.25,
                 save_pcap: Optional[str] = None, stop: Optional[threading.Event] = None,
                 on_frame: Optional[Callable[[dict], None]] = None,
                 on_status: Optional[Callable[[str], None]] = None,
                 stats: Optional[dict] = None, focus: Optional[dict] = None, control=None) -> int:
    """Sniff beacons / probe responses until `duration` seconds pass or `stop` is set.

    hop:       channel list to cycle through (None = stay on the current channel)
    save_pcap: also write every matching frame to this pcap (management frames only),
               so a live session can be replayed and labelled later (Phase 2)
    """
    from scapy.sendrecv import sniff

    from .hopper import ChannelHopper

    counter = {"n": 0}
    writer = None
    if save_pcap:
        from scapy.utils import PcapWriter
        parent = os.path.dirname(save_pcap)
        if parent:
            os.makedirs(parent, exist_ok=True)
        writer = PcapWriter(save_pcap, linktype=127, sync=True)  # 127 = RadioTap

    def handle(pkt):
        if control is not None and control.drop():      # F041: paused from the dashboard
            return
        obs = parse_frame(pkt, stats)
        if obs:
            store.add(obs)
            counter["n"] += 1
            if writer is not None:
                writer.write(pkt)
            if on_frame:
                on_frame(obs)
            return
        ev = parse_event(pkt, stats)
        if ev:
            store.add_event(ev)
            if writer is not None:
                writer.write(pkt)

    hopper = ChannelHopper(iface, hop, dwell, focus=focus).start() if hop else None
    if control is not None:
        control.iface, control.hopper = iface, hopper
    start = time.time()
    sock = None
    try:
        sock = _listen(iface)
        while not (stop is not None and stop.is_set()):
            if duration and time.time() - start >= duration:
                break
            chunk = 1.0 if not duration else max(0.1, min(1.0, duration - (time.time() - start)))
            # the socket stays open between calls: scapy closes only sockets it opened itself
            sniff(opened_socket=sock, prn=handle, lfilter=_is_beacon_or_probe_resp,
                  store=False, timeout=chunk)
            store.commit()
            if control is not None:
                hopper = control.hopper                  # may have been started from the dashboard
            if hopper is not None and on_status:
                on_status(hopper.describe())
    finally:
        if control is not None:
            hopper = control.hopper
            control.iface = None
        if hopper is not None:
            hopper.stop()
        if writer is not None:
            writer.close()
        if sock is not None:
            sock.close()
        store.commit()
    return counter["n"]


def print_rejected(rejected: dict) -> None:
    bad = {k: v for k, v in rejected.items() if k not in ("not_beacon", "events") and v}
    if bad:
        print("[i] skipped damaged frames: " + ", ".join(
            "{} {}".format(v, k.replace("_", " ")) for k, v in sorted(bad.items())))


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
    ap.add_argument("--hop", metavar="CHANNELS",
                    help="live: hop channels, e.g. 1,6,11 or 1-13 or 2.4 or 5 or all")
    ap.add_argument("--dwell", type=float, default=0.25,
                    help="live: seconds per channel when hopping (default 0.25)")
    ap.add_argument("--save-pcap", metavar="FILE",
                    help="live: also save the captured beacons / probe responses to a pcap")
    ap.add_argument("--db", default="data/ghostap.db",
                    help="SQLite database path (default data/ghostap.db)")
    ap.add_argument("--reset", action="store_true",
                    help="delete existing observations before collecting")
    args = ap.parse_args(argv)
    hop = None
    if args.hop:
        from .hopper import parse_channels
        try:
            hop = parse_channels(args.hop)
        except ValueError as e:
            ap.error(str(e))

    store = Store(args.db)
    if args.reset:
        store.reset()
    try:
        if args.pcap:
            rejected: dict = {}
            try:
                n = collect_pcap(args.pcap, store, rejected)
            except FileNotFoundError:
                print("[!] pcap not found: {}".format(args.pcap), file=sys.stderr)
                return 1
            print("[+] Parsed {} beacon/probe-response frames from {}".format(n, args.pcap))
            print_rejected(rejected)
        else:
            try:
                rejected = {}
                n = collect_live(args.iface, args.duration, store, hop=hop, dwell=args.dwell,
                                 save_pcap=args.save_pcap, stats=rejected,
                                 on_status=lambda m: print("[~] " + m, end="\r", flush=True))
            except (PermissionError, OSError) as e:
                print(LIVE_HELP.format(err=e), file=sys.stderr)
                return 2
            except Exception as e:  # Scapy_Exception etc.
                print(LIVE_HELP.format(err="{}: {}".format(type(e).__name__, e)),
                      file=sys.stderr)
                return 2
            print("[+] Captured {} beacon/probe-response frames on {} ({}s)".format(
                n, args.iface, args.duration))
            print_rejected(rejected)
            if args.save_pcap:
                print("[+] Saved them to {} (label it with tools/label_capture.py)".format(args.save_pcap))
        store.rebuild_profiles()
        profiles = store.profiles()
        print("[+] {} access point profiles in {}\n".format(len(profiles), args.db))
        print(format_table(profiles))
    except KeyboardInterrupt:
        store.rebuild_profiles()
        print("\n[!] Interrupted - partial data saved to {}".format(args.db))
    finally:
        store.close()
        from .ownership import give_back
        give_back(files=[args.db, args.save_pcap])     # made under sudo -> back to the user
    return 0


if __name__ == "__main__":
    sys.exit(main())
