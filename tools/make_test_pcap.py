#!/usr/bin/env python3
"""Generate a synthetic 802.11 beacon capture with one evil twin.

Writes:
    <out>/test_capture.pcap   300 s, 1 beacon / s / AP
    <out>/test_labels.json    bssid -> "legit" | "evil_twin", plus attack start

Usage:
    python tools/make_test_pcap.py [--out data]
"""
from __future__ import annotations

import argparse
import json
import os
import random

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import PcapWriter

DURATION = 300          # seconds
BASE_TIME = 1_700_000_000.0
BROADCAST = "ff:ff:ff:ff:ff:ff"
# RSN IE body: version 1, group CCMP, 1 pairwise CCMP, 1 AKM PSK, caps 0.
RSN_WPA2_PSK = bytes.fromhex("0100000fac040100000fac040100000fac020000")

# name, ssid, bssid, channel, wpa2, rssi_mean, rssi_jitter, tsf_start_us, start_s, label
APS = [
    ("a", "MVSR_WiFi",  "a4:2b:b0:11:22:33", 6,  True,  -55, 3, 9_000_000_000, 0,   "legit"),
    ("b", "MVSR_WiFi",  "a4:2b:b0:11:22:99", 1,  True,  -70, 3, 7_500_000_000, 0,   "legit"),
    ("c", "Cafe_Guest", "f0:9f:c2:aa:bb:cc", 11, False, -75, 3, 3_000_000_000, 0,   "legit"),
    ("d", "MVSR_WiFi",  "00:c0:ca:de:ad:01", 11, False, -38, 3, 1_000,         180, "evil_twin"),
]
ATTACK_START = 180


def make_beacon(ssid, bssid, channel, wpa2, rssi, tsf, seq):
    cap = "ESS+privacy" if wpa2 else "ESS"
    pkt = (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid,
                SC=(seq & 0xFFF) << 4)
        / Dot11Beacon(beacon_interval=100, timestamp=tsf, cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    if wpa2:
        pkt = pkt / Dot11Elt(ID=48, info=RSN_WPA2_PSK)
    return pkt


def generate(out_dir: str = "data", seed: int = 7):
    random.seed(seed)
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "test_capture.pcap")
    labels_path = os.path.join(out_dir, "test_labels.json")

    seqs = {ap[2]: random.randrange(4096) for ap in APS}
    frames = []
    for t in range(DURATION):
        for (_, ssid, bssid, ch, wpa2, rssi_mean, jit, tsf0, start, _) in APS:
            if t < start:
                continue
            # small sub-second offset so APs don't beacon at the identical instant
            ts = BASE_TIME + t + random.uniform(0, 0.1)
            rssi = int(round(rssi_mean + random.uniform(-jit, jit)))
            tsf = tsf0 + int((t - start) * 1_000_000)
            pkt = make_beacon(ssid, bssid, ch, wpa2, rssi, tsf, seqs[bssid])
            seqs[bssid] = (seqs[bssid] + 1) % 4096
            pkt.time = ts
            frames.append(pkt)

    frames.sort(key=lambda p: p.time)
    with PcapWriter(pcap_path, linktype=127, sync=False) as w:  # 127 = RadioTap
        for pkt in frames:
            w.write(pkt)

    labels = {
        "attack_start": BASE_TIME + ATTACK_START,
        "attack_start_offset_s": ATTACK_START,
        "capture_start": BASE_TIME,
        "duration_s": DURATION,
        "aps": {ap[2]: ap[9] for ap in APS},
    }
    with open(labels_path, "w") as f:
        json.dump(labels, f, indent=2)

    return pcap_path, labels_path, len(frames)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="data", help="output directory (default data)")
    args = ap.parse_args()
    pcap, labels, n = generate(args.out)
    print("[+] wrote {} frames to {}".format(n, pcap))
    print("[+] wrote labels to {}".format(labels))


if __name__ == "__main__":
    main()
