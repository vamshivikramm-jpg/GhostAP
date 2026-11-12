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

# name, ssid, bssid, channel, wpa2, rssi_mean, rssi_jitter, tsf_start_us, start_s, label, profile
APS = [
    ("a", "MVSR_WiFi",  "a4:2b:b0:11:22:33", 6,  True,  -55, 3, 9_000_000_000, 0,   "legit", "enterprise"),
    ("b", "MVSR_WiFi",  "a4:2b:b0:11:22:99", 1,  True,  -70, 3, 7_500_000_000, 0,   "legit", "enterprise"),
    ("c", "Cafe_Guest", "f0:9f:c2:aa:bb:cc", 11, False, -75, 3, 3_000_000_000, 0,   "legit", "soho"),
    ("d", "MVSR_WiFi",  "00:c0:ca:de:ad:01", 11, False, -38, 3, 1_000,         180, "evil_twin", "hostapd"),
]
ATTACK_START = 180

# --- How different AP software builds its beacons ----------------------------
# Simplified, but modelled on real differences: element order, rate sets, HT
# capabilities and vendor-specific elements. "rsn" marks where RSN goes for WPA2.
_TIM = bytes.fromhex("00010000")
_HT_INFO = bytes(22)
_WMM = bytes.fromhex("0050f2020101800003a4000027a4000042435e0062322f00")
PROFILES = {
    # enterprise AP (controller-managed): country, HT, ext. capabilities, own vendor element
    "enterprise": [(1, bytes.fromhex("8284 8b96 0c12 1824".replace(" ", ""))), (3, None), (5, _TIM),
                   (7, b"IN \x01\x0d\x14"), (42, b"\x00"), "rsn",
                   (50, bytes.fromhex("30486c60")), (45, bytes.fromhex("ad0117ff") + bytes(22)),
                   (61, _HT_INFO), (127, bytes.fromhex("0000080000000040")),
                   (221, bytes.fromhex("004096010104")), (221, _WMM)],
    # home / small-office router
    "soho": [(1, bytes.fromhex("82848b962430486c")), (3, None), (5, _TIM), (42, b"\x00"),
             (50, bytes.fromhex("0c121860")), "rsn", (45, bytes.fromhex("ee1103ff") + bytes(22)),
             (61, _HT_INFO), (221, _WMM), (221, bytes.fromhex("000c4304000000"))],
    # Linux hostapd with a default 802.11g configuration (typical attack tooling)
    "hostapd": [(1, bytes.fromhex("82848b96")), (3, None), (5, _TIM), (42, b"\x04"),
                (50, bytes.fromhex("0c1218243048606c")), "rsn", (127, bytes.fromhex("0000000000000040")),
                (221, _WMM)],
    # phone hotspot
    "phone": [(1, bytes.fromhex("82848b960c121824")), (3, None), (5, _TIM), (42, b"\x00"),
              (50, bytes.fromhex("30486c60")), "rsn", (45, bytes.fromhex("2d0013ff") + bytes(22)),
              (61, _HT_INFO), (127, bytes.fromhex("0400000000000040")), (221, _WMM),
              (221, bytes.fromhex("001018020000100000"))],
}


def make_beacon(ssid, bssid, channel, wpa2, rssi, tsf, seq, beacon_interval=100,
                profile="enterprise"):
    cap = "ESS+privacy" if wpa2 else "ESS"
    pkt = (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid,
                SC=(seq & 0xFFF) << 4)
        / Dot11Beacon(beacon_interval=beacon_interval, timestamp=tsf, cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode())
    )
    for item in PROFILES[profile]:
        if item == "rsn":
            if wpa2:
                pkt = pkt / Dot11Elt(ID=48, info=RSN_WPA2_PSK)
            continue
        eid, info = item
        pkt = pkt / Dot11Elt(ID=eid, info=bytes([channel]) if eid == 3 else info)
    return pkt


def generate(out_dir: str = "data", seed: int = 7):
    random.seed(seed)
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "test_capture.pcap")
    labels_path = os.path.join(out_dir, "test_labels.json")

    seqs = {ap[2]: random.randrange(4096) for ap in APS}
    frames = []
    for t in range(DURATION):
        for (_, ssid, bssid, ch, wpa2, rssi_mean, jit, tsf0, start, _, profile) in APS:
            if t < start:
                continue
            # small sub-second offset so APs don't beacon at the identical instant
            ts = BASE_TIME + t + random.uniform(0, 0.1)
            rssi = int(round(rssi_mean + random.uniform(-jit, jit)))
            tsf = tsf0 + int((t - start) * 1_000_000)
            pkt = make_beacon(ssid, bssid, ch, wpa2, rssi, tsf, seqs[bssid], profile=profile)
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
