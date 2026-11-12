#!/usr/bin/env python3
"""Generate a labelled, synthetic evaluation set for Phase 6.

Writes, for each scenario, into data/eval/ (or --out):
    <scenario>.pcap          300 s of beacons, 1 beacon / s / AP
    <scenario>.labels.json   ground truth: each BSSID -> legit / evil_twin

Five scenarios contain an evil twin (from easy to deliberately hard). Five are
benign situations that look suspicious, to measure false positives: a new AP
installed by IT, a reboot, a big enterprise network, a power change, a channel
change. Every scenario has a 2-minute clean period at the start for the baseline.

These are SYNTHETIC captures. They test the logic end to end, but the numbers
they produce are not a substitute for the real lab captures of Phase 2.

Usage:
    python tools/make_eval_set.py [--out data/eval]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_test_pcap import make_beacon  # noqa: E402

from scapy.utils import PcapWriter  # noqa: E402

DURATION = 300
BASE_TIME = 1_700_000_000.0
ATTACK = 180


def ap(ssid, bssid, ch, wpa2, rssi, tsf0, start=0, end=DURATION, label="legit",
       bi=100, events=None):
    return dict(ssid=ssid, bssid=bssid, ch=ch, wpa2=wpa2, rssi=rssi, tsf0=tsf0,
                start=start, end=end, label=label, bi=bi, events=events or [])


def office():
    """The normal environment: two enterprise APs and a cafe hotspot."""
    return [
        ap("MVSR_WiFi", "a4:2b:b0:11:22:33", 6, True, -55, 9_000_000_000),
        ap("MVSR_WiFi", "a4:2b:b0:11:22:99", 1, True, -70, 7_500_000_000),
        ap("Cafe_Guest", "f0:9f:c2:aa:bb:cc", 11, False, -75, 3_000_000_000),
    ]


SCENARIOS = {
    # ---------------------------------------------------------------- attacks
    "s01_classic_open_twin": (
        "Open evil twin of a WPA2 network: different vendor, new channel, strong "
        "signal, freshly booted.",
        office() + [ap("MVSR_WiFi", "00:c0:ca:de:ad:01", 11, False, -38, 1_000,
                       start=ATTACK, label="evil_twin")]),
    "s02_spoofed_oui_twin": (
        "Open evil twin that spoofs the legit vendor OUI and sits on the legit "
        "channel with a similar signal.",
        office() + [ap("MVSR_WiFi", "a4:2b:b0:11:22:5a", 6, False, -50, 2_000,
                       start=ATTACK, label="evil_twin")]),
    "s03_cloned_bssid_twin": (
        "Evil twin clones the exact BSSID of the main AP, open, on another channel.",
        office() + [ap("MVSR_WiFi", "a4:2b:b0:11:22:33", 11, False, -40, 3_000,
                       start=ATTACK, label="evil_twin")]),
    "s04_stealth_wpa2_twin": (
        "Hard case: attacker knows the PSK, so the twin is WPA2, spoofs the vendor "
        "OUI, uses the legit channel and a normal signal. Only its TSF gives it away.",
        office() + [ap("MVSR_WiFi", "a4:2b:b0:11:22:77", 6, True, -57, 4_000,
                       start=ATTACK, label="evil_twin")]),
    "s05_open_network_twin": (
        "Evil twin of an already-open hotspot: no security downgrade is possible; "
        "different vendor, channel, strong signal, fresh TSF.",
        office() + [ap("Cafe_Guest", "00:c0:ca:ca:fe:01", 1, False, -45, 5_000,
                       start=ATTACK, label="evil_twin")]),
    # ---------------------------------------------------------------- benign
    "s06_benign_new_ap": (
        "IT switches on a new AP of the same vendor (WPA2) on a new channel; it has "
        "just booted.",
        office() + [ap("MVSR_WiFi", "a4:2b:b0:11:22:c4", 11, True, -65, 6_000,
                       start=ATTACK)]),
    "s07_benign_reboot": (
        "The main AP reboots: 20 s silence, then its TSF restarts from zero.",
        [ap("MVSR_WiFi", "a4:2b:b0:11:22:33", 6, True, -55, 9_000_000_000,
            events=[{"at": 170, "reboot_gap": 20}])] + office()[1:]),
    "s08_benign_enterprise": (
        "Campus network: six APs share one SSID; a sixth AP of the same vendor, up "
        "for days, comes into range later.",
        [ap("Campus", "a4:2b:b0:20:00:0{}".format(i), ch, True, rssi, tsf)
         for i, (ch, rssi, tsf) in enumerate([(1, -60, 8e11), (6, -66, 9e11),
                                              (11, -71, 7e11), (36, -74, 6e11),
                                              (44, -78, 5e11)], start=1)]
        + [ap("Campus", "a4:2b:b0:20:00:06", 6, True, -72, 4e11, start=200)]
        + office()[2:]),
    "s09_benign_power_change": (
        "The second AP's transmit power is raised: about +15 dB from t=200.",
        office()[:1] + [ap("MVSR_WiFi", "a4:2b:b0:11:22:99", 1, True, -70, 7_500_000_000,
                           events=[{"at": 200, "rssi": -55}])] + office()[2:]),
    "s10_benign_channel_change": (
        "Auto channel selection moves the second AP from channel 1 to 11 at t=200.",
        office()[:1] + [ap("MVSR_WiFi", "a4:2b:b0:11:22:99", 1, True, -70, 7_500_000_000,
                           events=[{"at": 200, "ch": 11}])] + office()[2:]),
}


def render(aps, seed):
    rnd = random.Random(seed)
    frames = []
    for spec in aps:
        st = dict(ch=spec["ch"], rssi=spec["rssi"], boot_t=spec["start"],
                  tsf_at_boot=int(spec["tsf0"]), seq=rnd.randrange(4096), silent_until=-1)
        events = {e["at"]: e for e in spec["events"]}
        for t in range(int(spec["start"]), int(spec["end"])):
            e = events.get(t)
            if e:
                if "rssi" in e:
                    st["rssi"] = e["rssi"]
                if "ch" in e:
                    st["ch"] = e["ch"]
                if "reboot_gap" in e:
                    st["silent_until"] = t + e["reboot_gap"]
                    st["boot_t"] = t + e["reboot_gap"]
                    st["tsf_at_boot"] = 1_000
                    st["seq"] = rnd.randrange(4096)
            if t < st["silent_until"]:
                continue
            ts = BASE_TIME + t + rnd.uniform(0, 0.1)
            tsf = st["tsf_at_boot"] + int((t - st["boot_t"]) * 1_000_000)
            rssi = int(round(st["rssi"] + rnd.uniform(-3, 3)))
            pkt = make_beacon(spec["ssid"], spec["bssid"], st["ch"], spec["wpa2"], rssi,
                              tsf, st["seq"], beacon_interval=spec["bi"])
            st["seq"] = (st["seq"] + 1) % 4096
            pkt.time = ts
            frames.append(pkt)
    frames.sort(key=lambda p: p.time)
    return frames


def labels_for(name, desc, aps):
    out = {}
    for spec in aps:
        entry = out.setdefault(spec["bssid"], {"ssid": spec["ssid"], "label": "legit"})
        if spec["label"] == "evil_twin":
            entry["label"] = "evil_twin"
            entry["attack_start"] = BASE_TIME + spec["start"]
    return {"scenario": name, "description": desc, "synthetic": True,
            "capture_start": BASE_TIME, "duration_s": DURATION, "aps": out}


def generate(out_dir="data/eval"):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for i, (name, (desc, aps)) in enumerate(sorted(SCENARIOS.items())):
        frames = render(aps, seed=100 + i)
        pcap = os.path.join(out_dir, name + ".pcap")
        with PcapWriter(pcap, linktype=127, sync=False) as w:
            for pkt in frames:
                w.write(pkt)
        with open(os.path.join(out_dir, name + ".labels.json"), "w") as f:
            json.dump(labels_for(name, desc, aps), f, indent=2)
        written.append((name, len(frames)))
    return written


def main():
    ap_ = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap_.add_argument("--out", default="data/eval")
    args = ap_.parse_args()
    for name, n in generate(args.out):
        print("[+] {:<28} {:>5} frames".format(name, n))
    print("[+] wrote {} scenarios to {}".format(len(SCENARIOS), args.out))


if __name__ == "__main__":
    main()
