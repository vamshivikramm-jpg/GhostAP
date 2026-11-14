"""Sensor capability intelligence (PLAN_3.0, O18): what the capture adapter can and cannot do.

Reads `iw phy <phy> info` (read-only, no root needed) plus the driver and USB id from sysfs, and
turns them into a short list of things this sensor *cannot observe*, so the dashboard and reports
never imply coverage the hardware does not have (e.g. 6 GHz on a 2.4/5 GHz adapter).

    python -m ghostap.hwcaps wlan0
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional

_FREQ = re.compile(r"^\s*\*\s*(\d+)(?:\.\d+)?\s*MHz\s*\[(\d+)\](.*)$")


def _band(freq: int) -> Optional[str]:
    if 2400 <= freq <= 2500:
        return "2.4"
    if 4900 <= freq < 5925:
        return "5"
    if 5925 <= freq <= 7125:
        return "6"
    return None


def parse_iw_phy(text: str) -> dict:
    """Capabilities from the text of `iw phy <phy> info`."""
    caps: dict = {"modes": [], "software_modes": [], "ciphers": [], "bands": {}, "combinations": None,
                  "ht": False, "vht": False, "he": False, "eht": False, "antennas_rx": None, "antennas_tx": None,
                  "sae": False, "max_scan_ssids": None, "scheduled_scan": False}
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if raw.startswith("\t") and not raw.startswith("\t\t") and line.endswith(":"):
            section = line[:-1]
        if line.startswith("* ") and section in ("Supported interface modes", "software interface modes "
                                                 "(can always be added)", "Supported Ciphers"):
            name = line[2:].split(" (")[0].strip()
            key = {"Supported interface modes": "modes", "Supported Ciphers": "ciphers"}.get(section, "software_modes")
            caps[key].append(name)
        m = _FREQ.match(raw)
        if m and "disabled" not in m.group(3):
            freq, chan = int(m.group(1)), int(m.group(2))
            b = _band(freq)
            if b:
                caps["bands"].setdefault(b, []).append(chan)
        if "HT20/HT40" in line or line.startswith("HT20"):
            caps["ht"] = True
        if line.startswith("VHT Capabilities"):
            caps["vht"] = True
        if line.startswith("HE Iftypes") or line.startswith("HE MAC Capabilities"):
            caps["he"] = True
        if line.startswith("EHT Iftypes") or line.startswith("EHT MAC Capabilities"):
            caps["eht"] = True
        if line.startswith("Available Antennas:"):
            m2 = re.search(r"TX 0x([0-9a-f]+) RX 0x([0-9a-f]+)", line)
            if m2:
                caps["antennas_tx"] = bin(int(m2.group(1), 16)).count("1")
                caps["antennas_rx"] = bin(int(m2.group(2), 16)).count("1")
        if "interface combinations are not supported" in line:
            caps["combinations"] = False
        elif line.startswith("valid interface combinations"):
            caps["combinations"] = True
        if "SAE" in line and line.startswith("Device supports"):
            caps["sae"] = True
        if line.startswith("max # scan SSIDs:"):
            caps["max_scan_ssids"] = int(line.split(":")[1])
        if line.startswith("max # sched scan SSIDs:"):
            caps["scheduled_scan"] = int(line.split(":")[1]) > 0
    return caps


def limits(caps: dict) -> List[Dict[str, str]]:
    """What this sensor cannot observe or do, in plain words."""
    out = []
    bands = caps.get("bands") or {}
    if "monitor" not in caps.get("modes", []) and "monitor" not in caps.get("software_modes", []):
        out.append({"what": "no passive capture", "why": "the adapter has no monitor mode"})
    if "5" not in bands:
        out.append({"what": "5 GHz networks are not heard", "why": "the adapter has no 5 GHz band"})
    if "6" not in bands:
        out.append({"what": "6 GHz networks (Wi-Fi 6E / Wi-Fi 7 on 6 GHz) are not heard",
                    "why": "the adapter has no 6 GHz band"})
    if (caps.get("antennas_rx") or 1) < 2:
        out.append({"what": "no direction finding",
                    "why": "one receive antenna; location needs several sensors (coarse)"})
    if caps.get("combinations") is False:
        out.append({"what": "active checks pause passive capture",
                    "why": "the driver supports no concurrent interfaces (scan or test client vs monitor)"})
    if not caps.get("he"):
        out.append({"what": "cannot join Wi-Fi 6 (HE) networks as a test client",
                    "why": "no HE support; their beacons are still decoded passively"})
    if "GCMP-256" not in caps.get("ciphers", []):
        out.append({"what": "test client cannot use WPA3-Enterprise 192-bit or GCMP networks",
                    "why": "cipher list: " + (", ".join(caps.get("ciphers", [])) or "unknown")})
    return out


def _run(args: List[str]) -> Optional[str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def probe(iface: str) -> dict:
    """Capabilities of the adapter behind `iface`. Never raises; missing pieces become None."""
    out: dict = {"iface": iface, "available": False}
    info = _run(["iw", "dev", iface, "info"])
    m = re.search(r"wiphy (\d+)", info or "")
    if not m:
        out["error"] = "'iw dev {} info' failed (no such interface, or iw not installed)".format(iface)
        return out
    phy = "phy" + m.group(1)
    text = _run(["iw", "phy", phy, "info"])
    if text is None:
        out["error"] = "'iw phy {} info' failed".format(phy)
        return out
    caps = parse_iw_phy(text)
    dev = "/sys/class/net/{}/device".format(iface)
    driver = os.path.basename(os.path.realpath(dev + "/driver")) if os.path.exists(dev + "/driver") else None
    usb = None
    for base in (dev + "/..", dev):
        try:
            with open(base + "/idVendor") as v, open(base + "/idProduct") as p:
                usb = "{}:{}".format(v.read().strip(), p.read().strip())
                break
        except OSError:
            continue
    out.update(caps, available=True, phy=phy, driver=driver, usb_id=usb, limits=limits(caps),
               bands={b: sorted(c) for b, c in caps["bands"].items()})
    return out


_cache: Dict[str, dict] = {}


def cached(iface: str, refresh: bool = False) -> dict:
    """probe() once per interface per process (capabilities do not change while running)."""
    if refresh or iface not in _cache or not _cache[iface].get("available"):
        _cache[iface] = probe(iface)
    return _cache[iface]


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m ghostap.hwcaps <iface>", file=sys.stderr)
        return 2
    caps = probe(args[0])
    print(json.dumps(caps, indent=2))
    return 0 if caps.get("available") else 1


if __name__ == "__main__":
    sys.exit(main())
