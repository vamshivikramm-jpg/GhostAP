"""Vendor names for access-point addresses (F029).

Looked up offline in the manufacturer list that Scapy ships (built from the IEEE OUI
registry by Wireshark). An optional newer list can be put in data/oui.txt in either
Wireshark `manuf` format or the IEEE `oui.txt` format:

    python -m ghostap.vendors import /usr/share/wireshark/manuf
    python -m ghostap.vendors lookup 00:c0:ca:de:ad:01

GhostAP never downloads the list itself.

A vendor name is a clue, not proof: an attacker can copy any address. A locally
administered address (second hex digit 2, 6, A or E) has no vendor at all; phones,
hotspots and AP software often use one.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from functools import lru_cache
from typing import Dict, Optional

LOCAL_FILE = os.path.join("data", "oui.txt")
_HEX6 = re.compile(r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})$")


def is_local(mac: str) -> bool:
    """Locally administered (randomised or software-assigned) address."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def parse_list(text: str) -> Dict[str, str]:
    """Wireshark manuf ("00:C0:CA<TAB>Alfa<TAB>Alfa, Inc.") or IEEE oui.txt
    ("00-C0-CA   (hex)		Alfa, Inc."). 24-bit prefixes only."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "(hex)" in line:
            prefix, _, name = line.partition("(hex)")
        else:
            cols = re.split(r"\t+|\s{2,}", line)
            if len(cols) < 2:
                continue
            prefix, name = cols[0], cols[-1]
        m = _HEX6.match(prefix.strip())
        if m and name.strip():
            out[":".join(m.groups()).lower()] = name.strip()
    return out


@lru_cache(maxsize=1)
def _local_table() -> Dict[str, str]:
    if not os.path.isfile(LOCAL_FILE):
        return {}
    with open(LOCAL_FILE, encoding="utf-8", errors="replace") as f:
        return parse_list(f.read())


@lru_cache(maxsize=4096)
def lookup(mac: str) -> dict:
    """{"vendor": name or None, "local": bool, "source": "data/oui.txt" | "scapy" | None}"""
    mac = (mac or "").lower()
    if is_local(mac):
        return {"vendor": None, "local": True, "source": None}
    name = _local_table().get(mac[:8])
    if name:
        return {"vendor": name, "local": False, "source": LOCAL_FILE}
    try:
        from scapy.config import conf
        got = conf.manufdb._get_manuf(mac) if conf.manufdb is not None else mac
    except Exception:  # an old or broken Scapy: no names rather than an error
        got = mac
    if got and got.lower() != mac:
        return {"vendor": got, "local": False, "source": "scapy"}
    return {"vendor": None, "local": False, "source": None}


def name(mac: str) -> Optional[str]:
    return lookup(mac)["vendor"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.vendors", description="Vendor names for MAC addresses.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import", help="copy a manuf or oui.txt file to " + LOCAL_FILE)
    imp.add_argument("file")
    lk = sub.add_parser("lookup", help="look up one or more addresses")
    lk.add_argument("mac", nargs="+")
    args = ap.parse_args(argv)
    if args.cmd == "import":
        with open(args.file, encoding="utf-8", errors="replace") as f:
            n = len(parse_list(f.read()))
        if not n:
            print("[!] {} has no vendor lines in manuf or oui.txt format".format(args.file), file=sys.stderr)
            return 1
        os.makedirs(os.path.dirname(LOCAL_FILE), exist_ok=True)
        shutil.copyfile(args.file, LOCAL_FILE)
        print("[+] {} vendors imported to {}".format(n, LOCAL_FILE))
        return 0
    for m in args.mac:
        r = lookup(m)
        print("{}  {}".format(m, r["vendor"] or ("locally administered (no vendor)" if r["local"] else "unknown")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
