"""Kismet as a second comparison detector (F050).

Run Kismet next to GhostAP during a lab capture and save its log as <name>.kismet next to
<name>.pcap. The evaluation then counts an access point as "flagged by Kismet" when Kismet
raised one of the alerts below about that BSSID.

Kismet log files (.kismet) are SQLite databases; the `alerts` table holds
    ts_sec, ts_usec, phyname, devmac, lat, lon, header, json
where `header` is the alert name and `json` its details (source / transmitter / BSSID
addresses). Kismet was NOT available where this was written: the reader follows Kismet's
documented log format and is tested with a file built to that schema. Confirm it with
your own Kismet capture on Kali before quoting Kismet numbers.

    python -m ghostap.kismet data/lab/run1.kismet        # list the alerts it found
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from typing import Dict, Iterable, List, Optional

# Kismet alerts that point at a rogue / spoofed access point (others, like probe or
# client alerts, are not about the AP being an evil twin).
TWIN_ALERTS = ("APSPOOF", "BSSTIMESTAMP", "CRYPTODROP", "CHANCHANGE", "KARMAOUI", "SSIDCONFLICT",
               "DEAUTHFLOOD", "BCASTDISCON", "MACCONFLICT")
_MAC_KEYS = ("kismet.alert.transmitter_mac", "kismet.alert.source_mac", "kismet.alert.bssid",
             "kismet.alert.dest_mac")


def _norm(mac) -> Optional[str]:
    if not isinstance(mac, str) or len(mac) != 17:
        return None
    mac = mac.lower()
    return None if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def read_alerts(path: str) -> List[dict]:
    """Every alert in a .kismet log: ts, header, macs (the addresses it names)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    con = sqlite3.connect("file:{}?mode=ro".format(path), uri=True)
    try:
        cols = {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
        if not {"ts_sec", "header"} <= cols:
            raise ValueError("{} has no Kismet alerts table".format(path))
        rows = con.execute("SELECT ts_sec, ts_usec, devmac, header, json FROM alerts "
                           "ORDER BY ts_sec, ts_usec").fetchall()
    finally:
        con.close()
    out = []
    for sec, usec, devmac, header, blob in rows:
        macs = {m for m in [_norm(devmac)] if m}
        try:
            detail = json.loads(blob) if blob else {}
        except (ValueError, TypeError):
            detail = {}
        for k in _MAC_KEYS:
            m = _norm(detail.get(k)) if isinstance(detail, dict) else None
            if m:
                macs.add(m)
        out.append({"ts": float(sec) + float(usec or 0) / 1e6, "header": str(header), "macs": sorted(macs),
                    "text": (detail.get("kismet.alert.text") if isinstance(detail, dict) else "") or ""})
    return out


def first_alerts(path: str, headers: Iterable[str] = TWIN_ALERTS) -> Dict[str, float]:
    """bssid -> time of Kismet's first twin-related alert about it."""
    wanted = set(headers)
    first: Dict[str, float] = {}
    for a in read_alerts(path):
        if a["header"] in wanted:
            for m in a["macs"]:
                first[m] = min(first.get(m, a["ts"]), a["ts"])
    return first


def main(argv=None) -> int:
    args = (argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print("usage: python -m ghostap.kismet <file.kismet>", file=sys.stderr)
        return 2
    try:
        alerts = read_alerts(args[0])
    except (OSError, ValueError, sqlite3.Error) as e:
        print("[!] {}".format(e), file=sys.stderr)
        return 1
    for a in alerts:
        mark = "*" if a["header"] in TWIN_ALERTS else " "
        print("{} {:.1f} {:<14} {}  {}".format(mark, a["ts"], a["header"], ",".join(a["macs"]), a["text"][:80]))
    print("[i] {} alerts; * = counted as an evil-twin alert by the evaluation".format(len(alerts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
