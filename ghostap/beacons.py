"""Beacon difference viewer (F028): explain a fingerprint mismatch element by element.

A layout is the list that parser.beacon_layout() hashes into the fingerprint, e.g.
    ["cap=0401", "0", "1:82848b96", "3", "45:2c0103", "221:0050f202"]
Each part is "<element id>" (presence and order only), "<id>:<hex>" (the content or a
prefix of it that GhostAP compares) or "cap=<hex>" (capability bits).
"""
from __future__ import annotations

import difflib
from typing import List, Optional

from . import vendors

ELEMENTS = {
    0: "Network name (SSID)", 1: "Supported rates", 3: "Channel (DS parameter set)",
    5: "Traffic indication map (TIM)", 7: "Country", 11: "BSS load", 32: "Power constraint",
    35: "TPC report", 42: "ERP information", 45: "HT capabilities (Wi-Fi 4)",
    46: "QoS capability", 48: "Security (RSN)", 50: "Extended supported rates",
    54: "Mobility domain (fast roaming)", 59: "Supported operating classes",
    61: "HT operation (Wi-Fi 4)", 70: "Radio measurement capabilities", 74: "Overlapping BSS scan",
    107: "Interworking (Hotspot 2.0)", 108: "Advertisement protocol", 111: "Roaming consortium",
    127: "Extended capabilities", 191: "VHT capabilities (Wi-Fi 5)", 192: "VHT operation (Wi-Fi 5)",
    195: "Transmit power envelope", 199: "Operating mode notification", 201: "Reduced neighbour report",
    221: "Vendor specific", 244: "RSN extension",
}
EXTENSIONS = {35: "HE capabilities (Wi-Fi 6)", 36: "HE operation (Wi-Fi 6)", 38: "MU EDCA parameters",
              39: "Spatial reuse", 59: "HE 6 GHz band capabilities", 106: "EHT operation (Wi-Fi 7)",
              108: "EHT capabilities (Wi-Fi 7)"}
VENDOR_TYPES = {
    "0050f201": "Microsoft WPA (legacy security)", "0050f202": "WMM (quality of service)",
    "0050f204": "WPS (Wi-Fi Protected Setup)", "506f9a09": "Wi-Fi Direct (P2P)",
    "506f9a10": "Hotspot 2.0 indication", "506f9a1c": "OWE transition", "00101802": "Broadcom",
    "00037f01": "Atheros / Qualcomm", "8cfdf004": "Qualcomm", "000c4304": "Ralink / MediaTek",
    "00e04c02": "Realtek", "0017f201": "Apple", "00904c04": "Epigram / Broadcom HT",
    "00904c33": "Epigram / Broadcom HT capabilities", "00904c34": "Epigram / Broadcom HT info",
    "001a1101": "Google", "00163201": "Samsung",
}


def describe(part: str) -> dict:
    """Readable name and value of one layout part."""
    if part.startswith("cap="):
        return {"id": "cap", "name": "Capability bits", "value": part[4:]}
    eid, _, value = part.partition(":")
    try:
        n = int(eid)
    except ValueError:
        return {"id": eid, "name": "Unknown", "value": value}
    name = ELEMENTS.get(n, "Element {}".format(n))
    if n == 221 and value:
        oui = ":".join(value[i:i + 2] for i in (0, 2, 4))
        name = "Vendor: " + VENDOR_TYPES.get(value) if value in VENDOR_TYPES else \
            "Vendor: {} ({})".format(vendors.name(oui + ":00:00:00") or "OUI", oui)
    elif n == 255 and value:
        ext = value.split(":")[0]
        try:
            name = EXTENSIONS.get(int(ext, 16), "Extension element {}".format(int(ext, 16)))
        except ValueError:
            name = "Extension element"
        value = value.partition(":")[2]
    return {"id": n, "name": name, "value": value}


def diff(mine: Optional[List[str]], ref: Optional[List[str]]) -> List[dict]:
    """Element-by-element comparison; op is same | changed | only_this | only_known."""
    if mine is None or ref is None:
        return []
    def key(p):
        return p.split(":")[0] if not p.startswith(("221:", "255:")) else p
    out = []
    sm = difflib.SequenceMatcher(a=[key(p) for p in ref], b=[key(p) for p in mine], autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            for r, m in zip(ref[i1:i2], mine[j1:j2]):
                out.append(dict(describe(m), op="same" if r == m else "changed",
                                known_value=describe(r)["value"]))
        else:
            for r in ref[i1:i2]:
                out.append(dict(describe(r), op="only_known", known_value=describe(r)["value"], value=None))
            for m in mine[j1:j2]:
                out.append(dict(describe(m), op="only_this", known_value=None))
    return out


def summary(rows: List[dict]) -> str:
    changed = [r for r in rows if r["op"] != "same"]
    if not rows:
        return ""
    if not changed:
        return "Same elements in the same order."
    extra = sum(r["op"] == "only_this" for r in changed)
    missing = sum(r["op"] == "only_known" for r in changed)
    diff_val = sum(r["op"] == "changed" for r in changed)
    bits = []
    if extra:
        bits.append("{} element{} the known AP does not send".format(extra, "s" if extra > 1 else ""))
    if missing:
        bits.append("{} element{} missing".format(missing, "s" if missing > 1 else ""))
    if diff_val:
        bits.append("{} with different content".format(diff_val))
    return "; ".join(bits) + "."
