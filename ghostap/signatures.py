"""Attack signatures: KARMA/MANA (F001), look-alike network names (F002) and the
attack-tool fingerprint library (F003).

Signatures differ from the eight weighted indicators: each is strong evidence on its
own, so when one matches it raises the AP's risk score to at least a configured floor
(config.yaml -> signatures) instead of being averaged in with weights.

Library file format (JSON list):
    [{"name": "WiFi Pineapple Mark VII", "kind": "tool",
      "fingerprints": ["2d29fcb71e42"], "ouis": ["00:13:37"],
      "source": "lab capture 2026-11-20", "example": false}]
Entries with "example": true are format examples built from GhostAP's own synthetic
profiles; they are ignored unless explicitly enabled, so they cannot inflate results.

CLI (add a fingerprint you recorded in the lab):
    python -m ghostap.signatures add --db data/sessions/<id>/session.db --bssid <mac> --name "..."
    python -m ghostap.signatures list
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from typing import Dict, Iterable, List, Optional, Set

BUILTIN_LIBRARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "bandits.json")
SIGNATURE_NAMES = ("karma", "lookalike_ssid", "known_tool")

# ---------------------------------------------------------------- look-alike names (F002)
# Characters that render (nearly) identically. Cyrillic/Greek capitals and lower case.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ӏ": "l", "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h",
    "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x", "Ү": "y", "α": "a", "ο": "o", "ν": "v",
    "ι": "i", "Ι": "i", "Ο": "o", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Κ": "k",
    "Μ": "m", "Ν": "n", "Ρ": "p", "Τ": "t", "Χ": "x", "Υ": "y",
}
_CONFUSABLE = {"0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "$": "s", "3": "e", "@": "a", "vv": "w",
               "rn": "m"}
_SEPARATORS = set(" _-.·'’ ​‌‍﻿")


def normalize_ssid(ssid: str) -> str:
    """Fold a network name to a 'skeleton' in which look-alikes become equal."""
    s = unicodedata.normalize("NFKC", ssid or "")
    s = "".join(_HOMOGLYPHS.get(ch, ch) for ch in s).lower()
    s = "".join(ch for ch in s if ch not in _SEPARATORS)
    for a, b in sorted(_CONFUSABLE.items(), key=lambda kv: -len(kv[0])):
        s = s.replace(a, b)
    return s


def _distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein (optimal string alignment), stopping early above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def lookalike_target(ssid: str, known: Iterable[str], max_distance: int = 2) -> Optional[tuple]:
    """(known_ssid, how) if `ssid` imitates a different known network name, else None."""
    if not ssid or ssid == "<hidden>":
        return None
    sk = normalize_ssid(ssid)
    best = None
    for k in known:
        if k == ssid or k == "<hidden>":
            continue
        kk = normalize_ssid(k)
        if not kk:
            continue
        if sk == kk:
            return k, "identical once look-alike characters and separators are ignored"
        if min(len(sk), len(kk)) >= 5:
            d = _distance(sk, kk, max_distance)
            if d <= max_distance and (best is None or d < best[2]):
                best = (k, "{} character{} different".format(d, "s" if d > 1 else ""), d)
    return (best[0], best[1]) if best else None


# ---------------------------------------------------------------- attack-tool library (F003)

def load_library(paths: Iterable[Optional[str]] = (BUILTIN_LIBRARY,), include_examples: bool = False) -> List[dict]:
    out: List[dict] = []
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("{} must contain a list of signatures".format(p))
        for e in data:
            if e.get("example") and not include_examples:
                continue
            out.append({"name": str(e["name"]), "kind": e.get("kind", "tool"),
                        "fingerprints": {str(x) for x in e.get("fingerprints", [])},
                        "ouis": {str(x).lower() for x in e.get("ouis", [])},
                        "source": e.get("source", ""), "example": bool(e.get("example"))})
    return out


def match_tool(fingerprints: Set[str], oui: str, library: List[dict]) -> Optional[dict]:
    for e in library:
        if fingerprints & e["fingerprints"]:
            return dict(e, matched="beacon fingerprint")
        if oui and oui.lower() in e["ouis"]:
            return dict(e, matched="vendor prefix {}".format(oui))
    return None


# ---------------------------------------------------------------- KARMA (F001)

def karma_value(n_ssids: int, min_ssids: int) -> float:
    """0 below min_ssids distinct names from one radio, 1.0 at min_ssids or more."""
    return 1.0 if n_ssids >= max(2, min_ssids) else 0.0


def main(argv=None) -> int:
    from .config import ConfigError, load_config
    from .storage import Store

    ap = argparse.ArgumentParser(prog="python -m ghostap.signatures",
                                 description="Manage the attack-tool fingerprint library.")
    ap.add_argument("command", choices=("add", "list"))
    ap.add_argument("--db", help="session database containing the tool's beacons (add)")
    ap.add_argument("--bssid", help="the lab tool's BSSID (add)")
    ap.add_argument("--name", help="what the device is, e.g. 'WiFi Pineapple Mark VII' (add)")
    ap.add_argument("--kind", default="tool", choices=("tool", "hotspot", "other"))
    ap.add_argument("--file", help="library to write (default: config attack_tools_file)")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    path = args.file or cfg["attack_tools_file"]
    if args.command == "list":
        for e in load_library([BUILTIN_LIBRARY, path], include_examples=True):
            print("{:<40} {:<8} {} fingerprint(s){}  {}".format(
                e["name"], e["kind"], len(e["fingerprints"]),
                "  (synthetic example, disabled)" if e["example"] else "", e["source"]))
        return 0
    if not (args.db and args.bssid and args.name):
        ap.error("add needs --db, --bssid and --name")
    with Store(args.db) as s:
        fps = sorted({r[0] for r in s.conn.execute(
            "SELECT DISTINCT fingerprint FROM observations WHERE bssid = ? AND frame_type = 'beacon' "
            "AND fingerprint IS NOT NULL", (args.bssid.lower(),)).fetchall()})
    if not fps:
        print("[!] no beacon fingerprints for {} in {}".format(args.bssid, args.db), file=sys.stderr)
        return 1
    lib = []
    if os.path.exists(path):
        with open(path) as f:
            lib = json.load(f)
    lib.append({"name": args.name, "kind": args.kind, "fingerprints": fps, "ouis": [],
                "source": "lab capture {}".format(os.path.basename(os.path.dirname(args.db)) or args.db),
                "example": False})
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(lib, f, indent=2)
    os.replace(path + ".tmp", path)
    print("[+] added '{}' ({} fingerprint(s)) to {}".format(args.name, len(fps), path))
    return 0


def library_for(cfg: dict) -> List[dict]:
    """Built-in + user library, as configured."""
    return load_library([BUILTIN_LIBRARY, cfg.get("attack_tools_file")],
                        include_examples=bool(cfg.get("detection", {}).get("use_example_signatures")))


def counts(lib: List[dict]) -> Dict[str, int]:
    return {"entries": len(lib), "examples": sum(1 for e in lib if e["example"])}


if __name__ == "__main__":
    sys.exit(main())
