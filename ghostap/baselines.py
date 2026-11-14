"""Saved-baseline integrity, versions and approval (GhostAP 2.0 Phase 2, "anti-baseline poisoning").

A saved baseline (data/monitored.json) decides what GhostAP treats as normal, so changing it is a
security decision:

* **Integrity.** The file carries the SHA-256 of its canonical content and an HMAC with a key kept
  outside data/ (default ~/.config/ghostap/baseline.key, mode 0600; or GHOSTAP_BASELINE_KEY_FILE),
  so bundles and exports never contain the key. A file changed outside GhostAP is refused on load.
  Files from before this feature (no signature) still load and are signed at the next save.
* **Versions.** Every applied change is a numbered version in admin.db (`baseline_versions`), with
  who proposed and who approved it. Any earlier version can be rolled back to (as a new version).
* **Approval.** Changes by an analyst wait for an admin. With two or more admins, a second admin
  must approve (two-person rule). A lone admin, or local mode without accounts, applies directly,
  unless the learning checks found possible contamination: then the change waits for an explicit
  approval even from a lone admin.
* **Contamination checks.** When a baseline is learned, the learning window is checked for signs
  that an attack was already on the air (an attack during learning is otherwise learned as normal).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Iterable, List, Optional

KEY_ENV = "GHOSTAP_BASELINE_KEY_FILE"


class IntegrityError(ValueError):
    """The saved baseline does not match its signature (changed outside GhostAP)."""


# ---------------------------------------------------------------- integrity

def _home() -> str:
    """The user's home. Under sudo (live capture), the home of the user who ran sudo: Kali's sudo
    sets HOME=/root, and a key there would not be found by the same user's later non-sudo runs."""
    from .ownership import sudo_user
    owner = sudo_user()
    if owner:
        import pwd
        try:
            return pwd.getpwuid(owner[0]).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def key_path() -> str:
    return os.environ.get(KEY_ENV) or os.path.join(_home(), ".config", "ghostap", "baseline.key")


def load_key(create: bool = False) -> Optional[bytes]:
    """The signing key; with create=True a new random key is made (0600) if none exists."""
    path = key_path()
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read().strip()
        return key or None
    if not create:
        return None
    made, d = [], os.path.dirname(os.path.abspath(path))
    while not os.path.exists(d):                     # folders this call creates (~/.config/ghostap ...)
        made.append(d)
        d = os.path.dirname(d)
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    key = secrets.token_hex(32).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    from .ownership import sudo_user
    owner = sudo_user()
    if owner:                                        # made under sudo: it belongs to that user
        for p in [path] + made:
            try:
                os.chown(p, owner[0], owner[1], follow_symlinks=False)
            except OSError:
                pass
    return key


def content_of(data: dict) -> dict:
    """The part of monitored.json that decides detection: networks (with their settings) and
    the new-network inbox decisions."""
    return {"networks": data.get("networks") or {}, "inventory": data.get("inventory") or {}}


def canonical(content: dict) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(content: dict) -> str:
    return hashlib.sha256(canonical(content)).hexdigest()


def sign(data: dict, version: int) -> dict:
    """Integrity block for `data` as version `version` (creates the key on first use)."""
    content = content_of(data)
    mac = hmac.new(load_key(create=True), canonical(content) + b"|%d" % version, hashlib.sha256).hexdigest()
    return {"version": version, "sha256": digest(content), "hmac": mac}


def verify(data: dict, path: str = "the saved baseline") -> Optional[int]:
    """Version number of a correctly signed file, None for an unsigned (older) file.
    Raises IntegrityError when the content or signature does not match."""
    block = data.get("integrity")
    if not block:
        return None
    try:
        version = int(block["version"])
        want_sha, want_mac = str(block["sha256"]), str(block["hmac"])
    except (KeyError, TypeError, ValueError):
        raise IntegrityError("{}: damaged integrity block".format(path)) from None
    content = content_of(data)
    if digest(content) != want_sha:
        raise IntegrityError(
            "{} was changed outside GhostAP (content does not match its SHA-256). Review the file, "
            "then run 'python -m ghostap.monitored trust' to accept it, or restore a backup".format(path))
    key = load_key()
    if key is None:
        raise IntegrityError(
            "{} is signed, but the signing key {} is missing (another user or machine?). Set {} or run "
            "'python -m ghostap.monitored trust' after reviewing the file".format(path, key_path(), KEY_ENV))
    mac = hmac.new(key, canonical(content) + b"|%d" % version, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, want_mac):
        raise IntegrityError(
            "{}: signature does not match (signed with another key, or edited together with its "
            "checksum). Review it and run 'python -m ghostap.monitored trust' to accept it".format(path))
    return version


# ---------------------------------------------------------------- approval policy

def approval_needed(role: Optional[str], admins: int, checks: Iterable[dict] = ()) -> Optional[str]:
    """Why a change by someone with `role` must wait for approval, or None to apply it now.
    role None = local mode without accounts (the person at the machine, treated as admin)."""
    role = role or "admin"
    if role != "admin":
        return "waiting for an admin to approve (changes by an {} need approval)".format(role)
    if admins >= 2:
        return "waiting for a second admin to approve (two-person rule)"
    if list(checks):
        return ("waiting for explicit approval: the learning checks found possible signs of an attack "
                "in the learning window")
    return None


def approval_error(role: Optional[str], actor: str, proposer: str, admins: int) -> Optional[str]:
    """Why `actor` may not approve a proposal by `proposer`, or None."""
    if (role or "admin") != "admin":
        return "only an admin can approve baseline changes"
    if admins >= 2 and actor == proposer:
        return "two-person rule: a different admin must approve this change"
    return None


# ---------------------------------------------------------------- versions (admin.db)

def _row(r) -> dict:
    d = dict(r)
    for k in ("checks", "detail"):
        d[k] = json.loads(d[k]) if d.get(k) else ([] if k == "checks" else {})
    return d


def record(conn, *, status: str, content: dict, base_version: Optional[int], actor: str, action: str,
           target: Optional[str], detail: Optional[dict] = None, checks: Iterable[dict] = (),
           version: Optional[int] = None, approved_by: Optional[str] = None, now: Optional[float] = None) -> int:
    now = time.time() if now is None else now
    with conn:
        if status == "trusted":
            conn.execute("UPDATE baseline_versions SET status='superseded' WHERE status='trusted'")
        cur = conn.execute(
            "INSERT INTO baseline_versions (version, status, content, sha256, base_version, proposed_by, "
            "proposed_at, approved_by, approved_at, action, target, detail, checks) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (version, status, canonical(content).decode(), digest(content), base_version, actor, now,
             approved_by, now if approved_by else None, action, target, json.dumps(detail or {}),
             json.dumps(list(checks))))
    return cur.lastrowid


def versions(conn, limit: int = 100) -> List[dict]:
    rows = conn.execute("SELECT id, version, status, sha256, base_version, proposed_by, proposed_at, "
                        "approved_by, approved_at, action, target, detail, checks, reason "
                        "FROM baseline_versions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def get(conn, vid: int) -> Optional[dict]:
    r = conn.execute("SELECT * FROM baseline_versions WHERE id=?", (vid,)).fetchone()
    if r is None:
        return None
    d = _row(r)
    d["content"] = json.loads(d["content"])
    return d


def approve(conn, vid: int, version: int, approver: str, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    with conn:
        conn.execute("UPDATE baseline_versions SET status='superseded' WHERE status='trusted'")
        conn.execute("UPDATE baseline_versions SET status='trusted', version=?, approved_by=?, approved_at=? "
                     "WHERE id=?", (version, approver, now, vid))


def reject(conn, vid: int, actor: str, reason: str, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    with conn:
        conn.execute("UPDATE baseline_versions SET status='rejected', approved_by=?, approved_at=?, reason=? "
                     "WHERE id=?", (actor, now, reason, vid))


def diff(old: dict, new: dict) -> dict:
    """What a proposal changes, per network: added / removed networks, added / removed BSSIDs,
    changed settings or other learned values."""
    o, n = old.get("networks") or {}, new.get("networks") or {}
    out = {"added": sorted(set(n) - set(o)), "removed": sorted(set(o) - set(n)), "changed": {}}
    for ssid in sorted(set(o) & set(n)):
        a, b = o[ssid], n[ssid]
        if a == b:
            continue
        ch = {"bssids_added": sorted(set(b.get("bssids", [])) - set(a.get("bssids", []))),
              "bssids_removed": sorted(set(a.get("bssids", [])) - set(b.get("bssids", []))),
              "fields": sorted(k for k in set(a) | set(b) if k not in ("bssids",) and a.get(k) != b.get(k))}
        out["changed"][ssid] = ch
    if (old.get("inventory") or {}) != (new.get("inventory") or {}):
        out["inventory_changed"] = True
    return out


# ---------------------------------------------------------------- contamination checks

FRESH_BOOT_S = 600        # an AP up for less than this ...
LONG_RUNNING_S = 3600     # ... next to one of the same network up for more than this


def contamination(observations: List[dict], minutes: float, ssids: Iterable[str],
                  whole_capture: bool = False) -> List[dict]:
    """Signs that an attack was on the air while a baseline was learned. Each hit is
    {ssid, bssid, check, detail}. A hit does not block learning; it makes the new baseline
    wait for an explicit approval."""
    from .indicators import Analyzer

    obs = sorted(observations, key=lambda o: o["ts"])
    if not obs:
        return []
    end = obs[-1]["ts"] if whole_capture else obs[0]["ts"] + minutes * 60
    window = [o for o in obs if o["ts"] <= end]
    wanted = set(ssids)
    an = Analyzer(window, baseline_minutes=(end - obs[0]["ts"]) / 60 + 1)
    hits: List[dict] = []
    per_ssid: Dict[str, Dict[str, dict]] = {}
    for ssid, bssid in an.aps():
        if ssid not in wanted:
            continue
        res = an.evaluate(ssid, bssid, until=end)
        for r in res or ():
            if r.name in ("karma", "lookalike_ssid", "known_tool", "bssid_conflict") and r.value >= 0.5:
                hits.append({"ssid": ssid, "bssid": bssid, "check": r.name, "detail": r.reason})
        mine = [o for o in window if o["ssid"] == ssid and o["bssid"] == bssid]
        tsf = [o["tsf"] for o in mine if o.get("tsf") is not None]
        per_ssid.setdefault(ssid, {})[bssid] = {
            "securities": {o.get("security") for o in mine if o.get("security")},
            "uptime": tsf[0] / 1e6 if tsf else None}
    for ssid, aps in per_ssid.items():
        secs = set().union(*(a["securities"] for a in aps.values()))
        if "OPN" in secs and secs - {"OPN"}:
            opn = sorted(b for b, a in aps.items() if "OPN" in a["securities"])
            hits.append({"ssid": ssid, "bssid": opn[0], "check": "mixed_security",
                         "detail": "open and password-protected access points share this name ({})".format(
                             ", ".join(sorted(secs)))})
        ups = {b: a["uptime"] for b, a in aps.items() if a["uptime"] is not None}
        if len(ups) >= 2 and max(ups.values()) > LONG_RUNNING_S:
            for b, u in sorted(ups.items()):
                if u < FRESH_BOOT_S:
                    hits.append({"ssid": ssid, "bssid": b, "check": "fresh_boot",
                                 "detail": "started {:.0f} s before it was heard, next to an access point of the "
                                           "same network up for {:.1f} h".format(u, max(ups.values()) / 3600)})
    return hits
