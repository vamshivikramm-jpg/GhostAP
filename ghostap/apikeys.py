"""API keys (F061) for scripts and tools such as Grafana or a SIEM.

    python -m ghostap.apikeys create --name grafana --scope read
    python -m ghostap.apikeys list
    python -m ghostap.apikeys revoke 3

A key is shown once, when it is created; only its SHA-256 hash is stored (in the admin
database). Send it as `Authorization: Bearer gk_...`. A `read` key can only GET; a `write`
key can also triage alerts and change settings. Keys cannot create or revoke other keys.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import time
from typing import Optional, Tuple

from .storage import Store

PREFIX = "gk_"
SCOPES = ("read", "write")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create(admin_db: str, name: str, scope: str = "read") -> Tuple[int, str]:
    if scope not in SCOPES:
        raise ValueError("scope must be read or write")
    name = (name or "").strip()
    if not name or len(name) > 60:
        raise ValueError("a key needs a name of 1 to 60 characters")
    key = PREFIX + secrets.token_urlsafe(30)
    with Store(admin_db) as s:
        kid = s.add_api_key(name, key[:10], hash_key(key), scope, time.time())
    return kid, key


def check(admin_db: str, key: str) -> Optional[dict]:
    """The key's record if it is valid and not revoked (and marks it used)."""
    if not key.startswith(PREFIX) or len(key) > 200:
        return None
    with Store(admin_db) as s:
        row = s.api_key_by_hash(hash_key(key))
        if row:
            s.touch_api_key(row["id"], time.time())
    return row


def main(argv=None) -> int:
    from .config import ConfigError, load_config
    ap = argparse.ArgumentParser(prog="python -m ghostap.apikeys", description="Manage GhostAP API keys.")
    ap.add_argument("--config", default="config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--name", required=True)
    c.add_argument("--scope", choices=SCOPES, default="read")
    sub.add_parser("list")
    r = sub.add_parser("revoke")
    r.add_argument("id", type=int)
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    admin_db = os.path.join(os.path.dirname(cfg["sessions_dir"].rstrip("/")) or ".", "admin.db")
    if args.cmd == "create":
        kid, key = create(admin_db, args.name, args.scope)
        print("[+] key {} ({}, {}). Copy it now, it is not shown again:".format(kid, args.name, args.scope))
        print(key)
        return 0
    if args.cmd == "list":
        with Store(admin_db) as s:
            rows = s.api_keys()
        for k in rows:
            print("{:>3}  {:<20} {:<5} {}...  {}".format(k["id"], k["name"], k["scope"], k["prefix"],
                                                       "revoked" if k["revoked"] else "active"))
        if not rows:
            print("[i] no API keys")
        return 0
    with Store(admin_db) as s:
        ok = s.revoke_api_key(args.id, time.time())
    print("[+] revoked" if ok else "[!] no active key with that id")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
