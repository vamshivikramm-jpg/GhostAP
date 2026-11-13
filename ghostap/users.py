"""GhostAP accounts (F065) from the command line. Passwords are typed at a prompt, never
given as arguments (they would end up in the shell history).

    python -m ghostap.users add alice --role admin      # the first account switches sign-in on
    python -m ghostap.users list
    python -m ghostap.users passwd alice
    python -m ghostap.users role bob viewer
    python -m ghostap.users disable bob | enable bob
    python -m ghostap.users reset-2fa alice              # lost phone: alice sets it up again
    python -m ghostap.users signout alice                # end all of alice's sessions
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from .auth import MIN_PASSWORD, ROLES, Auth, AuthError


def _password(prompt_for: str) -> str:
    p1 = getpass.getpass("New password for {} (at least {} characters): ".format(prompt_for, MIN_PASSWORD))
    p2 = getpass.getpass("Again: ")
    if p1 != p2:
        raise AuthError("the two passwords differ")
    return p1


def main(argv=None) -> int:
    from .config import ConfigError, load_config
    ap = argparse.ArgumentParser(prog="python -m ghostap.users", description="Manage GhostAP accounts.")
    ap.add_argument("--config", default="config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("username")
    a.add_argument("--role", choices=ROLES, default="analyst")
    sub.add_parser("list")
    for name in ("passwd", "disable", "enable", "reset-2fa", "signout"):
        sub.add_parser(name).add_argument("username")
    r = sub.add_parser("role")
    r.add_argument("username")
    r.add_argument("role", choices=ROLES)
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    auth = Auth(os.path.join(os.path.dirname(cfg["sessions_dir"].rstrip("/")) or ".", "admin.db"))
    try:
        if args.cmd == "list":
            users = auth.users()
            for u in users:
                print("{:>3}  {:<20} {:<8} {}{}".format(u["id"], u["username"], u["role"],
                                                        "disabled " if u["disabled"] else "",
                                                        "2FA" if u["totp_enabled"] else ""))
            if not users:
                print("[i] no accounts: the dashboard does not ask anyone to sign in "
                      "(on localhost) or uses its start-up link (when exposed)")
            return 0
        if args.cmd == "add":
            first = not auth.accounts_on()
            if first and args.role != "admin":
                print("[!] the first account must be an admin (use --role admin)", file=sys.stderr)
                return 1
            uid = auth.add_user(args.username, _password(args.username), args.role)
            print("[+] added {} ({}), id {}".format(args.username, args.role, uid))
            if first:
                print("[i] accounts are now on: everyone signs in, also on localhost.")
            return 0
        u = next((x for x in auth.users() if x["username"].lower() == args.username.lower()), None)
        if u is None:
            print("[!] no user called {}".format(args.username), file=sys.stderr)
            return 1
        if args.cmd == "passwd":
            auth.update_user(u["id"], password=_password(u["username"]))
            auth.revoke_all(u["id"])
        elif args.cmd == "role":
            auth.update_user(u["id"], role=args.role)
        elif args.cmd in ("disable", "enable"):
            auth.update_user(u["id"], disabled=args.cmd == "disable")
        elif args.cmd == "reset-2fa":
            auth.update_user(u["id"], reset_totp=True)
            auth.revoke_all(u["id"])
        elif args.cmd == "signout":
            print("[+] ended {} session(s)".format(auth.revoke_all(u["id"])))
            return 0
        print("[+] {}: {} done ({})".format(u["username"], args.cmd, time.strftime("%H:%M:%S")))
        return 0
    except AuthError as e:
        print("[!] {}".format(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
