"""Give files made under sudo back to the user who ran sudo.

Live capture runs as root (`sudo .venv/bin/python -m ghostap.web --iface ...`). Everything
it creates (the session folder, the recorded pcap, data/admin.db, data/logs/, data/lab/)
would otherwise belong to root, and the next steps of the Phase 2 workflow, run as the
normal user (tools/label_capture.py writing <capture>.labels.json, a replay that creates
a new session, evaluate.py), fail with "Permission denied".

Only files owned by root are changed, only to the uid / gid that sudo recorded in
SUDO_UID / SUDO_GID, and only when the process really runs as root. Symbolic links are
never followed. Without sudo (normal user, systemd service, Docker) this does nothing.
"""
from __future__ import annotations

import os
import stat
from typing import Iterable, Optional, Tuple

Owner = Tuple[int, int]


def sudo_user() -> Optional[Owner]:
    """(uid, gid) of the user who started this process with sudo, else None."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ.get("SUDO_GID", uid))
    except (KeyError, ValueError):
        return None
    if uid == 0:
        return None
    return uid, gid


def _chown_if_root(path: str, owner: Owner) -> int:
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if st.st_uid != 0 or stat.S_ISLNK(st.st_mode):
        return 0
    try:
        os.chown(path, owner[0], owner[1], follow_symlinks=False)
    except OSError:
        return 0
    return 1


def _inside(path: str, base: str) -> bool:
    path, base = os.path.abspath(path), os.path.abspath(base)
    return path != base and os.path.commonpath([path, base]) == base


def give_back(files: Iterable[Optional[str]] = (), trees: Iterable[Optional[str]] = (),
              owner: Optional[Owner] = None, base: Optional[str] = None) -> int:
    """Hand root-owned files back to the sudo user. Returns how many were changed.

    files: single files (a database also gets its -wal / -shm / -journal companions)
    trees: GhostAP's own folders (sessions, logs, tls), changed recursively
    Parent folders are changed too, but only those inside `base` (default: the current
    directory, i.e. the project), so e.g. a freshly made data/ or data/lab/ is fixed
    and nothing outside the project is touched.
    """
    owner = owner or sudo_user()
    if owner is None:
        return 0
    base = base or os.getcwd()
    n = 0
    parents = set()
    for f in files:
        if not f:
            continue
        for p in (f, f + "-wal", f + "-shm", f + "-journal"):
            if os.path.lexists(p):
                n += _chown_if_root(p, owner)
                parents.add(os.path.dirname(os.path.abspath(p)))
    for t in trees:
        if not t or not os.path.isdir(t) or os.path.islink(t):
            continue
        parents.add(os.path.dirname(os.path.abspath(t)))
        n += _chown_if_root(t, owner)
        for root, dirs, names in os.walk(t):        # does not descend into symlinked dirs
            for x in dirs + names:
                n += _chown_if_root(os.path.join(root, x), owner)
    for d in parents:
        while _inside(d, base):
            n += _chown_if_root(d, owner)
            d = os.path.dirname(d)
    return n
