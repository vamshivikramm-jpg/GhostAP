"""Accounts and sign-in (F062-F067).

Off until the first account is created (python -m ghostap.users add <name>). From then
on every page and API call needs a signed-in user, an API key or a viewer link, also on
localhost.

  roles      admin    everything, including accounts, API keys and deleting sessions
             analyst  triage, baselines, notes, mutes, viewer links
             viewer   read only
  passwords  scrypt (n=2^14, r=8, p=1), at least 10 characters
  sessions   random 256-bit id in an HttpOnly, SameSite=Strict cookie; only its hash is
             stored; 12 h idle timeout, 7 days at most; listed and revocable (F067)
  2FA        TOTP (RFC 6238, 30 s, 6 digits, one step of clock drift), no code reuse,
             8 single-use recovery codes (F066)
  lockout    5 failed sign-ins for a user name or address within 10 min -> 10 min wait
  viewer     read-only links that expire and can be revoked (F063)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from .storage import Store

ROLES = ("admin", "analyst", "viewer")
MIN_PASSWORD = 10
IDLE_S = 12 * 3600
ABSOLUTE_S = 7 * 24 * 3600
LOCK_AFTER, LOCK_WINDOW_S, LOCK_S = 5, 600, 600
COOKIE = "ghostap_session"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash       TEXT NOT NULL,
    role          TEXT NOT NULL,
    created       REAL NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    totp_last     INTEGER,
    recovery      TEXT
);
CREATE TABLE IF NOT EXISTS logins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hash        TEXT NOT NULL UNIQUE,
    user_id     INTEGER,
    viewer_link INTEGER,
    role        TEXT NOT NULL,
    created     REAL NOT NULL,
    last_seen   REAL NOT NULL,
    ip          TEXT,
    agent       TEXT,
    revoked     REAL
);
CREATE TABLE IF NOT EXISTS viewer_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    hash        TEXT NOT NULL UNIQUE,
    created     REAL NOT NULL,
    expires     REAL NOT NULL,
    created_by  TEXT,
    revoked     REAL
);
"""


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400, **extra):
        super().__init__(message)
        self.status, self.extra = status, extra


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------- passwords
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1${}${}".format(salt.hex(), dk.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, want = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                            dklen=len(want) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), want)


_DUMMY: List[str] = []


def _dummy_hash() -> str:
    if not _DUMMY:
        _DUMMY.append(hash_password(secrets.token_hex(8)))
    return _DUMMY[0]


def check_password_rules(password: str, username: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AuthError("the password needs at least {} characters".format(MIN_PASSWORD))
    if password.lower() == (username or "").lower():
        raise AuthError("the password cannot be the user name")
    if len(password) > 200:
        raise AuthError("the password is too long (200 characters at most)")


# --------------------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return "{:06d}".format(code)


def check_totp(secret: str, code: str, last_step: Optional[int], now: Optional[float] = None) -> Optional[int]:
    """The matching time step (one step of drift allowed), or None. A step at or before
    `last_step` was already used and is refused (no replay)."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    step = int((time.time() if now is None else now) // 30)
    for s in (step, step - 1, step + 1):
        if (last_step is None or s > last_step) and hmac.compare_digest(totp(secret, s), code):
            return s
    return None


def totp_uri(secret: str, username: str) -> str:
    return "otpauth://totp/GhostAP:{}?secret={}&issuer=GhostAP&digits=6&period=30".format(quote(username), secret)


def new_recovery_codes() -> Tuple[List[str], List[str]]:
    codes = ["{}-{}".format(secrets.token_hex(2), secrets.token_hex(2)) for _ in range(8)]
    return codes, [_h(c) for c in codes]


# --------------------------------------------------------------------------- store
class Auth:
    """Accounts, sign-in sessions and viewer links in the admin database."""

    def __init__(self, admin_db: str):
        self.db = admin_db
        with Store(admin_db) as s:
            s.conn.executescript(SCHEMA)
        self._fails: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._count_cache: Tuple[float, int] = (0.0, -1)

    def _store(self) -> Store:
        return Store(self.db)

    # ---- accounts
    def accounts_on(self) -> bool:
        """True once any account exists (cached for a second; checked on every request)."""
        t, n = self._count_cache
        if time.time() - t > 1.0:
            with self._store() as s:
                n = s.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            self._count_cache = (time.time(), n)
        return n > 0

    def add_user(self, username: str, password: str, role: str) -> int:
        username = (username or "").strip()
        if not username or len(username) > 40 or not all(c.isalnum() or c in "._-" for c in username):
            raise AuthError("user names use letters, digits, . _ - (1 to 40 characters)")
        if role not in ROLES:
            raise AuthError("role must be admin, analyst or viewer")
        check_password_rules(password, username)
        with self._store() as s:
            if s.conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise AuthError("that user name is taken", 409)
            cur = s.conn.execute("INSERT INTO users (username, pw_hash, role, created) VALUES (?, ?, ?, ?)",
                                 (username, hash_password(password), role, time.time()))
            s.conn.commit()
        self._count_cache = (0.0, -1)
        return cur.lastrowid

    def users(self) -> List[dict]:
        with self._store() as s:
            rows = s.conn.execute("SELECT id, username, role, created, disabled, totp_enabled FROM users "
                                  "ORDER BY username").fetchall()
            last = {r[0]: r[1] for r in s.conn.execute(
                "SELECT user_id, MAX(last_seen) FROM logins WHERE user_id IS NOT NULL GROUP BY user_id")}
        return [dict(r, last_seen=last.get(r["id"])) for r in rows]

    def user(self, user_id: int) -> Optional[dict]:
        with self._store() as s:
            r = s.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(r) if r else None

    def update_user(self, user_id: int, role: Optional[str] = None, disabled: Optional[bool] = None,
                    reset_totp: bool = False, password: Optional[str] = None) -> None:
        u = self.user(user_id)
        if u is None:
            raise AuthError("no such user", 404)
        with self._store() as s:
            if role is not None:
                if role not in ROLES:
                    raise AuthError("role must be admin, analyst or viewer")
                if u["role"] == "admin" and role != "admin" and self._admins(s, exclude=user_id) == 0:
                    raise AuthError("keep at least one active admin")
                s.conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
                s.conn.execute("UPDATE logins SET role = ? WHERE user_id = ?", (role, user_id))
            if disabled is not None:
                if disabled and u["role"] == "admin" and self._admins(s, exclude=user_id) == 0:
                    raise AuthError("keep at least one active admin")
                s.conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(bool(disabled)), user_id))
                if disabled:
                    s.conn.execute("UPDATE logins SET revoked = ? WHERE user_id = ? AND revoked IS NULL",
                                   (time.time(), user_id))
            if reset_totp:
                s.conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last = NULL, "
                               "recovery = NULL WHERE id = ?", (user_id,))
            if password is not None:
                check_password_rules(password, u["username"])
                s.conn.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hash_password(password), user_id))
            s.conn.commit()

    @staticmethod
    def _admins(s: Store, exclude: int) -> int:
        return s.conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
                              (exclude,)).fetchone()[0]

    # ---- sign in
    def _locked(self, keys: List[str], now: float) -> float:
        with self._lock:
            wait = 0.0
            for k in keys:
                recent = [t for t in self._fails.get(k, []) if now - t < LOCK_WINDOW_S]
                self._fails[k] = recent
                if len(recent) >= LOCK_AFTER:
                    wait = max(wait, recent[-1] + LOCK_S - now)
            return wait

    def _fail(self, keys: List[str], now: float) -> None:
        with self._lock:
            for k in keys:
                self._fails.setdefault(k, []).append(now)

    def login(self, username: str, password: str, code: Optional[str], ip: str, agent: str) -> Tuple[str, dict]:
        """(session token for the cookie, user). Raises AuthError (401, 429)."""
        now = time.time()
        keys = ["u:" + (username or "").lower(), "ip:" + (ip or "")]
        wait = self._locked(keys, now)
        if wait > 0:
            raise AuthError("too many failed sign-ins; try again in {} min".format(int(wait // 60) + 1), 429,
                            retry_after=int(wait))
        with self._store() as s:
            u = s.conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip(),)).fetchone()
        # verify against a fixed dummy hash when the user does not exist: same work, so the
        # response time does not reveal which user names exist
        ok = verify_password(password or "", u["pw_hash"] if u else _dummy_hash())
        if not u or not ok or u["disabled"]:
            self._fail(keys, now)
            raise AuthError("wrong user name or password", 401)
        if u["totp_enabled"]:
            if not code:
                raise AuthError("enter the 6-digit code from your authenticator app", 401, need_code=True)
            if not self._second_factor(dict(u), code, now):
                self._fail(keys, now)
                raise AuthError("that code is not valid", 401, need_code=True)
        return self.start_session(u["id"], None, u["role"], ip, agent), dict(u)

    def _second_factor(self, u: dict, code: str, now: float) -> bool:
        step = check_totp(u["totp_secret"], code, u["totp_last"], now)
        with self._store() as s:
            if step is not None:
                s.conn.execute("UPDATE users SET totp_last = ? WHERE id = ?", (step, u["id"]))
                s.conn.commit()
                return True
            rec = json.loads(u["recovery"] or "[]")
            h = _h(str(code).strip().lower())
            if h in rec:                                       # single-use recovery code
                rec.remove(h)
                s.conn.execute("UPDATE users SET recovery = ? WHERE id = ?", (json.dumps(rec), u["id"]))
                s.conn.commit()
                return True
        return False

    def start_session(self, user_id: Optional[int], link_id: Optional[int], role: str, ip: str, agent: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._store() as s:
            s.conn.execute("INSERT INTO logins (hash, user_id, viewer_link, role, created, last_seen, ip, agent) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (_h(token), user_id, link_id, role, now, now, (ip or "")[:64], (agent or "")[:200]))
            s.conn.commit()
        return token

    def session(self, token: Optional[str]) -> Optional[dict]:
        """The sign-in behind a cookie, if it is still valid (and records activity)."""
        if not token or len(token) > 100:
            return None
        now = time.time()
        with self._store() as s:
            r = s.conn.execute(
                "SELECT l.*, u.username, u.disabled, u.totp_enabled, v.expires AS link_expires, "
                "v.revoked AS link_revoked, "
                "v.name AS link_name FROM logins l LEFT JOIN users u ON u.id = l.user_id "
                "LEFT JOIN viewer_links v ON v.id = l.viewer_link WHERE l.hash = ?", (_h(token),)).fetchone()
            if r is None or r["revoked"] or now - r["last_seen"] > IDLE_S or now - r["created"] > ABSOLUTE_S:
                return None
            if r["user_id"] is not None and (r["username"] is None or r["disabled"]):
                return None
            if r["viewer_link"] is not None and (r["link_revoked"] or now > r["link_expires"]):
                return None
            if now - r["last_seen"] > 60:                      # write at most once a minute
                s.conn.execute("UPDATE logins SET last_seen = ? WHERE id = ?", (now, r["id"]))
                s.conn.commit()
        return dict(r)

    def logout(self, token: str) -> None:
        with self._store() as s:
            s.conn.execute("UPDATE logins SET revoked = ? WHERE hash = ?", (time.time(), _h(token or "")))
            s.conn.commit()

    def sessions_of(self, user_id: int) -> List[dict]:
        with self._store() as s:
            rows = s.conn.execute("SELECT id, created, last_seen, ip, agent FROM logins WHERE user_id = ? "
                                  "AND revoked IS NULL AND last_seen > ? AND created > ? ORDER BY last_seen DESC",
                                  (user_id, time.time() - IDLE_S, time.time() - ABSOLUTE_S)).fetchall()
        return [dict(r) for r in rows]

    def revoke_session(self, login_id: int, user_id: Optional[int] = None) -> bool:
        with self._store() as s:
            q, p = "UPDATE logins SET revoked = ? WHERE id = ? AND revoked IS NULL", [time.time(), login_id]
            if user_id is not None:
                q += " AND user_id = ?"
                p.append(user_id)
            n = s.conn.execute(q, p).rowcount
            s.conn.commit()
        return n > 0

    def revoke_all(self, user_id: int, keep_hash: Optional[str] = None) -> int:
        with self._store() as s:
            n = s.conn.execute("UPDATE logins SET revoked = ? WHERE user_id = ? AND revoked IS NULL AND hash != ?",
                               (time.time(), user_id, keep_hash or "")).rowcount
            s.conn.commit()
        return n

    # ---- 2FA setup
    def totp_begin(self, user_id: int) -> Tuple[str, str]:
        u = self.user(user_id)
        if u["totp_enabled"]:
            raise AuthError("two-factor sign-in is already on")
        secret = new_totp_secret()
        with self._store() as s:
            s.conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
            s.conn.commit()
        return secret, totp_uri(secret, u["username"])

    def totp_enable(self, user_id: int, code: str) -> List[str]:
        u = self.user(user_id)
        if not u["totp_secret"] or u["totp_enabled"]:
            raise AuthError("start the setup first")
        step = check_totp(u["totp_secret"], code, None)
        if step is None:
            raise AuthError("that code is not valid; check the time on your phone")
        codes, hashes = new_recovery_codes()
        with self._store() as s:
            s.conn.execute("UPDATE users SET totp_enabled = 1, totp_last = ?, recovery = ? WHERE id = ?",
                           (step, json.dumps(hashes), user_id))
            s.conn.commit()
        return codes

    def totp_disable(self, user_id: int, password: str) -> None:
        u = self.user(user_id)
        if not verify_password(password or "", u["pw_hash"]):
            raise AuthError("wrong password", 401)
        self.update_user(user_id, reset_totp=True)

    # ---- viewer links (F063)
    def add_viewer_link(self, name: str, hours: float, created_by: str) -> Tuple[int, str]:
        name = (name or "").strip()
        if not name or len(name) > 60:
            raise AuthError("give the link a name (1 to 60 characters)")
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 0 < hours <= 24 * 30:
            raise AuthError("a link can be valid for up to 30 days (720 hours)")
        token = "gv_" + secrets.token_urlsafe(24)
        with self._store() as s:
            cur = s.conn.execute("INSERT INTO viewer_links (name, hash, created, expires, created_by) "
                                 "VALUES (?, ?, ?, ?, ?)", (name, _h(token), time.time(), time.time() + hours * 3600,
                                                            created_by))
            s.conn.commit()
        return cur.lastrowid, token

    def viewer_link(self, token: str) -> Optional[dict]:
        if not token or not token.startswith("gv_") or len(token) > 100:
            return None
        with self._store() as s:
            r = s.conn.execute("SELECT * FROM viewer_links WHERE hash = ? AND revoked IS NULL AND expires > ?",
                               (_h(token), time.time())).fetchone()
        return dict(r) if r else None

    def viewer_links(self) -> List[dict]:
        with self._store() as s:
            return [{k: r[k] for k in r.keys() if k != "hash"}
                    for r in s.conn.execute("SELECT * FROM viewer_links ORDER BY id DESC")]

    def revoke_viewer_link(self, link_id: int) -> bool:
        with self._store() as s:
            n = s.conn.execute("UPDATE viewer_links SET revoked = ? WHERE id = ? AND revoked IS NULL",
                               (time.time(), link_id)).rowcount
            s.conn.execute("UPDATE logins SET revoked = ? WHERE viewer_link = ? AND revoked IS NULL",
                           (time.time(), link_id))
            s.conn.commit()
        return n > 0
