"""Phase F: sign-in, accounts and roles, two-factor, viewer links, sessions, HTTPS."""
import json
import os
import socket
import ssl
import threading
import time
import urllib.request

import pytest

from ghostap import auth as A
from ghostap import tls, users
from ghostap.config import load_config
from ghostap.web import create_app, serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config.yaml")
PW = "correct horse battery"


@pytest.fixture()
def env(tmp_path):
    db, admin = str(tmp_path / "s.db"), str(tmp_path / "a.db")
    app = create_app(db, load_config(CONFIG), admin_db=admin, config_path=CONFIG,
                     monitored_path=str(tmp_path / "m.json"))
    return app, admin


def _accounts(admin):
    au = A.Auth(admin)
    ids = {n: au.add_user(n, PW, r) for n, r in (("alice", "admin"), ("bob", "analyst"), ("vic", "viewer"))}
    au._count_cache = (0.0, -1)
    return au, ids


def _login(app, name, code=None):
    c = app.test_client()
    body = {"username": name, "password": PW}
    if code:
        body["code"] = code
    r = c.post("/api/login", json=body)
    return c, r


def test_passwords_and_rules():
    h = A.hash_password(PW)
    assert h.startswith("scrypt$") and A.verify_password(PW, h) and not A.verify_password(PW + "x", h)
    assert not A.verify_password(PW, "garbage")
    for bad in ("short", "alice" * 1, None):
        with pytest.raises(A.AuthError):
            A.check_password_rules(bad, "alice")
    with pytest.raises(A.AuthError, match="user name"):
        A.check_password_rules("aliceALICE1", "aliceALICE1")


def test_totp_rfc6238_vectors_and_replay():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"            # "12345678901234567890"
    assert A.totp(secret, 59 // 30) == "287082"          # RFC 6238 appendix B (last 6 digits)
    assert A.totp(secret, 1111111109 // 30) == "081804"
    step = A.check_totp(secret, "287082", None, now=59)
    assert step == 1 and A.check_totp(secret, "287082", step, now=59) is None     # used once only
    assert A.check_totp(secret, A.totp(secret, 2), None, now=59) == 2             # one step of drift
    assert A.check_totp(secret, A.totp(secret, 5), None, now=59) is None
    assert A.check_totp(secret, "12345", None, now=59) is None


def test_open_until_first_account_then_sign_in_everywhere(env):
    app, admin = env
    c = app.test_client()
    assert c.get("/api/summary").status_code == 200
    assert c.get("/api/me").get_json()["kind"] == "local"
    _accounts(admin)
    app.extensions["ghostap"].gate.auth._count_cache = (0.0, -1)     # normally refreshed within 1 s
    assert c.get("/api/summary").status_code == 401
    page = c.get("/")
    assert page.status_code == 401 and b"login.js" in page.data
    assert c.get("/static/app.js").status_code == 200 and c.get("/api/login/state").get_json()["accounts"]
    c, r = _login(app, "alice")
    cookie = r.headers["Set-Cookie"]
    assert r.status_code == 200 and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert c.get("/api/summary").status_code == 200
    assert c.get("/api/audit?action=login").get_json()[0]["actor"] == "alice"


def test_roles(env):
    app, admin = env
    _accounts(admin)
    viewer, _ = _login(app, "vic")
    analyst, _ = _login(app, "bob")
    boss, _ = _login(app, "alice")
    assert viewer.get("/api/summary").status_code == 200
    assert viewer.post("/api/annotations", json={"ts": 1, "text": "x"}).status_code == 403
    assert viewer.get("/api/viewer_links").status_code == 403
    assert viewer.post("/api/logout").status_code == 200
    assert analyst.post("/api/viewer_links", json={"name": "examiner", "hours": 2}).status_code == 200
    assert analyst.get("/api/users").status_code == 403 and analyst.get("/api/keys").status_code == 403
    assert boss.get("/api/users").status_code == 200
    r = boss.post("/api/users", json={"username": "eve", "password": PW, "role": "analyst"})
    assert r.status_code == 200
    me = [u for u in boss.get("/api/users").get_json() if u["username"] == "alice"][0]
    demote = boss.post("/api/users/{}".format(me["id"]), json={"role": "viewer"}).get_json()
    assert demote["error"].startswith("keep at least")


def test_lockout_after_five_failures(env):
    app, admin = env
    _accounts(admin)
    c = app.test_client()
    for _ in range(5):
        assert c.post("/api/login", json={"username": "bob", "password": "wrong-password"}).status_code == 401
    r = c.post("/api/login", json={"username": "bob", "password": PW})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert c.post("/api/login", json={"username": "nobody", "password": PW}).status_code == 429   # same address


def test_two_factor_flow_and_recovery_code(env):
    app, admin = env
    au, ids = _accounts(admin)
    c, _ = _login(app, "bob")
    setup = c.post("/api/me/totp/setup").get_json()
    assert setup["uri"].startswith("otpauth://totp/GhostAP:bob?secret=")
    assert c.post("/api/me/totp/enable", json={"code": "000000"}).status_code == 400
    codes = c.post("/api/me/totp/enable", json={"code": A.totp(setup["secret"], int(time.time() // 30))}).get_json()
    codes = codes["recovery_codes"]
    assert len(codes) == 8
    c2, r = _login(app, "bob")
    assert r.status_code == 401 and r.get_json()["need_code"]
    c2, r = _login(app, "bob", code=codes[0])
    assert r.status_code == 200
    c3, r = _login(app, "bob", code=codes[0])                       # recovery codes work once
    assert r.status_code == 401
    assert c.post("/api/me/totp/disable", json={"password": "nope"}).status_code == 401
    assert c.post("/api/me/totp/disable", json={"password": PW}).status_code == 200


def test_viewer_link_is_read_only_and_revocable(env):
    app, admin = env
    _accounts(admin)
    boss, _ = _login(app, "alice")
    made = boss.post("/api/viewer_links", json={"name": "examiner", "hours": 1}).get_json()
    token = made["url"].split("view=")[1]
    guest = app.test_client()
    r = guest.get("/?view=" + token)
    assert r.status_code == 303 and r.headers["Location"].endswith("/")
    assert guest.get("/api/me").get_json()["role"] == "viewer"
    assert guest.post("/api/alerts/triage_bulk", json={"ids": [1], "status": "confirmed"}).status_code == 403
    assert boss.post("/api/viewer_links/{}/revoke".format(made["id"])).status_code == 200
    assert guest.get("/api/summary").status_code == 401
    assert app.test_client().get("/?view=" + token).status_code == 403
    assert boss.post("/api/viewer_links", json={"name": "x", "hours": 9999}).status_code == 400


def test_sessions_list_revoke_and_idle_timeout(env, monkeypatch):
    app, admin = env
    _accounts(admin)
    a1, _ = _login(app, "bob")
    a2, _ = _login(app, "bob")
    rows = a1.get("/api/me/sessions").get_json()
    assert len(rows) == 2 and sum(r["current"] for r in rows) == 1
    assert a1.post("/api/me/sessions/revoke_others").get_json()["revoked"] == 1
    assert a2.get("/api/summary").status_code == 401 and a1.get("/api/summary").status_code == 200
    assert a1.post("/api/me/password", json={"current": "nope", "new": PW + "!"}).status_code == 401
    assert a1.post("/api/me/password", json={"current": PW, "new": PW + "!"}).status_code == 200
    real = time.time
    monkeypatch.setattr(A.time, "time", lambda: real() + A.IDLE_S + 5)
    assert a1.get("/api/summary").status_code == 401


def test_start_up_token_still_works(tmp_path):
    db = str(tmp_path / "s.db")
    app = create_app(db, load_config(CONFIG), token="tok-123", local_only=False, admin_db=db + ".a")
    c = app.test_client()
    assert c.get("/api/summary").status_code == 401
    assert c.post("/api/login", json={"token": "wrong"}).status_code == 401
    assert c.post("/api/login", json={"token": "tok-123"}).status_code == 200
    assert c.get("/api/summary").status_code == 200
    c2 = app.test_client()
    assert c2.get("/?token=tok-123").status_code == 303 and c2.get("/api/me").get_json()["kind"] == "token"


def test_users_cli(tmp_path, monkeypatch, capsys):
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text("sessions_dir: {}\n".format(tmp_path / "sessions"))
    pw = iter([PW, PW, PW, "different-one"])
    monkeypatch.setattr(users.getpass, "getpass", lambda prompt="": next(pw))
    assert users.main(["--config", str(cfgfile), "add", "carol", "--role", "analyst"]) == 1   # first must be admin
    assert users.main(["--config", str(cfgfile), "add", "carol", "--role", "admin"]) == 0
    assert users.main(["--config", str(cfgfile), "passwd", "carol"]) == 1                       # mismatch
    assert users.main(["--config", str(cfgfile), "list"]) == 0
    assert "carol" in capsys.readouterr().out


def test_https_with_self_signed_certificate(tmp_path, env):
    app, _ = env
    cert, key = tls.self_signed(["127.0.0.1"], directory=str(tmp_path / "tls"))
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"
    assert len(tls.fingerprint(cert).split(":")) == 32
    tls.check_pair(cert, key)
    with pytest.raises(tls.TLSError):
        tls.check_pair(cert, str(tmp_path / "missing.pem"))
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    threading.Thread(target=serve, args=(app, "127.0.0.1", port, (cert, key)), daemon=True).start()
    ctx = ssl.create_default_context(cafile=cert)
    for _ in range(50):
        try:
            url = "https://127.0.0.1:{}/api/login/state".format(port)
            with urllib.request.urlopen(url, context=ctx, timeout=2) as r:
                data = json.load(r)
            break
        except OSError:
            time.sleep(0.1)
    assert data["secure"] is True
