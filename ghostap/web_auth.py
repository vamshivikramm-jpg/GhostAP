"""Sign-in, accounts, viewer links and signed-in devices (F062-F067). See auth.py."""
from __future__ import annotations

import re
import time
from typing import Optional

from flask import Response, abort, jsonify, redirect, request, send_from_directory

from . import apikeys
from .auth import ABSOLUTE_S, COOKIE, ROLES, Auth, AuthError

# What each role may do. Admin may do everything.
ADMIN_ONLY = (re.compile(r"^/api/users"), re.compile(r"^/api/keys"), re.compile(r"^/api/sessions/[^/]+/delete$"),
              re.compile(r"^/api/demo/"), re.compile(r"^/api/settings(/reset)?$"))
VIEWER_POSTS = ("/api/logout",)
PUBLIC = (re.compile(r"^/static/"), re.compile(r"^/vendor/"), re.compile(r"^/manifest\.webmanifest$"),
          re.compile(r"^/api/login(/state)?$"))


def allowed(role: str, method: str, path: str) -> bool:
    if role == "admin":
        return True
    if any(p.match(path) for p in ADMIN_ONLY):
        return False
    if role == "viewer":
        if path.startswith("/api/viewer_links"):
            return False
        return method in ("GET", "HEAD") or path in VIEWER_POSTS
    return role == "analyst"


def client_ip() -> str:
    return request.remote_addr or ""


class Gate:
    """Decides who a request comes from; installed by web.create_app's guard."""

    def __init__(self, ctx, token: Optional[str], token_ok, token_cookie: str, static_dir: str):
        self.ctx, self.token, self.token_ok = ctx, token, token_ok
        self.token_cookie, self.static = token_cookie, static_dir
        self.auth = Auth(ctx.admin_db)

    def _login_page(self, status=401):
        resp = send_from_directory(self.static, "login.html", max_age=0)
        resp.status_code = status
        return resp

    def _deny(self, msg, status):
        if request.path.startswith("/api/") or request.path == "/metrics":
            return jsonify({"error": msg}), status
        return self._login_page(status)

    def check(self):
        """None to continue, or a response. Sets request.environ['ghostap.principal']."""
        env = request.environ
        auth = request.headers.get("Authorization", "")
        # 1. API keys (F061)
        if auth.startswith("Bearer " + apikeys.PREFIX):
            row = apikeys.check(self.ctx.admin_db, auth[7:].strip())
            if row is None:
                return jsonify({"error": "unknown or revoked API key"}), 401
            env["ghostap.api_key"] = row
            env["ghostap.principal"] = {"kind": "key", "name": "key:" + row["name"],
                                        "role": "analyst" if row["scope"] == "write" else "viewer"}
            if row["scope"] == "read" and request.method not in ("GET", "HEAD"):
                return jsonify({"error": "this API key is read-only"}), 403
            return self._enforce()
        # 2. a read-only viewer link (F063): /?view=gv_...
        if request.path == "/" and request.args.get("view"):
            link = self.auth.viewer_link(request.args["view"])
            if link is None:
                return self._login_page(403)
            tok = self.auth.start_session(None, link["id"], "viewer", client_ip(),
                                          request.headers.get("User-Agent", ""))
            resp = redirect("/", code=303)                       # drop the link's secret from the URL bar
            resp.set_cookie(COOKIE, tok, httponly=True, samesite="Strict", secure=request.is_secure, max_age=ABSOLUTE_S)
            self.ctx.audit_as("viewer:" + link["name"], "viewer_link.used", str(link["id"]), {})
            return resp
        # 3. a signed-in session (accounts or viewer link)
        sess = self.auth.session(request.cookies.get(COOKIE))
        if sess:
            name = sess["username"] if sess["user_id"] is not None else "viewer:" + (sess["link_name"] or "link")
            env["ghostap.principal"] = {"kind": "user" if sess["user_id"] is not None else "viewer",
                                        "name": name, "role": sess["role"], "user_id": sess["user_id"],
                                        "login_id": sess["id"], "totp": bool(sess["totp_enabled"])}
            return self._enforce()
        if any(p.match(request.path) for p in PUBLIC):
            env["ghostap.principal"] = None
            return None
        # 4. the start-up token (exposed mode), also the way in for the person who started GhostAP
        if self.token:
            if request.path == "/" and self.token_ok(request.args.get("token")):
                resp = redirect("/", code=303)
                resp.set_cookie(self.token_cookie, self.token, httponly=True, samesite="Strict",
                                max_age=12 * 3600, secure=request.is_secure)
                return resp
            supplied = auth[7:] if auth.startswith("Bearer ") else request.cookies.get(self.token_cookie)
            if self.token_ok(supplied):
                env["ghostap.principal"] = {"kind": "token", "name": "token", "role": "admin"}
                return self._enforce()
            return self._deny("authentication required", 401)
        # 5. accounts exist: everybody signs in, also on localhost
        if self.auth.accounts_on():
            return self._deny("sign in first", 401)
        # 6. no accounts, bound to localhost: the local user is the admin (the old behaviour)
        env["ghostap.principal"] = {"kind": "local", "name": "local", "role": "admin"}
        return None

    def _enforce(self):
        p = request.environ["ghostap.principal"]
        if not allowed(p["role"], request.method, request.path):
            return self._deny("your role ({}) does not allow this".format(p["role"]), 403)
        return None


def register(app, ctx, gate: Gate) -> None:
    A = gate.auth

    def me():
        return request.environ.get("ghostap.principal")

    def need_user():
        p = me()
        if not p or p.get("user_id") is None:
            abort(Response('{"error": "sign in with an account first"}', 403, mimetype="application/json"))
        return p

    def fail(e: AuthError):
        body = {"error": str(e)}
        body.update(e.extra)
        resp = jsonify(body)
        resp.status_code = e.status
        if e.status == 429:
            resp.headers["Retry-After"] = str(e.extra.get("retry_after", 600))
        return resp

    # ---------------------------------------------------------------- F062 sign-in
    @app.get("/api/login/state")
    def login_state():
        """What the sign-in page should ask for."""
        return jsonify({"accounts": A.accounts_on(), "token": bool(gate.token), "secure": request.is_secure,
                        "signed_in": bool(gate.auth.session(request.cookies.get(COOKIE)))})

    @app.post("/api/login")
    def login():
        body, err = ctx.json_body()
        if err:
            return err
        if body.get("token") is not None:                      # start-up token (exposed mode)
            if not gate.token or not gate.token_ok(str(body["token"]).strip()):
                return jsonify({"error": "that is not the current access token"}), 401
            resp = jsonify({"ok": True, "role": "admin"})
            resp.set_cookie(gate.token_cookie, gate.token, httponly=True, samesite="Strict",
                            max_age=12 * 3600, secure=request.is_secure)
            return resp
        if not A.accounts_on():
            return jsonify({"error": "no accounts exist; create one with: python -m ghostap.users add <name>"}), 400
        try:
            tok, user = A.login(str(body.get("username") or ""), str(body.get("password") or ""),
                                body.get("code"), client_ip(), request.headers.get("User-Agent", ""))
        except AuthError as e:
            if e.status != 401 or not e.extra.get("need_code"):
                ctx.audit_as(str(body.get("username") or "?")[:40], "login.failed", client_ip(), {"why": str(e)})
            return fail(e)
        ctx.audit_as(user["username"], "login", client_ip(), {"two_factor": bool(user["totp_enabled"])})
        resp = jsonify({"ok": True, "user": user["username"], "role": user["role"]})
        resp.set_cookie(COOKIE, tok, httponly=True, samesite="Strict", secure=request.is_secure, max_age=ABSOLUTE_S)
        return resp

    @app.post("/api/logout")
    def logout():
        tok = request.cookies.get(COOKIE)
        if tok:
            A.logout(tok)
        p = me()
        if p:
            ctx.audit("logout", None, {})
        resp = jsonify({"ok": True})
        resp.delete_cookie(COOKIE)
        resp.delete_cookie(gate.token_cookie)
        return resp

    @app.get("/api/me")
    def whoami():
        p = me() or {}
        out = {"name": p.get("name"), "role": p.get("role"), "kind": p.get("kind"),
               "accounts": A.accounts_on(), "two_factor": p.get("totp", False),
               "can": {"write": p.get("role") in ("admin", "analyst"), "admin": p.get("role") == "admin"}}
        return jsonify(out)

    # ---------------------------------------------------------------- F067 my sessions, password, 2FA
    @app.get("/api/me/sessions")
    def my_sessions():
        p = need_user()
        rows = A.sessions_of(p["user_id"])
        for r in rows:
            r["current"] = r["id"] == p["login_id"]
        return jsonify(rows)

    @app.post("/api/me/sessions/<int:login_id>/revoke")
    def my_session_revoke(login_id):
        p = need_user()
        if not A.revoke_session(login_id, p["user_id"]):
            abort(404)
        ctx.audit("login.revoke", str(login_id), {})
        return jsonify({"revoked": login_id})

    @app.post("/api/me/sessions/revoke_others")
    def my_sessions_revoke_others():
        p = need_user()
        from .auth import _h
        n = A.revoke_all(p["user_id"], keep_hash=_h(request.cookies.get(COOKIE) or ""))
        ctx.audit("login.revoke_others", None, {"count": n})
        return jsonify({"revoked": n})

    @app.post("/api/me/password")
    def my_password():
        p = need_user()
        body, err = ctx.json_body()
        if err:
            return err
        from .auth import verify_password
        if not verify_password(str(body.get("current") or ""), A.user(p["user_id"])["pw_hash"]):
            return jsonify({"error": "the current password is wrong"}), 401
        try:
            A.update_user(p["user_id"], password=body.get("new"))
        except AuthError as e:
            return fail(e)
        from .auth import _h
        A.revoke_all(p["user_id"], keep_hash=_h(request.cookies.get(COOKIE) or ""))
        ctx.audit("password.change", p["name"], {})
        return jsonify({"ok": True, "note": "other signed-in devices were signed out"})

    @app.post("/api/me/totp/setup")
    def my_totp_setup():
        p = need_user()
        try:
            secret, uri = A.totp_begin(p["user_id"])
        except AuthError as e:
            return fail(e)
        return jsonify({"secret": secret, "uri": uri})

    @app.post("/api/me/totp/enable")
    def my_totp_enable():
        p = need_user()
        body, err = ctx.json_body()
        if err:
            return err
        try:
            codes = A.totp_enable(p["user_id"], str(body.get("code") or ""))
        except AuthError as e:
            return fail(e)
        ctx.audit("totp.enable", p["name"], {})
        return jsonify({"recovery_codes": codes})

    @app.post("/api/me/totp/disable")
    def my_totp_disable():
        p = need_user()
        body, err = ctx.json_body()
        if err:
            return err
        try:
            A.totp_disable(p["user_id"], str(body.get("password") or ""))
        except AuthError as e:
            return fail(e)
        ctx.audit("totp.disable", p["name"], {})
        return jsonify({"ok": True})

    # ---------------------------------------------------------------- F065 accounts (admin)
    @app.get("/api/users")
    def users_list():
        return jsonify(A.users())

    @app.post("/api/users")
    def users_add():
        body, err = ctx.json_body()
        if err:
            return err
        try:
            uid = A.add_user(str(body.get("username") or ""), str(body.get("password") or ""),
                             str(body.get("role") or "analyst"))
        except AuthError as e:
            return fail(e)
        ctx.audit("user.add", str(body.get("username")), {"role": body.get("role") or "analyst"})
        return jsonify({"id": uid})

    @app.post("/api/users/<int:user_id>")
    def users_update(user_id):
        body, err = ctx.json_body()
        if err:
            return err
        role, disabled = body.get("role"), body.get("disabled")
        if role is not None and role not in ROLES:
            return jsonify({"error": "role must be admin, analyst or viewer"}), 400
        try:
            A.update_user(user_id, role=role, disabled=disabled if isinstance(disabled, bool) else None,
                          reset_totp=bool(body.get("reset_totp")),
                          password=body.get("password") if body.get("password") else None)
        except AuthError as e:
            return fail(e)
        if body.get("password") or body.get("reset_totp"):
            A.revoke_all(user_id)
        ctx.audit("user.update", str(user_id), {k: body[k] for k in ("role", "disabled", "reset_totp") if k in body}
                  | ({"password": "reset"} if body.get("password") else {}))
        return jsonify({"ok": True})

    @app.post("/api/users/<int:user_id>/revoke_sessions")
    def users_revoke_sessions(user_id):
        n = A.revoke_all(user_id)
        ctx.audit("user.revoke_sessions", str(user_id), {"count": n})
        return jsonify({"revoked": n})

    # ---------------------------------------------------------------- F063 viewer links (analyst, admin)
    @app.get("/api/viewer_links")
    def viewer_links():
        return jsonify(A.viewer_links())

    @app.post("/api/viewer_links")
    def viewer_links_add():
        body, err = ctx.json_body()
        if err:
            return err
        try:
            lid, tok = A.add_viewer_link(body.get("name"), body.get("hours", 24), (me() or {}).get("name", "?"))
        except AuthError as e:
            return fail(e)
        ctx.audit("viewer_link.add", str(lid), {"name": body.get("name"), "hours": body.get("hours", 24)})
        return jsonify({"id": lid, "url": request.host_url.rstrip("/") + "/?view=" + tok,
                        "expires": time.time() + float(body.get("hours", 24)) * 3600})

    @app.post("/api/viewer_links/<int:link_id>/revoke")
    def viewer_links_revoke(link_id):
        if not A.revoke_viewer_link(link_id):
            abort(404)
        ctx.audit("viewer_link.revoke", str(link_id), {})
        return jsonify({"revoked": link_id})
