/* Sign-in page (F062): accounts (with two-factor codes) or the start-up access token. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  function error(msg) { $("login-error").textContent = msg || ""; show($("login-error"), !!msg); }

  async function post(body) {
    const r = await fetch("/api/login", { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    let data = {};
    try { data = await r.json(); } catch (e) { /* not JSON */ }
    return { ok: r.ok, status: r.status, data };
  }

  async function start() {
    if (/[?&]view=/.test(location.search)) {
      error("This viewer link has expired or was revoked. Ask for a new one.");
    }
    let st;
    try { st = await (await fetch("/api/login/state", { credentials: "same-origin" })).json(); } catch (e) {
      $("login-intro").textContent = "Cannot reach the GhostAP server.";
      return;
    }
    if (st.signed_in && !/[?&]view=/.test(location.search)) { location.replace("/"); return; }
    show($("tls-note"), !st.secure && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname));
    if (st.accounts) {
      $("login-intro").textContent = "Sign in with your GhostAP account.";
      show($("account-form"), true);
      $("username").focus();
    } else if (st.token) {
      $("login-intro").textContent = "This dashboard is reachable from the network, so it needs its access link.";
      show($("token-form"), true);
      $("token").focus();
    } else {
      $("login-intro").textContent = "This dashboard does not need a sign-in.";
      location.replace("/");
    }
  }

  $("account-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    error("");
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    const body = { username: $("username").value, password: $("password").value };
    if (!$("code-row").hidden) body.code = $("code").value;
    const r = await post(body);
    btn.disabled = false;
    if (r.ok) { location.replace("/"); return; }
    if (r.data.need_code) {
      show($("code-row"), true);
      $("code").focus();
      if (body.code) error(r.data.error);
      return;
    }
    error(r.data.error || "Sign-in failed (" + r.status + ")");
    $("password").select();
  });

  $("token-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    error("");
    let v = $("token").value.trim();
    const m = /[?&]token=([^&#\s]+)/.exec(v);
    if (m) v = decodeURIComponent(m[1]);
    const r = await post({ token: v });
    if (r.ok) location.replace("/");
    else error(r.data.error || "That did not work.");
  });

  start();
})();
