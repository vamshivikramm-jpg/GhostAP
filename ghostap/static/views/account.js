/* Account page: password, two-factor sign-in (F066), signed-in devices (F067), accounts
   and roles (F065, admins), read-only viewer links (F063, analysts and admins). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice } = G;
  let root = null, me = null, fresh = null;      // fresh: secrets shown once (key, codes, link)
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const agent = (a) => {
    a = a || "";
    const b = /Edg\//.test(a) ? "Edge" : /Firefox\//.test(a) ? "Firefox" : /Chrome\//.test(a) ? "Chrome" : /Safari\//.test(a) ? "Safari" : /curl|python/i.test(a) ? "script" : "browser";
    const os = /Android/.test(a) ? "Android" : /iPhone|iPad/.test(a) ? "iOS" : /Mac OS X/.test(a) ? "macOS" : /Windows/.test(a) ? "Windows" : /Linux/.test(a) ? "Linux" : "";
    return b + (os ? " on " + os : "");
  };

  async function load() {
    try { me = await get("/api/me"); } catch (e) { root.innerHTML = `<div class="card empty">${esc(e.message)}</div>`; return; }
    const isUser = me.kind === "user";
    const [sessions, users, links] = await Promise.all([
      isUser ? get("/api/me/sessions").catch(() => []) : [],
      me.can.admin ? get("/api/users").catch(() => []) : [],
      me.can.write ? get("/api/viewer_links").catch(() => []) : [],
    ]);
    const roleNote = { admin: "everything, including accounts and API keys", analyst: "triage, baselines, notes, mutes and viewer links", viewer: "read only" }[me.role] || "";
    root.innerHTML = `<div class="page-head"><div><h1>Account</h1>
        <p>${isUser ? `Signed in as <b>${esc(me.name)}</b>` : me.kind === "viewer" ? `Read-only view (${esc(me.name)})` : me.kind === "token" ? "Signed in with the start-up access link" : "Local access without an account"}
        · role <b>${esc(me.role)}</b> <span class="muted">(${esc(roleNote)})</span></p></div>
        ${me.kind !== "local" ? '<button class="btn" data-logout>Sign out</button>' : ""}</div>
      ${fresh ? `<div class="notice-box">${fresh}</div>` : ""}
      ${!me.accounts ? `<section class="card"><h2>Accounts are off</h2>
        <p>On localhost nobody signs in; on the network the start-up link is the only key. Create the first account (an admin) to give each person their own sign-in, role and two-factor code. After that everyone signs in, also on localhost.</p>
        <p class="muted small">In a terminal: <span class="mono">python -m ghostap.users add &lt;name&gt; --role admin</span>, or below.</p></section>` : ""}
      ${isUser ? `<section class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr)">
        <div class="card"><h2>Password</h2>
          <form class="stack-form" data-form="password" autocomplete="on">
            <input type="text" name="username" autocomplete="username" value="${esc(me.name)}" hidden>
            <label for="pw-cur">Current password</label><input class="input" id="pw-cur" type="password" autocomplete="current-password" required>
            <label for="pw-new">New password (at least 10 characters)</label><input class="input" id="pw-new" type="password" autocomplete="new-password" minlength="10" required>
            <button class="btn" type="submit">Change password</button></form></div>
        <div class="card"><h2>Two-factor sign-in <span class="muted">${me.two_factor ? "on" : "off"}</span></h2>
          ${me.two_factor ? `<p>A 6-digit code from your authenticator app is needed at every sign-in.</p>
            <form class="stack-form" data-form="totp-off"><label for="totp-pw">Password, to turn it off</label>
            <input class="input" id="totp-pw" type="password" autocomplete="current-password" required><button class="btn danger" type="submit">Turn off two-factor sign-in</button></form>`
            : `<p>Adds a code from an authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS…) to your password.</p>
            <div id="totp-setup"><button class="btn primary" data-totp-start>Set it up</button></div>`}</div>
      </section>
      <section class="card"><div class="card-head"><h2>Signed-in devices</h2>
          ${sessions.length > 1 ? '<button class="btn small" data-revoke-others>Sign out everywhere else</button>' : ""}</div>
        <div class="table-wrap"><table><thead><tr><th>Device</th><th>Address</th><th>Signed in</th><th>Last active</th><th></th></tr></thead><tbody>
        ${sessions.map((x) => `<tr><td>${esc(agent(x.agent))}${x.current ? ' <span class="tag">this device</span>' : ""}</td><td class="mono">${esc(x.ip)}</td>
          <td class="num">${when(x.created)}</td><td class="num">${when(x.last_seen)}</td>
          <td>${x.current ? "" : `<button class="btn small" data-revoke-login="${x.id}">Sign out</button>`}</td></tr>`).join("")}</tbody></table></div>
        <p class="muted small">Sessions end after 12 hours without activity and after 7 days at most.</p></section>` : ""}
      ${me.can.admin ? `<section class="card"><div class="card-head"><h2>Accounts</h2></div>
        ${users.length ? `<div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Two-factor</th><th>Last active</th><th></th></tr></thead><tbody>
          ${users.map((u) => `<tr class="${u.disabled ? "dismissed" : ""}" data-user="${u.id}"><td>${esc(u.username)}${u.username === me.name ? ' <span class="tag">you</span>' : ""}</td>
            <td><select class="input small-select" data-user-role aria-label="Role of ${esc(u.username)}">${["admin", "analyst", "viewer"].map((r) => `<option ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}</select></td>
            <td>${u.totp_enabled ? "on" : "off"}</td><td class="num">${when(u.last_seen)}</td>
            <td class="row-actions">${u.totp_enabled ? '<button class="btn small" data-user-act="reset_totp">Reset 2FA</button>' : ""}
              <button class="btn small" data-user-act="signout">Sign out</button>
              <button class="btn small ${u.disabled ? "" : "danger"}" data-user-act="${u.disabled ? "enable" : "disable"}">${u.disabled ? "Enable" : "Disable"}</button></td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No accounts yet.</p>'}
        <form class="key-form" data-form="add-user" autocomplete="off">
          <label class="sr-only" for="nu-name">User name</label><input class="input" id="nu-name" required maxlength="40" placeholder="User name">
          <label class="sr-only" for="nu-role">Role</label><select class="input" id="nu-role">${(users.length ? ["analyst", "viewer", "admin"] : ["admin"]).map((r) => `<option>${r}</option>`).join("")}</select>
          <label class="sr-only" for="nu-pw">First password</label><input class="input" id="nu-pw" type="password" autocomplete="new-password" minlength="10" required placeholder="First password (10+ characters)">
          <button class="btn" type="submit">Add</button></form>
        <p class="muted small">Give the first password to the person privately; they change it under Account. ${users.length ? "" : "Adding the first account turns sign-in on for everyone, including you: sign in with it right after."}</p></section>` : ""}
      ${me.can.write ? `<section class="card"><div class="card-head"><h2>Read-only viewer links</h2></div>
        <p class="hint">A link that opens this dashboard read-only, for a supervisor, an examiner or a screen in the lab. It works until it expires or you revoke it.</p>
        <form class="key-form" data-form="add-link" autocomplete="off">
          <label class="sr-only" for="vl-name">Who it is for</label><input class="input" id="vl-name" required maxlength="60" placeholder="Who it is for, e.g. viva examiner">
          <label class="sr-only" for="vl-hours">Valid for</label><select class="input" id="vl-hours"><option value="2">2 hours</option><option value="24" selected>1 day</option><option value="168">1 week</option><option value="720">30 days</option></select>
          <button class="btn" type="submit">Create link</button></form>
        ${links.length ? `<div class="table-wrap"><table><thead><tr><th>For</th><th>Created by</th><th>Expires</th><th></th></tr></thead><tbody>
          ${links.map((l) => { const dead = l.revoked || l.expires * 1000 < Date.now(); return `<tr class="${dead ? "dismissed" : ""}"><td>${esc(l.name)}</td><td>${esc(l.created_by || "")}</td><td class="num">${l.revoked ? "revoked" : when(l.expires)}</td>
            <td>${dead ? "" : `<button class="btn small danger" data-link-revoke="${l.id}">Revoke</button>`}</td></tr>`; }).join("")}</tbody></table></div>` : ""}</section>` : ""}`;
  }

  async function act(r, ok, after) {
    if (!r.ok) { notice((r.data && r.data.error) || "That did not work (" + r.status + ")", "error"); return false; }
    if (ok) notice(ok, "ok");
    if (after) after(r.data);
    await load();
    return true;
  }

  function onClick(e) {
    if (!root || !root.isConnected) return;
    const t = e.target;
    if (t.closest("[data-logout]")) { post("/api/logout", {}).then(() => location.replace("/")); return; }
    if (t.closest("[data-revoke-others]")) { post("/api/me/sessions/revoke_others", {}).then((r) => act(r, "Signed out everywhere else.")); return; }
    const rl = t.closest("[data-revoke-login]");
    if (rl) { post(`/api/me/sessions/${rl.dataset.revokeLogin}/revoke`, {}).then((r) => act(r, "Signed out that device.")); return; }
    const lr = t.closest("[data-link-revoke]");
    if (lr) { post(`/api/viewer_links/${lr.dataset.linkRevoke}/revoke`, {}).then((r) => act(r, "Link revoked; anyone using it is signed out.")); return; }
    if (t.closest("[data-totp-start]")) {
      post("/api/me/totp/setup", {}).then((r) => {
        if (!r.ok) { notice(r.data.error || "Could not start", "error"); return; }
        const grouped = r.data.secret.replace(/(.{4})/g, "$1 ").trim();
        root.querySelector("#totp-setup").innerHTML = `<ol class="setup-steps">
          <li>In your authenticator app choose <b>add account → enter a setup key</b> and type this key (time-based):<br><code class="mono big-code">${esc(grouped)}</code>
            <details><summary class="muted small">Setup link instead</summary><code class="mono small" style="word-break:break-all">${esc(r.data.uri)}</code></details></li>
          <li>Type the 6-digit code the app shows:</li></ol>
          <form class="key-form" data-form="totp-on"><label class="sr-only" for="totp-code">Code</label>
          <input class="input" id="totp-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required placeholder="123456"><button class="btn primary" type="submit">Turn on</button></form>`;
        root.querySelector("#totp-code").focus();
      });
      return;
    }
    const ua = t.closest("[data-user-act]");
    if (ua) {
      const id = ua.closest("[data-user]").dataset.user, a = ua.dataset.userAct;
      if (a === "disable" && !confirm("Disable this account? The person is signed out at once.")) return;
      const req = a === "signout" ? post(`/api/users/${id}/revoke_sessions`, {}) :
        post(`/api/users/${id}`, a === "reset_totp" ? { reset_totp: true } : { disabled: a === "disable" });
      req.then((r) => act(r, { signout: "Signed out.", reset_totp: "Two-factor reset: they set it up again at next sign-in.", disable: "Account disabled.", enable: "Account enabled." }[a]));
    }
  }

  function onChange(e) {
    if (!root || !root.isConnected || !e.target.matches("[data-user-role]")) return;
    const id = e.target.closest("[data-user]").dataset.user;
    post(`/api/users/${id}`, { role: e.target.value }).then((r) => act(r, "Role changed."));
  }

  function onSubmit(e) {
    if (!root || !root.isConnected) return;
    const f = e.target.dataset.form;
    if (!f) return;
    e.preventDefault();
    const v = (id) => root.querySelector("#" + id).value;
    if (f === "password") post("/api/me/password", { current: v("pw-cur"), new: v("pw-new") }).then((r) => act(r, "Password changed. Other devices were signed out."));
    else if (f === "totp-off") post("/api/me/totp/disable", { password: v("totp-pw") }).then((r) => act(r, "Two-factor sign-in is off."));
    else if (f === "totp-on") post("/api/me/totp/enable", { code: v("totp-code") }).then((r) => act(r, "Two-factor sign-in is on.", (d) => {
      fresh = `<b>Recovery codes.</b> Each works once if you lose your phone. Store them somewhere safe now; they are not shown again.<br><code class="mono">${d.recovery_codes.map(esc).join(" · ")}</code>`;
    }));
    else if (f === "add-user") {
      const first = !me.accounts;
      post("/api/users", { username: v("nu-name"), role: v("nu-role"), password: v("nu-pw") }).then((r) => {
        if (r.ok && first) { notice("Sign-in is on now. Sign in with the new account.", "ok"); setTimeout(() => location.replace("/"), 1200); return; }
        act(r, "Account added.");
      });
    } else if (f === "add-link") post("/api/viewer_links", { name: v("vl-name"), hours: Number(v("vl-hours")) }).then((r) => act(r, null, (d) => {
      fresh = `<b>Viewer link</b> (read-only, until ${esc(new Date(d.expires * 1000).toLocaleString())}). Copy it now; it is not shown again:<br><code class="mono" style="word-break:break-all">${esc(d.url)}</code>`;
    }));
  }

  document.addEventListener("click", onClick);
  document.addEventListener("change", onChange);
  document.addEventListener("submit", onSubmit);
  G.register("account", { title: "Account", show(el) { root = el; fresh = null; load(); }, hide() { root = null; fresh = null; } });
})();
