/* System page: health (F068), capture quality (F042), audit log (F069). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, fmt } = G;
  let root = null, timer = null, auditFilter = "", main = null, integ = null, newKey = null;

  const bytes = (n) => (n == null ? "–" : n < 1e6 ? Math.round(n / 1024) + " KB" : n < 1e9 ? (n / 1e6).toFixed(1) + " MB" : (n / 1e9).toFixed(1) + " GB");
  const secs = (s) => (s == null ? "–" : s < 120 ? Math.round(s) + " s" : s < 7200 ? Math.round(s / 60) + " min" : (s / 3600).toFixed(1) + " h");

  function tile(label, value, sub, warn) {
    return `<div class="tile ${warn ? "tile-high hot" : ""}" role="group" aria-label="${esc(label)}"><span class="tile-label">${esc(label)}</span>
      <span class="tile-value" style="font-size:22px">${esc(value)}</span><span class="tile-sub">${esc(sub || "")}</span></div>`;
  }

  async function load() {
    let h, q, a;
    try {
      [h, q, a] = await Promise.all([get("/api/health"), get("/api/quality"),
        get("/api/audit?limit=100" + (auditFilter ? "&action=" + encodeURIComponent(auditFilter) : ""))]);
    } catch (e) {
      main.innerHTML = `<div class="card empty">Could not load system information (${esc(e.message)}).</div>`;
      return;
    }
    const st = h.status || {};
    const silent = h.last_frame_age_s != null && h.last_frame_age_s > 15;
    const damaged = Object.values(q.damaged_frames || {}).reduce((x, y) => x + y, 0);
    const maxCh = Math.max(1, ...q.channels.map((c) => c.frames));
    const actions = [...new Set(a.map((r) => r.action))].sort();
    main.innerHTML = `<div class="page-head"><div><h1>System</h1>
        <p>Health of this GhostAP server and of the capture, plus a record of every change analysts made.</p>
        <div class="meta-line"><span>GhostAP ${esc(h.version)}</span><span>Python ${esc(h.python)}</span><span>${esc(h.platform)}</span></div></div></div>
      <section class="tiles" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
        ${tile("Server running", secs(h.server_uptime_s), st.mode ? st.mode + " · " + (st.state || "") : "")}
        ${tile("Beacons last minute", Number(h.frames_last_minute).toLocaleString(), h.last_frame_age_s != null ? "last frame " + secs(h.last_frame_age_s) + " ago" : "", silent)}
        ${tile("Scoring round", st.score_seconds != null ? fmt(st.score_seconds * 1000, 0) + " ms" : "–", "work per 2-second round")}
        ${tile("Database", bytes(h.database.bytes), Number(h.database.raw_frames).toLocaleString() + " raw frames")}
        ${tile("Free disk", bytes(h.disk.free_bytes), "of " + bytes(h.disk.total_bytes), h.disk.free_bytes < 1e9)}
        ${tile("Retention", h.retention.raw_hours ? h.retention.raw_hours + " h of raw frames" : "keep everything", (h.retention.pruned_frames || 0).toLocaleString() + " frames pruned")}
        ${tile("Damaged frames skipped", damaged.toLocaleString(), Object.entries(q.damaged_frames || {}).map(([k, v]) => v + " " + k.replace("_", " ")).join(", "))}
        ${tile("Deauth frames", Number(q.deauth_events || 0).toLocaleString(), "deauthentication / disassociation")}
      </section>
      ${silent ? '<div class="banner error" style="white-space:normal">The adapter has been silent for a while. A quiet dashboard may mean “not listening”, not “safe”. Check monitor mode and the antenna.</div>' : ""}
      <section class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr)">
        <div class="card"><div class="card-head"><h2>Channels heard <span class="muted">last minute of capture</span></h2></div>
          ${q.hopping ? `<p class="hint">${esc(q.hopping)}</p>` : ""}
          ${q.channels.length ? `<ul class="list-plain">${q.channels.map((c) => `<li><span class="mono" style="min-width:40px">ch ${esc(c.channel)}</span>
            <span class="riskbar" style="flex:1"><span class="track"><span class="fill" style="width:${(100 * c.frames) / maxCh}%;display:block;background:var(--accent)"></span></span><span class="n">${c.frames}</span></span>
            <span class="muted">${c.aps} AP${c.aps === 1 ? "" : "s"}</span></li>`).join("")}</ul>` : '<p class="empty">No frames in the last minute.</p>'}
        </div>
        <div class="card"><div class="card-head"><h2>Beacons heard per access point</h2></div>
          <p class="hint">Share of each AP's expected beacons that reached GhostAP. Low values mean a weak signal or that hopping spends little time on its channel.</p>
          <div class="table-wrap" style="max-height:320px;overflow:auto"><table><thead><tr><th>Network</th><th>BSSID</th><th class="num">Heard</th></tr></thead>
          <tbody>${q.aps.map((x) => `<tr><td>${esc(G.ssidLabel(x.ssid))}</td><td class="mono">${esc(x.bssid)}</td>
            <td class="num">${x.heard_ratio == null ? "–" : fmt(x.heard_ratio * 100, 0) + "%"}</td></tr>`).join("")}</tbody></table></div>
        </div>
      </section>
      <section class="card"><div class="card-head"><h2>Audit log</h2>
        <select class="input" id="audit-filter" aria-label="Filter by action"><option value="">All actions</option>${actions.concat(auditFilter && !actions.includes(auditFilter) ? [auditFilter] : []).map((x) => `<option ${x === auditFilter ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></div>
        ${a.length ? `<div class="table-wrap"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>What</th><th>Details</th></tr></thead>
          <tbody>${a.map((r) => `<tr><td class="num">${new Date(r.ts * 1000).toLocaleString()}</td><td>${esc(r.actor)}</td><td class="mono">${esc(r.action)}</td>
            <td>${esc(r.target || "")}</td><td class="reason">${esc(Object.entries(r.detail || {}).map(([k, v]) => k + ": " + (typeof v === "object" ? JSON.stringify(v) : v)).join(" · "))}</td></tr>`).join("")}</tbody></table></div>`
          : '<p class="empty">Nothing recorded yet. Triage changes, baseline edits and settings changes appear here.</p>'}
      </section>`;
  }

  // ------------------------------------------------------------------ F013/F055-F061 integrations
  // Rendered separately from the 5-second refresh so forms and a new key stay on screen.
  async function loadIntegrations() {
    let n, keys, cap;
    try { [n, keys, cap] = await Promise.all([get("/api/notifications"), get("/api/keys"), get("/api/capture")]); } catch (e) {
      integ.innerHTML = `<div class="card empty">Could not load integrations (${esc(e.message)}).</div>`;
      return;
    }
    const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
    integ.innerHTML = (cap.live ? `<section class="card"><div class="card-head"><h2>Capture control <span class="muted">${esc(cap.iface || "")}</span></h2>
        <button class="btn small ${cap.paused ? "primary" : ""}" data-cap="${cap.paused ? "resume" : "pause"}">${cap.paused ? "Resume" : "Pause"}</button></div>
        <p>${cap.paused ? `<b>Paused</b> since ${new Date(cap.paused_since * 1000).toLocaleTimeString()} (${cap.dropped_while_paused} frames ignored). Nothing is scored while paused; the timeline shows the gap.` : "Capturing."} ${esc(cap.hopping || "")}</p>
        <form class="key-form" data-hop-form><label class="sr-only" for="hop-ch">Channels</label><input class="input" id="hop-ch" placeholder="1,6,11 · 1-13 · 2.4 · 5 · all · or one channel to park" value="${esc((cap.channels || []).join(","))}">
        <label class="sr-only" for="hop-dw">Seconds per channel</label><input class="input" id="hop-dw" type="number" min="0.05" max="10" step="0.05" value="${cap.dwell || 0.25}">
        <button class="btn" type="submit">Apply</button></form></section>` : "") + `<section class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr)">
      <div class="card"><div class="card-head"><h2>Notifications <span class="muted">${n.enabled ? (n.running ? "on" : "on, no channel running") : "off"}</span></h2>
          ${n.channels.length ? '<button class="btn small" data-notify-test>Send a test message</button>' : ""}</div>
        ${n.enabled ? "" : '<p class="hint">Switched off. Set <span class="mono">notifications.enabled: true</span> and add a webhook, ntfy topic, e-mail or syslog target in config.yaml (examples there). Secrets go in environment variables.</p>'}
        ${n.problems.map((p) => `<div class="banner error">${esc(p)}</div>`).join("")}
        ${n.channels.length ? `<ul class="list-plain">${n.channels.map((c) => `<li><b>${esc(c.name)}</b> <span class="mono">${esc(c.target)}</span> <span class="muted">from ${esc(c.min_level)}</span></li>`).join("")}</ul>
          <p class="muted small">Sends when an alert reaches ${esc(n.rules.min_level)}, when it becomes HIGH, and every ${n.rules.realert_minutes} min while it stays active · at most ${n.rules.max_per_minute} per channel per minute · muted and false-positive alerts are skipped.</p>` : ""}
        ${n.log.length ? `<h3>Recent messages</h3><div class="table-wrap" style="max-height:240px;overflow:auto"><table><thead><tr><th>When</th><th>Channel</th><th>Event</th><th>Access point</th><th>Result</th></tr></thead><tbody>
          ${n.log.map((r) => `<tr><td class="num">${when(r.ts)}</td><td>${esc(r.channel)}</td><td>${esc(r.event)}</td><td>${esc(r.target)}</td><td>${r.ok ? "✓ " : "✗ "}${esc(r.detail)}</td></tr>`).join("")}</tbody></table></div>` : ""}
        <h3>On this computer</h3>
        <p class="hint">Desktop notifications from this browser tab when a new alert appears while the tab is in the background.</p>
        <button class="btn small" data-desktop-notify>${G.desktopNotifyOn() ? "Turn off desktop notifications" : "Turn on desktop notifications"}</button>
      </div>
      <div class="card"><div class="card-head"><h2>API keys <span class="muted">for scripts, Grafana, a SIEM</span></h2>
          <a class="btn small" href="/api/openapi.json" target="_blank" rel="noopener">API description (OpenAPI)</a></div>
        ${newKey ? `<div class="notice-box"><b>New key for ${esc(newKey.name)}.</b> Copy it now; it is not shown again.<br><code class="mono" style="word-break:break-all">${esc(newKey.key)}</code><br><span class="muted">Send it as <span class="mono">Authorization: Bearer &lt;key&gt;</span>. Prometheus/Grafana: scrape <span class="mono">/metrics</span> with it.</span></div>` : ""}
        <form class="key-form" data-key-form autocomplete="off">
          <label class="sr-only" for="key-name">Key name</label><input class="input" id="key-name" maxlength="60" required placeholder="Name, e.g. grafana">
          <label class="sr-only" for="key-scope">Permission</label><select class="input" id="key-scope"><option value="read">read only</option><option value="write">read and change</option></select>
          <button class="btn" type="submit">Create key</button></form>
        ${keys.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Key</th><th>Permission</th><th>Last used</th><th></th></tr></thead><tbody>
          ${keys.map((k) => `<tr class="${k.revoked ? "dismissed" : ""}"><td>${esc(k.name)}</td><td class="mono">${esc(k.prefix)}…</td><td>${esc(k.scope)}</td><td class="num">${when(k.last_used)}</td>
            <td>${k.revoked ? '<span class="muted">revoked</span>' : `<button class="btn small danger" data-key-revoke="${k.id}">Revoke</button>`}</td></tr>`).join("")}</tbody></table></div>` : '<p class="empty">No API keys.</p>'}
      </div></section>`;
  }

  document.addEventListener("click", async (e) => {
    if (!integ || !integ.isConnected) return;
    if (e.target.closest("[data-notify-test]")) {
      const r = await G.post("/api/notifications/test", {});
      if (!r.ok) { G.notice((r.data && r.data.error) || "Could not send", "error"); return; }
      const bad = r.data.results.filter((x) => !x.ok);
      G.notice(bad.length ? "Failed: " + bad.map((x) => x.channel + " (" + x.detail + ")").join(", ") : "Test message sent to " + r.data.results.length + " channel(s).", bad.length ? "error" : "ok");
      loadIntegrations();
      return;
    }
    const cb = e.target.closest("[data-cap]");
    if (cb) {
      const r = await G.post("/api/capture", { action: cb.dataset.cap });
      G.notice(r.ok ? (r.data.paused ? "Capture paused." : "Capture resumed.") : (r.data && r.data.error) || "Failed", r.ok ? "ok" : "error");
      loadIntegrations();
      return;
    }
    if (e.target.closest("[data-desktop-notify]")) { await G.toggleDesktopNotify(); loadIntegrations(); return; }
    const rv = e.target.closest("[data-key-revoke]");
    if (rv) {
      if (!confirm("Revoke this API key? Anything using it stops working immediately.")) return;
      const r = await G.post(`/api/keys/${rv.dataset.keyRevoke}/revoke`, {});
      G.notice(r.ok ? "Key revoked." : "Could not revoke the key", r.ok ? "ok" : "error");
      newKey = null;
      loadIntegrations();
    }
  });
  document.addEventListener("submit", async (e) => {
    if (e.target.matches("[data-hop-form]")) {
      e.preventDefault();
      const r = await G.post("/api/capture", { action: "hop", channels: integ.querySelector("#hop-ch").value, dwell: Number(integ.querySelector("#hop-dw").value) });
      G.notice(r.ok ? r.data.hopping : (r.data && r.data.error) || "Failed", r.ok ? "ok" : "error");
      loadIntegrations();
      return;
    }
    if (!e.target.matches("[data-key-form]")) return;
    e.preventDefault();
    const name = integ.querySelector("#key-name").value, scope = integ.querySelector("#key-scope").value;
    const r = await G.post("/api/keys", { name, scope });
    if (!r.ok) { G.notice((r.data && r.data.error) || "Could not create the key", "error"); return; }
    newKey = { name, key: r.data.key };
    loadIntegrations();
  });

  G.register("system", {
    title: "System",
    show(el) {
      root = el;
      el.innerHTML = '<div id="sys-main" class="view-root"><div class="card empty">Loading system information…</div></div><div id="sys-int" class="view-root"></div>';
      main = el.querySelector("#sys-main");
      integ = el.querySelector("#sys-int");
      loadIntegrations();
      el.onchange = (e) => { if (e.target.id === "audit-filter") { auditFilter = e.target.value; load(); } };
      load();
      clearInterval(timer);
      timer = setInterval(() => { if (!document.hidden) load(); }, 5000);
    },
    hide() { clearInterval(timer); newKey = null; },
  });
})();
