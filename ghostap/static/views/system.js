/* System page: health (F068), capture quality (F042), audit log (F069). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, fmt } = G;
  let root = null, timer = null, auditFilter = "";

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
      root.innerHTML = `<div class="card empty">Could not load system information (${esc(e.message)}).</div>`;
      return;
    }
    const st = h.status || {};
    const silent = h.last_frame_age_s != null && h.last_frame_age_s > 15;
    const damaged = Object.values(q.damaged_frames || {}).reduce((x, y) => x + y, 0);
    const maxCh = Math.max(1, ...q.channels.map((c) => c.frames));
    const actions = [...new Set(a.map((r) => r.action))].sort();
    root.innerHTML = `<div class="page-head"><div><h1>System</h1>
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

  G.register("system", {
    title: "System",
    show(el) {
      root = el;
      el.innerHTML = '<div class="card empty">Loading system information…</div>';
      el.onchange = (e) => { if (e.target.id === "audit-filter") { auditFilter = e.target.value; load(); } };
      load();
      clearInterval(timer);
      timer = setInterval(() => { if (!document.hidden) load(); }, 5000);
    },
    hide() { clearInterval(timer); },
  });
})();
