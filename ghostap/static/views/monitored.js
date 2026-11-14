/* Monitored networks page: saved baselines (F014-F019, F034, F035). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice, fmt, rel, label, ssidLabel } = G;
  const CHECKS = ["security_downgrade", "new_bssid_oui", "channel_deviation", "rssi_jump", "tsf_anomaly",
    "ie_fingerprint", "bssid_conflict", "beacon_interval_mismatch", "karma", "lookalike_ssid", "known_tool"];
  let root = null, data = null, showIgnored = false, confirming = null;

  async function load() {
    try {
      data = await get("/api/monitored");
      render();
    } catch (e) {
      root.innerHTML = `<div class="card empty">Could not load monitored networks (${esc(e.message)}).</div>`;
    }
  }

  function spark(points, level) {
    if (!points || points.length < 2) return '<span class="muted">no trend yet</span>';
    const W = 140, H = 32, t0 = points[0][0], t1 = points[points.length - 1][0] || t0 + 1;
    const x = (t) => ((t - t0) / Math.max(1, t1 - t0)) * (W - 4) + 2;
    const y = (v) => H - 3 - (Math.min(100, v || 0) / 100) * (H - 6);
    const d = points.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + " " + y(p[1]).toFixed(1)).join(" ");
    const col = level === "HIGH" ? "var(--critical)" : level === "MEDIUM" ? "var(--serious)" : "var(--accent)";
    const last = points[points.length - 1];
    return `<svg class="spark" viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk trend, latest ${fmt(last[1], 0)}">
      <line x1="0" x2="${W}" y1="${y(30)}" y2="${y(30)}" stroke="var(--grid)" stroke-dasharray="3 3"/>
      <path class="line" d="${d}" stroke="${col}"/><circle cx="${x(last[0])}" cy="${y(last[1])}" r="2.6" fill="${col}"/></svg>`;
  }

  function levelOf(score) {
    const th = (G.state.summary && G.state.summary.thresholds) || { medium: 30, high: 60 };
    return score == null ? null : score >= th.high ? "HIGH" : score >= th.medium ? "MEDIUM" : "LOW";
  }

  function networkCard(n) {
    const b = n.baseline, h = n.health, s = n.settings, lvlNow = levelOf(n.risk_now);
    const heardAll = h.expected.length && !h.missing.length;
    const rows = b.bssids.map((bssid) => {
      const heard = h.heard_now.includes(bssid);
      const rssi = (b.bssid_rssi || {})[bssid];
      return `<tr><td class="mono">${esc(bssid)}</td><td class="mono">${esc(bssid.slice(0, 8))}</td>
        <td class="num">${esc(((b.bssid_channels || {})[bssid] || []).join(", "))}</td>
        <td class="num">${rssi ? fmt(rssi[0], 0) + " dBm" : "–"}</td>
        <td class="num">${((b.bssid_fingerprints || {})[bssid] || []).length}</td>
        <td>${data.capture_end ? (heard ? '<span class="pill-state ok">heard now</span>' : '<span class="pill-state warn">not heard in the last minute</span>') : '<span class="muted">–</span>'}</td>
        <td><button class="btn small" data-remove-ap="${esc(bssid)}" data-ssid="${esc(n.ssid)}" title="Remove from this network's baseline">Remove</button></td></tr>`;
    }).join("");
    const unexpected = h.unexpected.length ? `<div class="unexpected">
        <b>Access points using this name that are not in the baseline</b>
        <ul class="list-plain">${h.unexpected.map((u) => `<li>
          <span><span class="mono">${esc(u.bssid)}</span> · ch ${esc(u.channels)} · ${esc(u.securities)} · ${fmt(u.rssi_avg, 0)} dBm · appeared ${rel(u.first_seen)}</span>
          <span class="row-actions"><button class="btn small" data-inspect-ap="${esc(u.bssid)}" data-ssid="${esc(n.ssid)}">Inspect</button>
          <button class="btn small primary" data-accept="${esc(u.bssid)}" data-ssid="${esc(n.ssid)}" title="It is ours: add it to the baseline so it stops alerting">Accept into baseline</button></span></li>`).join("")}</ul></div>` : "";
    const toggles = CHECKS.map((c) => `<label class="switch"><input type="checkbox" data-check="${c}" ${s.enabled[c] === false ? "" : "checked"}><span>${esc(label(c))}</span></label>`).join("");
    const removing = confirming === n.ssid;
    return `<article class="card net-card" data-net="${esc(n.ssid)}">
      <div class="net-card-head">
        <div><h2>${esc(ssidLabel(n.ssid))}</h2>
          <div class="meta-line"><span>${b.bssids.length} expected AP${b.bssids.length === 1 ? "" : "s"}</span><span>${esc(b.security || "security unknown")}</span>
          <span>channels ${esc(b.channels.join(", ") || "–")}</span><span>${b.fingerprints.length} beacon fingerprint${b.fingerprints.length === 1 ? "" : "s"}</span>
          ${data.capture_end ? `<span>${h.heard_now.length} of ${h.expected.length} heard now</span>` : ""}</div></div>
        <div class="row-actions">
          <div title="Highest current risk among this network's access points">${n.risk_now == null ? '<span class="muted">not scored yet</span>' : G.lvl(lvlNow) + " " + fmt(n.risk_now, 0)}</div>
          ${spark(n.trend, lvlNow)}
          ${heardAll ? '<span class="pill-state ok">all expected APs heard</span>' : h.missing.length ? `<span class="pill-state warn">${h.missing.length} missing</span>` : ""}
        </div>
      </div>
      <div class="table-wrap"><table><thead><tr><th>BSSID</th><th>Vendor prefix</th><th class="num">Channels</th><th class="num">Signal</th><th class="num">Fingerprints</th><th>Status</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="empty">No access points in this baseline.</td></tr>'}</tbody></table></div>
      ${unexpected}
      <details class="settings"><summary>Checks and alert threshold for this network</summary>
        <div class="switch-grid">${toggles}</div>
        <div class="row-actions" style="margin-top:12px">
          <div class="field"><label for="thr-${esc(n.ssid)}">MEDIUM alert threshold (empty = use ${((G.state.summary || {}).thresholds || { medium: 30 }).medium})</label>
            <input class="input" type="number" min="1" max="99" step="1" id="thr-${esc(n.ssid)}" data-threshold value="${s.threshold_medium == null ? "" : s.threshold_medium}"></div>
          <button class="btn primary" data-save-settings="${esc(n.ssid)}">Save checks</button>
        </div>
      </details>
      <div class="row-actions">${removing
        ? `<span class="confirm">Stop protecting “${esc(n.ssid)}” and delete its baseline? <button class="btn danger primary" data-remove-net="${esc(n.ssid)}">Delete baseline</button><button class="btn" data-cancel>Keep it</button></span>`
        : `<button class="btn danger" data-ask-remove="${esc(n.ssid)}">Stop protecting this network</button>`}</div>
    </article>`;
  }

  function render() {
    const nets = data.networks, inbox = data.inbox.filter((i) => showIgnored || i.decision !== "ignored");
    const candidates = data.inbox.filter((i) => i.decision !== "ignored");
    root.innerHTML = `
      <div class="page-head"><div><h1>Monitored networks</h1>
        <p>A saved baseline tells GhostAP what your networks should look like, so it protects them from the first second of a capture and catches a twin that is already running when you start.</p>
        <div class="meta-line"><span class="mono">${esc(data.file)}</span><span>${data.updated_at ? "saved " + new Date(data.updated_at * 1000).toLocaleString() : "nothing saved yet"}</span>
        <span>${data.applies_live ? "changes apply to the running live capture immediately" : "used by live captures; for a replay start GhostAP with --monitored"}</span></div></div></div>

      ${nets.length ? nets.map(networkCard).join("") : '<div class="card empty big-empty"><p><b>No protected networks yet.</b></p><p>Pick your networks below and GhostAP will learn what they normally look like from this session.</p></div>'}

      <section class="card"><div class="card-head"><h2>Protect networks heard in this session</h2></div>
        ${candidates.length ? `<p class="hint">GhostAP learns each network's access points, channels, security, signal and beacon fingerprints. Only do this when you know no evil twin is on the air.</p>
        <div class="switch-grid" id="learn-list">${candidates.map((c) => `<label class="switch"><input type="checkbox" value="${esc(c.ssid)}"><span>${esc(c.ssid)} <span class="muted">· ${c.aps} AP${c.aps === 1 ? "" : "s"} · ${esc(c.securities.join(", "))}</span></span></label>`).join("")}</div>
        <div class="row-actions" style="margin-top:12px">
          <div class="field"><label for="learn-span">Learn from</label><select class="input" id="learn-span"><option value="first">the first ${esc(String(((G.state.summary || {}).baseline_seconds || 120) / 60))} minutes (the learning period)</option><option value="whole">the whole session</option></select></div>
          <button class="btn primary" id="learn-btn">Learn and save</button></div>`
        : '<p class="empty">Every network heard in this session is already protected or ignored.</p>'}
      </section>

      <section class="card"><div class="card-head"><h2>New networks <span class="muted">inbox</span></h2>
        <label class="switch"><input type="checkbox" id="show-ignored" ${showIgnored ? "checked" : ""}><span>Show ignored</span></label></div>
        <p class="hint">Networks heard in this session that are not protected. Approve the ones you recognise, ignore the rest, or protect them.</p>
        ${inbox.length ? `<ul class="list-plain">${inbox.map((i) => `<li><span><b>${esc(ssidLabel(i.ssid))}</b> <span class="muted">${i.aps} AP${i.aps === 1 ? "" : "s"} · ${esc(i.securities.join(", "))}</span>
          ${i.decision ? `<span class="tag">${esc(i.decision)}</span>` : '<span class="tag new">new</span>'}</span>
          <span class="row-actions">${i.decision !== "approved" ? `<button class="btn small" data-decide="approved" data-ssid="${esc(i.ssid)}">Approve</button>` : ""}
          ${i.decision !== "ignored" ? `<button class="btn small" data-decide="ignored" data-ssid="${esc(i.ssid)}">Ignore</button>` : ""}
          ${i.decision ? `<button class="btn small" data-decide="reset" data-ssid="${esc(i.ssid)}">Undo</button>` : ""}
          <button class="btn small primary" data-protect="${esc(i.ssid)}">Protect</button></span></li>`).join("")}</ul>`
        : '<p class="empty">No new networks.</p>'}
      </section>

      <section class="card"><div class="card-head"><h2>Trusted access points <span class="muted">allow-list</span></h2></div>
        <p class="hint">An allow-listed access point that appears later is not treated as new. Cloning one is still detected.</p>
        <ul class="list-plain">${data.allowlist.map((b) => `<li><span class="mono">${esc(b)}</span><button class="btn small" data-unallow="${esc(b)}">Remove</button></li>`).join("") || '<li class="muted">No trusted access points.</li>'}</ul>
        <form class="row-actions" id="allow-form" style="margin-top:10px" novalidate>
          <div class="field"><label for="allow-input">Add a BSSID</label><input class="input mono" id="allow-input" placeholder="a4:2b:b0:11:22:33" autocomplete="off" spellcheck="false"></div>
          <button class="btn" type="submit">Add</button></form>
      </section>`;
  }

  async function act(promise, okText) {
    const r = await promise;
    if (r.ok) { notice(okText, "ok"); await load(); G.refresh(); }
    else notice((r.data && r.data.error) || "Something went wrong (" + r.status + ")", "error");
    return r.ok;
  }

  function onClick(e) {
    const t = e.target.closest("button");
    if (!t || !root.contains(t)) return;
    if (t.id === "learn-btn") {
      const ssids = [...root.querySelectorAll("#learn-list input:checked")].map((i) => i.value);
      if (!ssids.length) { notice("Tick at least one network first.", "error"); return; }
      act(post("/api/monitored/learn", { ssids, whole: root.querySelector("#learn-span").value === "whole" }),
        `Saved the baseline for ${ssids.length} network${ssids.length > 1 ? "s" : ""}.`);
    } else if (t.dataset.protect) {
      act(post("/api/monitored/learn", { ssids: [t.dataset.protect], whole: true }), `Now protecting ${t.dataset.protect}.`);
    } else if (t.dataset.decide) {
      act(post("/api/monitored/inbox", { ssid: t.dataset.ssid, decision: t.dataset.decide }), "Saved.");
    } else if (t.dataset.accept) {
      act(post("/api/monitored/accept", { ssid: t.dataset.ssid, bssid: t.dataset.accept }),
        `${t.dataset.accept} is now part of ${t.dataset.ssid}'s baseline.`);
    } else if (t.dataset.removeAp) {
      act(post("/api/monitored/remove_ap", { ssid: t.dataset.ssid, bssid: t.dataset.removeAp }), "Removed from the baseline.");
    } else if (t.dataset.askRemove) {
      confirming = t.dataset.askRemove; render();
    } else if (t.hasAttribute("data-cancel")) {
      confirming = null; render();
    } else if (t.dataset.removeNet) {
      confirming = null;
      act(post("/api/monitored/remove", { ssid: t.dataset.removeNet, confirm: t.dataset.removeNet }), "Baseline deleted.");
    } else if (t.dataset.saveSettings) {
      const card = t.closest("[data-net]");
      const enabled = {};
      card.querySelectorAll("[data-check]").forEach((i) => { enabled[i.dataset.check] = i.checked; });
      const v = card.querySelector("[data-threshold]").value.trim();
      act(post("/api/monitored/settings", { ssid: card.dataset.net, settings: { enabled, threshold_medium: v === "" ? null : Number(v) } }),
        "Checks saved for " + card.dataset.net + ".");
    } else if (t.dataset.unallow) {
      act(post("/api/allowlist", { remove: t.dataset.unallow }), "Removed from the allow-list.");
    } else if (t.dataset.inspectAp) {
      G.select(t.dataset.ssid, t.dataset.inspectAp);
    }
  }

  G.register("monitored", {
    title: "Protected networks",
    show(el) {
      root = el;
      el.innerHTML = '<div class="card empty">Loading monitored networks…</div>';
      el.onclick = onClick;
      el.onchange = (e) => { if (e.target.id === "show-ignored") { showIgnored = e.target.checked; render(); } };
      el.onsubmit = (e) => {
        if (e.target.id !== "allow-form") return;
        e.preventDefault();
        const v = el.querySelector("#allow-input").value.trim().toLowerCase();
        if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(v)) { notice("Enter an address like a4:2b:b0:11:22:33.", "error"); return; }
        act(post("/api/allowlist", { add: v }), v + " is now trusted.");
      };
      load();
    },
  });
})();
