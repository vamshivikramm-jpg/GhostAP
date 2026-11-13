/* What-if page (F031): move the weights and thresholds, see which alerts would change.
   Nothing is saved: the configured weights stay as they are. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, fmt, lvl, label, ssidLabel, post, IND } = G;
  let root = null, cur = null, timer = null, last = null, seq = 0;

  const slider = (group, key, name, val, min, max, step) => `
    <label class="wi-row"><span>${esc(name)}</span>
      <input type="range" min="${min}" max="${max}" step="${step}" value="${val}" data-g="${group}" data-k="${esc(key)}" aria-label="${esc(name)}">
      <output>${fmt(val, step < 1 ? 1 : 0)}</output></label>`;

  function form(c) {
    return `<div class="two wi-grid">
      <div class="card"><h2 class="wi-h">Indicator weights <span class="muted">0 = ignore it</span></h2>
        ${Object.entries(c.weights).map(([k, v]) => slider("weights", k, label(k), v, 0, 10, 0.5)).join("")}</div>
      <div class="card"><h2 class="wi-h">Attack signatures <span class="muted">minimum score when matched</span></h2>
        ${Object.entries(c.signatures).map(([k, v]) => slider("signatures", k, label(k), v, 0, 100, 5)).join("")}
        <h2 class="wi-h" style="margin-top:14px">Alert thresholds</h2>
        ${slider("thresholds", "medium", "MEDIUM from", c.thresholds.medium, 1, 99, 1)}
        ${slider("thresholds", "high", "HIGH from", c.thresholds.high, 2, 100, 1)}
        <div class="row-actions" style="margin-top:10px"><button class="btn" data-reset>Back to configured values</button></div>
      </div></div>`;
  }

  function values() {
    const out = { weights: {}, signatures: {}, thresholds: {} };
    root.querySelectorAll("input[data-g]").forEach((i) => { out[i.dataset.g][i.dataset.k] = Number(i.value); });
    return out;
  }

  const CHANGE = { new_alert: "would alert", no_longer: "would stop alerting", level: "level changes", same: "no change" };

  function renderResult(r) {
    const s = r.summary, el = root.querySelector("#wi-result");
    if (r.error) { el.innerHTML = `<div class="card empty">${esc(r.error)}</div>`; return; }
    const changed = r.rows.filter((x) => x.change !== "same");
    el.innerHTML = `<section class="tiles" style="grid-template-columns:repeat(auto-fill,minmax(170px,1fr))">
        <div class="tile"><span class="tile-label">Alerts</span><span class="tile-value">${s.alerts_now} → ${s.alerts_whatif}</span><span class="tile-sub">configured → what-if</span></div>
        <div class="tile"><span class="tile-label">HIGH alerts</span><span class="tile-value">${s.high_now} → ${s.high_whatif}</span><span class="tile-sub">likely evil twins</span></div>
        <div class="tile ${s.new_alerts ? "tile-med" : ""}"><span class="tile-label">New alerts</span><span class="tile-value">${s.new_alerts}</span><span class="tile-sub">access points that would alert</span></div>
        <div class="tile ${s.no_longer ? "tile-high" : ""}"><span class="tile-label">Missed</span><span class="tile-value">${s.no_longer}</span><span class="tile-sub">alerts that would disappear</span></div>
      </section>
      <div class="card"><div class="card-head"><h2>Access points <span class="muted">${changed.length} changed · re-scored ${r.evaluations.toLocaleString()} steps in ${fmt(r.seconds * 1000, 0)} ms</span></h2>
        <label class="check"><input type="checkbox" id="wi-all" ${root.dataset.all ? "checked" : ""}> Show unchanged</label></div>
        <div class="table-wrap"><table class="ap-table"><thead><tr><th>Network</th><th>BSSID</th><th class="num">Peak now</th><th>Level now</th><th class="num">Peak what-if</th><th>Level what-if</th><th>Change</th></tr></thead><tbody>
        ${(root.dataset.all ? r.rows : changed).map((x) => `<tr data-ssid="${esc(x.ssid)}" data-bssid="${esc(x.bssid)}" tabindex="0" class="${x.change !== "same" ? "wi-" + x.change : ""}">
          <td>${esc(ssidLabel(x.ssid))}</td><td class="mono">${esc(x.bssid)}</td><td class="num">${fmt(x.peak_now, 1)}</td><td>${lvl(x.level_now)}</td>
          <td class="num">${fmt(x.peak_whatif, 1)}</td><td>${lvl(x.level_whatif)}</td><td>${esc(CHANGE[x.change])}</td></tr>`).join("") ||
          '<tr><td colspan="7" class="empty">No access point changes level with these values.</td></tr>'}
        </tbody></table></div></div>`;
  }

  /** POST, waiting while the server prepares the session the first time (202). */
  async function ask(body, my) {
    for (;;) {
      const r = await post("/api/whatif", body);
      if (!root || my !== seq) return null;
      if (r.status !== 202) return r;
      const el = root.querySelector(cur ? "#wi-result" : "#wi-form");
      el.innerHTML = `<div class="card empty"><p><b>Preparing…</b> ${esc(r.data.message)}</p><p class="muted">${fmt(r.data.elapsed_s, 0)} s so far</p></div>`;
      await new Promise((ok) => setTimeout(ok, 2000));
    }
  }

  async function run() {
    const my = ++seq;
    const r = await ask(values(), my);
    if (!r) return;                              // a newer request was sent meanwhile
    last = r.ok ? r.data : { error: (r.data && r.data.error) || "Could not re-score" };
    renderResult(last);
  }

  async function show(el) {
    root = el;
    el.innerHTML = `<div class="page-head"><div><h1>What-if</h1>
        <p>Move a weight or threshold and see which access points in this session would alert. Nothing is saved; the configured values stay in force.</p></div></div>
      <div class="notice-box">Use this to understand the score, not to tune it: choosing weights by looking at results on the data you report makes those results look better than they are. The project keeps its configured threshold for that reason.</div>
      <div id="wi-form"><p class="muted">Loading…</p></div><div id="wi-result"></div>`;
    cur = null;
    const my = ++seq;
    const r = await ask({}, my);
    if (!r) return;
    if (!r.ok) { el.querySelector("#wi-form").innerHTML = `<div class="card empty">${esc((r.data && r.data.error) || "Could not load")}</div>`; return; }
    cur = r.data.configured;
    el.querySelector("#wi-form").innerHTML = form(cur);
    last = r.data;
    renderResult(last);
  }

  function hide() { root = null; clearTimeout(timer); }

  document.addEventListener("input", (e) => {
    if (!root || !e.target.matches("input[data-g]")) return;
    const step = Number(e.target.step);
    e.target.nextElementSibling.textContent = fmt(Number(e.target.value), step < 1 ? 1 : 0);
    clearTimeout(timer);
    timer = setTimeout(run, 250);
  });
  document.addEventListener("change", (e) => {
    if (root && e.target.id === "wi-all") { if (e.target.checked) root.dataset.all = "1"; else delete root.dataset.all; renderResult(last); }
  });
  document.addEventListener("click", (e) => {
    if (!root) return;
    if (e.target.closest("[data-reset]")) { root.querySelector("#wi-form").innerHTML = form(cur); run(); return; }
    const tr = e.target.closest("#wi-result tr[data-bssid]");
    if (tr) G.select(tr.dataset.ssid, tr.dataset.bssid);
  });

  G.register("whatif", { title: "What-if", show, hide });
})();
