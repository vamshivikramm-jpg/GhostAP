/* Labelling page (F046) with suggestions (F088): mark each access point of a lab session as
   legit or evil twin, save the labels next to the session, and copy capture + labels into
   data/lab/ for the evaluation. Suggestions are only suggestions: nothing is labelled until
   you save. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice, rel, lvl, ssidLabel, fmt } = G;
  let root = null, data = null, draft = {};

  const pick = (a) => draft[a.bssid] || (a.label ? { label: a.label.label, attack_start: a.label.attack_start } : null);

  function render() {
    const nTwin = Object.values(draft).filter((d) => d && d.label === "evil_twin").length;
    const undecided = data.aps.filter((a) => !pick(a)).length;
    root.innerHTML = `<div class="page-head"><div><h1>Label this session</h1>
        <p>Say which access points were your lab evil twin and which were real. The labels are saved with the session and used by the evaluation (Phase 2: real captures).</p>
        <div class="meta-line"><span>${data.aps.length} access points</span><span>${data.saved_at ? "labels saved " + new Date(data.saved_at * 1000).toLocaleString() : "not labelled yet"}</span>
        <span>${data.has_pcap ? "recording available" : "no recording (start live capture without --no-record)"}</span></div></div>
        <div class="row-actions"><button class="btn" data-accept-all>Use every suggestion</button></div></div>
      <div class="notice-box">Label what you <b>know</b> from the experiment (which device you switched on, when), not what GhostAP says: labels copied from the detector's own output would make the evaluation meaningless. Suggestions are there to speed things up and to catch typos.</div>
      <section class="card"><div class="table-wrap"><table class="ap-table"><thead><tr><th>Network</th><th>BSSID</th><th>First seen</th><th>GhostAP</th><th>Suggestion</th><th>Your label</th><th>Attack start</th></tr></thead><tbody>
      ${data.aps.map((a) => {
        const p = pick(a), s = a.suggestion;
        return `<tr data-bssid="${esc(a.bssid)}"><td>${esc(ssidLabel(a.ssid))}</td><td class="mono">${esc(a.bssid)}</td>
          <td class="num">${rel(a.first_seen)}${a.in_baseline ? ' <span class="muted">(learning)</span>' : ""}</td>
          <td>${a.level ? lvl(a.level) + " " + fmt(a.score, 0) : '<span class="muted">no alert</span>'}</td>
          <td><span class="tag ${s.label === "evil_twin" ? "triage-confirmed" : ""}">${s.label === "evil_twin" ? "evil twin" : "legit"}</span> <span class="muted small">${esc(s.confidence)} · ${esc(s.why)}</span></td>
          <td><div class="seg" role="group" aria-label="Label for ${esc(a.bssid)}">
            <button class="seg-btn ${p && p.label === "legit" ? "active" : ""}" data-set="legit" aria-pressed="${!!(p && p.label === "legit")}">Legit</button>
            <button class="seg-btn ${p && p.label === "evil_twin" ? "active" : ""}" data-set="evil_twin" aria-pressed="${!!(p && p.label === "evil_twin")}">Evil twin</button></div></td>
          <td>${p && p.label === "evil_twin" ? `<input class="input" size="8" data-start value="${p.attack_start != null ? "t+" + Math.round(p.attack_start - data.capture_start) : ""}" aria-label="Attack start for ${esc(a.bssid)}" placeholder="t+180">` : ""}</td></tr>`;
      }).join("")}</tbody></table></div>
      <div class="row-actions" style="margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label class="check"><input type="checkbox" id="lab-synth"> These are synthetic frames (not a real capture)</label>
        <button class="btn primary" data-save ${undecided ? "disabled" : ""}>Save labels</button>
        <span class="muted">${undecided ? undecided + " access point(s) still need a label" : nTwin + " evil twin(s)"}</span></div></section>
      <section class="card"><h2>Use it in the evaluation</h2>
        <p class="hint">Copies the recording and the labels to <span class="mono">data/lab/&lt;name&gt;.pcap</span> and <span class="mono">.labels.json</span>. Then open the Evaluation page and run “Your labelled lab captures”, or <span class="mono">python evaluate.py --dataset data/lab --out results/lab</span>.</p>
        <form class="key-form" data-export-form><label class="sr-only" for="lab-name">Capture name</label><input class="input" id="lab-name" required maxlength="60" placeholder="run1" pattern="[A-Za-z0-9_-]+">
        <button class="btn" type="submit" ${data.saved_at && data.has_pcap ? "" : "disabled"}>Copy to data/lab</button></form></section>`;
  }

  async function load() {
    try { data = await get("/api/labels"); } catch (e) {
      root.innerHTML = `<div class="card empty">${e.status === 400 ? "Labelling needs sessions: start the dashboard without --db." : esc(e.message)}</div>`;
      return;
    }
    draft = {};
    render();
  }

  function parseStart(v) {
    v = (v || "").trim();
    const m = /^t?\+?(\d+(?:\.\d+)?)\s*s?$/.exec(v);
    return m ? data.capture_start + Number(m[1]) : null;
  }

  document.addEventListener("click", async (e) => {
    if (!root || !root.isConnected || !data) return;
    const b = e.target.closest("[data-set]");
    if (b) {
      const tr = b.closest("tr"), a = data.aps.find((x) => x.bssid === tr.dataset.bssid);
      draft[a.bssid] = { label: b.dataset.set, attack_start: b.dataset.set === "evil_twin" ? (pick(a) && pick(a).attack_start) || a.suggestion.attack_start || a.first_seen : null };
      render();
      return;
    }
    if (e.target.closest("[data-accept-all]")) {
      data.aps.forEach((a) => { draft[a.bssid] = { label: a.suggestion.label, attack_start: a.suggestion.attack_start }; });
      render();
      notice("Suggestions filled in. Check each one against what you did in the lab, then save.", "ok");
      return;
    }
    if (e.target.closest("[data-save]")) {
      const aps = {};
      for (const a of data.aps) {
        const p = pick(a);
        const row = root.querySelector(`tr[data-bssid="${CSS.escape(a.bssid)}"] [data-start]`);
        const start = row ? parseStart(row.value) : null;
        if (p.label === "evil_twin" && start == null) { notice(`Give an attack start (like t+180) for ${a.bssid}.`, "error"); return; }
        aps[a.bssid] = p.label === "evil_twin" ? { label: "evil_twin", attack_start: start } : { label: "legit" };
      }
      const r = await post("/api/labels", { aps, synthetic: root.querySelector("#lab-synth").checked });
      if (r.ok) { notice(`Saved labels for ${r.data.saved} access points.`, "ok"); load(); }
      else notice((r.data && r.data.error) || "Could not save", "error");
    }
  });
  document.addEventListener("change", (e) => {          // keep a typed attack start across re-renders
    if (!root || !root.isConnected || !e.target.matches("[data-start]")) return;
    const bssid = e.target.closest("tr").dataset.bssid, a = data.aps.find((x) => x.bssid === bssid);
    draft[bssid] = { label: "evil_twin", attack_start: parseStart(e.target.value) ?? (pick(a) || {}).attack_start };
  });
  document.addEventListener("submit", async (e) => {
    if (!root || !root.isConnected || !e.target.matches("[data-export-form]")) return;
    e.preventDefault();
    const name = root.querySelector("#lab-name").value;
    let r = await post("/api/labels/export", { name });
    if (r.status === 409 && confirm(r.data.error + "\nReplace it?")) r = await post("/api/labels/export", { name, overwrite: true });
    if (r.ok) notice(`Copied to ${r.data.pcap}. Run the evaluation on “Your labelled lab captures”.`, "ok");
    else notice((r.data && r.data.error) || "Could not copy", "error");
  });

  G.register("label", { title: "Label", show(el) { root = el; load(); }, hide() { root = null; } });
})();
