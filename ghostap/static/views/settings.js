/* Settings page (F075): edit config.yaml's settings through the validated overlay
   (data/settings.yaml). Admins only. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice } = G;
  let root = null, data = null, dirty = {};

  const show = (v, f) => (f.type === "json" ? JSON.stringify(v) : v === true ? "on" : v === false ? "off" : String(v ?? ""));

  /** Weights and signatures use the same plain names as the rest of the dashboard. */
  const nameOf = (f) => {
    const m = /^(weights|signatures)\.(.+)$/.exec(f.key);
    return m && G.IND[m[2]] ? G.IND[m[2]].label : f.label;
  };
  function input(f, v) {
    const id = "set-" + f.key.replace(/\./g, "-"), cur = f.key in dirty ? dirty[f.key] : v.saved;
    const attrs = `id="${id}" data-key="${esc(f.key)}" aria-describedby="${id}-help"`;
    if (f.type === "bool") return `<label class="switch-row"><input type="checkbox" ${attrs} ${cur ? "checked" : ""}> <span>${esc(nameOf(f))}</span></label>`;
    const ctl = f.type === "select" ? `<select class="input" ${attrs}>${f.choices.map((c) => `<option ${c === cur ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>`
      : f.type === "json" ? `<textarea class="input mono" rows="2" ${attrs}>${esc(JSON.stringify(cur))}</textarea>`
      : `<input class="input" ${attrs} type="${f.type === "number" ? "number" : "text"}" value="${esc(cur ?? "")}" ${f.min != null ? `min="${f.min}"` : ""} ${f.max != null ? `max="${f.max}"` : ""} ${f.step != null ? `step="${f.step}"` : ""}>`;
    return `<label for="${id}">${esc(nameOf(f))}</label>${ctl}`;
  }

  function render() {
    const restart = Object.entries(data.values).filter(([k, v]) => JSON.stringify(v.saved) !== JSON.stringify(v.running) && !findField(k).live).map(([k]) => k);
    root.innerHTML = `<div class="page-head"><div><h1>Settings</h1>
        <p>Saved to <span class="mono">${esc(data.overlay_path)}</span>, on top of <span class="mono">${esc(data.config_path)}</span> (which is never rewritten). Every change is checked with the same rules as config.yaml and recorded in the audit log.</p></div>
        <div class="row-actions"><button class="btn" data-reset>Back to config.yaml</button></div></div>
      ${restart.length ? `<div class="notice-box"><b>Restart GhostAP to use:</b> ${restart.map((k) => `<span class="mono">${esc(k)}</span>`).join(", ")}. Scores in a running session keep the settings they started with, so their timeline stays consistent.</div>` : ""}
      <div class="notice-box">Do not choose weights or thresholds by looking at results on the captures you report: the What-if page shows their effect without changing anything.</div>
      ${data.sections.map((sec) => `<section class="card"><h2>${esc(sec.title)}</h2><div class="settings-grid">
        ${sec.fields.map((f) => { const v = data.values[f.key]; const changed = JSON.stringify(v.saved) !== JSON.stringify(v.file);
          return `<div class="setting ${f.key in dirty ? "dirty" : ""}">${input(f, v)}
            <span class="muted small" id="set-${f.key.replace(/\./g, "-")}-help">${esc(f.help || "")}${changed ? ` ${f.help ? "· " : ""}config.yaml: ${esc(show(v.file, f))}` : ""}${f.live ? " · applies at once" : ""}${JSON.stringify(v.saved) !== JSON.stringify(v.running) && !f.live ? " · running: " + esc(show(v.running, f)) : ""}</span></div>`; }).join("")}
      </div></section>`).join("")}
      <div class="save-bar" ${Object.keys(dirty).length ? "" : "hidden"}><span>${Object.keys(dirty).length} unsaved change(s)</span>
        <button class="btn" data-discard>Discard</button><button class="btn primary" data-save>Save</button></div>`;
  }
  const findField = (k) => data.sections.flatMap((s) => s.fields).find((f) => f.key === k) || {};

  async function load() {
    try { data = await get("/api/settings"); } catch (e) {
      root.innerHTML = `<div class="card empty">${e.status === 403 ? "Only admins can change settings." : esc(e.message)}</div>`;
      return;
    }
    render();
  }

  document.addEventListener("change", (e) => {
    if (!root || !root.isConnected || !e.target.dataset.key) return;
    const f = findField(e.target.dataset.key);
    let v;
    if (f.type === "bool") v = e.target.checked;
    else if (f.type === "number") v = e.target.value === "" ? null : Number(e.target.value);
    else if (f.type === "json") {
      try { v = JSON.parse(e.target.value || "null"); } catch (err) { notice(`${f.label}: not valid JSON`, "error"); return; }
    } else v = e.target.value;
    if (JSON.stringify(v) === JSON.stringify(data.values[f.key].saved)) delete dirty[f.key]; else dirty[f.key] = v;
    const y = window.scrollY;
    render();
    window.scrollTo(0, y);
  });
  document.addEventListener("click", async (e) => {
    if (!root || !root.isConnected) return;
    if (e.target.closest("[data-discard]")) { dirty = {}; render(); return; }
    if (e.target.closest("[data-save]")) {
      const r = await post("/api/settings", { changes: dirty });
      if (!r.ok) { notice((r.data && r.data.error) || "Not saved", "error"); return; }
      dirty = {};
      notice(`Saved. ${r.data.applied_now.length ? "In use now: " + r.data.applied_now.join(", ") + ". " : ""}${r.data.restart_needed.length ? "After a restart: " + r.data.restart_needed.join(", ") + "." : ""}`, "ok");
      load();
      return;
    }
    if (e.target.closest("[data-reset]")) {
      if (!confirm("Remove every change saved here and go back to config.yaml? Takes effect after a restart.")) return;
      const r = await post("/api/settings/reset", { confirm: true });
      notice(r.ok ? "Saved changes removed. Restart GhostAP to run with config.yaml." : (r.data && r.data.error) || "Failed", r.ok ? "ok" : "error");
      dirty = {};
      load();
    }
  });
  G.register("settings", { title: "Settings", show(el) { root = el; dirty = {}; load(); }, hide() { root = null; } });
})();
