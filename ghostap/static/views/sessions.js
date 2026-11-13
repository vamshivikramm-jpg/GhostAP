/* Sessions page (F040): every replay / live run, kept separately. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice, fmt } = G;
  let root = null, data = null, confirming = null, renaming = null, compare = new Set();

  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const dur = (a, b) => {
    if (!a || !b) return "–";
    const s = Math.max(0, b - a);
    return s < 120 ? Math.round(s) + " s" : s < 7200 ? Math.round(s / 60) + " min" : (s / 3600).toFixed(1) + " h";
  };
  const size = (n) => (n < 1e6 ? Math.round(n / 1024) + " KB" : (n / 1e6).toFixed(1) + " MB");

  async function load() {
    try { data = await get("/api/sessions"); render(); }
    catch (e) { root.innerHTML = `<div class="card empty">Could not load sessions (${esc(e.message)}).</div>`; }
  }

  function row(s) {
    const viewing = G.state.session === s.id || (!G.state.session && s.current);
    const name = renaming === s.id
      ? `<form class="row-actions" data-rename-form="${esc(s.id)}"><input class="input" id="rename-${esc(s.id)}" value="${esc(s.name)}" maxlength="120" aria-label="New name"><button class="btn small primary" type="submit">Save</button><button class="btn small" type="button" data-cancel>Cancel</button></form>`
      : `<b>${esc(s.name)}</b>${s.current ? ' <span class="tag new">running now</span>' : ""}${viewing && !s.current ? ' <span class="tag">viewing</span>' : ""}`;
    const del = confirming === s.id
      ? `<span class="confirm">Delete this session and its data for good? <button class="btn small danger primary" data-delete="${esc(s.id)}">Delete</button><button class="btn small" data-cancel>Keep</button></span>`
      : `<button class="btn small" data-ask-delete="${esc(s.id)}" ${s.current ? "disabled title=\"The running session cannot be deleted\"" : ""}>Delete</button>`;
    return `<tr>
      <td><input type="checkbox" data-compare="${esc(s.id)}" ${compare.has(s.id) ? "checked" : ""} aria-label="Compare ${esc(s.name)}"></td>
      <td>${name}<div class="meta-line"><span>${esc(s.mode || "")}</span><span class="mono">${esc(s.source || "")}</span></div></td>
      <td class="num">${when(s.started_at)}</td>
      <td class="num">${dur(s.capture_start, s.capture_end)}</td>
      <td class="num">${Number(s.frames || 0).toLocaleString()}</td>
      <td class="num">${s.aps || 0}</td>
      <td class="num">${s.alerts_high ? G.lvl("HIGH") + " " + s.alerts_high : ""} ${s.alerts_medium ? G.lvl("MEDIUM") + " " + s.alerts_medium : ""}${!s.alerts_high && !s.alerts_medium ? '<span class="muted">none</span>' : ""}</td>
      <td class="num">${size(s.size_bytes || 0)}${s.has_pcap ? ' <span class="tag" title="Recorded beacons are kept with this session">pcap</span>' : ""}</td>
      <td><span class="row-actions">${viewing ? "" : `<button class="btn small primary" data-open="${esc(s.id)}" data-name="${esc(s.name)}" data-current="${s.current ? 1 : ""}">Open</button>`}
        <button class="btn small" data-rename="${esc(s.id)}">Rename</button>
        <a class="btn small" href="/api/report.html?session=${encodeURIComponent(s.id)}" target="_blank" rel="noopener" title="Printable incident report (save as PDF from the browser)">Report</a>
        <a class="btn small" href="/api/sessions/${encodeURIComponent(s.id)}/bundle.zip" download title="Zip of the database, recording and labels (import with python -m ghostap.sessions import)">Download</a>${del}</span></td></tr>`;
  }

  function compareTable() {
    const picked = data.sessions.filter((s) => compare.has(s.id));
    if (picked.length < 2) return "";
    const rows = [["Frames", (s) => Number(s.frames || 0).toLocaleString()], ["Access points", (s) => s.aps || 0],
      ["HIGH alerts", (s) => s.alerts_high || 0], ["MEDIUM alerts", (s) => s.alerts_medium || 0],
      ["Capture length", (s) => dur(s.capture_start, s.capture_end)], ["Started", (s) => when(s.started_at)]];
    return `<section class="card"><div class="card-head"><h2>Comparison</h2></div><div class="table-wrap"><table>
      <thead><tr><th></th>${picked.map((s) => `<th>${esc(s.name)}</th>`).join("")}</tr></thead>
      <tbody>${rows.map(([n, f]) => `<tr><td class="attr">${n}</td>${picked.map((s) => `<td class="num">${esc(f(s))}</td>`).join("")}</tr>`).join("")}</tbody>
      </table></div></section>`;
  }

  function render() {
    const list = data.sessions;
    root.innerHTML = `<div class="page-head"><div><h1>Sessions</h1>
        <p>Every replay and live capture is kept as its own session, so a new run never erases the last one. Open a session to see its dashboard; tick two or more to compare them.</p></div></div>
      <section class="card">${list.length ? `<div class="table-wrap"><table>
        <thead><tr><th><span class="sr-only">Compare</span></th><th>Session</th><th class="num">Started</th><th class="num">Length</th><th class="num">Beacons</th><th class="num">APs</th><th class="num">Alerts</th><th class="num">Size</th><th></th></tr></thead>
        <tbody>${list.map(row).join("")}</tbody></table></div>`
        : '<div class="empty big-empty"><p><b>No sessions yet.</b></p><p>Start a replay or a live capture: <code>python -m ghostap.web --pcap file.pcap</code></p></div>'}</section>
      ${compareTable()}`;
  }

  async function act(p, ok) {
    const r = await p;
    if (r.ok) { notice(ok, "ok"); await load(); } else notice((r.data && r.data.error) || "Something went wrong", "error");
  }

  G.register("sessions", {
    title: "Sessions",
    show(el) {
      root = el;
      el.innerHTML = '<div class="card empty">Loading sessions…</div>';
      el.onclick = (e) => {
        const t = e.target.closest("button");
        if (!t) return;
        if (t.dataset.open) {
          G.setSession(t.dataset.current ? null : t.dataset.open, t.dataset.name);
          location.hash = "";
        } else if (t.dataset.rename) { renaming = t.dataset.rename; render(); el.querySelector("#rename-" + CSS.escape(renaming)).focus(); }
        else if (t.dataset.askDelete) { confirming = t.dataset.askDelete; render(); }
        else if (t.hasAttribute("data-cancel")) { confirming = renaming = null; render(); }
        else if (t.dataset.delete) {
          const id = t.dataset.delete;
          confirming = null; compare.delete(id);
          if (G.state.session === id) G.setSession(null, null);
          act(post(`/api/sessions/${encodeURIComponent(id)}/delete`, { confirm: id }), "Session deleted.");
        }
      };
      el.onchange = (e) => {
        const id = e.target.dataset.compare;
        if (id) { e.target.checked ? compare.add(id) : compare.delete(id); render(); }
      };
      el.onsubmit = (e) => {
        const id = e.target.dataset.renameForm;
        if (!id) return;
        e.preventDefault();
        const name = el.querySelector("#rename-" + CSS.escape(id)).value.trim();
        renaming = null;
        act(post(`/api/sessions/${encodeURIComponent(id)}/rename`, { name }), "Renamed.");
      };
      load();
    },
  });
})();
