/* Sensors page (F044, F045): every GhostAP sensor reporting to this one, the access points
   they hear, and a rough position for access points heard by three or more placed sensors. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice, lvl, ssidLabel, fmt } = G;
  let root = null, timer = null, all = false;

  function map(sensors, aps) {
    const placed = sensors.filter((s) => s.x != null);
    const pts = placed.map((s) => [s.x, s.y]).concat(aps.filter((a) => a.location).map((a) => [a.location.x, a.location.y]));
    if (!placed.length) return '<p class="muted">Give at least one sensor a position (metres on your floor plan) to see the map.</p>';
    const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
    const pad = 3, minX = Math.min(...xs) - pad, maxX = Math.max(...xs) + pad, minY = Math.min(...ys) - pad, maxY = Math.max(...ys) + pad;
    const W = 640, H = Math.max(240, Math.min(520, W * (maxY - minY) / Math.max(1, maxX - minX)));
    const sx = (x) => ((x - minX) / Math.max(1, maxX - minX)) * W, sy = (y) => H - ((y - minY) / Math.max(1, maxY - minY)) * H;
    const scale = W / Math.max(1, maxX - minX);
    return `<svg class="sensor-map" viewBox="0 0 ${W} ${H}" role="img" aria-label="Map of sensors and estimated access-point positions">
      ${aps.filter((a) => a.location && a.location.sensors >= 3).map((a) => `<g><title>${esc(ssidLabel(a.ssid))} ${esc(a.bssid)}: ${esc(a.location.method)}, ±${fmt(a.location.radius, 1)} m</title>
        <circle cx="${sx(a.location.x)}" cy="${sy(a.location.y)}" r="${Math.max(6, a.location.radius * scale)}" class="est ${esc(a.level || "LOW")}"></circle>
        <circle cx="${sx(a.location.x)}" cy="${sy(a.location.y)}" r="4" class="dot ${esc(a.level || "LOW")}"></circle>
        <text x="${sx(a.location.x) + 7}" y="${sy(a.location.y) - 7}">${esc(ssidLabel(a.ssid))}</text></g>`).join("")}
      ${placed.map((s) => `<g><rect x="${sx(s.x) - 6}" y="${sy(s.y) - 6}" width="12" height="12" class="sensor ${s.online ? "" : "off"}"></rect>
        <text x="${sx(s.x) + 9}" y="${sy(s.y) + 4}" class="sname">${esc(s.name)}</text></g>`).join("")}
    </svg><p class="muted small">Squares: sensors. Circles: estimated position of access points heard by 3+ placed sensors; the ring is the uncertainty. Rough: walls and bodies change signal strength.</p>`;
  }

  async function load() {
    let d, aps;
    try { [d, aps] = await Promise.all([get("/api/sensors"), get("/api/sensors/aps")]); } catch (e) {
      root.innerHTML = `<div class="card empty">${esc(e.message)}</div>`;
      return;
    }
    const me = d.this_sensor;
    const shown = all ? aps : aps.filter((a) => a.level && a.level !== "LOW" || a.heard_by.length > 1).slice(0, 200);
    const focus = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.pos : null;
    if (focus) return;                                    // do not redraw while typing a position
    root.innerHTML = `<div class="page-head"><div><h1>Sensors</h1>
        <p>GhostAP sensors that report to this dashboard. Each runs its own capture and detection; this page brings their views together.</p>
        <div class="meta-line"><span>model: signal at 1 m ${d.model.p0} dBm, path-loss exponent ${d.model.n}</span>
        ${me.reports_to ? `<span>this GhostAP reports as <b>${esc(me.name)}</b> to ${esc(me.reports_to)}: ${me.last_error ? "⚠ " + esc(me.last_error) : me.last_ok ? "ok " + new Date(me.last_ok * 1000).toLocaleTimeString() : "waiting"}</span>` : ""}</div></div></div>
      ${!d.sensors.length ? `<section class="card"><h2>No sensors yet</h2><p>On each sensor set in config.yaml:</p>
        <pre class="mono small">sensors:\n  name: lab-1\n  report_to: https://this-dashboard:8050\n  report_ca: data/central-cert.pem   # this server's certificate, if self-signed</pre>
        <p>and <span class="mono">export GHOSTAP_REPORT_KEY=gk_…</span> with a <b>read and change</b> API key from System → API keys on this server.</p></section>` : `
      <section class="card"><h2>Sensors</h2><div class="table-wrap"><table><thead><tr><th>Sensor</th><th>Last report</th><th class="num">Beacons / min</th><th class="num">APs</th><th>Open alerts</th><th>Position (m)</th><th></th></tr></thead><tbody>
        ${d.sensors.map((s) => `<tr data-sensor="${esc(s.name)}"><td><i class="dot ${s.online ? "ok" : "error"}"></i> <b>${esc(s.name)}</b> <span class="muted small">${esc(s.address || "")} · ${esc(s.version || "")}</span></td>
          <td class="num">${s.last_seen ? new Date(s.last_seen * 1000).toLocaleString() : "–"}</td><td class="num">${s.status.frames_last_minute ?? "–"}</td><td class="num">${s.aps}</td>
          <td>${(s.status.alerts || []).map((a) => `${lvl(a.level)} ${esc(ssidLabel(a.ssid))}`).join("<br>") || '<span class="muted">none</span>'}</td>
          <td><input class="input pos" size="5" data-pos="x" value="${s.x ?? ""}" aria-label="x of ${esc(s.name)}" placeholder="x"> <input class="input pos" size="5" data-pos="y" value="${s.y ?? ""}" aria-label="y of ${esc(s.name)}" placeholder="y"></td>
          <td><button class="btn small" data-save-pos>Save</button> <button class="btn small danger" data-del-sensor>Remove</button></td></tr>`).join("")}</tbody></table></div></section>
      <section class="card"><h2>Map</h2>${map(d.sensors, aps)}</section>
      <section class="card"><div class="card-head"><h2>Access points across sensors</h2><label class="check"><input type="checkbox" id="sens-all" ${all ? "checked" : ""}> Show all (${aps.length})</label></div>
        <div class="table-wrap"><table><thead><tr><th>Network</th><th>BSSID</th><th>Level</th><th>Heard by (signal)</th><th>Position</th></tr></thead><tbody>
        ${shown.map((a) => `<tr><td>${esc(ssidLabel(a.ssid))}</td><td class="mono">${esc(a.bssid)}</td><td>${lvl(a.level)}</td>
          <td>${a.heard_by.map((h) => `${esc(h.sensor)} ${h.rssi == null ? "–" : fmt(h.rssi, 0) + " dBm"}`).join(", ")}</td>
          <td>${a.location ? `${fmt(a.location.x, 1)}, ${fmt(a.location.y, 1)} ±${fmt(a.location.radius, 1)} m <span class="muted small">${esc(a.location.method)}</span>` : '<span class="muted">–</span>'}</td></tr>`).join("") || '<tr><td colspan="5" class="empty">No alerting or shared access points.</td></tr>'}
        </tbody></table></div></section>`}`;
  }

  document.addEventListener("click", async (e) => {
    if (!root || !root.isConnected) return;
    const tr = e.target.closest("tr[data-sensor]");
    if (!tr) return;
    const name = tr.dataset.sensor;
    if (e.target.closest("[data-save-pos]")) {
      const v = (k) => { const s = tr.querySelector(`[data-pos="${k}"]`).value.trim(); return s === "" ? null : Number(s); };
      const r = await post(`/api/sensors/${encodeURIComponent(name)}/position`, { x: v("x"), y: v("y") });
      notice(r.ok ? `Position of ${name} saved.` : (r.data && r.data.error) || "Not saved", r.ok ? "ok" : "error");
      document.activeElement.blur();
      load();
    } else if (e.target.closest("[data-del-sensor]") && confirm(`Remove ${name}? It reappears if it reports again.`)) {
      const r = await post(`/api/sensors/${encodeURIComponent(name)}/delete`, {});
      notice(r.ok ? "Removed." : "Could not remove (admins only)", r.ok ? "ok" : "error");
      load();
    }
  });
  document.addEventListener("change", (e) => { if (root && root.isConnected && e.target.id === "sens-all") { all = e.target.checked; load(); } });
  G.register("sensors", { title: "Sensors", show(el) { root = el; load(); clearInterval(timer); timer = setInterval(() => { if (!document.hidden) load(); }, 10000); },
    hide() { root = null; clearInterval(timer); } });
})();
