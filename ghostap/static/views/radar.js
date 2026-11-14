/* Live radar: every access point heard in the last minute, around the sensor.
   Distance from the centre = signal strength (stronger = closer). Direction is NOT
   measured: one antenna cannot tell where a signal comes from, so each network name gets
   its own slice of the circle and its access points stay together (a twin lands in the
   slice of the network it copies). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, lvl, ssidLabel, fmt } = G;
  const SIZE = 600, C = SIZE / 2, R_MIN = 26, R_MAX = 262;
  const RSSI_NEAR = -30, RSSI_FAR = -95;
  let root = null, timer = null, paused = false, data = null, selected = null, lastOk = 0;
  const filt = { q: "", band: "all", suspicious: false, min: -95 };
  const dots = new Map();                      // key -> <g>, kept so dots glide between updates

  // stable placement: a network's slice comes from a hash of its name, never from the order seen
  function hash(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  const keyOf = (a) => a.ssid + "|" + a.bssid;
  const radius = (rssi) => {
    if (rssi == null) return R_MAX;
    const f = Math.min(1, Math.max(0, (RSSI_NEAR - rssi) / (RSSI_NEAR - RSSI_FAR)));
    return R_MIN + f * (R_MAX - R_MIN);
  };
  const angle = (a) => ((hash(a.ssid) % 360) + ((hash(a.bssid) % 9) - 4) * 4.5) * Math.PI / 180;
  const pos = (a, rssi) => {
    const r = radius(rssi), t = angle(a);
    return [C + r * Math.cos(t), C + r * Math.sin(t)];
  };
  const metres = (rssi) => (rssi == null || !data ? null : Math.pow(10, (data.model.p0 - rssi) / (10 * data.model.n)));
  const level = (a) => (a.level === "HIGH" || a.level === "MEDIUM" ? a.level : "LOW");
  const size = (a) => 5 + Math.min(4, Math.log2(1 + (a.frames_per_s || 0)) * 1.4);

  function shape(a) {
    const s = size(a), lv = level(a);
    if (lv === "HIGH") return `<path class="mark" d="M0 ${-s * 1.35} L${s * 1.25} ${s * 0.9} L${-s * 1.25} ${s * 0.9} Z"/>`;
    if (lv === "MEDIUM") return `<path class="mark" d="M0 ${-s * 1.3} L${s * 1.3} 0 L0 ${s * 1.3} L${-s * 1.3} 0 Z"/>`;
    return `<circle class="mark" r="${s}"/>`;
  }
  const visible = (a) => (!filt.q || [a.ssid, a.bssid, a.vendor || ""].join(" ").toLowerCase().includes(filt.q))
    && (filt.band === "all" || a.band === filt.band)
    && (!filt.suspicious || level(a) !== "LOW")
    && (a.rssi == null || a.rssi >= filt.min);
  const describe = (a) => `${ssidLabel(a.ssid)}, ${a.bssid}, signal ${a.rssi == null ? "unknown" : fmt(a.rssi, 0) + " dBm"}, ` +
    `channel ${a.channel ?? "?"}, ${level(a) === "LOW" ? "no alert" : level(a)}`;

  function skeleton() {
    const rings = [-45, -60, -75, -90].map((r) => {
      const rr = radius(r);
      return `<circle class="ring" cx="${C}" cy="${C}" r="${rr}"/>
        <text class="ring-label" x="${C + 4}" y="${C - rr + 13}">${r} dBm</text>`;
    }).join("");
    root.innerHTML = `<div class="page-head"><div><h1>Live radar</h1>
        <p>Every access point heard in the last minute, around this sensor. <b>Closer to the centre = stronger signal.</b>
        Direction is not measured (one antenna cannot tell where a signal comes from): each network gets its own slice, so a
        copy of a network lands next to it.</p></div>
        <div class="row-actions"><span class="radar-live" id="radar-live" aria-live="polite"></span>
        <button class="btn small" id="radar-pause" aria-pressed="false">Pause</button></div></div>
      <div class="radar-filters card">
        <label class="sr-only" for="radar-q">Search</label><input class="input" id="radar-q" type="search" placeholder="Search name, address, vendor…">
        <label class="sr-only" for="radar-band">Band</label><select class="input" id="radar-band"><option value="all">2.4 + 5 GHz</option><option value="2.4">2.4 GHz</option><option value="5">5 GHz</option><option value="6">6 GHz</option></select>
        <label class="check"><input type="checkbox" id="radar-susp"> Only suspicious</label>
        <label class="radar-min">Hide weaker than <output id="radar-min-out">−95</output> dBm
          <input type="range" id="radar-min" min="-95" max="-40" step="5" value="-95"></label>
      </div>
      <div class="radar-grid">
        <div class="card radar-card">
          <div class="radar-wrap">
            <svg class="radar" id="radar-svg" viewBox="0 0 ${SIZE} ${SIZE}" role="group" aria-label="Radar of access points; use Tab to move between them">
              <defs><radialGradient id="radar-bg"><stop offset="0%" class="bg-in"/><stop offset="100%" class="bg-out"/></radialGradient>
                <linearGradient id="sweep-grad" x1="0" x2="1"><stop offset="0%" class="sw0"/><stop offset="100%" class="sw1"/></linearGradient></defs>
              <circle cx="${C}" cy="${C}" r="${R_MAX + 8}" fill="url(#radar-bg)" class="plate"/>
              ${rings}
              <line class="axis" x1="${C - R_MAX}" y1="${C}" x2="${C + R_MAX}" y2="${C}"/><line class="axis" x1="${C}" y1="${C - R_MAX}" x2="${C}" y2="${C + R_MAX}"/>
              <g class="sweep" style="transform-origin:${C}px ${C}px"><path d="M${C} ${C} L${C + R_MAX} ${C} A${R_MAX} ${R_MAX} 0 0 0 ${C + R_MAX * Math.cos(-0.5)} ${C + R_MAX * Math.sin(-0.5)} Z" fill="url(#sweep-grad)"/></g>
              <g id="radar-dots"></g>
              <g class="me"><circle cx="${C}" cy="${C}" r="7"/><text x="${C}" y="${C + 22}" text-anchor="middle">you</text></g>
            </svg>
            <div class="radar-tip" id="radar-tip" hidden></div>
          </div>
          <ul class="radar-legend">
            <li><svg viewBox="-8 -8 16 16"><circle class="mark lv-LOW" r="5"/></svg> no alert</li>
            <li><svg viewBox="-8 -8 16 16"><path class="mark lv-MEDIUM" d="M0 -6.5 L6.5 0 L0 6.5 L-6.5 0 Z"/></svg> MEDIUM</li>
            <li><svg viewBox="-8 -8 16 16"><path class="mark lv-HIGH" d="M0 -7 L6.5 4.5 L-6.5 4.5 Z"/></svg> HIGH</li>
            <li><span class="pulse-dot"></span> appeared this minute</li>
            <li class="muted">bigger = heard more often · faded = not heard for 15 s · line = signal over the last minute</li>
          </ul>
        </div>
        <aside class="card radar-side" id="radar-side"><p class="muted">Click or tab to an access point to see it here.</p></aside>
      </div>
      <section class="card"><div class="card-head"><h2>Heard in the last minute <span class="muted" id="radar-count"></span></h2></div>
        <div class="table-wrap"><table class="ap-table radar-table"><thead><tr><th>Network</th><th>BSSID</th><th class="num">Signal</th><th class="num">CH</th><th>Risk</th></tr></thead>
        <tbody id="radar-rows"></tbody></table></div></section>`;
    dots.clear();
    root.querySelector("#radar-pause").addEventListener("click", togglePause);
  }

  function update() {
    if (!root || !data) return;
    const layer = root.querySelector("#radar-dots");
    const shown = data.aps.filter(visible);
    const keep = new Set();
    // suspicious on top, then stronger signals
    shown.sort((a, b) => (level(a) !== "LOW") - (level(b) !== "LOW") || (a.rssi ?? -99) - (b.rssi ?? -99));
    shown.forEach((a) => {
      const k = keyOf(a);
      keep.add(k);
      let g = dots.get(k);
      const [x, y] = pos(a, a.rssi);
      const fresh = !g;
      if (fresh) {
        g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("tabindex", "0");
        g.setAttribute("role", "button");
        g.dataset.key = k;
        dots.set(k, g);
      }
      const old = a.trail.length > 1 ? pos(a, a.trail[0][1]) : [x, y];
      g.setAttribute("class", `rdot lv-${level(a)} ${a.new ? "is-new" : ""} ${a.silent_s > 15 ? "silent" : ""} ` +
        `${selected && selected.split("|")[0] === a.ssid ? "same-net" : ""} ${selected === k ? "is-sel" : ""} ${selected && selected.split("|")[0] !== a.ssid ? "dim" : ""}`);
      g.setAttribute("aria-label", describe(a));
      g.innerHTML = `<line class="trail" x1="${old[0] - x}" y1="${old[1] - y}" x2="0" y2="0"/>${a.new ? '<circle class="pulse" r="10"/>' : ""}${shape(a)}` +
        (level(a) !== "LOW" || selected === k ? `<text class="dot-label" x="${size(a) + 6}" y="4">${esc(ssidLabel(a.ssid))}</text>` : "");
      if (fresh) {
        g.style.transform = `translate(${x}px, ${y}px)`;
        layer.appendChild(g);
      } else {
        requestAnimationFrame(() => { g.style.transform = `translate(${x}px, ${y}px)`; });
      }
      layer.appendChild(g);                         // keeps the paint order (suspicious last = on top)
    });
    for (const [k, g] of dots) if (!keep.has(k)) { g.remove(); dots.delete(k); }
    root.querySelector("#radar-count").textContent = `${shown.length} of ${data.aps.length}`;
    root.querySelector("#radar-rows").innerHTML = data.aps.slice().sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999)).filter(visible).map((a) =>
      `<tr data-key="${esc(keyOf(a))}" tabindex="0" class="${selected === keyOf(a) ? "selected" : ""}"><td>${esc(ssidLabel(a.ssid))}${a.new ? ' <span class="tag new">new</span>' : ""}</td>
        <td class="mono">${esc(a.bssid)}<span class="vendor">${esc(a.vendor || "")}</span></td><td class="num">${a.rssi == null ? "–" : fmt(a.rssi, 0) + " dBm"}</td>
        <td class="num">${esc(a.channel ?? "–")}</td><td>${level(a) === "LOW" ? '<span class="muted">–</span>' : lvl(level(a))}</td></tr>`).join("") ||
      '<tr><td colspan="5" class="empty">Nothing heard in the last minute matches these filters.</td></tr>';
    side();
  }

  function side() {
    const el = root.querySelector("#radar-side");
    const a = selected && data ? data.aps.find((x) => keyOf(x) === selected) : null;
    if (!a) { el.innerHTML = '<p class="muted">Click or tab to an access point to see it here.</p>'; return; }
    const same = data.aps.filter((x) => x.ssid === a.ssid && x.bssid !== a.bssid);
    const m = metres(a.rssi);
    el.innerHTML = `<h2>${esc(ssidLabel(a.ssid))}</h2><p class="mono">${esc(a.bssid)}</p>
      <dl class="radar-facts">
        <dt>Risk</dt><dd>${level(a) === "LOW" ? "no alert" : lvl(level(a))}${a.score != null ? ` <span class="muted">score ${fmt(a.score, 0)}</span>` : ""}</dd>
        <dt>Signal</dt><dd>${a.rssi == null ? "–" : fmt(a.rssi, 0) + " dBm"}${m ? ` <span class="muted">≈ ${m < 10 ? fmt(m, 1) : fmt(m, 0)} m (rough guess)</span>` : ""}</dd>
        <dt>Channel</dt><dd>${esc(a.channel ?? "–")} <span class="muted">${esc(a.band)} GHz</span></dd>
        <dt>Security</dt><dd>${esc(a.security || "–")}</dd>
        <dt>Vendor</dt><dd>${esc(a.vendor || "unknown")}</dd>
        <dt>Status</dt><dd>${a.known ? "known (present while learning)" : "appeared later"}${a.silent_s > 15 ? ` · silent for ${fmt(a.silent_s, 0)} s` : ""}</dd>
      </dl>
      ${same.length ? `<p class="muted small">Same network name, also heard now:</p><ul class="list-plain">${same.map((x) => `<li><button class="linkish" data-pick="${esc(keyOf(x))}">${esc(x.bssid)}</button> ${x.rssi == null ? "" : fmt(x.rssi, 0) + " dBm"} ${level(x) === "LOW" ? "" : lvl(level(x))}</li>`).join("")}</ul>` : ""}
      <button class="btn primary" data-open>Open full details</button>`;
  }

  function tip(e, a) {
    const t = root.querySelector("#radar-tip");
    if (!a) { t.hidden = true; return; }
    const box = root.querySelector(".radar-wrap").getBoundingClientRect();
    t.innerHTML = `<b>${esc(ssidLabel(a.ssid))}</b><span class="mono">${esc(a.bssid)}</span>
      <span>${a.rssi == null ? "–" : fmt(a.rssi, 0) + " dBm"} · ch ${esc(a.channel ?? "?")} · ${esc(a.security || "?")}</span>
      <span>${level(a) === "LOW" ? "no alert" : level(a) + (a.score != null ? " · score " + fmt(a.score, 0) : "")}</span>`;
    t.hidden = false;
    const x = Math.min(box.width - 220, Math.max(0, e.clientX - box.left + 14)), y = Math.max(0, e.clientY - box.top + 14);
    t.style.left = x + "px";
    t.style.top = y + "px";
  }

  function pick(k) {
    selected = selected === k ? null : k;
    update();
  }

  async function poll() {
    clearTimeout(timer);
    if (!root) return;
    if (!paused && !document.hidden) {
      try {
        data = await get("/api/live?seconds=60");
        lastOk = Date.now();
        update();
      } catch (e) { /* keep the last picture; the status line says it is stale */ }
    }
    status();
    timer = setTimeout(poll, 2000);
  }

  function status() {
    const el = root && root.querySelector("#radar-live");
    if (!el) return;
    const st = (G.state.summary && G.state.summary.status) || {};
    const live = st.state === "running";
    const age = lastOk ? Math.round((Date.now() - lastOk) / 1000) : null;
    el.innerHTML = paused ? '<i class="dot"></i> paused'
      : age != null && age > 10 ? `<i class="dot error"></i> no update for ${age} s`
      : live ? '<i class="dot running"></i> live'
      : '<i class="dot"></i> capture finished: showing its last minute';
    root.querySelector(".radar").classList.toggle("is-live", live && !paused);
  }

  function togglePause() {
    paused = !paused;
    const b = root.querySelector("#radar-pause");
    b.textContent = paused ? "Resume" : "Pause";
    b.setAttribute("aria-pressed", paused);
    poll();
  }

  // ---- events (one set of listeners; they only act while the page is shown)
  document.addEventListener("mousemove", (e) => {
    if (!root || !root.isConnected || !data) return;
    const g = e.target.closest && e.target.closest(".rdot");
    tip(e, g ? data.aps.find((a) => keyOf(a) === g.dataset.key) : null);
  });
  document.addEventListener("click", (e) => {
    if (!root || !root.isConnected) return;
    const g = e.target.closest(".rdot, .radar-table tr[data-key], [data-pick]");
    if (g) { pick(g.dataset.key || g.dataset.pick); return; }
    if (e.target.closest("[data-open]") && selected) {
      const [ssid, ...rest] = selected.split("|");
      G.select(ssid, rest.join("|"));
    }
  });
  document.addEventListener("keydown", (e) => {
    if (!root || !root.isConnected || (e.key !== "Enter" && e.key !== " ")) return;
    const g = e.target.closest && e.target.closest(".rdot, .radar-table tr[data-key]");
    if (g) { e.preventDefault(); pick(g.dataset.key); }
  });
  document.addEventListener("input", (e) => {
    if (!root || !root.isConnected) return;
    if (e.target.id === "radar-q") filt.q = e.target.value.trim().toLowerCase();
    else if (e.target.id === "radar-min") { filt.min = Number(e.target.value); root.querySelector("#radar-min-out").textContent = filt.min === -95 ? "−95" : String(filt.min).replace("-", "−"); }
    else return;
    update();
  });
  document.addEventListener("change", (e) => {
    if (!root || !root.isConnected) return;
    if (e.target.id === "radar-band") filt.band = e.target.value;
    else if (e.target.id === "radar-susp") filt.suspicious = e.target.checked;
    else return;
    update();
  });
  document.addEventListener("visibilitychange", () => { if (root && !document.hidden) poll(); });

  G.register("radar", {
    title: "Live radar",
    show(el) { root = el; data = null; selected = null; skeleton(); poll(); },
    hide() { root = null; clearTimeout(timer); dots.clear(); },
  });
})();
