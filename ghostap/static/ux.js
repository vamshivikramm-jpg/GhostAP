/* Dashboard helpers: shareable links (F083), command palette (F078), guided tour (F076)
   and glossary tooltips (F077). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, notice, ssidLabel } = G;
  const $ = (id) => document.getElementById(id);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
  };

  // ------------------------------------------------------------------ F083 copy a link to this view
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {                                   // not a secure context (http on the LAN): old way
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.className = "sr-only";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
      ta.remove();
      return ok;
    }
  }
  async function copyLink() {
    const link = G.viewLink();
    if (await copyText(link)) notice("Link copied. It opens this access point, tab, filters and time range" + (G.state.session ? " in this session" : "") + ". Viewers still need access to this dashboard.", "ok");
    else notice("Copy this link: " + link, "info");
  }

  // ------------------------------------------------------------------ F077 glossary tooltips
  const TERMS = {
    ssid: ["SSID", "The network name people see in their Wi-Fi list. Anyone can broadcast any name, which is why a name alone proves nothing."],
    bssid: ["BSSID", "The radio address of one access point (like a MAC address). One network (SSID) can have many access points, each with its own BSSID."],
    oui: ["Vendor prefix (OUI)", "The first half of a BSSID, assigned to the manufacturer. Easy to fake, so it is a clue, not proof."],
    beacon: ["Beacon", "The short announcement every access point broadcasts about ten times a second: its name, address, channel, security and capabilities. GhostAP only listens to these."],
    channel: ["Channel", "The radio frequency an access point uses. A network normally stays on the channels it was seen on."],
    signal: ["Signal (dBm)", "Received signal strength in dBm; closer to 0 is stronger (−40 is strong, −85 is weak). An attacker near you is often unusually strong."],
    uptime: ["Uptime (TSF)", "Each beacon carries a microsecond clock that starts at zero when the access point boots. A real access point has usually run for hours or days."],
    security: ["Security", "What the network asks of devices: OPN (open, no password), WPA2/PSK or WPA3/SAE (password), or 802.1X (enterprise login). A twin is often open."],
    baseline: ["Learning period (baseline)", "The first minutes of a capture, when GhostAP records what each network normally looks like. A twin already present then is learned as normal."],
    fingerprint: ["Beacon fingerprint", "A short hash of how a beacon is built (order of fields, supported rates, capabilities, vendor extras). It depends on the hardware and software, not the network name."],
    risk: ["Risk score", "0 to 100: the weighted share of the eight indicators that fired, averaged over the last 30 seconds. MEDIUM from the MEDIUM threshold, HIGH from the HIGH threshold."],
    tu: ["TU (time unit)", "1.024 milliseconds. Access points usually send a beacon every 100 TU."],
    twin: ["Evil twin", "A fake access point that copies a real network's name so that devices connect to it instead."],
    nameonly: ["Name-only check", "The simple comparison method: it flags every access point whose network name is used by more than one access point. Big networks trigger it all the time."],
  };
  let tip = null, tipFor = null;
  function showTip(el) {
    const t = TERMS[el.dataset.term];
    if (!t) return;
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "term-tip";
      tip.className = "term-tip";
      tip.setAttribute("role", "tooltip");
      document.body.appendChild(tip);
    }
    tip.innerHTML = `<b>${esc(t[0])}</b><span>${esc(t[1])}</span>`;
    tip.hidden = false;
    tipFor = el;
    el.setAttribute("aria-describedby", "term-tip");
    const r = el.getBoundingClientRect(), w = Math.min(320, window.innerWidth - 24);
    tip.style.width = w + "px";
    const left = Math.max(12, Math.min(window.innerWidth - w - 12, r.left + r.width / 2 - w / 2));
    const below = r.bottom + 8 + tip.offsetHeight < window.innerHeight;
    tip.style.left = left + window.scrollX + "px";
    tip.style.top = (below ? r.bottom + 8 : r.top - tip.offsetHeight - 8) + window.scrollY + "px";
  }
  function hideTip() {
    if (tip) tip.hidden = true;
    if (tipFor) tipFor.removeAttribute("aria-describedby");
    tipFor = null;
  }
  document.addEventListener("mouseover", (e) => { const t = e.target.closest("[data-term]"); if (t) showTip(t); else if (tipFor && !e.target.closest("#term-tip")) hideTip(); });
  document.addEventListener("focusin", (e) => { const t = e.target.closest("[data-term]"); if (t) showTip(t); else hideTip(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideTip(); });
  window.addEventListener("scroll", hideTip, { passive: true });
  /** Static labels that get a definition on hover / focus. */
  function markTerms() {
    const marks = [
      ['.ap-table th[data-sort="ssid"]', "ssid"], ['.ap-table th[data-sort="bssid"]', "bssid"],
      ['.ap-table th[data-sort="channels"]', "channel"], ['.ap-table th[data-sort="securities"]', "security"],
      ['.ap-table th[data-sort="rssi_avg"]', "signal"], ['.ap-table th[data-sort="frames"]', "beacon"],
      ['.ap-table th[data-sort="score"]', "risk"], ['.ap-table th[data-sort="peak_score"]', "risk"],
      ['.tile[data-go="networks"] .tile-label', "ssid"], ['.tile[data-go="table"] .tile-label', "bssid"],
      ['.tile[data-go="baseline"] .tile-label', "nameonly"], ["#timeline-card h2", "risk"],
    ];
    marks.forEach(([sel, term]) => document.querySelectorAll(sel).forEach((el) => {
      if (el.querySelector("[data-term]") || el.dataset.term) return;
      const span = document.createElement("span");
      span.className = "term";
      span.dataset.term = term;
      span.tabIndex = 0;
      while (el.firstChild && !(el.firstChild.nodeType === 1 && el.firstChild.classList.contains("muted"))) span.appendChild(el.firstChild);
      el.insertBefore(span, el.firstChild);
    }));
  }
  /** Dynamic content (comparison table) is marked after each render. */
  const ROW_TERMS = { "Vendor (first half of address)": "oui", Channel: "channel", Security: "security", Signal: "signal",
    "Uptime when this AP appeared": "uptime", "Beacon fingerprint": "fingerprint", "Beacon interval": "tu", "First seen": "baseline" };
  new MutationObserver(() => {
    document.querySelectorAll("#detail table th:first-child, #detail table td:first-child").forEach((c) => {
      const term = ROW_TERMS[c.textContent.trim()];
      if (term && !c.dataset.term) { c.dataset.term = term; c.tabIndex = 0; c.classList.add("term"); }
    });
  }).observe($("detail"), { childList: true, subtree: true });

  // ------------------------------------------------------------------ F076 guided tour
  const TOUR = [
    ["#verdict", "The verdict", "One sentence on what GhostAP thinks right now. It turns red when an evil twin is likely."],
    [".tiles", "The numbers", "Networks and access points heard, alerts by level, and how many alarms the simple name-only check would have raised."],
    [".card.side", "Alerts and networks", "Suspicious access points, highest risk first. Filter them, tick several to triage them together, or switch to the network view."],
    ["#detail", "Why it was flagged", "Pick an access point to see what differs from the real network, which checks fired, its risk over time, and the evidence you can download."],
    ["#timeline-card", "Risk over time", "Every access point's score. Dashed lines are the MEDIUM and HIGH thresholds. Add notes to mark what you did during an experiment."],
    ["#table-card", "Every access point", "Search, sort, choose columns and export to a spreadsheet."],
    ["#nav", "More pages", "Monitored networks (saved baselines), past sessions, system health and the what-if page."],
    [".top-actions", "Tools", "Presentation mode, layout, clock time and theme. Press Ctrl+K (⌘K on a Mac) for every command."],
  ];
  let tourAt = -1, spot = null, card = null, lastFocus = null;
  function tourStep(i) {
    const steps = TOUR.filter(([sel]) => { const el = document.querySelector(sel); return el && el.offsetParent !== null; });
    if (i < 0 || i >= steps.length) { endTour(); return; }
    tourAt = i;
    const [sel, title, text] = steps[i];
    const el = document.querySelector(sel);
    el.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    if (!spot) {
      spot = document.createElement("div"); spot.className = "tour-spot"; document.body.appendChild(spot);
      card = document.createElement("div"); card.className = "tour-card"; card.setAttribute("role", "dialog");
      card.setAttribute("aria-modal", "false"); card.setAttribute("aria-labelledby", "tour-title");
      document.body.appendChild(card);
    }
    setTimeout(() => {
      const r = el.getBoundingClientRect();
      Object.assign(spot.style, { left: r.left - 6 + window.scrollX + "px", top: r.top - 6 + window.scrollY + "px", width: r.width + 12 + "px", height: r.height + 12 + "px" });
      card.innerHTML = `<p class="muted">Step ${i + 1} of ${steps.length}</p><h3 id="tour-title">${esc(title)}</h3><p>${esc(text)}</p>
        <div class="row-actions"><button class="btn" data-tour="skip">End tour</button>
        ${i ? '<button class="btn" data-tour="back">Back</button>' : ""}<button class="btn primary" data-tour="next">${i === steps.length - 1 ? "Done" : "Next"}</button></div>`;
      const w = Math.min(340, window.innerWidth - 24);
      const below = r.bottom + 12 + 190 < window.innerHeight;
      Object.assign(card.style, { width: w + "px", left: Math.max(12, Math.min(window.innerWidth - w - 12, r.left)) + window.scrollX + "px",
        top: (below ? r.bottom + 14 : Math.max(12, r.top - 200)) + window.scrollY + "px" });
      card.querySelector('[data-tour="next"]').focus();
    }, 250);
  }
  function startTour() {
    lastFocus = document.activeElement;
    const help = $("help");
    if (help && help.open) help.close();
    if (G.currentView() !== "dashboard") location.hash = "";
    store.set("ghostap-toured", "1");
    tourStep(0);
  }
  function endTour() {
    tourAt = -1;
    if (spot) { spot.remove(); card.remove(); spot = card = null; }
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-tour]");
    if (!b) return;
    const a = b.dataset.tour;
    if (a === "start") startTour();
    else if (a === "next") tourStep(tourAt + 1);
    else if (a === "back") tourStep(tourAt - 1);
    else endTour();
  });
  document.addEventListener("keydown", (e) => { if (tourAt >= 0 && e.key === "Escape") endTour(); });

  // ------------------------------------------------------------------ F078 command palette
  function commands() {
    const nav = [["dashboard", "Dashboard"]].concat(Object.entries(G.views).map(([k, v]) => [k, v.title]));
    const list = [
      ...nav.map(([k, t]) => ({ group: "Go to", label: t, run: () => { location.hash = k === "dashboard" ? "" : k; } })),
      { group: "Dashboard", label: "Show alerts", run: () => { location.hash = ""; G.setTab("alerts"); } },
      { group: "Dashboard", label: "Show networks", run: () => { location.hash = ""; G.setTab("networks"); } },
      { group: "Dashboard", label: "Show the name-only check", run: () => { location.hash = ""; G.setTab("baseline"); } },
      { group: "Dashboard", label: "Mark all alerts as seen", run: () => G.markAllSeen() },
      ...["5m", "15m", "1h", "all"].map((r) => ({ group: "Timeline", label: "Time range: " + { "5m": "last 5 minutes", "15m": "last 15 minutes", "1h": "last hour", all: "whole capture" }[r], run: () => { location.hash = ""; G.setRange(r); } })),
      { group: "View", label: "Copy a link to this view", run: copyLink },
      { group: "View", label: "Switch clock time / capture time", run: () => G.toggleClock() },
      { group: "View", label: "Switch light / dark theme", run: () => G.toggleTheme() },
      { group: "View", label: "Customise the dashboard layout", run: () => G.openLayout() },
      { group: "View", label: "Presentation mode", run: () => G.setPresent && G.setPresent(!G.presenting()) },
      { group: "Data", label: "Export the access-point table (CSV)", run: () => G.exportCsv() },
      { group: "Help", label: "How GhostAP works", run: () => G.openHelp() },
      { group: "Help", label: "Take the guided tour", run: startTour },
      { group: "Demo", label: "Run the demo (synthetic test capture)", run: () => G.startDemo(false) },
      { group: "Demo", label: "Run the demo and present it", run: () => G.startDemo(true) },
    ];
    return list;
  }
  let pal = null, palItems = [], palAt = 0;
  function score(text, q) {
    text = text.toLowerCase();
    if (!q) return 1;
    if (text.includes(q)) return 3 - text.indexOf(q) / 100;
    let i = 0;                                         // letters in order: "exc" matches "Export … CSV"
    for (const ch of text) if (ch === q[i]) i++;
    return i === q.length ? 1 : 0;
  }
  function palRender() {
    const q = pal.querySelector("input").value.trim().toLowerCase();
    let items = commands().map((c) => ({ ...c, s: score(c.group + " " + c.label, q) })).filter((c) => c.s > 0);
    if (q.length >= 2) {
      const aps = (G.state.aps || []).filter((a) => [a.ssid, a.bssid, a.vendor || ""].join(" ").toLowerCase().includes(q)).slice(0, 8);
      items = items.concat(aps.map((a) => ({ group: "Access point", label: `${ssidLabel(a.ssid)} ${a.bssid}${a.level && a.level !== "LOW" ? " · " + a.level : ""}`, s: 2, run: () => G.select(a.ssid, a.bssid) })));
    }
    palItems = items.sort((a, b) => b.s - a.s).slice(0, 14);
    palAt = Math.min(palAt, Math.max(0, palItems.length - 1));
    const ul = pal.querySelector("ul");
    ul.innerHTML = palItems.length ? palItems.map((c, i) => `<li id="pal-${i}" role="option" aria-selected="${i === palAt}" class="${i === palAt ? "on" : ""}" data-i="${i}">
      <span class="muted">${esc(c.group)}</span> ${esc(c.label)}</li>`).join("") : '<li class="muted" role="option" aria-disabled="true">No matching command</li>';
    pal.querySelector("input").setAttribute("aria-activedescendant", palItems.length ? "pal-" + palAt : "");
    const on = ul.querySelector(".on");
    if (on) on.scrollIntoView({ block: "nearest" });
  }
  function openPalette() {
    if (!pal) {
      pal = document.createElement("dialog");
      pal.className = "palette";
      pal.setAttribute("aria-label", "Command palette");
      pal.innerHTML = `<input class="input" type="text" placeholder="Type a command or an access point…" role="combobox" aria-expanded="true" aria-controls="pal-list" aria-autocomplete="list">
        <ul id="pal-list" role="listbox"></ul><p class="muted small">↑ ↓ to move · Enter to run · Esc to close</p>`;
      document.body.appendChild(pal);
      const input = pal.querySelector("input");
      input.addEventListener("input", () => { palAt = 0; palRender(); });
      input.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); palAt = Math.min(palItems.length - 1, palAt + 1); palRender(); }
        else if (e.key === "ArrowUp") { e.preventDefault(); palAt = Math.max(0, palAt - 1); palRender(); }
        else if (e.key === "Enter") { e.preventDefault(); runAt(palAt); }
      });
      pal.querySelector("ul").addEventListener("click", (e) => { const li = e.target.closest("[data-i]"); if (li) runAt(Number(li.dataset.i)); });
      pal.addEventListener("click", (e) => { if (e.target === pal) pal.close(); });   // click outside the box
    }
    pal.querySelector("input").value = "";
    palAt = 0;
    palRender();
    pal.showModal();
  }
  function runAt(i) {
    const c = palItems[i];
    if (!c) return;
    pal.close();
    c.run();
  }
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") { e.preventDefault(); if (pal && pal.open) pal.close(); else openPalette(); }
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-palette]")) openPalette();
    if (e.target.closest("[data-copy-link]")) copyLink();
  });

  markTerms();
  // first visit: offer the tour once
  if (!store.get("ghostap-toured")) {
    store.set("ghostap-toured", "1");
    setTimeout(() => {
      const t = document.createElement("div");
      t.className = "toast notice";
      t.innerHTML = '<p><b>New to GhostAP?</b> A one-minute tour shows what each part of the dashboard does.</p><div class="row-actions"><button class="btn primary small" data-tour="start">Take the tour</button><button class="btn small" data-close-toast>No thanks</button></div>';
      t.addEventListener("click", (e) => { if (e.target.closest("[data-tour], [data-close-toast]")) t.remove(); });
      $("toasts").appendChild(t);
      setTimeout(() => t.remove(), 20000);
    }, 1500);
  }
  G.copyLink = copyLink;
  G.openPalette = openPalette;
  G.startTour = startTour;
})();
