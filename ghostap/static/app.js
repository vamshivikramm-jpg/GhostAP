/* GhostAP dashboard: polls the Flask API, renders with plain DOM + Plotly.
 * Every value that came from the air (SSIDs, reasons, notes) goes through esc(). */
(function () {
  "use strict";

  // ------------------------------------------------------------------ copy
  const IND = {
    security_downgrade: {
      label: "Security downgrade",
      long: "Compares the security this access point advertises with what the network used while GhostAP was learning it. An evil twin usually can't know the real password, so it often runs open (no password) to let victims join.",
    },
    new_bssid_oui: {
      label: "New radio / vendor",
      long: "Every radio has an address (BSSID) whose first half identifies the manufacturer. A radio that appears after the learning period is new; one from a manufacturer the network has never used is much more suspicious than one from the same vendor.",
    },
    channel_deviation: {
      label: "Unusual channel",
      long: "Checks whether this access point uses a channel the network never used. Attackers often pick a free channel; real networks can also add channels, so this weighs little on its own.",
    },
    rssi_jump: {
      label: "Signal jump",
      long: "Compares signal strength with what was learned. An attacker usually sits close to the victim, so the twin is often much stronger than the real access points.",
    },
    tsf_anomaly: {
      label: "Freshly booted",
      long: "Every beacon carries a microsecond clock (TSF) that starts at zero when the device boots. Real access points run for hours or days; an evil twin is usually started just before the attack. A clock that jumps back means a reboot, or two devices sharing an address.",
    },
    ie_fingerprint: {
      label: "Beacon fingerprint",
      long: "How a beacon is built (the order of its fields, supported speeds, capabilities, vendor extras) depends on the hardware and software. A laptop or phone pretending to be an enterprise access point usually builds its beacons differently, even if it copies the name, vendor and channel.",
    },
    bssid_conflict: {
      label: "Cloned address",
      long: "Looks for one radio address behaving like two devices: jumping back and forth between channels, or frame counters that run backwards. That happens when an attacker copies the exact address of a real access point.",
    },
    beacon_interval_mismatch: {
      label: "Beacon timing",
      long: "Access points announce themselves at a fixed interval (usually 100 time units). A different interval from the rest of the network suggests different equipment or configuration.",
    },
    duplicate_ssid: {
      label: "Duplicate name",
      long: "The simple comparison detector: it flags every access point whose network name is used by more than one access point.",
    },
    karma: {
      label: "KARMA / MANA",
      long: "Attack signature. One radio answering with many different network names is how KARMA and MANA tools lure phones that look for networks they joined before. When it matches, the score is raised to at least the signature's minimum.",
    },
    lookalike_ssid: {
      label: "Look-alike name",
      long: "Attack signature. A name that is one or two characters away from a known network (for example MVSR_WiFi vs. MVSR-WiFi, or a zero for an O). The access point is then compared with the network it imitates.",
    },
    known_tool: {
      label: "Known attack tool",
      long: "Attack signature. The beacon matches an entry in the attack-tool fingerprint library (data/attack_tools.json). The built-in entries are synthetic examples and are switched off until real lab recordings replace them.",
    },
    deauth_flood: {
      label: "Deauthentication flood",
      long: "Many deauthentication or disassociation frames sent in the name of one access point in a short time. Attackers use this to push clients off the real network and onto the twin. GhostAP records only the access point's address, never the clients'.",
    },
    beacon_flood: {
      label: "Beacon flood",
      long: "An unusual number of new access points appearing within a minute, as tools that broadcast many fake networks do.",
    },
  };
  const TRIAGE = [
    ["new", "New"], ["investigating", "Investigating"],
    ["confirmed", "Confirmed attack"], ["false_positive", "False positive"],
  ];
  const SLOTS = 7;

  const state = {
    tab: "alerts", sel: null, summary: null, t0: null,
    colorOf: new Map(), last: {}, scoreField: "score", onlyAlerting: false,
    evFilter: "all", sort: { key: "peak_score", dir: -1 }, search: "",
    aps: [], ghost: [], base: [], networks: [], series: [], events: [],
    known: null, plotBound: false, version: null, offline: false,
    alertFilter: { level: "all", status: "open", q: "" }, picked: new Set(), incidents: [],
    clock: false, range: "all", notes: [],
  };

  // ------------------------------------------------------------------ helpers
  const $ = (id) => document.getElementById(id);
  /** F082: translated text when the chosen language has it, else the English given here. */
  const T = (key, english, vars) => (window.GA_I18N ? window.GA_I18N.t(key, english, vars) : english);
  const esc = (v) => String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  // F036: relative capture time ("t+200s") or clock time, chosen with the clock button.
  const two = (n) => String(n).padStart(2, "0");
  function clockText(ts) {
    const d = new Date(ts * 1000), now = new Date();
    const hms = `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
    return d.toDateString() === now.toDateString() ? hms : d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: d.getFullYear() === now.getFullYear() ? undefined : "numeric" }) + " " + hms;
  }
  const rel = (ts) => (ts == null || state.t0 == null) ? "–" : state.clock ? clockText(ts) : "t+" + Math.round(ts - state.t0) + "s";
  /** x value on every chart: seconds since the capture started, or a Date in clock mode. */
  const X = (ts) => (state.clock ? new Date(ts * 1000) : ts - state.t0);
  const xAxisTitle = () => (state.clock ? "time" : "capture time (s)");
  const fmt = (n, d = 1) => (n == null || Number.isNaN(n) ? "–" : Number(n).toFixed(d));
  const keyOf = (o) => o.ssid + "\u0000" + o.bssid;
  const isSel = (o) => state.sel && state.sel.ssid === o.ssid && state.sel.bssid === o.bssid;
  const lvl = (l) => l ? `<span class="lvl"><i class="lvl-icon ${esc(l)}"></i>${esc(l)}</span>` : `<span class="muted">–</span>`;
  const label = (n) => (IND[n] ? IND[n].label : n);
  const th = () => (state.summary ? state.summary.thresholds : { medium: 30, high: 60 });
  const levelFor = (s) => (s == null ? null : s >= th().high ? "HIGH" : s >= th().medium ? "MEDIUM" : "LOW");
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* private mode */ } },
  };

  function uptime(s) {
    if (s == null) return "–";
    if (s < 1) return Math.round(s * 1000) + " ms";
    if (s < 120) return Math.round(s) + " s";
    if (s < 7200) return Math.round(s / 60) + " min";
    if (s < 172800) return (s / 3600).toFixed(1) + " h";
    return (s / 86400).toFixed(1) + " days";
  }
  function riskbar(score, level) {
    if (score == null) return '<span class="muted">–</span>';
    const w = Math.max(2, Math.min(100, score));
    return `<span class="riskbar" title="Risk ${fmt(score)} of 100"><span class="track"><span class="fill ${esc(level || "")}" style="width:${w}%;display:block"></span></span><span class="n">${fmt(score, 0)}</span></span>`;
  }
  function triageTag(t) {
    if (!t || t === "new") return "";
    const name = (TRIAGE.find((x) => x[0] === t) || [t, t])[1];
    return `<span class="tag triage-${esc(t)}">${esc(name)}</span>`;
  }
  function colorFor(k) {
    if (!state.colorOf.has(k)) state.colorOf.set(k, state.colorOf.size);
    const i = state.colorOf.get(k);
    return i < SLOTS ? css("--s" + (i + 1)) : css("--s-other");
  }
  // Every API call carries ?session=<id> while a past session is being viewed.
  function withSession(url) {
    if (!state.session) return url;
    return url + (url.includes("?") ? "&" : "?") + "session=" + encodeURIComponent(state.session);
  }
  async function get(url) {
    const r = await fetch(withSession(url), { cache: "no-store", credentials: "same-origin" });
    if (!r.ok) { const e = new Error(url + " -> " + r.status); e.status = r.status; throw e; }
    return r.json();
  }
  /** POST JSON; resolves to {ok, status, data} and never throws on HTTP errors. */
  async function post(url, body) {
    try {
      const r = await fetch(withSession(url), {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      let data = null;
      try { data = await r.json(); } catch (e) { /* empty body */ }
      return { ok: r.ok, status: r.status, data };
    } catch (e) {
      return { ok: false, status: 0, data: { error: "GhostAP server not reachable" } };
    }
  }
  /** Short status message in the corner (not an alert toast). */
  function notice(text, kind) {
    const t = document.createElement("div");
    t.className = "toast notice " + (kind || "");
    t.setAttribute("role", "status");
    t.innerHTML = `<div>${esc(text)}</div>`;
    $("toasts").appendChild(t);
    setTimeout(() => t.remove(), 5000);
  }
  const ssidLabel = (s) => (s === "<hidden>" ? "Hidden network" : s);
  function changed(name, data) {
    const s = JSON.stringify(data);
    if (state.last[name] === s) return false;
    state.last[name] = s;
    return true;
  }
  function topReasonNames(reasons) {
    return [...String(reasons || "").matchAll(/([a-z_]+) \(\+/g)].map((m) => label(m[1]).toLowerCase());
  }
  const PLOT_CFG = { displayModeBar: false, responsive: true };
  function baseLayout(extra) {
    return Object.assign({
      paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
      font: { family: 'system-ui, -apple-system, "Segoe UI", sans-serif', size: 12, color: css("--text-2") },
      margin: { l: 42, r: 14, t: 10, b: 40 },
      hoverlabel: { bgcolor: css("--surface"), bordercolor: css("--axis"), font: { color: css("--text") } },
      xaxis: { gridcolor: css("--grid"), linecolor: css("--axis"), zeroline: false, tickfont: { color: css("--muted") },
               type: state.clock ? "date" : "linear",
               title: { text: xAxisTitle(), font: { size: 11, color: css("--muted") } } },
      yaxis: { range: [0, 100], gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
      showlegend: false,
    }, extra || {});
  }
  function thresholdDecor() {
    const t = th();
    const line = (y, c) => ({ type: "line", xref: "paper", x0: 0, x1: 1, y0: y, y1: y, line: { color: c, width: 1, dash: "dash" }, layer: "below" });
    const ann = (y, text) => ({ xref: "paper", x: 1, y, yanchor: "bottom", xanchor: "right", showarrow: false, text, font: { size: 11, color: css("--muted") } });
    const shapes = [line(t.medium, css("--serious")), line(t.high, css("--critical"))];
    const annotations = [ann(t.medium, "MEDIUM ≥ " + t.medium), ann(t.high, "HIGH ≥ " + t.high)];
    const s = state.summary;
    if (s && s.baseline_seconds) {
      shapes.push({ type: "rect", xref: "x", yref: "paper", x0: 0, x1: s.baseline_seconds, y0: 0, y1: 1,
                    fillcolor: css("--band"), line: { width: 0 }, layer: "below" });
      annotations.push({ xref: "x", yref: "paper", x: s.baseline_seconds / 2, y: 1, yanchor: "top", showarrow: false,
                         text: "learning normal", font: { size: 11, color: css("--muted") } });
    }
    return { shapes, annotations };
  }

  // ------------------------------------------------------------------ status, verdict, tiles
  const ICONS = {
    ok: '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
    high: '<svg viewBox="0 0 24 24"><path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5"/><circle cx="12" cy="17.3" r=".5"/></svg>',
    medium: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><circle cx="12" cy="16.3" r=".5"/></svg>',
    learning: '<svg viewBox="0 0 24 24"><path d="M2.5 9a14 14 0 0 1 19 0M6 12.5a9 9 0 0 1 12 0M9.5 16a4 4 0 0 1 5 0"/><circle cx="12" cy="19" r=".8"/></svg>',
    error: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
  };

  function renderStatus(s) {
    const st = s.status || {};
    const mode = st.mode === "replay" ? `Replay ×${st.speed || "max"}` : st.mode === "live" ? "Live capture" : "Saved data";
    const clock = s.capture_end != null && s.capture_start != null ? `capture t+${Math.round(s.capture_end - s.capture_start)}s` : "no frames yet";
    $("status").innerHTML =
      `<span class="pill"><i class="dot ${esc(st.state)}"></i>${esc(mode)} · ${esc(st.state || "")}</span>` +
      `<span class="mono">${esc(st.source || "")}</span><span>${esc(clock)}</span>` +
      (st.hopping ? `<span>${esc(st.hopping)}</span>` : "") +
      (st.save_pcap ? `<span>recording → <span class="mono">${esc(st.save_pcap)}</span></span>` : "") +
      damaged(st.rejected) + heartbeat(s);
  }

  /** F021: in live mode, show beacons per minute and warn when the adapter goes quiet. */
  function heartbeat(s) {
    const hb = s.heartbeat || {};
    if (hb.last_frame_age_s == null) return "";
    const silent = hb.last_frame_age_s > 15;
    return `<span class="pill ${silent ? "pill-bad" : ""}" title="${silent ? "No beacons recently: check monitor mode, the antenna and channel hopping" : "Beacons received in the last minute"}">
      <i class="dot ${silent ? "error" : "running"}"></i>${silent ? "adapter silent " + Math.round(hb.last_frame_age_s) + " s" : Number(hb.frames_last_minute).toLocaleString() + " beacons/min"}</span>`;
  }

  function damaged(rej) {
    const n = Object.values(rej || {}).reduce((a, b) => a + b, 0);
    if (!n) return "";
    const detail = Object.entries(rej).map(([k, v]) => `${v} ${k.replace("_", " ")}`).join(", ");
    return `<span title="Damaged frames are skipped so they cannot cause false alarms: ${esc(detail)}">skipped ${n} damaged frame${n > 1 ? "s" : ""}</span>`;
  }

  function renderVerdict(s) {
    const st = s.status || {};
    const v = $("verdict"), prog = $("baseline-progress");
    let cls, title, sub, actions = "";
    prog.hidden = true;
    if (st.state === "error") {
      cls = "error"; title = T("verdict.error", "Live capture could not start"); sub = st.message;
    } else if (s.capture_start == null) {
      cls = "learning"; title = T("verdict.waiting", "Waiting for Wi-Fi beacons…");
      sub = "Nothing has been heard yet. Live capture needs a monitor-mode adapter on Linux.";
    } else if (!s.baseline_complete) {
      const done = Math.max(0, s.capture_end - s.capture_start);
      cls = "learning"; title = T("verdict.learning", "Learning what normal looks like");
      sub = `${Math.round(done)} of ${Math.round(s.baseline_seconds)} s. GhostAP first watches every network so it can spot what changes later. ${s.aps} access points heard so far.`;
      prog.hidden = false;
      prog.firstElementChild.style.width = Math.min(100, (100 * done) / s.baseline_seconds) + "%";
    } else if (s.top_alert && s.top_alert.detector === "deauth") {
      const a = s.top_alert;
      cls = a.level === "HIGH" ? "high" : "medium"; title = T("verdict.deauth", `Deauthentication attack on “${a.ssid}”`, { ssid: a.ssid });
      sub = `Bursts of frames are disconnecting clients from ${a.bssid}. Attackers do this to push phones onto an evil twin; watch for a new access point using this name.`;
      actions = `<button class="btn primary" data-inspect="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">${esc(T("btn.inspect", "Inspect"))}</button>`;
    } else if (s.top_alert && s.top_alert.detector === "flood") {
      cls = "high"; title = T("verdict.flood", "Beacon flood: many fake networks appeared at once");
      sub = "A large number of new radios appeared within a minute, which is typical of fake-AP generators.";
    } else if (s.top_alert && s.top_alert.level === "HIGH") {
      const a = s.top_alert, why = topReasonNames(a.reasons).slice(0, 3);
      cls = "high"; title = T("verdict.twin", `Evil twin suspected on “${a.ssid}”`, { ssid: a.ssid });
      sub = `Access point ${a.bssid} scores ${fmt(a.score, 0)}/100${why.length ? ": " + why.join(", ") : ""}.` +
        (s.alerts.HIGH + s.alerts.MEDIUM > 1 ? ` ${s.alerts.HIGH + s.alerts.MEDIUM} alerts in total.` : "");
      actions = `<button class="btn primary" data-inspect="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">${esc(T("btn.inspect", "Inspect"))}</button>`;
    } else if (s.top_alert) {
      const a = s.top_alert, why = topReasonNames(a.reasons).slice(0, 2);
      cls = "medium"; title = T("verdict.suspicious", `Suspicious access point on “${a.ssid}”`, { ssid: a.ssid });
      sub = `${a.bssid} scores ${fmt(a.score, 0)}/100${why.length ? " (" + why.join(", ") + ")" : ""}. Worth a look.`;
      actions = `<button class="btn primary" data-inspect="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">${esc(T("btn.inspect", "Inspect"))}</button>`;
    } else {
      cls = "ok"; title = T("verdict.clear", `All clear: ${s.aps} access point${s.aps === 1 ? "" : "s"} on ${s.networks} network${s.networks === 1 ? "" : "s"} look normal`, { aps: s.aps, nets: s.networks });
      sub = (s.dismissed_alerts ? `${s.dismissed_alerts} alert${s.dismissed_alerts === 1 ? " was" : "s were"} marked as false positive by an analyst. ` : "") +
        (s.muted_alerts ? `${s.muted_alerts} muted. ` : "") +
        (s.baseline_alerts
          ? `A name-only check would have raised ${s.baseline_alerts} alarm${s.baseline_alerts === 1 ? "" : "s"} here, because some networks have several access points.`
          : "No network name is shared between access points.");
    }
    actions += `<button class="btn" data-help>How it works</button>`;
    v.className = "verdict " + cls;
    $("verdict-icon").innerHTML = ICONS[cls] || ICONS.ok;
    $("verdict-title").textContent = title;
    $("verdict-sub").textContent = sub;
    $("verdict-actions").innerHTML = actions;
  }

  function renderTiles(s) {
    $("t-networks").textContent = s.networks;
    $("t-aps").textContent = s.aps;
    $("t-frames").textContent = Number(s.frames).toLocaleString() + " beacons heard";
    $("t-high").textContent = s.alerts.HIGH;
    $("t-medium").textContent = s.alerts.MEDIUM;
    $("t-base").textContent = s.baseline_alerts;
    document.querySelector(".tile-high").classList.toggle("hot", s.alerts.HIGH > 0);
    document.querySelector(".tile-med").classList.toggle("hot", s.alerts.MEDIUM > 0);
    const c = $("c-alerts");
    c.textContent = s.alerts.HIGH + s.alerts.MEDIUM || "";
    c.classList.toggle("hot", s.alerts.HIGH > 0);
    $("c-baseline").textContent = s.baseline_alerts || "";
    $("help-baseline").textContent = Math.round(s.baseline_seconds / 60);
    $("help-med").textContent = s.thresholds.medium;
    $("help-high").textContent = s.thresholds.high;
    document.title = (s.alerts.HIGH ? `(${s.alerts.HIGH}) ` : "") + "GhostAP Dashboard";
  }

  // ------------------------------------------------------------------ side panel
  const HINTS = {
    alerts: "Access points GhostAP finds suspicious, highest risk first.",
    networks: "Access points grouped by network name. An evil twin shows up as an extra entry under a real network.",
    baseline: "For comparison: the simple check that flags every access point whose name is shared. Most of these are normal.",
  };
  function renderSide() {
    $("side-hint").textContent = HINTS[state.tab];
    $("c-networks").textContent = state.networks.length || "";
    const el = $("side-list");
    if (state.tab === "alerts") {
      if (!state.ghost.length) {
        const learning = state.summary && !state.summary.baseline_complete;
        el.innerHTML = `<div class="empty">${learning ? "Alerts appear once the learning period is over." : "No alerts. Every access point looks consistent with what was learned."}</div>`;
        return;
      }
      const f = state.alertFilter;
      const q = f.q.trim().toLowerCase();
      const shown = state.ghost.filter((a) => (f.level === "all" || a.level === f.level)
        && (f.status === "all" || (f.status === "open" ? a.triage_status !== "false_positive" && !a.muted
          : f.status === "dismissed" ? a.triage_status === "false_positive" || a.muted : (a.triage_status || "new") === f.status))
        && (!q || [a.ssid, a.bssid, a.detector, a.reasons].join(" ").toLowerCase().includes(q)));
      const kind = (a) => (a.detector === "deauth" ? '<span class="tag triage-confirmed">deauth attack</span>'
        : a.detector === "flood" ? '<span class="tag triage-confirmed">beacon flood</span>' : "");
      const nPicked = state.picked.size;
      el.innerHTML = `<div class="filters">
          <select class="input" data-f="level" aria-label="Level"><option value="all">All levels</option><option ${f.level === "HIGH" ? "selected" : ""}>HIGH</option><option ${f.level === "MEDIUM" ? "selected" : ""}>MEDIUM</option></select>
          <select class="input" data-f="status" aria-label="Status">${[["open", "Open"], ["all", "All"], ["new", "New"], ["investigating", "Investigating"], ["confirmed", "Confirmed"], ["dismissed", "Dismissed or muted"]].map(([v, t]) => `<option value="${v}" ${f.status === v ? "selected" : ""}>${t}</option>`).join("")}</select>
          <input class="input" data-f="q" type="search" placeholder="Filter…" value="${esc(f.q)}" aria-label="Filter alerts">
        </div>
        ${nPicked ? `<div class="bulk"><b>${nPicked} selected</b>${TRIAGE.map(([k, n]) => `<button class="btn small" data-bulk="${k}">${esc(n)}</button>`).join("")}<button class="btn small" data-bulk-clear>Clear</button></div>` : ""}
        ${shown.length ? shown.map((a) => `<div class="item-row">
          <input type="checkbox" data-pick="${a.id}" ${state.picked.has(a.id) ? "checked" : ""} aria-label="Select alert ${esc(a.ssid)} ${esc(a.bssid)}">
          <button class="item ${isSel(a) ? "selected" : ""} ${a.triage_status === "false_positive" || a.muted ? "dismissed" : ""}" data-ssid="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">
          ${lvl(a.level)}<span class="who">${unseenOf(a) ? `<i class="unseen-dot" title="${unseenOf(a) === "new" ? "New" : "Escalated to HIGH"} since you last looked"></i>` : ""}${esc(ssidLabel(a.ssid))}</span><span class="score">${fmt(a.score, 0)}</span>
          <span class="sub"><span class="mono">${esc(a.bssid)}</span>· first ${rel(a.first_ts)} ${kind(a)} ${triageTag(a.triage_status)} ${a.muted ? '<span class="tag">muted</span>' : ""}</span>
        </button></div>`).join("") : '<div class="empty">No alert matches these filters.</div>'}`;
    } else if (state.tab === "networks") {
      el.innerHTML = state.networks.length ? state.networks.map((n) => {
        const hot = n.aps.some((a) => a.alert_id);
        return `<div class="net ${hot ? "hot" : ""}">
          <div class="net-head"><b>${esc(ssidLabel(n.ssid))}</b>
            <span class="net-meta">${n.aps.length} AP${n.aps.length > 1 ? "s" : ""} · ${esc(n.securities.join(", "))} · ch ${esc(n.channels.join(", "))}</span></div>
          ${n.aps.map((a) => `
            <button class="net-ap ${isSel(a) ? "selected" : ""}" data-ssid="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">
              ${lvl(a.level)}
              <span class="addr"><span class="mono">${esc(a.bssid)}</span>
                <small>ch ${esc(a.channels)} · ${esc(a.securities)} · ${a.in_baseline ? "known" : "appeared " + rel(a.first_seen)}</small></span>
              ${riskbar(a.score, a.level)}
            </button>`).join("")}
        </div>`;
      }).join("") : '<div class="empty">No networks heard yet.</div>';
    } else {
      const ghostKeys = new Set(state.ghost.map(keyOf));
      el.innerHTML = state.base.length ? state.base.map((a) => `
        <button class="item ${isSel(a) ? "selected" : ""}" data-ssid="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">
          <span class="lvl"><i class="lvl-icon"></i>flag</span><span class="who">${esc(a.ssid)}</span>
          <span>${ghostKeys.has(keyOf(a)) ? '<span class="tag triage-confirmed">GhostAP agrees</span>' : '<span class="tag">GhostAP: normal</span>'}</span>
          <span class="sub"><span class="mono">${esc(a.bssid)}</span>· flagged ${rel(a.first_ts)}</span>
        </button>`).join("") : '<div class="empty">No network name is shared between access points.</div>';
    }
  }
  $("side-list").addEventListener("click", async (e) => {
    const bulk = e.target.closest("[data-bulk]");
    if (bulk) {
      const r = await post("/api/alerts/triage_bulk", { ids: [...state.picked], status: bulk.dataset.bulk });
      notice(r.ok ? `Updated ${r.data.updated.length} alert${r.data.updated.length === 1 ? "" : "s"}.` : (r.data && r.data.error) || "Could not update", r.ok ? "ok" : "error");
      state.picked.clear();
      refresh(true, true);
      return;
    }
    if (e.target.closest("[data-bulk-clear]")) { state.picked.clear(); renderSide(); return; }
    const b = e.target.closest("[data-bssid]");
    if (b) select(b.dataset.ssid, b.dataset.bssid, true);
  });
  $("side-list").addEventListener("change", (e) => {
    const id = e.target.dataset.pick;
    if (id) { e.target.checked ? state.picked.add(Number(id)) : state.picked.delete(Number(id)); renderSide(); return; }
    const f = e.target.dataset.f;
    if (f && f !== "q") { state.alertFilter[f] = e.target.value; renderSide(); }
  });
  $("side-list").addEventListener("input", (e) => {
    if (e.target.dataset.f !== "q") return;
    state.alertFilter.q = e.target.value;
    const pos = e.target.selectionStart;
    renderSide();
    const box = $("side-list").querySelector('[data-f="q"]');
    if (box) { box.focus(); box.setSelectionRange(pos, pos); }
  });

  // ------------------------------------------------------------------ F020 incident story
  function renderIncident() {
    const el = $("incident");
    const open = state.incidents || [];
    if (!open.length) { el.hidden = true; return; }
    const inc = open[0];
    const byId = new Map(state.ghost.map((a) => [a.id, a]));
    el.hidden = false;
    el.className = "card incident " + inc.level;
    el.innerHTML = `<div class="card-head"><h2>${lvl(inc.level)} ${esc(inc.summary)}</h2>
        <span class="muted">${rel(inc.first_ts)} – ${rel(inc.last_ts)}${open.length > 1 ? ` · ${open.length - 1} more incident${open.length > 2 ? "s" : ""}` : ""}</span></div>
      <ol class="story">${inc.story.map((st) => {
        const a = byId.get(st.alert_id);
        return `<li><span class="t">${rel(st.ts)}</span>${a ? `<button class="linkish" data-inspect="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">${esc(st.text)}</button>` : esc(st.text)}</li>`;
      }).join("")}</ol>`;
  }
  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.toggle("active", t.dataset.tab === tab);
      t.setAttribute("aria-selected", t.dataset.tab === tab);
    });
    renderSide();
  }
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));
  document.querySelectorAll(".tile").forEach((t) => t.addEventListener("click", () => {
    const go = t.dataset.go;
    if (go === "table") { $("table-card").scrollIntoView({ block: "start" }); $("ap-search").focus({ preventScroll: true }); return; }
    setTab(go);
    document.querySelector(".side").scrollIntoView({ block: "nearest" });
  }));

  // ------------------------------------------------------------------ selection
  function select(ssid, bssid, user) {
    state.sel = { ssid, bssid };
    if (user) markSeen((state.ghost || []).filter((a) => a.ssid === ssid && a.bssid === bssid));
    try { history.replaceState(null, "", "#ap=" + encodeURIComponent(ssid) + "|" + encodeURIComponent(bssid)); } catch (e) { /* ignore */ }
    renderSide();
    renderTable();
    if (state.series.length) renderTimeline();
    delete state.last.detail;
    loadDetail();
    if (user && window.matchMedia("(max-width: 900px)").matches) $("detail").scrollIntoView({ block: "start" });
  }

  // ------------------------------------------------------------------ detail
  async function loadDetail() {
    if (!state.sel) return;
    if (state.version !== null && !state.aps.some(isSel)) {
      // e.g. a shared #ap= link opened before this capture reached that access point
      delete state.last.detail;
      $("detail").innerHTML = `<div class="empty big-empty"><p><b>${esc(ssidLabel(state.sel.ssid))}</b> <span class="mono">${esc(state.sel.bssid)}</span></p>
        <p>This access point has not been heard in this capture yet. It will appear here as soon as it is.</p></div>`;
      return;
    }
    let d;
    try {
      d = await get(`/api/ap?ssid=${encodeURIComponent(state.sel.ssid)}&bssid=${encodeURIComponent(state.sel.bssid)}`);
    } catch (e) { return; }
    if (!isSel(d.ap)) return;                       // selection changed meanwhile
    if (!changed("detail", [d, state.summary && state.summary.thresholds])) return;
    renderDetail(d);
  }

  function gauge(score, level, caption) {
    const s = Math.max(0, Math.min(100, score || 0));
    const R = 70, cx = 85, cy = 84;
    const pt = (v) => {
      const a = Math.PI * (1 - v / 100);
      return [cx + R * Math.cos(a), cy - R * Math.sin(a)];
    };
    const arc = (a, b, color, w) => {
      const [x1, y1] = pt(a), [x2, y2] = pt(b);
      return `<path d="M${x1.toFixed(1)} ${y1.toFixed(1)} A${R} ${R} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}" fill="none" stroke="${color}" stroke-width="${w}" stroke-linecap="butt"/>`;
    };
    const t = th(), col = level === "HIGH" ? css("--critical") : level === "MEDIUM" ? css("--serious") : css("--good");
    return `<div class="gauge" role="img" aria-label="Risk ${fmt(score, 0)} of 100, ${esc(level || "")}">
      <svg viewBox="0 0 170 98">
        ${arc(0, t.medium, css("--good-soft"), 12)}${arc(t.medium, t.high, css("--serious-soft"), 12)}${arc(t.high, 100, css("--critical-soft"), 12)}
        ${s > 0.5 ? arc(0, s, col, 12) : ""}
        <text x="85" y="78" text-anchor="middle" class="g-num">${fmt(score, 0)}</text>
        <text x="85" y="95" text-anchor="middle" class="g-cap">${esc(caption)}</text>
      </svg>${lvl(level)}</div>`;
  }

  /** Rows of the "this AP vs. the network's known APs" comparison (shared by the
   *  on-screen table and the exported report). */
  function compareData(ap, sibs) {
    const known = sibs.filter((x) => x.in_baseline);
    // An AP that was there while GhostAP learned the network is itself part of "normal".
    const ref = ap.in_baseline ? [ap, ...known] : known.length ? known : sibs;
    const cols = [...known, ...sibs.filter((x) => !x.in_baseline)].slice(0, 3);
    const upAt = (x) => (x.uptime_first_seen == null ? null
      : x.first_seen <= ap.first_seen ? x.uptime_first_seen + (ap.first_seen - x.first_seen) : x.uptime_first_seen);
    const defs = [
      ["Vendor (first half of address)", (x) => x.oui + (x.vendor && x.vendor.vendor ? " · " + x.vendor.vendor : x.vendor && x.vendor.local ? " · locally administered" : ""), (x) => x.oui],
      ["Channel", (x) => x.channels, (x) => x.channels],
      ["Security", (x) => x.securities, (x) => x.securities],
      ["Signal", (x) => (x.rssi_avg == null ? "–" : fmt(x.rssi_avg, 0) + " dBm"), null,
        (me, r) => me.rssi_avg != null && r.every((x) => x.rssi_avg != null && me.rssi_avg > x.rssi_avg + 6)],
      ["Uptime when this AP appeared", (x) => uptime(x === ap ? ap.uptime_first_seen : upAt(x)), null,
        (me, r) => me.uptime_first_seen != null && r.some((x) => upAt(x) != null) &&
          me.uptime_first_seen < 0.1 * Math.max(...r.map((x) => upAt(x) || 0))],
      ["Beacon fingerprint", (x) => (x.fingerprints || []).join(", ") || "–", null,
        (me, r) => (me.fingerprints || []).length > 0 && !r.some((x) => (x.fingerprints || []).some((f) => me.fingerprints.includes(f)))],
      ["Beacon interval", (x) => (x.beacon_interval == null ? "–" : x.beacon_interval + " TU"), (x) => x.beacon_interval],
      ["First seen", (x) => rel(x.first_seen) + (x.in_baseline ? " (while learning)" : ""), null, (me) => !me.in_baseline],
    ];
    const rows = defs.map(([name, show, val, diffFn]) => {
      const diff = sibs.length ? (diffFn ? diffFn(ap, ref) : !new Set(ref.map(val)).has(val(ap))) : null;
      return { name, me: show(ap), diff, others: cols.map(show) };
    });
    return { rows, cols, more: sibs.length - cols.length };
  }

  function comparison(ap, sibs) {
    if (!sibs.length) {
      return `<p class="muted">This is the only access point using the name “${esc(ssidLabel(ap.ssid))}”, so there is nothing to compare it with. GhostAP still checks its security, uptime and behaviour over time.</p>`;
    }
    const { rows, cols, more } = compareData(ap, sibs);
    const body = rows.map((r) => `<tr><td class="attr">${esc(r.name)}</td>
        <td class="me ${r.diff ? "diff" : "same"}" title="${r.diff ? "differs from the network's known access points" : "matches the network's known access points"}">${esc(r.me)}</td>
        ${r.others.map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("");
    return `<div class="table-wrap"><table class="cmp">
      <thead><tr><th></th><th class="me"><span class="colhead">This access point<small class="mono">${esc(ap.bssid)}</small></span></th>
      ${cols.map((x) => `<th><span class="colhead">${x.in_baseline ? "Known AP" : "Other new AP"}<small class="mono">${esc(x.bssid)}</small></span></th>`).join("")}</tr></thead>
      <tbody>${body}</tbody></table></div>
      <p class="cmp-legend"><b style="color:var(--critical-ink)">≠</b> differs from every access point known for “${esc(ssidLabel(ap.ssid))}” · <b style="color:var(--good)">=</b> matches${more > 0 ? ` · ${more} more access point${more > 1 ? "s" : ""} not shown` : ""}</p>`;
  }

  // ------------------------------------------------------------------ export
  function exportReport(d) {
    const md = (v) => String(v == null ? "–" : v).replace(/[\r\n]+/g, " ").replace(/\|/g, "\\|");
    const ap = d.ap, alert = d.alert, latest = d.latest;
    const level = alert ? alert.level : latest ? latest.level : "not scored";
    const score = alert ? alert.score : latest ? latest.score : null;
    const inds = ((alert && alert.indicators && alert.indicators.length) ? alert.indicators : latest ? latest.indicators : []) || [];
    const st = (state.summary && state.summary.status) || {};
    const L = [];
    L.push(`# GhostAP access point report: ${md(ssidLabel(ap.ssid))} (${md(ap.bssid)})`, "");
    L.push(`- Generated: ${new Date().toISOString()}`);
    L.push(`- Source: ${md(st.mode)} ${md(st.source)}`);
    L.push(`- Verdict: **${md(level)}**, risk ${fmt(score, 1)} / 100${alert ? ` (peak at ${rel(alert.peak_ts)}; first alert ${rel(alert.first_ts)}; HIGH ${rel(alert.high_ts)})` : ""}`);
    L.push(`- First seen: ${rel(ap.first_seen)}${ap.in_baseline ? " (present while GhostAP learned the network)" : " (appeared after the learning period)"}`);
    if (alert) L.push(`- Triage: ${md((TRIAGE.find((t) => t[0] === (alert.triage_status || "new")) || ["", "New"])[1])}${alert.triage_note ? ` · note: ${md(alert.triage_note)}` : ""}`);
    if (d.siblings && d.siblings.length) {
      const { rows, cols } = compareData(ap, d.siblings);
      L.push("", "## Compared with the network's known access points", "");
      L.push(`| Attribute | This AP ${md(ap.bssid)} | ${cols.map((c) => `${c.in_baseline ? "Known AP" : "Other new AP"} ${md(c.bssid)}`).join(" | ")} |`);
      L.push(`|---|---|${cols.map(() => "---").join("|")}|`);
      rows.forEach((r) => L.push(`| ${md(r.name)} | ${r.diff ? "≠ " : "= "}${md(r.me)} | ${r.others.map(md).join(" | ")} |`));
    }
    L.push("", "## Indicators", "", "| Indicator | Value | Weight | Points | Finding |", "|---|---|---|---|---|");
    inds.slice().sort((a, b) => b.contribution - a.contribution).forEach((c) =>
      L.push(`| ${md(label(c.name))} | ${fmt(c.value, 2)} | ${fmt(c.weight)} | ${fmt(c.contribution)} | ${md(c.reason)} |`));
    if (alert && alert.benign_causes && alert.benign_causes.length) {
      const ruled = new Set(JSON.parse(store.get("ghostap-ruleout-" + alert.id) || "[]"));
      L.push("", "## Innocent explanations", "");
      alert.benign_causes.forEach((b, i) => L.push(`- [${ruled.has(i) ? "x" : " "}] ${md(b)}`));
    }
    L.push("", "---", "Generated by GhostAP (passive monitoring of beacon / probe-response frames only).", "");
    const blob = new Blob([L.join("\n")], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ghostap-${ssidLabel(ap.ssid).replace(/[^A-Za-z0-9_-]+/g, "_")}-${ap.bssid.replace(/:/g, "")}.md`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  function indicatorRows(inds) {
    const w = state.summary ? state.summary.weights : {};
    const total = Object.values(w).reduce((a, b) => a + b, 0) || 1;
    return inds.slice().sort((a, b) => b.contribution - a.contribution).map((c) => {
      const info = IND[c.name] || { label: c.name, long: "" };
      const max = ((c.weight || 0) / total) * 100;
      return `<details class="ind ${c.contribution > 0 ? "" : "zero"}">
        <summary>
          <svg class="chev" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3l5 5-5 5"/></svg>
          <span class="name">${esc(info.label)}</span>
          <span class="bar" title="${fmt(c.contribution)} of a possible ${fmt(max)} points"><div style="width:${Math.min(100, (c.value || 0) * 100)}%"></div></span>
          <span class="pts">${c.contribution > 0 ? "+" + fmt(c.contribution) : "0"}</span>
        </summary>
        <div class="body">
          <p><b>Finding:</b> ${esc(c.reason)}</p>
          <p>${esc(info.long)}</p>
          <p class="math">value ${fmt(c.value, 2)} × weight ${fmt(c.weight)} → ${fmt(c.contribution)} of 100 points (max ${fmt(max)})</p>
        </div>
      </details>`;
    }).join("");
  }

  function renderDetail(d) {
    state.detail = d;
    const ap = d.ap, alert = d.alert, latest = d.latest;
    const score = alert ? alert.score : latest ? latest.score : null;
    const level = alert ? alert.level : latest ? latest.level : null;
    const inds = (alert && alert.indicators && alert.indicators.length ? alert.indicators : latest ? latest.indicators : []) || [];
    const hits = inds.filter((c) => c.contribution > 0).sort((a, b) => b.contribution - a.contribution);
    const whatIs = level === "HIGH" ? "Likely an evil twin." : level === "MEDIUM" ? "Suspicious, worth checking." : level === "LOW" ? "Looks normal." : "Not scored yet.";
    const whyList = hits.slice(0, 3).map((c) => `<li><b style="display:inline">${esc(label(c.name))}:</b> ${esc(c.reason)}</li>`).join("");
    const tags = [
      ap.in_baseline ? '<span class="tag">present while learning</span>' : `<span class="tag new">new: appeared ${rel(ap.first_seen)}</span>`,
      ap.allowlisted ? '<span class="tag">on allow-list</span>' : "",
      alert ? triageTag(alert.triage_status) : "",
      d.baseline_alert ? '<span class="tag" title="The name-only check flags every AP whose name is shared">name-only check: flagged</span>' : "",
    ].join("");

    let html = `
      <div class="d-head">
        <div>
          <h2 class="d-title">${esc(ssidLabel(ap.ssid))} <span class="mono muted">${esc(ap.bssid)}</span></h2>
          <div class="d-tags">${tags}
            <details class="menu actions-menu" style="margin-left:auto"><summary class="btn small">Actions ▾</summary>
              <div class="menu-body menu-list row-actions">
              ${ap.ssid !== "<hidden>" ? `<button data-accept-baseline>It's ours: accept it<small>Adds it to ${esc(ap.ssid)}'s saved baseline, so it stops alerting</small></button>` : ""}
              ${ap.allowlisted ? "" : "<button data-trust>Trust this address<small>Not treated as new any more; a copy of it is still detected</small></button>"}
              <label class="menu-select">Mute alerts <select class="input small-select" data-mute aria-label="Mute this access point"><option value="">…</option><option value="1">for 1 hour</option><option value="8">for 8 hours</option><option value="24">for 24 hours</option><option value="168">for a week</option></select></label>
              <button data-export>Download a write-up<small>Markdown summary for your notes or report</small></button>
              <button data-copy-link>Copy a link to this view<small>Opens this access point with the same filters</small></button>
              <a data-evidence href="${esc(withSession(`/api/ap/evidence.pcap?ssid=${encodeURIComponent(ap.ssid)}&bssid=${encodeURIComponent(ap.bssid)}`))}" download>Download evidence (pcap)<small>This access point's beacons around the alert, for Wireshark</small></a>
              </div></details></div>
          <div class="why ${esc(level || "")}"><b>${esc(whatIs)}</b>
            ${hits.length ? `<span class="muted">${alert ? "At its peak (" + rel(alert.peak_ts) + ") the main reasons were:" : "What raised the score:"}</span><ul>${whyList}</ul>`
              : `<span class="muted">${inds.length ? "None of the eight checks found anything unusual about this access point." : "Scoring starts after the learning period."}</span>`}
          </div>
        </div>
        ${gauge(score, level, alert ? "peak risk" : "risk now")}
      </div>

      <div class="section-title"><h3>Compared with the network's known access points</h3><span class="muted">what an analyst would check first</span></div>
      ${comparison(ap, d.siblings || [])}

      <div class="two">
        <div>
          <div class="section-title"><h3>${alert ? "Why it was flagged" : "What GhostAP checked"}</h3><span class="muted">click a row to see why</span></div>
          ${inds.length ? indicatorRows(inds) : '<p class="muted">No indicator results yet.</p>'}
        </div>
        <div>
          <div class="section-title"><h3>Risk of this access point over time</h3></div>
          <div id="ap-chart" class="chart"></div>
        </div>
      </div>

      <details class="tech" id="tech-details" ${state.techOpen ? "open" : ""}><summary>Technical details <span class="muted">signal and uptime charts, beacon structure, related access points</span></summary>
      <div class="two">
        <div>
          <div class="section-title"><h3>Signal and uptime</h3><span class="muted">compared with the network's other access points</span></div>
          <div class="seg" role="group" aria-label="Series"><button class="seg-btn active" data-series="rssi" aria-pressed="true">Signal</button><button class="seg-btn" data-series="uptime" aria-pressed="false">Uptime</button><button class="seg-btn" data-series="rate" aria-pressed="false">Beacons/s</button></div>
          <div id="ap-series" class="chart"></div>
        </div>
        <div>
          <div class="section-title"><h3>Beacon structure</h3><span class="muted">element by element, against the closest known AP</span></div>
          <div id="beacon-diff" class="bdiff"><p class="muted">Loading…</p></div>
        </div>
      </div>
      <div id="related" class="related" hidden></div>
      </details>`;

    if (alert) {
      const ruled = new Set(JSON.parse(store.get("ghostap-ruleout-" + alert.id) || "[]"));
      html += `
      <div class="two">
        <div>
          <div class="section-title"><h3>Triage</h3><span class="muted">saved on the GhostAP server</span></div>
          <div class="triage" data-alert="${alert.id}">
            <div class="seg seg-grid" role="group" aria-label="Alert status">
              ${TRIAGE.map(([k, n]) => `<button class="seg-btn ${alert.triage_status === k || (!alert.triage_status && k === "new") ? "active" : ""}" data-triage="${k}" aria-pressed="${alert.triage_status === k}">${esc(n)}</button>`).join("")}
            </div>
            <textarea id="triage-note" aria-label="Triage notes" placeholder="Notes: who checked it, what you found…" maxlength="2000">${esc(alert.triage_note || "")}</textarea>
            <div class="triage-row"><button class="btn primary" id="triage-save">Save</button>
              <span class="saved" id="triage-saved">${alert.triage_ts ? "Last saved " + new Date(alert.triage_ts * 1000).toLocaleTimeString() : ""}</span></div>
            <div id="triage-history" class="history" aria-live="polite"></div>
          </div>
        </div>
        <div>
          <div class="section-title"><h3>Rule out innocent explanations</h3><span class="muted">tick what you have checked</span></div>
          <ul class="checklist" data-alert="${alert.id}">
            ${(alert.benign_causes || []).map((b, i) => `<li><label><input type="checkbox" data-i="${i}" ${ruled.has(i) ? "checked" : ""}><span>${esc(b)}</span></label></li>`).join("")}
          </ul>
        </div>
      </div>`;
    }
    $("detail").innerHTML = html;
    drawApChart(d, alert);
    if (alert) loadHistory(alert.id);
    loadApExtras(ap);
  }

  // ------------------------------------------------------------------ F028 F030 F033
  async function loadApExtras(ap) {
    const q = `ssid=${encodeURIComponent(ap.ssid)}&bssid=${encodeURIComponent(ap.bssid)}`;
    const same = () => state.detail && state.detail.ap.bssid === ap.bssid && state.detail.ap.ssid === ap.ssid;
    const [diff, series, related] = await Promise.all([
      get("/api/ap/beacon_diff?" + q).catch(() => null),
      get("/api/ap/series?" + q).catch(() => null),
      get("/api/ap/related?" + q).catch(() => []),
    ]);
    if (!same()) return;
    state.apSeries = series;
    drawSeries();
    const bd = $("beacon-diff");
    if (bd) bd.innerHTML = !diff ? '<p class="muted">Not available.</p>' : !diff.available ? `<p class="muted">${esc(diff.reason)}</p>` : `
      <p><b>${esc(diff.summary)}</b> <span class="muted">This AP <span class="mono">${esc(diff.fingerprint)}</span> vs. ${esc(diff.known.bssid)} <span class="mono">${esc(diff.known.fingerprint)}</span>${diff.known.in_baseline ? " (known while learning)" : ""}.</span></p>
      <table class="bd-table"><thead><tr><th>Element</th><th>This AP</th><th>Known AP</th></tr></thead><tbody>
      ${diff.rows.map((r) => `<tr class="bd-${r.op}"><td>${esc(r.name)}</td>
        <td class="mono">${r.op === "only_known" ? '<span class="bd-tag">missing</span>' : esc(r.value || "✓")}</td>
        <td class="mono">${r.op === "only_this" ? '<span class="bd-tag">not sent</span>' : esc(r.known_value || "✓")}</td></tr>`).join("")}
      </tbody></table>
      <p class="muted small">✓ = present (GhostAP compares only its position). Security and the network name are compared by other checks.</p>`;
    const rel_ = $("related");
    if (rel_ && related.length) {
      rel_.hidden = false;
      rel_.innerHTML = `<div class="section-title"><h3>Related access points</h3><span class="muted">possibly the same device or the same attack</span></div>
        <ul class="rel-list">${related.map((r) => `<li><button class="linkish" data-inspect="${esc(r.ssid)}" data-bssid="${esc(r.bssid)}">${esc(ssidLabel(r.ssid))} <span class="mono">${esc(r.bssid)}</span></button>
          <span class="muted">${r.reasons.map((x) => esc(x.text)).join(" · ")}</span></li>`).join("")}</ul>`;
    }
  }

  function drawSeries() {
    const s = state.apSeries, el = $("ap-series");
    if (!el) return;
    if (!s || !s.series.length) { el.innerHTML = '<div class="empty">No data.</div>'; return; }
    const kind = state.seriesKind || "rssi";
    const idx = { rssi: 1, rate: 2, uptime: 3 }[kind];
    const pal = ["--s1", "--s2", "--s3", "--s4", "--s5"];
    const traces = s.series.slice(0, 6).map((ser, i) => ({
      x: ser.points.map((p) => X(p[0])), y: ser.points.map((p) => (kind === "uptime" && p[idx] != null ? p[idx] / 3600 : p[idx])),
      name: ser.bssid === s.focus ? "this AP" : esc(ser.bssid), mode: "lines", connectgaps: false,
      line: { color: ser.bssid === s.focus ? css("--critical") : css(pal[(i - 1 + pal.length) % pal.length]), width: ser.bssid === s.focus ? 2.5 : 1.5 },
      hovertemplate: (kind === "rssi" ? "%{y:.0f} dBm" : kind === "uptime" ? "%{y:.2f} h" : "%{y:.1f}/s") + "<extra>" + esc(ser.bssid) + "</extra>",
    }));
    Plotly.react(el, traces, baseLayout({
      showlegend: true, legend: { orientation: "h", y: -0.28, x: 0, font: { color: css("--text-2"), size: 11 } },
      margin: { l: 40, r: 10, t: 8, b: 64 },
      yaxis: { title: { text: kind === "rssi" ? "dBm" : kind === "uptime" ? "hours since boot" : "beacons per second", font: { size: 11 } }, gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
    }), PLOT_CFG);
  }

  /** F027: every status change and note on this alert, newest first. */
  async function loadHistory(id) {
    let rows = [];
    try { rows = await get(`/api/alerts/${id}/history`); } catch (e) { return; }
    const el = $("triage-history");
    if (!el || !rows.length) return;
    const name = (k) => (TRIAGE.find((t) => t[0] === k) || [k, k])[1];
    el.innerHTML = `<b>History</b><ul>${rows.map((r) => `<li><span class="muted">${new Date(r.ts * 1000).toLocaleString()} · ${esc(r.actor)}</span>
      ${r.action === "triage.bulk" ? "bulk update to" : esc(name(r.detail.from || "new")) + " →"} <b>${esc(name(r.detail.to))}</b>${r.detail.note_changed ? " · note edited" : ""}</li>`).join("")}</ul>`;
  }

  function drawApChart(d, alert) {
    const tl = d.timeline || [];
    if (!tl.length) {
      $("ap-chart").innerHTML = '<div class="empty">Appears once the learning period is over.</div>';
      return;
    }
    const x = tl.map((r) => X(r.ts));
    const decor = thresholdDecor();
    const traces = [
      { x, y: tl.map((r) => r.raw_score), name: "Raw (each 10 s)", mode: "lines",
        line: { color: css("--muted"), width: 1, dash: "dot" }, hovertemplate: "raw %{y:.1f}<extra></extra>" },
      { x, y: tl.map((r) => r.score), name: "Smoothed (used for alerts)", mode: "lines",
        line: { color: css("--s1"), width: 2.5 }, hovertemplate: "smoothed %{y:.1f}<extra></extra>" },
    ];
    if (alert) {
      const pts = [[alert.first_ts, "alert raised", "diamond"], [alert.high_ts, "reached HIGH", "triangle-up"]].filter((p) => p[0] != null);
      traces.push({ x: pts.map((p) => X(p[0])), y: pts.map((p) => (tl.find((r) => r.ts === p[0]) || {}).score),
        mode: "markers", name: "Alert", text: pts.map((p) => p[1]), hovertemplate: "%{text}<extra></extra>",
        marker: { size: 11, symbol: pts.map((p) => p[2]), color: css("--critical"), line: { color: css("--surface"), width: 2 } } });
    }
    Plotly.react("ap-chart", traces, baseLayout({
      showlegend: true, legend: { orientation: "h", y: -0.28, x: 0, font: { color: css("--text-2"), size: 11 } },
      hovermode: "x unified", margin: { l: 36, r: 10, t: 8, b: 64 },
      shapes: decor.shapes, annotations: decor.annotations,
    }), PLOT_CFG);
  }

  // detail interactions (event delegation; survives re-render)
  $("detail").addEventListener("click", async (e) => {
    if (e.target.closest("[data-export]") && state.detail) { exportReport(state.detail); return; }
    const sb = e.target.closest("[data-series]");
    if (sb) {
      state.seriesKind = sb.dataset.series;
      sb.parentElement.querySelectorAll(".seg-btn").forEach((b) => { b.classList.toggle("active", b === sb); b.setAttribute("aria-pressed", b === sb); });
      drawSeries();
      return;
    }
    const ev = e.target.closest("[data-evidence]");
    if (ev) {
      e.preventDefault();
      const r = await fetch(ev.href, { credentials: "same-origin" });
      if (!r.ok) { const j = await r.json().catch(() => ({})); notice(j.error || "No evidence available", "error"); return; }
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a");
      a.href = url; a.download = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "evidence.pcap";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      notice(`Saved ${r.headers.get("X-GhostAP-Frames") || "the"} beacons. Open the file in Wireshark.`, "ok");
      return;
    }
    if (e.target.closest("[data-accept-baseline]") && state.detail) {
      const a = state.detail.ap;
      const r = await post("/api/monitored/accept", { ssid: a.ssid, bssid: a.bssid });
      notice(r.ok ? `${a.bssid} added to ${a.ssid}'s saved baseline.` : (r.data && r.data.error) || "Could not save", r.ok ? "ok" : "error");
      return;
    }
    if (e.target.closest("[data-trust]") && state.detail) {
      const r = await post("/api/allowlist", { add: state.detail.ap.bssid });
      notice(r.ok ? `${state.detail.ap.bssid} is now trusted.` : (r.data && r.data.error) || "Could not save", r.ok ? "ok" : "error");
      if (r.ok) { delete state.last.detail; loadDetail(); }
      return;
    }
    const tb = e.target.closest("[data-triage]");
    if (tb) {
      tb.parentElement.querySelectorAll(".seg-btn").forEach((b) => { b.classList.toggle("active", b === tb); b.setAttribute("aria-pressed", b === tb); });
      return;
    }
    if (e.target.id === "triage-save") {
      const box = e.target.closest(".triage");
      const active = box.querySelector(".seg-btn.active");
      const r = await post(`/api/alerts/${box.dataset.alert}/triage`,
        { status: active ? active.dataset.triage : "new", note: $("triage-note").value });
      $("triage-saved").textContent = r.ok ? "Saved " + new Date().toLocaleTimeString() : "Could not save (" + r.status + ")";
      refresh(true, true);
    }
  });
  $("detail").addEventListener("change", async (e) => {
    if (e.target.dataset && e.target.hasAttribute("data-mute") && e.target.value && state.detail) {
      const hours = Number(e.target.value), ap = state.detail.ap;
      const r = await post("/api/mutes", { kind: "bssid", value: ap.bssid, hours });
      notice(r.ok ? `${ap.bssid} muted for ${hours < 24 ? hours + " h" : hours / 24 + " day" + (hours > 24 ? "s" : "")}. Unmute it on the System page.` : (r.data && r.data.error) || "Could not mute", r.ok ? "ok" : "error");
      e.target.value = "";
      if (r.ok) refresh(true, true);
      return;
    }
    const list = e.target.closest(".checklist");
    if (!list) return;
    const ids = [...list.querySelectorAll("input:checked")].map((i) => Number(i.dataset.i));
    store.set("ghostap-ruleout-" + list.dataset.alert, JSON.stringify(ids));
  });

  // ------------------------------------------------------------------ F023 since you last looked
  // Kept in this browser only: which alerts (and at which level) you have already seen.
  const seenKey = () => "ghostap-seen-" + ((state.summary && state.summary.status && state.summary.status.session) || "db");
  function initSeen(ghost) {
    let s = null;
    try { s = JSON.parse(store.get(seenKey()) || "null"); } catch (e) { s = null; }
    if (!s || !s.alerts) {                       // first visit: nothing is "new" yet
      s = { at: Date.now(), alerts: Object.fromEntries(ghost.map((a) => [a.id, a.level])) };
      store.set(seenKey(), JSON.stringify(s));
    }
    state.seen = s;
  }
  function unseenOf(a) {
    const s = state.seen;
    if (!s || a.muted || a.triage_status === "false_positive") return null;
    const prev = s.alerts[a.id];
    return prev == null ? "new" : prev !== "HIGH" && a.level === "HIGH" ? "escalated" : null;
  }
  function markSeen(alerts, all) {
    if (!state.seen) return;
    alerts.forEach((a) => { state.seen.alerts[a.id] = a.level; });
    if (all) state.seen.at = Date.now();
    store.set(seenKey(), JSON.stringify(state.seen));
    renderSince();
  }
  function ago(ms) {
    const m = Math.round((Date.now() - ms) / 60000);
    return m < 1 ? "just now" : m < 60 ? m + " min ago" : m < 48 * 60 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " days ago";
  }
  function renderSince() {
    const el = $("since");
    const fresh = (state.ghost || []).filter(unseenOf);
    if (!fresh.length) { el.hidden = true; return; }
    const nNew = fresh.filter((a) => unseenOf(a) === "new").length, nUp = fresh.length - nNew;
    el.hidden = false;
    el.innerHTML = `<span><b>Since you last looked</b> <span class="muted">(${ago(state.seen.at)})</span>:
      ${nNew ? `${nNew} new alert${nNew > 1 ? "s" : ""}` : ""}${nNew && nUp ? ", " : ""}${nUp ? `${nUp} escalated to HIGH` : ""}.</span>
      <button class="btn small" data-since-show>Show</button><button class="btn small" data-since-ok>Mark all as seen</button>`;
  }
  $("since").addEventListener("click", (e) => {
    if (e.target.closest("[data-since-ok]")) { markSeen(state.ghost, true); renderSide(); return; }
    if (e.target.closest("[data-since-show]")) {
      const a = (state.ghost || []).find(unseenOf);
      state.tab = "alerts";
      document.querySelector('[data-tab="alerts"]').click();
      if (a) select(a.ssid, a.bssid, true);
    }
  });

  // ------------------------------------------------------------------ F039 table columns and export
  const COLS = ["Network", "BSSID", "CH", "Security", "Signal", "Beacons", "First seen", "Risk now", "Peak", "Level"];
  function loadHidden() { try { return new Set(JSON.parse(store.get("ghostap-hidden-cols") || "[]")); } catch (e) { return new Set(); } }
  function applyColumns() {
    const hidden = loadHidden(), table = document.querySelector(".ap-table");
    COLS.forEach((_, i) => table.classList.toggle("hide-c" + (i + 1), hidden.has(i + 1)));
    $("col-list").innerHTML = COLS.map((c, i) => `<label class="check"><input type="checkbox" data-col="${i + 1}" ${hidden.has(i + 1) ? "" : "checked"} ${i < 2 ? "disabled" : ""}> ${esc(c)}</label>`).join("");
  }
  $("col-list").addEventListener("change", (e) => {
    const n = Number(e.target.dataset.col), hidden = loadHidden();
    if (e.target.checked) hidden.delete(n); else hidden.add(n);
    store.set("ghostap-hidden-cols", JSON.stringify([...hidden]));
    applyColumns();
  });
  /** Spreadsheet-safe CSV: text that starts like a formula is prefixed with ' (SSIDs come from the air). */
  function csvCell(v) {
    if (v == null) return "";
    if (typeof v === "number") return String(v);
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  $("export-csv").addEventListener("click", () => {
    const rows = tableRows();
    const head = ["ssid", "bssid", "vendor", "channels", "security", "rssi_avg_dbm", "beacons", "first_seen_utc", "first_seen_s",
      "risk_now", "peak_risk", "level", "triage", "in_baseline"];
    const lines = [head.join(",")].concat(rows.map((p) => [p.ssid, p.bssid, p.vendor, p.channels, p.securities,
      p.rssi_avg == null ? null : Math.round(p.rssi_avg * 10) / 10, p.frames, new Date(p.first_seen * 1000).toISOString(),
      Math.round(p.first_seen - state.t0), p.score, p.peak_score, p.level, p.triage_status, p.in_baseline ? "yes" : "no"].map(csvCell).join(",")));
    const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "ghostap_access_points.csv";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    notice(`Exported ${rows.length} access point${rows.length === 1 ? "" : "s"}${state.search ? " matching the search" : ""}.`, "ok");
  });

  // ------------------------------------------------------------------ F022 layout
  const PANELS = [["tiles", "Summary tiles"], ["since", "Since you last looked"], ["incident", "Incident story"],
    ["main", "Alerts and details"], ["timeline", "Risk over time"], ["table", "All access points"]];
  function loadLayout() {
    try {
      const l = JSON.parse(store.get("ghostap-layout") || "null");
      if (l && Array.isArray(l.order)) return { order: l.order.filter((k) => PANELS.some((p) => p[0] === k)), hidden: l.hidden || [] };
    } catch (e) { /* default */ }
    return { order: PANELS.map((p) => p[0]), hidden: [] };
  }
  function applyLayout() {
    const l = loadLayout();
    PANELS.forEach(([k]) => { if (!l.order.includes(k)) l.order.push(k); });
    l.order.forEach((k, i) => {
      const el = document.querySelector(`[data-panel="${k}"]`);
      if (el) { el.style.order = String(i + 1); el.classList.toggle("panel-off", l.hidden.includes(k)); }
    });
    $("layout-list").innerHTML = l.order.map((k, i) => {
      const name = (PANELS.find((p) => p[0] === k) || [k, k])[1];
      return `<li><label class="check"><input type="checkbox" data-show="${k}" ${l.hidden.includes(k) ? "" : "checked"}> ${esc(name)}</label>
        <span><button class="btn small" data-move="${k}" data-dir="-1" ${i === 0 ? "disabled" : ""} aria-label="Move ${esc(name)} up">↑</button>
        <button class="btn small" data-move="${k}" data-dir="1" ${i === l.order.length - 1 ? "disabled" : ""} aria-label="Move ${esc(name)} down">↓</button></span></li>`;
    }).join("");
    return l;
  }
  $("layout-list").addEventListener("click", (e) => {
    const b = e.target.closest("[data-move]");
    if (!b) return;
    const l = loadLayout(), i = l.order.indexOf(b.dataset.move), j = i + Number(b.dataset.dir);
    if (i < 0 || j < 0 || j >= l.order.length) return;
    [l.order[i], l.order[j]] = [l.order[j], l.order[i]];
    store.set("ghostap-layout", JSON.stringify(l));
    applyLayout();
    const again = $("layout-list").querySelector(`[data-move="${b.dataset.move}"][data-dir="${b.dataset.dir}"]`);
    if (again && !again.disabled) again.focus();
  });
  $("layout-list").addEventListener("change", (e) => {
    const k = e.target.dataset.show;
    if (!k) return;
    const l = loadLayout();
    l.hidden = e.target.checked ? l.hidden.filter((x) => x !== k) : [...new Set([...l.hidden, k])];
    store.set("ghostap-layout", JSON.stringify(l));
    applyLayout();
    if (e.target.checked && k === "timeline") renderTimeline();
  });
  // F080 colour-blind safe palette and high contrast
  function applyAppearance() {
    const palette = store.get("ghostap-palette") || "standard";
    const contrast = store.get("ghostap-contrast") || (window.matchMedia("(prefers-contrast: more)").matches ? "more" : "normal");
    const root = document.documentElement;
    if (palette === "cb") root.setAttribute("data-palette", "cb"); else root.removeAttribute("data-palette");
    root.setAttribute("data-contrast", contrast);
    document.querySelectorAll('input[name="palette"]').forEach((i) => { i.checked = i.value === palette; });
    document.querySelectorAll('input[name="contrast"]').forEach((i) => { i.checked = i.value === contrast; });
  }
  $("layout-dlg").addEventListener("change", (e) => {
    if (e.target.name !== "palette" && e.target.name !== "contrast") return;
    store.set("ghostap-" + e.target.name, e.target.value);
    applyAppearance();
    rethemeCharts();
    renderTable();
  });
  $("layout-reset").addEventListener("click", () => { store.del("ghostap-layout"); applyLayout(); renderTimeline(); });
  $("layout-btn").addEventListener("click", () => { applyLayout(); $("layout-dlg").showModal(); });

  // ------------------------------------------------------------------ timeline + events
  function renderTimeline() {
    const el = $("timeline-chart");
    let series = state.series;
    if (state.onlyAlerting) series = series.filter((s) => s.peak >= th().medium);
    if (!state.series.length) {
      Plotly.purge(el);
      el.innerHTML = '<div class="empty">The risk timeline appears once the learning period is over.</div>';
      return;
    }
    const ph = el.querySelector(".empty");
    if (ph) ph.remove();
    state.series.filter((s) => !s.aggregate).sort((a, b) => a.ts[0] - b.ts[0] || keyOf(a).localeCompare(keyOf(b))).forEach((s) => colorFor(keyOf(s)));
    const anySel = state.sel && series.some(isSel);
    const traces = [];
    let otherShown = false;
    series.forEach((s) => {
      if (s.aggregate) {               // F038: every other access point folded into one line
        traces.push({ x: s.ts.map((t) => X(t)), y: state.scoreField === "raw" ? s.raw : s.score, mode: "lines",
          name: `${s.aggregate} other access points (highest)`, line: { color: css("--s-other"), width: 1, dash: "dot" },
          hovertemplate: `highest of ${s.aggregate} other APs: %{y:.1f}<extra></extra>` });
        return;
      }
      const k = keyOf(s), other = state.colorOf.get(k) >= SLOTS, sel = isSel(s);
      traces.push({
        x: s.ts.map((t) => X(t)), y: state.scoreField === "raw" ? s.raw : s.score, mode: "lines",
        name: other ? "Other APs" : esc(`${s.ssid} ${s.bssid}`), legendgroup: other ? "other" : k,
        showlegend: !other || !otherShown,
        opacity: anySel && !sel ? 0.35 : 1,
        line: { color: colorFor(k), width: sel ? 4 : other ? 1 : 2 },
        customdata: s.ts.map(() => [s.ssid, s.bssid]),
        hovertemplate: `${esc(s.ssid)} ${esc(s.bssid)}: %{y:.1f}<extra></extra>`,
      });
      if (other) otherShown = true;
    });
    const marks = state.events.filter((e) => (e.type === "alert" || e.type === "escalated") && series.some((s) => s.ssid === e.ssid && s.bssid === e.bssid));
    if (marks.length) {
      const yAt = (e) => {
        const s = series.find((x) => x.ssid === e.ssid && x.bssid === e.bssid);
        const i = s ? s.ts.indexOf(e.ts) : -1;
        return i >= 0 ? (state.scoreField === "raw" ? s.raw : s.score)[i] : null;
      };
      traces.push({
        x: marks.map((e) => X(e.ts)), y: marks.map(yAt), mode: "markers", name: "Alert events",
        customdata: marks.map((e) => [e.ssid, e.bssid]),
        marker: { size: 11, symbol: marks.map((e) => (e.type === "escalated" ? "triangle-up" : "diamond")),
                  color: marks.map((e) => colorFor(keyOf(e))), line: { color: css("--surface"), width: 2 } },
        text: marks.map((e) => `${esc(e.text)}: ${esc(e.ssid)} ${esc(e.bssid)}`), hovertemplate: "%{text}<extra></extra>",
      });
    }
    const decor = thresholdDecor(), s = state.summary;
    const end = s && s.capture_end != null ? s.capture_end : null;
    const win = { "5m": 300, "15m": 900, "1h": 3600 }[state.range];
    const from = win && end != null ? Math.max(state.t0, end - win) : state.t0;
    // F037: analyst notes as dotted vertical lines
    (state.notes || []).forEach((n) => {
      decor.shapes.push({ type: "line", xref: "x", yref: "paper", x0: X(n.ts), x1: X(n.ts), y0: 0, y1: 1,
        line: { color: css("--accent"), width: 1, dash: "dot" } });
      decor.annotations.push({ xref: "x", yref: "paper", x: X(n.ts), y: 1, yanchor: "bottom", showarrow: false,
        text: esc(n.text.length > 28 ? n.text.slice(0, 27) + "…" : n.text), font: { size: 10, color: css("--accent-ink") },
        hovertext: esc(n.text + " (" + rel(n.ts) + ")") });
    });
    Plotly.react(el, traces, baseLayout({
      showlegend: true, legend: { orientation: "h", y: -0.22, x: 0, font: { color: css("--text-2") } },
      hovermode: "closest", margin: { l: 40, r: 14, t: state.notes && state.notes.length ? 22 : 8, b: 40 },
      xaxis: Object.assign(baseLayout().xaxis, { range: end != null ? [X(from), X(end)] : undefined }),
      yaxis: Object.assign(baseLayout().yaxis, { title: { text: state.scoreField === "raw" ? "raw risk" : "risk", font: { size: 11, color: css("--muted") } } }),
      shapes: decor.shapes, annotations: decor.annotations, uirevision: "zoom-" + state.range + "-" + state.clock,
    }), PLOT_CFG);
    if (!state.plotBound) {
      el.on("plotly_click", (ev) => {
        const p = ev.points && ev.points[0];
        if (p && p.customdata) select(p.customdata[0], p.customdata[1], true);
      });
      state.plotBound = true;
    }
  }
  document.querySelectorAll("[data-score]").forEach((b) => b.addEventListener("click", () => {
    state.scoreField = b.dataset.score;
    document.querySelectorAll("[data-score]").forEach((x) => { x.classList.toggle("active", x === b); x.setAttribute("aria-pressed", x === b); });
    renderTimeline();
  }));
  $("only-alerting").addEventListener("change", (e) => { state.onlyAlerting = e.target.checked; renderTimeline(); });
  document.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => {
    state.range = b.dataset.range;
    document.querySelectorAll("[data-range]").forEach((x) => { x.classList.toggle("active", x === b); x.setAttribute("aria-pressed", x === b); });
    renderTimeline();
  }));

  // ------------------------------------------------------------------ F037 notes on the timeline
  async function loadNotes() {
    try { state.notes = await get("/api/annotations"); } catch (e) { state.notes = []; }
    renderNotes();
  }
  function renderNotes() {
    const end = state.summary && state.summary.capture_end;
    const at = $("note-at");
    if (at && !at.value && end != null) at.placeholder = state.clock ? clockText(end).split(" ").pop() : "t+" + Math.round(end - state.t0);
    $("notes").innerHTML = (state.notes || []).map((n) => `<li><span class="t">${rel(n.ts)}</span><span>${esc(n.text)}</span>
      <button class="icon-x" data-note-del="${n.id}" aria-label="Delete note">✕</button></li>`).join("");
  }
  /** "t+120", "120", "14:05" or "14:05:30" (clock time on the capture's last day) -> epoch seconds */
  function parseWhen(v) {
    const s = state.summary;
    if (!v) return s ? s.capture_end : null;
    v = v.trim();
    let m = /^t?\+?(\d+(?:\.\d+)?)\s*s?$/.exec(v);
    if (m) return state.t0 + Number(m[1]);
    m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(v);
    if (m && s) {
      const d = new Date(s.capture_end * 1000);
      d.setHours(Number(m[1]), Number(m[2]), Number(m[3] || 0), 0);
      return d.getTime() / 1000;
    }
    return NaN;
  }
  $("note-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const ts = parseWhen($("note-at").value), text = $("note-text").value;
    if (!Number.isFinite(ts)) { notice("Write the time as t+120, 120 or 14:05:30.", "error"); return; }
    const r = await post("/api/annotations", { ts, text });
    if (!r.ok) { notice((r.data && r.data.error) || "Could not save the note", "error"); return; }
    $("note-text").value = ""; $("note-at").value = "";
    await loadNotes();
    renderTimeline();
  });
  $("notes").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-note-del]");
    if (!b) return;
    const r = await post(`/api/annotations/${b.dataset.noteDel}/delete`, {});
    if (!r.ok) { notice("Could not delete the note", "error"); return; }
    await loadNotes();
    renderTimeline();
  });

  // Advanced view: off by default, so the everyday screen shows only what most people need.
  function applyAdvanced() {
    const on = store.get("ghostap-advanced") === "1";
    document.body.classList.toggle("simple", !on);
    $("advanced-btn").setAttribute("aria-pressed", on);
    $("advanced-btn").classList.toggle("on", on);
  }
  $("advanced-btn").addEventListener("click", () => {
    store.set("ghostap-advanced", store.get("ghostap-advanced") === "1" ? "0" : "1");
    applyAdvanced();
    if (state.series.length) renderTimeline();
  });
  // menus (details.menu) close on outside clicks, Escape, and after choosing an item
  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.menu[open]").forEach((m) => {
      const item = e.target.closest("details.menu .menu-body button, details.menu .menu-body a");
      if (!m.contains(e.target) || (item && m.contains(item))) m.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") document.querySelectorAll("details.menu[open]").forEach((m) => m.removeAttribute("open"));
  });
  // a menu opens towards the side with room, so it never leaves the window
  document.addEventListener("toggle", (e) => {
    const m = e.target;
    if (!(m instanceof HTMLDetailsElement) || !m.classList.contains("menu") || !m.open) return;
    const body = m.querySelector(".menu-body");
    if (!body) return;
    body.style.left = ""; body.style.right = "";
    const r = body.getBoundingClientRect();
    if (r.left < 8) { body.style.left = "0"; body.style.right = "auto"; }
    else if (r.right > window.innerWidth - 8) { body.style.right = "0"; body.style.left = "auto"; }
  }, true);
  // the technical section stays open across refreshes; its chart is drawn when it opens
  $("detail").addEventListener("toggle", (e) => {
    if (e.target.id !== "tech-details") return;
    state.techOpen = e.target.open;
    if (e.target.open) drawSeries();
  }, true);

  // F036: clock time switch
  function applyClock() {
    $("clock-btn").setAttribute("aria-pressed", state.clock);
    $("clock-btn").classList.toggle("on", state.clock);
    document.body.classList.toggle("clock", state.clock);
    $("clock-btn").title = state.clock ? "Showing clock time: switch to time since the capture started" : "Showing time since the capture started: switch to clock time";
  }
  $("clock-btn").addEventListener("click", () => {
    state.clock = !state.clock;
    store.set("ghostap-clock", state.clock ? "1" : "0");
    applyClock();
    state.last = {};                    // re-render everything that shows times
    refresh(true, true);
    renderNotes();
  });

  function renderEvents() {
    const f = state.evFilter;
    const keep = (e) => f === "all" || (f === "alerts" && (e.type === "alert" || e.type === "escalated"))
      || (f === "aps" && e.type === "ap_seen") || (f === "baseline" && e.type === "baseline_alert");
    const shown = state.events.filter(keep).slice().reverse();
    $("events").innerHTML = shown.length ? shown.map((e) => `
      <li data-ssid="${esc(e.ssid)}" data-bssid="${esc(e.bssid)}" title="Inspect this access point">
        <span class="t">${rel(e.ts)}</span>
        <span>${e.type === "baseline_alert" ? '<span class="lvl"><i class="lvl-icon"></i>name-only</span>' : e.level ? lvl(e.level) : '<span class="muted">new AP</span>'}</span>
        <span class="what"><span class="swatch" style="background:${colorFor(keyOf(e))}"></span>${esc(e.text)}: <b>${esc(e.ssid)}</b> <span class="mono muted">${esc(e.bssid)}</span></span>
      </li>`).join("") : '<li class="empty">No events of this kind yet.</li>';
  }
  $("events").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-bssid]");
    if (li) select(li.dataset.ssid, li.dataset.bssid, true);
  });
  document.querySelectorAll("[data-ev]").forEach((c) => c.addEventListener("click", () => {
    state.evFilter = c.dataset.ev;
    document.querySelectorAll("[data-ev]").forEach((x) => x.classList.toggle("active", x === c));
    renderEvents();
  }));

  // ------------------------------------------------------------------ AP table
  /** The access points as the table shows them: searched and sorted. */
  function tableRows() {
    const q = state.search.trim().toLowerCase();
    const rows = state.aps.filter((a) => !q || [a.ssid, a.bssid, a.vendor, a.securities, a.channels, a.level].join(" ").toLowerCase().includes(q));
    const { key, dir } = state.sort;
    return rows.slice().sort((a, b) => {
      const x = a[key], y = b[key];
      if (x == null && y == null) return 0;
      if (x == null) return 1;
      if (y == null) return -1;
      return (typeof x === "number" ? x - y : String(x).localeCompare(String(y))) * dir;
    });
  }
  function renderTable() {
    const q = state.search.trim().toLowerCase();
    const all = tableRows();
    const LIMIT = 300;                 // F038: a large site renders in pages; search, sort and export see every row
    const rows = state.tableAll ? all : all.slice(0, LIMIT);
    $("ap-rows").innerHTML = (rows.length ? rows.map((p) => `
      <tr class="${isSel(p) ? "selected" : ""}" data-ssid="${esc(p.ssid)}" data-bssid="${esc(p.bssid)}" tabindex="0">
        <td><span class="swatch" style="background:${colorFor(keyOf(p))}"></span>${esc(p.ssid)}${p.in_baseline ? "" : ' <span class="tag new">new</span>'}</td>
        <td class="mono">${esc(p.bssid)}<span class="vendor">${esc(p.vendor || (p.local_mac ? "locally administered" : ""))}</span></td>
        <td class="num">${esc(p.channels)}</td>
        <td>${esc(p.securities)}</td>
        <td class="num">${fmt(p.rssi_avg, 0)} dBm</td>
        <td class="num">${Number(p.frames).toLocaleString()}</td>
        <td class="num">${rel(p.first_seen)}</td>
        <td class="num risk-col">${riskbar(p.score, p.level)}</td>
        <td class="num">${fmt(p.peak_score, 0)}</td>
        <td>${lvl(p.level)} ${triageTag(p.triage_status)}</td>
      </tr>`).join("") : `<tr><td colspan="10" class="empty">${q ? "No access point matches “" + esc(state.search) + "”." : "No access points yet."}</td></tr>`)
      + (all.length > rows.length ? `<tr><td colspan="10" class="more-row">Showing ${rows.length} of ${all.length} access points. <button class="btn small" data-table-all>Show all</button> or search to narrow them down.</td></tr>` : "");
  }
  $("ap-rows").addEventListener("click", (e) => {
    if (e.target.closest("[data-table-all]")) { state.tableAll = true; renderTable(); return; }
    const tr = e.target.closest("tr[data-bssid]");
    if (tr) select(tr.dataset.ssid, tr.dataset.bssid, true);
  });
  $("ap-rows").addEventListener("keydown", (e) => {
    const tr = e.target.closest("tr[data-bssid]");
    if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); select(tr.dataset.ssid, tr.dataset.bssid, true); }
  });
  $("ap-search").addEventListener("input", (e) => { state.search = e.target.value; renderTable(); });
  document.querySelectorAll("th[data-sort]").forEach((h) => h.addEventListener("click", () => {
    const k = h.dataset.sort;
    state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : (["ssid", "bssid", "securities", "channels", "level"].includes(k) ? 1 : -1) };
    document.querySelectorAll("th[data-sort]").forEach((x) => x.removeAttribute("aria-sort"));
    h.setAttribute("aria-sort", state.sort.dir > 0 ? "ascending" : "descending");
    renderTable();
  }));

  // ------------------------------------------------------------------ toasts
  function notify(alerts) {
    const now = new Map(alerts.map((a) => [a.id, a.level]));
    if (state.known) {
      alerts.forEach((a) => {
        const before = state.known.get(a.id);
        if (before === undefined || (before === "MEDIUM" && a.level === "HIGH")) toast(a, before === undefined);
      });
    }
    state.known = now;
  }
  function toast(a, isNew) {
    const t = document.createElement("div");
    t.className = "toast " + a.level;
    t.innerHTML = `<div>${lvl(a.level)} <b>${isNew ? "New alert" : "Escalated"}: ${esc(a.ssid)}</b></div>
      <button class="btn primary" data-inspect="${esc(a.ssid)}" data-bssid="${esc(a.bssid)}">Inspect</button>
      <p><span class="mono">${esc(a.bssid)}</span> · risk ${fmt(a.score, 0)}</p>`;
    $("toasts").appendChild(t);
    setTimeout(() => t.remove(), 9000);
    desktopNotify(a, isNew);
  }

  // ------------------------------------------------------------------ F055 desktop notifications
  // Only while this tab is in the background, only after the user switched them on (which
  // asks the browser for permission), and never with more than the network name and score.
  const desktopNotifyOn = () => store.get("ghostap-desktop-notify") === "1" && "Notification" in window && Notification.permission === "granted";
  function desktopNotify(a, isNew) {
    if (!desktopNotifyOn() || !document.hidden) return;
    try {
      const n = new Notification(`GhostAP: ${a.level} ${isNew ? "alert" : "escalated"}`, {
        body: `${a.ssid} · ${a.bssid} · risk ${fmt(a.score, 0)}`, tag: "ghostap-" + a.id, icon: "/static/icons/ghostap-192.png" });
      n.onclick = () => { window.focus(); select(a.ssid, a.bssid, true); n.close(); };
    } catch (e) { /* some browsers only allow notifications from a service worker */ }
  }
  async function toggleDesktopNotify() {
    if (desktopNotifyOn()) { store.set("ghostap-desktop-notify", "0"); notice("Desktop notifications off.", "ok"); return; }
    if (!("Notification" in window)) { notice("This browser does not support desktop notifications.", "error"); return; }
    const p = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
    if (p !== "granted") { notice("The browser did not allow notifications. Change it in the site settings (lock icon in the address bar).", "error"); return; }
    store.set("ghostap-desktop-notify", "1");
    notice("Desktop notifications on: you get one when a new alert appears while this tab is in the background.", "ok");
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-inspect]");
    if (b) {
      select(b.dataset.inspect, b.dataset.bssid, true);
      const toastEl = b.closest(".toast");
      if (toastEl) toastEl.remove();
      if (!window.matchMedia("(max-width: 900px)").matches) $("detail").scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
    if (e.target.closest("[data-help]")) openHelp();
    if (e.target.closest("[data-retry]")) refresh(false, true);
  });

  // ------------------------------------------------------------------ help, theme, keys
  function openHelp() {
    const w = state.summary ? state.summary.weights : {};
    $("glossary").innerHTML = Object.keys(IND).filter((k) => k !== "duplicate_ssid").map((k) =>
      `<dt>${esc(IND[k].label)} <span class="muted">(${w[k] != null ? "weight " + fmt(w[k]) : "signature / separate detector"})</span></dt><dd>${esc(IND[k].long)}</dd>`).join("");
    const dlg = $("help");
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
  }
  $("help-btn").addEventListener("click", openHelp);

  function applyTheme(t) {
    if (t) document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme(store.get("ghostap-theme"));
  $("theme-btn").addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark" ||
      (!document.documentElement.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const next = dark ? "light" : "dark";
    applyTheme(next);
    store.set("ghostap-theme", next);
    rethemeCharts();
  });
  function rethemeCharts() {
    state.last = {};
    if (state.series.length) renderTimeline();
    loadDetail();
  }
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", rethemeCharts);

  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
    if (e.key === "Escape" && typing) { document.activeElement.blur(); return; }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "/") { e.preventDefault(); $("ap-search").focus(); $("table-card").scrollIntoView({ block: "start" }); }
    else if (e.key === "?") { e.preventDefault(); openHelp(); }
    else if (e.key === "j" || e.key === "k") {
      const items = [...document.querySelectorAll("#side-list [data-bssid]")];
      if (!items.length) return;
      let i = items.findIndex((b) => b.classList.contains("selected"));
      i = e.key === "j" ? Math.min(items.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
      items[i].focus();
      select(items[i].dataset.ssid, items[i].dataset.bssid, false);
    }
  });

  // ------------------------------------------------------------------ polling
  let timer = null;
  const hooks = [];                 // extra scripts (presentation mode) run after every refresh
  async function refresh(once, force) {
    try {
      const summary = await get("/api/summary");
      state.summary = summary;
      state.t0 = summary.capture_start;
      state.offline = false;
      renderStatus(summary);
      if (changed("verdict", [summary.top_alert, summary.alerts, summary.dismissed_alerts, summary.baseline_complete,
        summary.aps, summary.status.state, summary.status.message,
        Math.round((summary.capture_end || 0) - (summary.capture_start || 0))])) renderVerdict(summary);
      renderTiles(summary);
      hooks.forEach((h) => { try { h(summary); } catch (err) { console.error(err); } });

      // The heavy lists only change when the server's data version changes.
      if (force || summary.data_version !== state.version) {
        const [ghost, base, networks, series, events, aps] = await Promise.all([
          get("/api/alerts?detector=ghostap,deauth,flood"), get("/api/alerts?detector=baseline"),
          get("/api/networks"), get("/api/timeline"), get("/api/events"), get("/api/aps"),
        ]);
        state.version = summary.data_version;
        try { state.incidents = await get("/api/incidents"); } catch (e) { state.incidents = []; }
        await loadNotes();
        if (state.seen === undefined) initSeen(ghost);
        notify(ghost);
        state.ghost = ghost; state.base = base; state.networks = networks; state.events = events; state.aps = aps; state.series = series;
        if (changed("side", [ghost, base, networks, state.tab])) renderSide();
        if (changed("incident", state.incidents)) renderIncident();
        renderSince();
        if (changed("timeline", [series, events, summary.capture_end, state.notes])) renderTimeline();
        if (changed("events", events)) renderEvents();
        if (changed("aps", aps)) renderTable();
        if (state.sel) loadDetail();
      }
      if (!state.sel) {
        const v = readViewHash();
        if (v && v.ap) select(v.ap[0], v.ap[1], false);
        else if (state.ghost.length) select(state.ghost[0].ssid, state.ghost[0].bssid, false);
      }
      if (!once) schedule(summary.status && summary.status.state === "running" ? 2000 : 10000);
    } catch (e) {
      showOffline(e);
      if (!once) schedule(e.status === 401 ? 30000 : 5000);
    }
  }
  function showOffline(e) {
    state.offline = true;
    delete state.last.verdict;
    const auth = e && e.status === 401;
    $("status").innerHTML = `<span class="pill"><i class="dot error"></i>${auth ? "sign-in needed" : "not connected"}</span>`;
    $("verdict").className = "verdict error offline";
    $("verdict-icon").innerHTML = ICONS.error;
    $("verdict-title").textContent = auth ? "Sign-in needed" : "Lost connection to the GhostAP server";
    $("verdict-sub").textContent = auth
      ? "Your sign-in ended (signed out, expired after 12 hours without activity, or revoked)."
      : "The data below is from the last successful update. Is GhostAP still running? Retrying every 5 seconds.";
    $("verdict-actions").innerHTML = auth ? '<a class="btn primary" href="/">Sign in</a>' : '<button class="btn" data-retry>Retry now</button>';
    $("baseline-progress").hidden = true;
  }
  function schedule(ms) { clearTimeout(timer); timer = setTimeout(() => refresh(false), ms); }

  // ------------------------------------------------------------------ pages (router)
  // Other pages live in static/views/*.js and register themselves in GA.views.
  const views = {};
  let currentView = "dashboard";
  /** F083: "#ap=<ssid>|<bssid>&tab=…&range=…&clock=1&lvl=…&st=…&q=…&s=<session>" (each value
   *  URI-encoded; "|" separates the encoded SSID and BSSID). */
  function readViewHash() {
    const h = location.hash.replace(/^#/, "");
    if (!/^(ap|tab|range|s)=/.test(h)) return null;
    const out = {};
    h.split("&").forEach((part) => {
      const i = part.indexOf("=");
      if (i < 1) return;
      const k = part.slice(0, i), raw = part.slice(i + 1);
      try {
        if (k === "ap") { const j = raw.indexOf("|"); if (j > 0) out.ap = [decodeURIComponent(raw.slice(0, j)), decodeURIComponent(raw.slice(j + 1))]; }
        else out[k] = decodeURIComponent(raw);
      } catch (e) { /* malformed part: ignore it */ }
    });
    return out;
  }
  function viewLink() {
    const enc = encodeURIComponent, p = [];
    if (state.sel) p.push("ap=" + enc(state.sel.ssid) + "|" + enc(state.sel.bssid));
    if (state.tab !== "alerts") p.push("tab=" + enc(state.tab));
    if (state.range !== "all") p.push("range=" + enc(state.range));
    if (state.clock) p.push("clock=1");
    const f = state.alertFilter;
    if (f.level !== "all") p.push("lvl=" + enc(f.level));
    if (f.status !== "open") p.push("st=" + enc(f.status));
    if (f.q) p.push("q=" + enc(f.q));
    if (state.session) p.push("s=" + enc(state.session));
    return location.origin + location.pathname + (p.length ? "#" + p.join("&") : "");
  }
  /** Apply a shared link's settings once, before the first refresh. */
  function applyViewHash() {
    const v = readViewHash();
    if (!v) return;
    if (v.s && v.s !== state.session) { state.session = v.s; state.sessionName = v.s; }
    if (["alerts", "networks", "baseline"].includes(v.tab)) state.tab = v.tab;
    if (["5m", "15m", "1h", "all"].includes(v.range)) {
      state.range = v.range;
      document.querySelectorAll("[data-range]").forEach((x) => { x.classList.toggle("active", x.dataset.range === v.range); x.setAttribute("aria-pressed", x.dataset.range === v.range); });
    }
    if (v.clock === "1") state.clock = true;              // this tab only; not saved
    if (["HIGH", "MEDIUM"].includes(v.lvl)) state.alertFilter.level = v.lvl;
    if (["open", "all", "new", "investigating", "confirmed", "dismissed"].includes(v.st)) state.alertFilter.status = v.st;
    if (v.q) state.alertFilter.q = v.q.slice(0, 100);
    document.querySelectorAll(".tab").forEach((t) => { t.classList.toggle("active", t.dataset.tab === state.tab); t.setAttribute("aria-selected", t.dataset.tab === state.tab); });
  }

  function viewFromHash() {
    const h = location.hash.replace(/^#/, "");
    if (!h || /^(ap|tab|range|s)=/.test(h)) return "dashboard";
    const name = h.split(/[?&=]/)[0];
    return views[name] ? name : "dashboard";
  }
  // Four everyday pages in the bar; everything else in "More", each with a one-line purpose.
  const PRIMARY = ["dashboard", "monitored", "sessions", "system"];
  const PURPOSE = {
    label: "Lab work: mark which access points were your test twin",
    evaluation: "Lab work: measure how accurate detection is on labelled captures",
    whatif: "Try other weights and thresholds without changing anything",
    sensors: "Other GhostAP sensors that report to this one",
    ask: "Ask questions about this session (AI, opt-in)",
    settings: "Change detection and notification settings (admins)",
    account: "Password, two-factor sign-in, signed-in devices",
  };
  const MORE_ORDER = ["label", "evaluation", "whatif", "sensors", "ask", "settings", "account"];
  function renderNav() {
    const name = (k) => (k === "dashboard" ? T("nav.dashboard", "Dashboard") : T("nav." + k, views[k].title));
    const link = (k) => `<a href="#${k === "dashboard" ? "" : k}" class="nav-link ${k === currentView ? "active" : ""}" ${k === currentView ? 'aria-current="page"' : ""}>${esc(name(k))}</a>`;
    const more = Object.keys(views).filter((k) => !PRIMARY.includes(k) && !views[k].navHidden)
      .sort((a, b) => (MORE_ORDER.indexOf(a) + 1 || 99) - (MORE_ORDER.indexOf(b) + 1 || 99));
    const inMore = more.includes(currentView);
    $("nav").innerHTML = PRIMARY.filter((k) => k === "dashboard" || views[k]).map(link).join("") + (more.length ? `
      <details class="menu nav-more"><summary class="nav-link ${inMore ? "active" : ""}">${inMore ? esc(name(currentView)) : "More"} ▾</summary>
        <div class="menu-body menu-list">${more.map((k) => `<a href="#${k}" class="${k === currentView ? "on" : ""}">${esc(name(k))}<small>${esc(PURPOSE[k] || "")}</small></a>`).join("")}</div>
      </details>` : "");
  }
  function route() {
    const name = viewFromHash();
    const prev = currentView;
    currentView = name;
    document.querySelector('[data-view="dashboard"]').hidden = name !== "dashboard";
    const root = $("view-root");
    root.hidden = name === "dashboard";
    if (prev !== name && views[prev] && views[prev].hide) views[prev].hide();
    if (name !== "dashboard") {
      root.innerHTML = "";
      views[name].show(root);
      document.title = views[name].title + " · GhostAP";
    }
    renderNav();
    renderSessionBanner();
  }
  window.addEventListener("hashchange", route);
  function renderSessionBanner() {
    const b = $("session-banner");
    if (!state.session) { b.hidden = true; return; }
    b.hidden = false;
    b.innerHTML = `Viewing saved session <b>${esc(state.sessionName || state.session)}</b>. Changes such as triage are saved into that session. <button class="btn small" data-live>Back to the current session</button>`;
  }
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-live]")) setSession(null, null);
  });
  /** Switch every page to a past session (id) or back to the current one (null). */
  function setSession(id, name) {
    state.session = id;
    state.sessionName = name;
    try { sessionStorage.setItem("ghostap-session", JSON.stringify(id ? [id, name] : null)); } catch (e) { /* ignore */ }
    state.version = null; state.sel = null; state.last = {}; state.known = null;
    state.colorOf = new Map();
    renderSessionBanner();
    if (currentView !== "dashboard" && views[currentView]) { $("view-root").innerHTML = ""; views[currentView].show($("view-root")); }
    refresh(true, true);
  }
  try {
    const saved = JSON.parse(sessionStorage.getItem("ghostap-session") || "null");
    if (saved) { state.session = saved[0]; state.sessionName = saved[1]; }
  } catch (e) { /* ignore */ }

  window.GA = {
    state, views, $, esc, css, rel, fmt, lvl, label, ssidLabel, IND, get, post, notice, uptime,
    select: (ssid, bssid) => { location.hash = ""; select(ssid, bssid, true); },
    refresh: () => refresh(true, true), setSession, route, onRefresh: (fn) => hooks.push(fn),
    openHelp: () => openHelp(), openLayout: () => { applyLayout(); $("layout-dlg").showModal(); },
    toggleClock: () => $("clock-btn").click(), toggleTheme: () => $("theme-btn").click(),
    exportCsv: () => $("export-csv").click(), tableRows: () => tableRows(),
    desktopNotifyOn: () => desktopNotifyOn(), toggleDesktopNotify: () => toggleDesktopNotify(),
    setTab: (t) => setTab(t), viewLink: () => viewLink(), renderNav: () => renderNav(), markAllSeen: () => { markSeen(state.ghost, true); renderSide(); },
    setRange: (r) => { const b = document.querySelector(`[data-range="${r}"]`); if (b) b.click(); },
    currentView: () => currentView,
    register(name, view) { views[name] = view; renderNav(); if (viewFromHash() === name) route(); },
  };
  applyAppearance();
  // F065: who is signed in; viewers get a read-only page (the server enforces it anyway)
  get("/api/me").then((m) => {
    state.me = m;
    document.body.classList.toggle("role-viewer", m.role === "viewer");
    const chip = $("user-chip");
    if (m.kind === "user" || m.kind === "viewer") {
      chip.hidden = false;
      chip.innerHTML = `<a href="#account" class="nav-link" title="Account, two-factor sign-in, signed-in devices">${esc(m.kind === "viewer" ? "read-only view" : m.name)} <span class="muted">${esc(m.role)}</span></a>`;
    }
  }).catch(() => {});
  // F082 language picker
  if (window.GA_I18N) {
    $("lang-select").innerHTML = window.GA_I18N.langs.map(([k, n]) => `<option value="${k}" ${k === window.GA_I18N.lang ? "selected" : ""}>${esc(n)}</option>`).join("");
    $("lang-select").addEventListener("change", (e) => {
      window.GA_I18N.set(e.target.value);
      state.last = {};
      renderNav();
      if (state.summary) renderVerdict(state.summary);
    });
    window.GA_I18N.apply();
  }
  state.clock = store.get("ghostap-clock") === "1";
  applyViewHash();
  applyClock();
  applyAdvanced();
  renderSessionBanner();
  applyColumns();
  applyLayout();
  renderNav();
  refresh(false);
})();
