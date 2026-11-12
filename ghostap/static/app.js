/* GhostAP dashboard: polls the Flask API and renders with Plotly. */
(function () {
  "use strict";

  const LABELS = {
    security_downgrade: "Security downgrade",
    new_bssid_oui: "New BSSID / vendor",
    tsf_anomaly: "TSF / uptime",
    bssid_conflict: "Cloned BSSID",
    rssi_jump: "Signal jump",
    channel_deviation: "Channel deviation",
    beacon_interval_mismatch: "Beacon interval",
    duplicate_ssid: "Duplicate SSID",
  };
  const SLOTS = 7; // categorical slots before folding into "Other"

  const state = {
    detector: "ghostap",
    selected: null,       // alert id
    summary: null,
    t0: null,
    colorOf: new Map(),   // "ssid|bssid" -> slot index (by first appearance; never re-ranked)
    lastJSON: {},
  };

  // ---------- helpers ----------
  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const rel = (ts) => (ts == null || state.t0 == null) ? "–" : "t+" + Math.round(ts - state.t0) + "s";
  const fmt = (n, d = 1) => (n == null ? "–" : Number(n).toFixed(d));
  const key = (o) => o.ssid + "|" + o.bssid;
  const level = (lvl) => lvl
    ? `<span class="lvl"><i class="lvl-icon ${esc(lvl)}"></i>${esc(lvl)}</span>`
    : `<span class="muted">–</span>`;

  function colorFor(k) {
    if (!state.colorOf.has(k)) state.colorOf.set(k, state.colorOf.size);
    const i = state.colorOf.get(k);
    return i < SLOTS ? css("--s" + (i + 1)) : css("--s-other");
  }

  async function get(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url + " -> " + r.status);
    return r.json();
  }

  // Only re-render a section when its data actually changed.
  function changed(name, data) {
    const s = JSON.stringify(data);
    if (state.lastJSON[name] === s) return false;
    state.lastJSON[name] = s;
    return true;
  }

  function baseLayout(extra) {
    return Object.assign({
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
      font: { family: 'system-ui, -apple-system, "Segoe UI", sans-serif', size: 12, color: css("--text-2") },
      margin: { l: 44, r: 16, t: 10, b: 40 },
      hoverlabel: { bgcolor: css("--surface"), bordercolor: css("--axis"), font: { color: css("--text") } },
      xaxis: { gridcolor: css("--grid"), linecolor: css("--axis"), zeroline: false, tickfont: { color: css("--muted") } },
      yaxis: { gridcolor: css("--grid"), linecolor: css("--axis"), zeroline: false, tickfont: { color: css("--muted") } },
      showlegend: false,
    }, extra || {});
  }
  const PLOT_CFG = { displayModeBar: false, responsive: true };

  function thresholdShapes(xmax) {
    const th = state.summary ? state.summary.thresholds : { medium: 30, high: 60 };
    const line = (y, color) => ({
      type: "line", xref: "paper", x0: 0, x1: 1, y0: y, y1: y,
      line: { color, width: 1, dash: "dash" }, layer: "below",
    });
    const ann = (y, text) => ({
      xref: "paper", x: 1, y, yanchor: "bottom", xanchor: "right", showarrow: false,
      text, font: { size: 11, color: css("--muted") },
    });
    return {
      shapes: [line(th.medium, css("--serious")), line(th.high, css("--critical"))],
      annotations: [ann(th.medium, "MEDIUM ≥ " + th.medium), ann(th.high, "HIGH ≥ " + th.high)],
    };
  }

  // ---------- status + tiles ----------
  function renderSummary(s) {
    state.summary = s;
    state.t0 = s.capture_start;
    const st = s.status || {};
    const modeText = st.mode === "replay" ? `Replay ×${st.speed || "max"}`
      : st.mode === "live" ? "Live capture" : "Database";
    const clock = s.capture_end != null && s.capture_start != null
      ? `capture t+${Math.round(s.capture_end - s.capture_start)}s` : "no frames yet";
    $("status").innerHTML =
      `<span class="pill"><i class="dot ${esc(st.state)}"></i>${esc(modeText)} · ${esc(st.state || "")}</span>` +
      `<span class="mono">${esc(st.source || "")}</span><span>${esc(clock)}</span>`;

    $("t-aps").textContent = s.aps;
    $("t-frames").textContent = Number(s.frames).toLocaleString();
    $("t-high").textContent = s.alerts.HIGH;
    $("t-medium").textContent = s.alerts.MEDIUM;
    $("t-base").textContent = s.baseline_alerts;

    const banner = $("baseline-banner");
    banner.classList.remove("error");
    if (st.state === "error") {
      banner.hidden = false;
      banner.classList.add("error");
      banner.textContent = st.message;
    } else if (s.capture_start == null) {
      banner.hidden = false;
      banner.textContent = "Waiting for beacon frames…";
    } else if (!s.baseline_complete) {
      const done = Math.max(0, Math.round(s.capture_end - s.capture_start));
      banner.hidden = false;
      banner.textContent = `Learning the baseline: ${done} of ${Math.round(s.baseline_seconds)} s. ` +
        "Risk scoring starts once the baseline window is complete.";
    } else {
      banner.hidden = true;
    }
  }

  // ---------- alert list ----------
  function renderAlerts(alerts) {
    $("detector-hint").textContent = state.detector === "ghostap"
      ? "Multi-indicator weighted risk with temporal smoothing."
      : "Comparison baseline: flags every BSSID whose SSID is advertised by more than one BSSID.";
    const ul = $("alert-list");
    if (!alerts.length) {
      ul.innerHTML = `<li class="empty">No alerts${state.detector === "ghostap" ? ": all access points look normal" : ""}.</li>`;
      return;
    }
    if (state.selected == null || !alerts.some((a) => a.id === state.selected)) {
      if (state.detector === "ghostap" || state.selected == null) select(alerts[0].id, false);
    }
    ul.innerHTML = alerts.map((a) => `
      <li><button class="alert-item ${a.id === state.selected ? "selected" : ""}" data-id="${a.id}">
        ${level(a.level)}
        <span class="who">${esc(a.ssid)}</span>
        <span class="score">${fmt(a.score, 0)}</span>
        <span class="sub mono">${esc(a.bssid)} · first ${rel(a.first_ts)}${a.high_ts != null && a.high_ts !== a.first_ts ? " · HIGH " + rel(a.high_ts) : ""}</span>
      </button></li>`).join("");
  }

  $("alert-list").addEventListener("click", (e) => {
    const b = e.target.closest(".alert-item");
    if (b) select(Number(b.dataset.id), true);
  });

  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => {
      x.classList.toggle("active", x === t);
      x.setAttribute("aria-selected", x === t);
    });
    state.detector = t.dataset.detector;
    state.selected = null;
    delete state.lastJSON.alerts;
    refresh();
  }));

  function select(id, user) {
    state.selected = id;
    document.querySelectorAll(".alert-item").forEach((b) =>
      b.classList.toggle("selected", Number(b.dataset.id) === id));
    delete state.lastJSON.detail;
    loadDetail();
    if (user) $("detail").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ---------- alert detail ----------
  async function loadDetail() {
    if (state.selected == null) return;
    let a;
    try { a = await get("/api/alerts/" + state.selected); } catch (e) { return; }
    if (!changed("detail", a)) return;
    const p = a.profile || {};
    const ind = a.indicators.slice().sort((x, y) => y.contribution - x.contribution);
    $("detail").innerHTML = `
      <div class="detail-head">
        <div>
          <h2>${esc(a.ssid)} <span class="mono muted">${esc(a.bssid)}</span></h2>
          <div class="facts">
            <span>Detector <b>${a.detector === "ghostap" ? "GhostAP" : "Baseline"}</b></span>
            <span>First alert <b>${rel(a.first_ts)}</b></span>
            <span>Reached HIGH <b>${rel(a.high_ts)}</b></span>
            <span>Peak at <b>${rel(a.peak_ts)}</b></span>
            <span>Channel <b>${esc(p.channels || "–")}</b></span>
            <span>Security <b>${esc(p.securities || "–")}</b></span>
            <span>RSSI <b>${fmt(p.rssi_avg, 0)} dBm</b></span>
          </div>
        </div>
        <div style="text-align:right">
          <div class="big">${fmt(a.score, 1)}</div>
          ${level(a.level)} <span class="muted">peak risk</span>
        </div>
      </div>
      <div class="two">
        <div>
          <h3>Contribution of each indicator to the risk score (points)</h3>
          <div id="contrib-chart" class="chart"></div>
        </div>
        <div>
          <h3>Risk score of this access point over time</h3>
          <div id="ap-chart" class="chart"></div>
        </div>
      </div>
      <h3>Indicators at peak</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Indicator</th><th class="num">Value</th><th class="num">Weight</th><th class="num">Points</th><th>Reason</th></tr></thead>
        <tbody>${ind.map((c) => `
          <tr class="${c.contribution > 0 ? "" : "zero"}">
            <td>${esc(LABELS[c.name] || c.name)}</td>
            <td class="num">${fmt(c.value, 2)}</td>
            <td class="num">${fmt(c.weight, 1)}</td>
            <td class="num">${c.contribution > 0 ? "+" + fmt(c.contribution, 1) : "0"}</td>
            <td class="reason">${esc(c.reason)}</td>
          </tr>`).join("")}</tbody>
      </table></div>
      <h3>Possible benign causes to rule out</h3>
      <ul class="benign">${(a.benign_causes || []).map((b) => `<li>${esc(b)}</li>`).join("") || "<li>none</li>"}</ul>`;

    // Contribution bars: one series, one color; labels only on non-zero bars.
    const bars = ind.slice().reverse();
    Plotly.react("contrib-chart", [{
      type: "bar", orientation: "h",
      x: bars.map((c) => c.contribution),
      y: bars.map((c) => LABELS[c.name] || c.name),
      marker: { color: css("--s1") },
      text: bars.map((c) => (c.contribution > 0 ? "+" + c.contribution.toFixed(1) : "")),
      textposition: "outside", cliponaxis: false,
      textfont: { color: css("--text-2") },
      customdata: bars.map((c) => [c.value, c.weight, c.reason]),
      hovertemplate: "<b>%{y}</b><br>+%{x:.1f} points (value %{customdata[0]:.2f} × weight %{customdata[1]})<br>%{customdata[2]}<extra></extra>",
    }], baseLayout({
      margin: { l: 130, r: 40, t: 4, b: 30 },
      barcornerradius: 4, bargap: 0.35,
      xaxis: { gridcolor: css("--grid"), zeroline: false, rangemode: "tozero", tickfont: { color: css("--muted") } },
      yaxis: { automargin: true, tickfont: { color: css("--text-2") } },
    }), PLOT_CFG);

    // AP risk line: smoothed (accent) vs raw (muted).
    const tl = a.timeline || [];
    const x = tl.map((r) => r.ts - state.t0);
    const th = thresholdShapes();
    Plotly.react("ap-chart", [
      { x, y: tl.map((r) => r.raw_score), name: "Raw score", mode: "lines",
        line: { color: css("--muted"), width: 1, dash: "dot" }, hovertemplate: "raw %{y:.1f}<extra></extra>" },
      { x, y: tl.map((r) => r.score), name: "Smoothed score", mode: "lines",
        line: { color: css("--s1"), width: 2 }, hovertemplate: "smoothed %{y:.1f}<extra></extra>" },
    ], baseLayout({
      showlegend: true, legend: { orientation: "h", y: 1.12, x: 0, font: { color: css("--text-2") } },
      hovermode: "x unified",
      margin: { l: 36, r: 12, t: 24, b: 36 },
      xaxis: { title: { text: "capture time (s)", font: { size: 11, color: css("--muted") } },
               gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
      yaxis: { range: [0, 100], gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
      shapes: th.shapes, annotations: th.annotations,
    }), PLOT_CFG);
  }

  // ---------- timeline + events ----------
  function renderTimeline(series, events) {
    if (!series.length) {
      Plotly.purge("timeline-chart");
      $("timeline-chart").innerHTML = '<div class="empty">The risk timeline appears once the baseline is learned.</div>';
    } else {
      const placeholder = $("timeline-chart").querySelector(".empty");
      if (placeholder) placeholder.remove();
      // Assign colors by first appearance, so a color always follows the same AP.
      series.slice().sort((a, b) => a.ts[0] - b.ts[0] || key(a).localeCompare(key(b)))
        .forEach((s) => colorFor(key(s)));
      const traces = [];
      let otherShown = false;
      series.forEach((s) => {
        const k = key(s);
        const isOther = state.colorOf.get(k) >= SLOTS;
        traces.push({
          x: s.ts.map((t) => t - state.t0), y: s.score, mode: "lines",
          name: isOther ? "Other APs" : esc(`${s.ssid} ${s.bssid}`),
          legendgroup: isOther ? "other" : k,
          showlegend: !isOther || !otherShown,
          line: { color: colorFor(k), width: isOther ? 1 : 2 },
          hovertemplate: `${esc(s.ssid)} ${esc(s.bssid)}: %{y:.1f}<extra></extra>`,
        });
        if (isOther) otherShown = true;
      });
      // Alert markers on the line where they fired.
      const marks = events.filter((e) => e.type === "alert" || e.type === "escalated");
      const scoreAt = (e) => {
        const s = series.find((x) => x.ssid === e.ssid && x.bssid === e.bssid);
        if (!s) return null;
        const i = s.ts.indexOf(e.ts);
        return i >= 0 ? s.score[i] : null;
      };
      if (marks.length) {
        traces.push({
          x: marks.map((e) => e.ts - state.t0), y: marks.map(scoreAt), mode: "markers",
          name: "Alert events", showlegend: true,
          marker: { size: 10, symbol: marks.map((e) => (e.type === "escalated" ? "triangle-up" : "diamond")),
                    color: marks.map((e) => colorFor(key(e))), line: { color: css("--surface"), width: 2 } },
          text: marks.map((e) => `${esc(e.text)}: ${esc(e.ssid)} ${esc(e.bssid)}`),
          hovertemplate: "%{text}<extra></extra>",
        });
      }
      const th = thresholdShapes();
      const s = state.summary;
      const shapes = th.shapes.slice();
      const annotations = th.annotations.slice();
      if (s && s.baseline_seconds) {
        shapes.push({ type: "rect", xref: "x", yref: "paper", x0: 0, x1: s.baseline_seconds, y0: 0, y1: 1,
                      fillcolor: css("--band"), line: { width: 0 }, layer: "below" });
        annotations.push({ xref: "x", yref: "paper", x: s.baseline_seconds / 2, y: 1, yanchor: "top",
                           showarrow: false, text: "learning baseline", font: { size: 11, color: css("--muted") } });
      }
      const xmax = s && s.capture_end != null ? s.capture_end - s.capture_start : undefined;
      Plotly.react("timeline-chart", traces, baseLayout({
        showlegend: true,
        legend: { orientation: "h", y: -0.2, x: 0, font: { color: css("--text-2") } },
        hovermode: "x unified",
        margin: { l: 40, r: 16, t: 8, b: 40 },
        xaxis: { range: [0, xmax], title: { text: "capture time (s)", font: { size: 11, color: css("--muted") } },
                 gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
        yaxis: { range: [0, 100], title: { text: "risk", font: { size: 11, color: css("--muted") } },
                 gridcolor: css("--grid"), zeroline: false, tickfont: { color: css("--muted") } },
        shapes, annotations,
      }), PLOT_CFG);
    }

    const ul = $("events");
    const shown = events.slice().reverse();
    ul.innerHTML = shown.length ? shown.map((e) => `
      <li class="${e.alert_id ? "link" : ""}" data-id="${e.alert_id || ""}" data-detector="${e.type === "baseline_alert" ? "baseline" : "ghostap"}">
        <span class="t">${rel(e.ts)}</span>
        <span>${e.level ? level(e.level) : '<span class="muted">info</span>'}</span>
        <span class="what"><span class="swatch" style="background:${colorFor(key(e))}"></span>${esc(e.text)}: <b>${esc(e.ssid)}</b> <span class="mono muted">${esc(e.bssid)}</span></span>
      </li>`).join("") : '<li class="empty">No events yet.</li>';
  }

  $("events").addEventListener("click", (e) => {
    const li = e.target.closest("li.link");
    if (!li || !li.dataset.id) return;
    const det = li.dataset.detector;
    if (det !== state.detector) document.querySelector(`.tab[data-detector="${det}"]`).click();
    select(Number(li.dataset.id), true);
  });

  // ---------- AP table ----------
  function renderAps(aps) {
    $("ap-rows").innerHTML = aps.length ? aps.map((p) => `
      <tr class="${p.alert_id ? "clickable" : ""}" data-id="${p.alert_id || ""}">
        <td><span class="swatch" style="background:${colorFor(key(p))}"></span>${esc(p.ssid)}</td>
        <td class="mono">${esc(p.bssid)}</td>
        <td class="num">${esc(p.channels)}</td>
        <td>${esc(p.securities)}</td>
        <td class="num">${fmt(p.rssi_avg, 1)}</td>
        <td class="num">${p.frames}</td>
        <td class="num">${rel(p.first_seen)}</td>
        <td class="num">${fmt(p.score, 1)}</td>
        <td class="num">${fmt(p.peak_score, 1)}</td>
        <td>${level(p.level)}</td>
      </tr>`).join("") : '<tr><td colspan="10" class="empty">No access points yet.</td></tr>';
  }

  $("ap-rows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr.clickable");
    if (!tr) return;
    if (state.detector !== "ghostap") document.querySelector('.tab[data-detector="ghostap"]').click();
    select(Number(tr.dataset.id), true);
  });

  // ---------- polling ----------
  let timer = null;
  async function refresh() {
    try {
      const [summary, alerts, series, events, aps] = await Promise.all([
        get("/api/summary"), get("/api/alerts?detector=" + state.detector),
        get("/api/timeline"), get("/api/events"), get("/api/aps"),
      ]);
      renderSummary(summary);
      if (changed("timeline", [series, events, summary.capture_end])) renderTimeline(series, events);
      if (changed("alerts", alerts)) renderAlerts(alerts);
      if (changed("aps", aps)) renderAps(aps);
      if (state.selected != null) loadDetail();
      const live = summary.status && summary.status.state === "running";
      schedule(live ? 2000 : 10000);
    } catch (e) {
      $("status").innerHTML = '<span class="pill"><i class="dot error"></i>dashboard server not reachable</span>';
      schedule(5000);
    }
  }
  function schedule(ms) { clearTimeout(timer); timer = setTimeout(refresh, ms); }

  // Re-theme charts when the OS colour scheme changes.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    state.lastJSON = {};
    refresh();
  });

  refresh();
})();
