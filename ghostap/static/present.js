/* Demo button (F089) and presentation mode (F090).
   Presentation mode enlarges the dashboard, hides the detail lists and narrates what is
   happening from the live summary, so a viva or class demo needs no clicking. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, fmt, post, notice, label } = G;
  const KEY = "ghostap-present";
  let on = false, picked = null;

  async function startDemo(present) {
    const r = await post("/api/demo/start", { speed: 10 });
    if (!r.ok) { notice((r.data && r.data.error) || "Could not start the demo", "error"); return; }
    try {
      sessionStorage.removeItem("ghostap-session");           // back to the current (demo) session
      if (present) sessionStorage.setItem(KEY, "1");
    } catch (e) { /* private mode */ }
    location.hash = "";
    location.reload();
  }

  function bar() {
    let b = document.getElementById("present-bar");
    if (!b) {
      b = document.createElement("div");
      b.id = "present-bar";
      b.className = "present-bar";
      b.setAttribute("role", "status");
      b.setAttribute("aria-live", "polite");
      document.body.appendChild(b);
    }
    return b;
  }

  function setPresent(v) {
    on = v;
    document.body.classList.toggle("present", v);
    try { if (v) sessionStorage.setItem(KEY, "1"); else sessionStorage.removeItem(KEY); } catch (e) { /* ignore */ }
    if (!v) {
      const b = document.getElementById("present-bar");
      if (b) b.remove();
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    } else if (G.state.summary) narrate(G.state.summary);
    window.dispatchEvent(new Event("resize"));                  // let Plotly fit the new sizes
  }

  function narrate(s) {
    if (!on) return;
    const st = s.status || {}, top = s.top_alert;
    let step, title, text;
    if (!s.aps) {
      step = 0; title = "Waiting for beacons"; text = "GhostAP is listening. Nothing has been heard yet.";
    } else if (!s.baseline_complete) {
      const pct = s.capture_end && s.baseline_end ? Math.min(100, Math.round(100 * (s.capture_end - s.capture_start) / (s.baseline_end - s.capture_start))) : 0;
      step = 1; title = "Learning what normal looks like · " + pct + "%";
      text = `${s.aps} access point${s.aps > 1 ? "s" : ""} in ${s.networks} network${s.networks > 1 ? "s" : ""} so far. GhostAP records each one's vendor, channel, security, signal, uptime and beacon structure.`;
    } else if (!top) {
      step = 2; title = "Watching";
      text = "Every access point still matches what was learned. A copy of a network would have to imitate all of it to stay unnoticed.";
    } else {
      step = top.level === "HIGH" ? 4 : 3;
      title = (top.level === "HIGH" ? "Evil twin detected: " : "Something changed: ") + `“${top.ssid}”`;
      // reasons look like "security_downgrade (+19): advertises OPN …; ie_fingerprint (+16): …"
      const why = (top.reasons || "").split("; ").slice(0, 3).map((r) => {
        const m = /^([a-z_]+) \(\+(\d+)\)/.exec(r);
        return m ? `${esc(label(m[1]))} <b>+${m[2]}</b>` : "";
      }).filter(Boolean).join(" · ");
      text = `<span class="mono">${esc(top.bssid)}</span> scores <b>${fmt(top.score, 0)}</b>/100${why ? ": " + why : "."}`;
      const key = top.ssid + "|" + top.bssid + "|" + top.level;
      if (picked !== key) { picked = key; G.select(top.ssid, top.bssid); }
    }
    const steps = ["Listen", "Learn", "Watch", "Suspect", "Detect"];
    bar().innerHTML = `<ol class="present-steps">${steps.map((n, i) => `<li class="${i === step ? "now" : i < step ? "done" : ""}">${n}</li>`).join("")}</ol>
      <div class="present-text"><b>${esc(title)}</b><span>${text}</span></div>
      <div class="present-actions"><span class="muted">${esc(st.mode || "")} ${st.speed ? "×" + st.speed : ""}</span>
        <button class="btn small" data-fullscreen>Full screen</button><button class="btn small" data-present-exit>Exit (Esc)</button></div>`;
  }

  G.onRefresh(narrate);
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-demo]")) { e.preventDefault(); startDemo(false); return; }
    if (e.target.closest("[data-demo-present]")) { e.preventDefault(); startDemo(true); return; }
    if (e.target.closest("[data-present]")) { e.preventDefault(); const d = document.getElementById("help"); if (d && d.open) d.close(); setPresent(!on); return; }
    if (e.target.closest("[data-present-exit]")) { setPresent(false); return; }
    if (e.target.closest("[data-fullscreen]")) {
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      else document.documentElement.requestFullscreen().catch(() => notice("Full screen is not available here", "error"));
    }
  });
  document.addEventListener("keydown", (e) => {
    if (on && e.key === "Escape" && !document.querySelector("dialog[open]")) setPresent(false);
  });
  G.startDemo = startDemo;
  G.setPresent = setPresent;
  G.presenting = () => on;
  try { if (sessionStorage.getItem(KEY) === "1") setPresent(true); } catch (e) { /* ignore */ }
})();
