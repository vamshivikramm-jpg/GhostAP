/* Evaluation page (F047): run the evaluation on a labelled dataset and read the results,
   with confidence intervals (F048), ROC / precision-recall (F049), learned weights (F084)
   and the anomaly model (F085). */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, get, post, notice, fmt, css } = G;
  let root = null, current = "eval", timer = null;

  const pct = (v) => (v === "" || v == null ? "–" : fmt(Number(v), 2));
  const ci = (pair) => (pair && pair[0] != null ? `${fmt(pair[0], 2)}–${fmt(pair[1], 2)}` : "–");

  async function load() {
    let ds, res, st;
    try {
      [ds, res, st] = await Promise.all([get("/api/evaluation/datasets"), get("/api/evaluation/result?dataset=" + current),
        get("/api/evaluation/status")]);
    } catch (e) { root.innerHTML = `<div class="card empty">${esc(e.message)}</div>`; return; }
    const running = st.state === "running";
    const ext = res.available ? res.extended : null;
    root.innerHTML = `<div class="page-head"><div><h1>Evaluation</h1>
        <p>How well GhostAP finds evil twins on labelled captures, compared with a check that only looks for duplicated network names.</p></div></div>
      <section class="card"><div class="card-head"><h2>Dataset</h2></div>
        <div class="ds-list">${ds.map((d) => `<label class="ds ${d.name === current ? "on" : ""}"><input type="radio" name="ds" value="${esc(d.name)}" ${d.name === current ? "checked" : ""}>
          <span><b>${esc(d.description)}</b><span class="muted small"> ${esc(d.dir)} · ${d.captures} labelled capture${d.captures === 1 ? "" : "s"}${d.results_at ? " · results from " + new Date(d.results_at * 1000).toLocaleString() : ""}</span></span></label>`).join("")}</div>
        <div class="row-actions" style="display:flex;gap:10px;align-items:center;margin-top:10px">
          <button class="btn primary" data-run ${running ? "disabled" : ""}>${running ? "Running…" : "Run the evaluation"}</button>
          <span class="muted">${running ? esc(st.progress || "") + " (" + Math.round((Date.now() / 1000 - st.started)) + " s)" : st.state === "error" ? "Last run failed: " + esc(st.error) : "Takes about 10–60 s. Results are also written to results/."}</span></div>
      </section>
      ${!res.available ? '<section class="card empty">No results for this dataset yet. Run the evaluation.</section>' : `
      ${(ext && ext.synthetic) || current !== "lab" ? '<div class="notice-box">These captures are <b>synthetic and author-designed</b>: they show what the method does on designed cases, not field results. Real numbers come from your labelled lab captures.</div>' : ""}
      <section class="card"><div class="card-head"><h2>Results <span class="muted">threshold MEDIUM ≥ ${esc(res.metrics[0].threshold)} · ${new Date(res.written_at * 1000).toLocaleString()}</span></h2></div>
        <div class="table-wrap"><table><thead><tr><th>Detector</th><th class="num">TP</th><th class="num">FP</th><th class="num">TN</th><th class="num">FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th class="num">Latency mean / max</th></tr></thead><tbody>
        ${res.metrics.map((m) => { const c = ext ? ext.ci.find((x) => x.detector === m.detector) : null; return `<tr><td><b>${m.detector === "ghostap" ? "GhostAP" : "Name-only check"}</b></td>
          <td class="num">${m.TP}</td><td class="num">${m.FP}</td><td class="num">${m.TN}</td><td class="num">${m.FN}</td>
          ${["precision", "recall", "f1", "fpr"].map((k) => `<td>${pct(m[k])}${c ? `<br><span class="muted small">${k === "f1" ? "B " + ci(c.f1_bootstrap) : "W " + ci(c[k + "_wilson"])}</span>` : ""}</td>`).join("")}
          <td class="num">${m.latency_mean ? fmt(Number(m.latency_mean), 0) + " / " + fmt(Number(m.latency_max), 0) + " s" : "–"}</td></tr>`; }).join("")}
        </tbody></table></div>
        ${ext ? '<p class="muted small">95% intervals: W = Wilson, B = bootstrap over captures. Few captures make them wide; that is the real uncertainty.</p>' : ""}</section>
      ${ext ? `<section class="grid two">
        <div class="card"><h2>ROC <span class="muted">AUC ${fmt(ext.curves.auc, 2)}</span></h2><div id="ev-roc" class="chart"></div></div>
        <div class="card"><h2>Precision–recall <span class="muted">AP ${fmt(ext.curves.average_precision, 2)}</span></h2><div id="ev-pr" class="chart"></div></div></section>
      <section class="grid two">
        <div class="card"><h2>Tune / test split</h2>
          ${ext.split_results.usable ? `<p>Test captures only (${ext.split.test.length}, ${ext.split.test_twins} twins): configured threshold → F1 <b>${fmt(ext.split_results.test_configured.f1, 2)}</b>; threshold chosen on the tune captures (${ext.split_results.threshold_chosen_on_tune}) → F1 ${fmt(ext.split_results.test_tuned.f1, 2)}; name-only check → F1 ${fmt(ext.split_results.test_baseline.f1, 2)}.</p>
            <p class="muted small">Tune: ${esc(ext.split.tune.join(", "))}<br>Test: ${esc(ext.split.test.join(", "))}</p>` : '<p class="muted">Each half needs at least one evil twin: add more labelled captures.</p>'}</div>
        <div class="card"><h2>Experiments <span class="muted">not used for alerts</span></h2>
          ${ext.learned_weights.usable ? `<p><b>Learned weights</b> (fitted on tune, scored on test, simplified score): test F1 ${fmt(ext.learned_weights.test_learned_static.f1, 2)} vs. ${fmt(ext.learned_weights.test_configured_static.f1, 2)} with the configured weights.</p>
            <table><thead><tr><th>Indicator</th><th class="num">Configured</th><th class="num">Learned</th></tr></thead><tbody>${Object.keys(ext.learned_weights.configured).map((k) => `<tr><td>${esc(G.label(k))}</td><td class="num">${ext.learned_weights.configured[k]}</td><td class="num">${ext.learned_weights.weights[k]}</td></tr>`).join("")}</tbody></table>` : ""}
          ${ext.anomaly.usable ? `<p><b>Anomaly model</b> (no labels): test AUC ${fmt(ext.anomaly.test_auc, 2)} vs. ${fmt(ext.anomaly.ghostap_test_auc, 2)} for GhostAP's score.</p>` : '<p class="muted">Needs a usable tune / test split.</p>'}
          <p class="muted small">Never choose weights or the threshold by looking at results on the captures you report.</p></div></section>` : ""}
      <section class="card"><h2>Per capture</h2><div class="table-wrap"><table><thead><tr><th>Capture</th><th class="num">APs</th><th class="num">Twins</th><th>GhostAP TP / FP / FN</th><th>Name-only TP / FP / FN</th></tr></thead><tbody>
        ${res.per_scenario.map((s) => `<tr><td title="${esc(s.description)}">${esc(s.scenario)}</td><td class="num">${s.aps}</td><td class="num">${s.evil_twins}</td>
          <td>${s.ghostap_TP} / ${s.ghostap_FP} / ${s.ghostap_FN}</td><td>${s.baseline_TP} / ${s.baseline_FP} / ${s.baseline_FN}</td></tr>`).join("")}</tbody></table></div></section>`}`;
    if (ext) drawCurves(ext.curves);
    clearTimeout(timer);
    if (running) timer = setTimeout(load, 2000);
  }

  function drawCurves(c) {
    const layout = (x, y) => ({ paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)", margin: { l: 44, r: 10, t: 6, b: 40 },
      font: { color: css("--text-2"), size: 12 }, showlegend: true, legend: { x: 0.45, y: 0.05, font: { size: 11 } },
      xaxis: { title: { text: x }, range: [0, 1.02], gridcolor: css("--grid") }, yaxis: { title: { text: y }, range: [0, 1.04], gridcolor: css("--grid") } });
    const bp = c.baseline_point;
    Plotly.react("ev-roc", [
      { x: c.roc.map((p) => p.fpr), y: c.roc.map((p) => p.tpr), mode: "lines", line: { shape: "hv", color: css("--s1"), width: 2.5 }, name: "GhostAP" },
      { x: [0, 1], y: [0, 1], mode: "lines", line: { dash: "dot", color: css("--axis"), width: 1 }, name: "chance", hoverinfo: "skip" },
      ...(bp.fpr != null ? [{ x: [bp.fpr], y: [bp.tpr], mode: "markers", marker: { size: 11, color: css("--critical"), symbol: "diamond" }, name: "Name-only check" }] : []),
    ], layout("false-positive rate", "true-positive rate"), { displaylogo: false, responsive: true });
    Plotly.react("ev-pr", [
      { x: c.pr.map((p) => p.recall), y: c.pr.map((p) => p.precision), mode: "lines", line: { shape: "hv", color: css("--s1"), width: 2.5 }, name: "GhostAP" },
      ...(bp.precision != null ? [{ x: [bp.tpr], y: [bp.precision], mode: "markers", marker: { size: 11, color: css("--critical"), symbol: "diamond" }, name: "Name-only check" }] : []),
    ], layout("recall", "precision"), { displaylogo: false, responsive: true });
  }

  document.addEventListener("change", (e) => {
    if (root && root.isConnected && e.target.name === "ds") { current = e.target.value; load(); }
  });
  document.addEventListener("click", async (e) => {
    if (!root || !root.isConnected || !e.target.closest("[data-run]")) return;
    const r = await post("/api/evaluation/run", { dataset: current });
    if (!r.ok) { notice((r.data && r.data.error) || "Could not start", "error"); return; }
    load();
  });

  G.register("evaluation", { title: "Evaluation", show(el) { root = el; load(); }, hide() { root = null; clearTimeout(timer); } });
})();
