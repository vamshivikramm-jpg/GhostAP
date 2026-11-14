/* Opt-in AI help (F086, F087): "Explain with AI" on an alert, and the Ask GhostAP page.
   Nothing is sent until you press a button; the first time, the page says what is sent. */
(function () {
  "use strict";
  const G = window.GA;
  const { esc, post, get, notice } = G;
  let status = null, root = null, history = [];

  const consentKey = "ghostap-ai-consent";
  function consent() {
    try { if (localStorage.getItem(consentKey) === "1") return true; } catch (e) { /* ignore */ }
    const ok = confirm(`This sends data about this session to ${status.sends_to} (model ${status.model}).` +
      (status.redact ? " Network names and addresses are replaced by placeholders first." : " Network names and addresses are sent as they are.") +
      " The answer is an aid, not evidence. Continue?");
    if (ok) try { localStorage.setItem(consentKey, "1"); } catch (e) { /* ignore */ }
    return ok;
  }
  // plain text with paragraphs; everything escaped (the answer may quote names from the air)
  const para = (t) => esc(t).split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");

  // ---- F086 button in the AP detail
  new MutationObserver(() => {
    if (!status || !status.enabled) return;
    const bar = document.querySelector("#detail .row-actions");
    const alert = G.state.detail && G.state.detail.alert;
    if (!bar || !alert || bar.querySelector("[data-ai-explain]")) return;
    const b = document.createElement("button");
    b.className = "btn small";
    b.dataset.aiExplain = alert.id;
    b.textContent = "Explain with AI";
    b.title = "Plain-language explanation from Claude (opt-in; sends this alert's details)";
    bar.appendChild(b);
  }).observe(document.getElementById("detail"), { childList: true, subtree: true });

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-ai-explain]");
    if (!b || !consent()) return;
    b.disabled = true;
    b.textContent = "Asking Claude…";
    const r = await post("/api/ai/explain", { alert_id: Number(b.dataset.aiExplain) });
    b.disabled = false;
    b.textContent = "Explain with AI";
    if (!r.ok) { notice((r.data && r.data.error) || "No answer", "error"); return; }
    let box = document.getElementById("ai-explain");
    if (!box) {
      box = document.createElement("section");
      box.id = "ai-explain";
      box.className = "ai-box";
      document.querySelector("#detail .why").after(box);
    }
    box.innerHTML = `<div class="card-head"><h3>AI explanation</h3><span class="muted small">${esc(r.data.info.model)}${r.data.redacted ? " · names were hidden from the model" : ""} · an aid, not evidence</span></div>${para(r.data.text)}`;
  });

  // ---- F087 page
  function render() {
    root.innerHTML = `<div class="page-head"><div><h1>Ask GhostAP</h1>
        <p>Questions about this session, answered by Claude from a summary of it. Opt-in; an aid, not evidence.</p></div></div>
      ${!status.enabled ? `<section class="card"><p>AI help is off. To turn it on: <span class="mono">pip install -r requirements-ai.txt</span>, set <span class="mono">ANTHROPIC_API_KEY</span>, and <span class="mono">ai.enabled: true</span> in config.yaml. Network names and addresses are hidden from the model by default (<span class="mono">ai.redact</span>).</p></section>` : `
      <section class="card ask-log">${history.map((h) => `<div class="q"><b>You:</b> ${esc(h.q)}</div><div class="a">${h.a ? para(h.a) : '<span class="muted">…</span>'}</div>`).join("") || '<p class="muted">Try: “Which access point is most suspicious and why?”, “Did anything happen on Cafe_Guest?”, “Summarise this session for my report.”</p>'}</section>
      <form class="key-form" data-ask><label class="sr-only" for="ask-q">Question</label><input class="input" id="ask-q" maxlength="500" required placeholder="Ask about this session…"><button class="btn primary" type="submit">Ask</button></form>
      <p class="muted small">Model ${esc(status.model)} · ${status.redact ? "names and addresses replaced before sending" : "names and addresses are sent as they are"} · each question is sent on its own (no chat memory).</p>`}`;
  }
  document.addEventListener("submit", async (e) => {
    if (!root || !root.isConnected || !e.target.matches("[data-ask]")) return;
    e.preventDefault();
    const q = root.querySelector("#ask-q").value.trim();
    if (!q || !consent()) return;
    const item = { q, a: null };
    history.push(item);
    render();
    const r = await post("/api/ai/ask", { question: q });
    item.a = r.ok ? r.data.text : "⚠ " + ((r.data && r.data.error) || "No answer");
    render();
    const box = root.querySelector("#ask-q");
    if (box) box.focus();
  });

  get("/api/ai/status").then((s) => { status = s; }).catch(() => { status = { enabled: false }; });
  G.register("ask", { title: "Ask", async show(el) { root = el; if (!status) status = await get("/api/ai/status"); render(); }, hide() { root = null; } });
})();
