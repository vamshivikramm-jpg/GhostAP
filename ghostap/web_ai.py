"""Opt-in AI API (F086, F087). See ai.py for what is sent and how it is redacted."""
from __future__ import annotations

from flask import abort, jsonify

from .ai import SYSTEM_ASK, SYSTEM_EXPLAIN, AIError, Client, Redactor, alert_context, session_context

MAX_QUESTION = 500


def register(app, ctx) -> None:
    ctx.ai_client = None

    def client():
        if not ctx.cfg["ai"]["enabled"]:
            raise AIError("AI help is off. Set ai.enabled: true in config.yaml (and ANTHROPIC_API_KEY).", 400)
        if ctx.ai_client is None:
            ctx.ai_client = Client(ctx.cfg)
        return ctx.ai_client

    def fail(e: AIError):
        return jsonify({"error": str(e)}), e.status

    @app.get("/api/ai/status")
    def ai_status():
        a = ctx.cfg["ai"]
        return jsonify({"enabled": a["enabled"], "model": a["model"], "redact": a["redact"],
                        "sends_to": "Anthropic (Claude API)"})

    @app.post("/api/ai/explain")
    def ai_explain():
        """F086: a plain-language explanation of one alert."""
        body, err = ctx.json_body()
        if err:
            return err
        aid = body.get("alert_id")
        if isinstance(aid, bool) or not isinstance(aid, int):
            return jsonify({"error": "alert_id must be a number"}), 400
        with ctx.store() as s:
            alert = s.alert(aid)
            if alert is None:
                abort(404)
            profiles = [p for p in s.profiles() if p["ssid"] == alert["ssid"]]
        facts = {x["bssid"]: x for x in ctx.ap_facts_for(alert["ssid"], [p["bssid"] for p in profiles])}
        me = facts.get(alert["bssid"]) or {"bssid": alert["bssid"]}
        sibs = [f for b, f in facts.items() if b != alert["bssid"]]
        r = Redactor(ctx.cfg["ai"]["redact"])
        try:
            text, info = client().ask(SYSTEM_EXPLAIN, alert_context(alert, me, sibs, r),
                                      "Explain this alert for the analyst.")
        except AIError as e:
            return fail(e)
        ctx.audit("ai.explain", str(aid), {"model": info["model"], "redacted": r.on,
                                           "tokens": [info["input_tokens"], info["output_tokens"]]})
        return jsonify({"text": r.restore(text), "info": info, "redacted": r.on})

    @app.post("/api/ai/ask")
    def ai_ask():
        """F087: answer a question about the viewed session."""
        body, err = ctx.json_body()
        if err:
            return err
        q = body.get("question")
        if not isinstance(q, str) or not q.strip() or len(q) > MAX_QUESTION:
            return jsonify({"error": "ask a question of 1 to {} characters".format(MAX_QUESTION)}), 400
        from .risk import build_incidents
        summary = ctx.summary_dict()
        with ctx.store() as s:
            alerts = s.alerts("ghostap,deauth,flood")
        rows = ctx.ap_rows_now()
        r = Redactor(ctx.cfg["ai"]["redact"])
        try:
            context = session_context(summary, rows, alerts, build_incidents(alerts), r)
            text, info = client().ask(SYSTEM_ASK, context, r.text(q.strip()))
        except AIError as e:
            return fail(e)
        ctx.audit("ai.ask", None, {"question_chars": len(q), "model": info["model"], "redacted": r.on})
        return jsonify({"text": r.restore(text), "info": info, "redacted": r.on})
