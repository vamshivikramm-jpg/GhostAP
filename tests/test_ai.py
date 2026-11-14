"""Phase I: opt-in AI explainer (F086) and Ask GhostAP (F087), with a fake Claude client:
nothing leaves this machine in the tests."""
import json
import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.ai import Client, Redactor  # noqa: E402
from ghostap.config import ConfigError, DEFAULT_CONFIG, load_config, validate  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.web import create_app  # noqa: E402

EVIL = "00:c0:ca:de:ad:01"


class FakeSDK:
    def __init__(self, reply="AP-1 on Network A looks like a twin.", stop="end_turn"):
        self.sent, self.reply, self.stop = [], reply, stop
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.sent.append(kw)
        return SimpleNamespace(stop_reason=self.stop, model=kw["model"],
                               content=[SimpleNamespace(type="text", text=self.reply)],
                               usage=SimpleNamespace(input_tokens=10, output_tokens=5))


@pytest.fixture(scope="module")
def app_env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ai")
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    db = str(tmp / "s.db")
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    app = create_app(db, cfg, pipe, admin_db=str(tmp / "a.db"), config_path=os.path.join(ROOT, "config.yaml"))
    return app, cfg


def test_off_by_default_and_settings(app_env):
    app, cfg = app_env
    assert DEFAULT_CONFIG["ai"]["enabled"] is False and cfg["ai"]["redact"] is True
    c = app.test_client()
    assert c.get("/api/ai/status").get_json()["enabled"] is False
    assert c.post("/api/ai/ask", json={"question": "hi"}).status_code == 400
    bad = json.loads(json.dumps(DEFAULT_CONFIG))
    bad["ai"]["effort"] = "huge"
    with pytest.raises(ConfigError):
        validate(bad)


def test_redactor_round_trip():
    r = Redactor()
    assert r.ssid("MVSR_WiFi") == "Network A" and r.bssid("00:C0:CA:DE:AD:01") == "AP-1"
    assert r.text("twin of MVSR_WiFi at 00:c0:ca:de:ad:01, also 11:22:33:44:55:66") == \
        "twin of Network A at AP-1, also AP-?"
    assert r.restore("AP-1 copies Network A") == "00:c0:ca:de:ad:01 copies MVSR_WiFi"


def test_explain_and_ask_send_only_redacted_data(app_env):
    app, cfg = app_env
    ctx = app.extensions["ghostap"]
    cfg["ai"]["enabled"] = True
    fake = FakeSDK()
    ctx.ai_client = Client(cfg, sdk_client=fake)
    c = app.test_client()
    try:
        aid = [a for a in c.get("/api/alerts").get_json() if a["bssid"] == EVIL][0]["id"]
        r = c.post("/api/ai/explain", json={"alert_id": aid}).get_json()
        assert r["text"] == "{} on MVSR_WiFi looks like a twin.".format(EVIL) and r["redacted"]
        sent = json.dumps(fake.sent[-1])
        assert "MVSR_WiFi" not in sent and EVIL not in sent and "Cafe_Guest" not in sent
        assert fake.sent[-1]["model"] == "claude-opus-5-5" and fake.sent[-1]["fallbacks"] == "default"
        assert "untrusted" in fake.sent[-1]["system"]
        a = c.post("/api/ai/ask", json={"question": "Is MVSR_WiFi under attack?"}).get_json()
        assert "MVSR_WiFi" in a["text"] and "MVSR_WiFi" not in json.dumps(fake.sent[-1])
        assert c.post("/api/ai/ask", json={"question": "x" * 501}).status_code == 400
        assert c.get("/api/audit?action=ai.explain").get_json()[0]["detail"]["redacted"] is True
        ctx.ai_client = Client(cfg, sdk_client=FakeSDK(stop="refusal", reply=""))
        assert c.post("/api/ai/ask", json={"question": "hi"}).status_code == 422
    finally:
        cfg["ai"]["enabled"] = False
        ctx.ai_client = None
