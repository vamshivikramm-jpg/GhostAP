"""Phase C: monitored-networks API (F015-F019, F034, F035) incl. live hot-reload."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import monitored as mon  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture()
def env(tmp_path):
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    db = str(tmp_path / "s.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    mpath = str(tmp_path / "monitored.json")
    app = create_app(db, cfg, pipe, admin_db=str(tmp_path / "admin.db"), config_path=CONFIG,
                     monitored_path=mpath)
    return app.test_client(), pipe, mpath, cfg


def test_wizard_learns_and_health_shows_the_twin(env):
    c, pipe, mpath, _ = env
    first = c.get("/api/monitored").get_json()
    assert first["networks"] == [] and {i["ssid"] for i in first["inbox"]} == {"MVSR_WiFi", "Cafe_Guest"}
    assert c.post("/api/monitored/learn", json={"ssids": []}).status_code == 400
    r = c.post("/api/monitored/learn", json={"ssids": ["MVSR_WiFi"]})            # first 2 minutes: no twin
    assert r.get_json()["saved"] == ["MVSR_WiFi"]
    net = c.get("/api/monitored").get_json()["networks"][0]
    assert set(net["baseline"]["bssids"]) == {"a4:2b:b0:11:22:33", "a4:2b:b0:11:22:99"}
    assert net["health"]["missing"] == [] and len(net["health"]["heard_now"]) == 2     # F034
    assert [u["bssid"] for u in net["health"]["unexpected"]] == [EVIL]
    assert net["risk_now"] >= 60 and net["trend"]                                      # F035
    assert "MVSR_WiFi" in mon.load(mpath)["networks"]
    # the running capture now uses the saved baseline (hot reload)
    assert pipe._scorer.analyzer.baseline.ssids["MVSR_WiFi"].saved


def test_accept_and_remove_ap_with_live_reload(env):
    c, pipe, mpath, _ = env
    c.post("/api/monitored/learn", json={"ssids": ["MVSR_WiFi"]})
    assert c.post("/api/monitored/accept", json={"ssid": "MVSR_WiFi", "bssid": "nope"}).status_code == 400
    assert c.post("/api/monitored/accept", json={"ssid": "MVSR_WiFi", "bssid": EVIL}).status_code == 200
    assert EVIL in pipe._scorer.analyzer.baseline.ssids["MVSR_WiFi"].bssids
    net = c.get("/api/monitored").get_json()["networks"][0]
    assert net["health"]["unexpected"] == [] and EVIL in net["baseline"]["bssids"]
    assert c.post("/api/monitored/remove_ap", json={"ssid": "MVSR_WiFi", "bssid": EVIL}).status_code == 200
    assert EVIL not in mon.load(mpath)["networks"]["MVSR_WiFi"]["bssids"]


def test_per_network_settings_are_validated_and_applied(env):
    c, pipe, _, _ = env
    c.post("/api/monitored/learn", json={"ssids": ["MVSR_WiFi"]})
    bad = c.post("/api/monitored/settings", json={"ssid": "MVSR_WiFi", "settings": {"enabled": {"nope": False}}})
    assert bad.status_code == 400
    assert c.post("/api/monitored/settings", json={"ssid": "MVSR_WiFi",
                                                   "settings": {"threshold_medium": 500}}).status_code == 400
    ok = c.post("/api/monitored/settings", json={"ssid": "MVSR_WiFi", "settings": {
        "enabled": {"rssi_jump": False}, "threshold_medium": 45}})
    assert ok.status_code == 200 and ok.get_json()["enabled"]["rssi_jump"] is False
    assert pipe._scorer.analyzer.network_settings["MVSR_WiFi"]["threshold_medium"] == 45
    r = {x.name: x for x in pipe._scorer.analyzer.evaluate("MVSR_WiFi", EVIL)}
    assert r["rssi_jump"].reason == "turned off for this network"


def test_remove_network_needs_confirmation(env):
    c, _, mpath, _ = env
    c.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]})
    assert c.post("/api/monitored/remove", json={"ssid": "Cafe_Guest"}).status_code == 400
    assert c.post("/api/monitored/remove", json={"ssid": "Cafe_Guest", "confirm": "Cafe_Guest"}).status_code == 200
    assert mon.load(mpath)["networks"] == {}


def test_inbox_decisions(env):
    c, _, _, _ = env
    assert c.post("/api/monitored/inbox", json={"ssid": "Cafe_Guest", "decision": "bogus"}).status_code == 400
    c.post("/api/monitored/inbox", json={"ssid": "Cafe_Guest", "decision": "ignored"})
    inbox = {i["ssid"]: i["decision"] for i in c.get("/api/monitored").get_json()["inbox"]}
    assert inbox["Cafe_Guest"] == "ignored" and inbox["MVSR_WiFi"] is None
    c.post("/api/monitored/inbox", json={"ssid": "Cafe_Guest", "decision": "reset"})
    assert {i["ssid"]: i["decision"] for i in c.get("/api/monitored").get_json()["inbox"]}["Cafe_Guest"] is None


def test_allowlist_editor_with_live_reload(env, tmp_path):
    c, pipe, _, _ = env
    assert c.post("/api/allowlist", json={"add": "not-a-mac"}).status_code == 400
    r = c.post("/api/allowlist", json={"add": EVIL.upper()})
    assert r.status_code == 200 and r.get_json()["allowlist"] == [EVIL]
    assert EVIL in pipe._scorer.analyzer.baseline.allowlist
    r = {x.name: x for x in pipe._scorer.analyzer.evaluate("MVSR_WiFi", EVIL)}
    assert r["new_bssid_oui"].value == 0 and r["security_downgrade"].value == 1.0     # cloning still caught
    assert c.post("/api/allowlist", json={"remove": EVIL}).get_json()["allowlist"] == []
    assert load_config(CONFIG)["known_bssids"] == []          # config.yaml itself untouched (overlay)
    actions = [a["action"] for a in c.get("/api/audit").get_json()]
    assert actions[:2] == ["allowlist.remove", "allowlist.add"]
