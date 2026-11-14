"""Phase D backend: mutes (F026), bulk triage (F025), triage history (F027), incidents (F020)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture()
def client(tmp_path):
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    db = str(tmp_path / "s.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    app = create_app(db, cfg, pipe, admin_db=str(tmp_path / "admin.db"), config_path=CONFIG,
                     monitored_path=str(tmp_path / "m.json"))
    return app.test_client()


def test_mute_hides_alert_from_open_count_and_can_be_removed(client):
    before = client.get("/api/summary").get_json()
    assert before["top_alert"] and before["top_alert"]["bssid"] == EVIL
    assert client.post("/api/mutes", json={"kind": "bssid", "value": EVIL, "hours": 0}).status_code == 400
    assert client.post("/api/mutes", json={"kind": "mac", "value": EVIL, "hours": 1}).status_code == 400
    mid = client.post("/api/mutes", json={"kind": "bssid", "value": EVIL, "hours": 1}).get_json()["id"]
    assert [m["value"] for m in client.get("/api/mutes").get_json()] == [EVIL]
    after = client.get("/api/summary").get_json()
    assert after["muted_alerts"] >= 1 and (after["top_alert"] is None or after["top_alert"]["bssid"] != EVIL)
    assert client.post("/api/mutes/{}/delete".format(mid), json={}).status_code == 200
    assert client.post("/api/mutes/{}/delete".format(mid), json={}).status_code == 404
    assert client.get("/api/mutes").get_json() == []


def test_bulk_triage_and_history(client):
    alerts = client.get("/api/alerts?detector=ghostap,deauth,flood").get_json()
    ids = [a["id"] for a in alerts]
    assert ids
    assert client.post("/api/alerts/triage_bulk", json={"ids": ["1"], "status": "confirmed"}).status_code == 400
    assert client.post("/api/alerts/triage_bulk", json={"ids": ids, "status": "bogus"}).status_code == 400
    r = client.post("/api/alerts/triage_bulk", json={"ids": ids + [999999], "status": "confirmed"})
    assert r.status_code == 200 and r.get_json()["updated"] == ids
    assert {a["triage_status"] for a in client.get("/api/alerts").get_json()} == {"confirmed"}
    hist = client.get("/api/alerts/{}/history".format(ids[0])).get_json()
    assert hist and hist[0]["action"] == "triage.bulk" and hist[0]["detail"]["to"] == "confirmed"
    assert client.get("/api/alerts/999999/history").get_json() == []


def test_incidents_tell_a_story(client):
    inc = client.get("/api/incidents").get_json()
    assert inc and inc[0]["story"] and inc[0]["summary"]
    assert {"ts", "text"} <= set(inc[0]["story"][0])
