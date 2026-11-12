import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.risk import load_config  # noqa: E402
from ghostap.web import create_app  # noqa: E402

DATA = os.path.join(ROOT, "data")
PCAP = os.path.join(DATA, "test_capture.pcap")
LABELS = os.path.join(DATA, "test_labels.json")
CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    if not (os.path.exists(PCAP) and os.path.exists(LABELS)):
        make_test_pcap.generate(DATA)
    db = str(tmp_path_factory.mktemp("web") / "web.db")
    cfg = load_config(CONFIG)
    # speed=0: replay as fast as possible, then a final rescore
    pipe = Pipeline(db, cfg, pcap=PCAP, speed=0, rescore_seconds=0.2).start()
    pipe.wait(timeout=60)
    assert pipe.snapshot()["state"] == "done", pipe.snapshot()
    app = create_app(db, cfg, pipe)
    app.testing = True
    return app.test_client()


def test_index_and_assets(client):
    assert b"GhostAP" in client.get("/").data
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/vendor/plotly.min.js").status_code == 200


def test_summary(client):
    s = client.get("/api/summary").get_json()
    assert s["status"]["mode"] == "replay" and s["status"]["state"] == "done"
    assert s["frames"] == 1020 and s["aps"] == 4
    assert s["baseline_complete"] is True
    assert s["alerts"] == {"HIGH": 1, "MEDIUM": 0}
    assert s["baseline_alerts"] == 3


def test_aps_ranked_by_risk(client):
    aps = client.get("/api/aps").get_json()
    assert len(aps) == 4
    assert aps[0]["bssid"] == EVIL and aps[0]["level"] == "HIGH" and aps[0]["alert_id"]
    assert all(a["level"] == "LOW" for a in aps[1:])


def test_alert_list_and_detail(client):
    alerts = client.get("/api/alerts").get_json()
    assert [a["bssid"] for a in alerts] == [EVIL]
    detail = client.get("/api/alerts/{}".format(alerts[0]["id"])).get_json()
    assert detail["profile"]["securities"] == "OPN"
    names = {c["name"] for c in detail["indicators"]}
    assert "security_downgrade" in names
    assert sum(c["contribution"] for c in detail["indicators"]) == pytest.approx(detail["score"], abs=0.1)
    assert detail["timeline"] and detail["benign_causes"]
    assert client.get("/api/alerts/999999").status_code == 404


def test_baseline_detector_alerts(client):
    base = client.get("/api/alerts?detector=baseline").get_json()
    assert len(base) == 3 and all(a["detector"] == "baseline" for a in base)


def test_timeline_and_events(client):
    with open(LABELS) as f:
        attack = json.load(f)["attack_start"]
    series = client.get("/api/timeline").get_json()
    evil = next(s for s in series if s["bssid"] == EVIL)
    assert evil["peak"] >= 60 and len(evil["ts"]) == len(evil["score"])
    events = client.get("/api/events").get_json()
    kinds = [(e["type"], e["bssid"]) for e in events]
    assert ("alert", EVIL) in kinds and ("escalated", EVIL) in kinds
    raised = next(e for e in events if e["type"] == "alert" and e["bssid"] == EVIL)
    assert raised["ts"] >= attack
    assert [e["ts"] for e in events] == sorted(e["ts"] for e in events)


def test_alert_ids_stable_across_rescoring(client, tmp_path):
    from ghostap.storage import Store
    a = {"ssid": "X", "bssid": "aa:bb:cc:dd:ee:ff", "level": "MEDIUM", "score": 40.0,
         "first_ts": 1.0, "high_ts": None, "peak_ts": 1.0, "last_ts": 1.0,
         "indicators": [], "reasons": "", "benign_causes": []}
    with Store(str(tmp_path / "ids.db")) as s:
        s.save_alerts("ghostap", [a])
        first = s.alerts()[0]["id"]
        s.save_alerts("ghostap", [dict(a, score=70.0, level="HIGH")])
        after = s.alerts()
        assert after[0]["id"] == first and after[0]["level"] == "HIGH"
        s.save_alerts("ghostap", [])
        assert s.alerts() == []


def test_live_capture_error_is_reported(tmp_path):
    # On a dev machine without root / monitor mode, live capture must fail cleanly.
    pipe = Pipeline(str(tmp_path / "live.db"), load_config(CONFIG),
                    iface="ghostap-no-such-iface0", rescore_seconds=0.2).start()
    pipe.wait(timeout=30)
    st = pipe.snapshot()
    assert st["state"] == "error"
    assert "monitor mode" in st["message"]
