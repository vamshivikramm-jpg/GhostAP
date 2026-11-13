"""Phase D: what-if weights (F031) and timeline annotations (F037)."""
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import whatif  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    tmp = tmp_path_factory.mktemp("wi")
    db = str(tmp / "s.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    app = create_app(db, cfg, pipe, admin_db=str(tmp / "a.db"), config_path=CONFIG, monitored_path=str(tmp / "m.json"))
    return app.test_client(), db, cfg


def test_whatif_with_configured_values_reproduces_stored_scores(env):
    c, db, cfg = env
    r = c.post("/api/whatif", json={}).get_json()
    with Store(db) as s:
        stored = {(a["ssid"], a["bssid"]): (a["score"], a["level"]) for a in s.alerts("ghostap")}
        peaks = {(x[0], x[1]): x[2] for x in s.conn.execute(
            "SELECT ssid, bssid, MAX(score) FROM risk_timeline GROUP BY ssid, bssid")}
    for row in r["rows"]:
        key = (row["ssid"], row["bssid"])
        assert row["peak_now"] == row["peak_whatif"] == peaks[key]
        assert (row["level_now"] != "LOW") == (key in stored)
        if key in stored:
            assert (row["peak_now"], row["level_now"]) == stored[key]
    assert r["summary"]["new_alerts"] == r["summary"]["no_longer"] == 0


def test_whatif_changes_and_validation(env):
    c, _, _ = env
    r = c.post("/api/whatif", json={"thresholds": {"medium": 80, "high": 90}}).get_json()
    assert r["summary"]["alerts_whatif"] == 0 and r["summary"]["no_longer"] == 1
    assert r["rows"][0]["bssid"] == EVIL and r["rows"][0]["change"] == "no_longer"
    r = c.post("/api/whatif", json={"weights": {"security_downgrade": 0, "ie_fingerprint": 0}}).get_json()
    assert r["rows"][0]["peak_whatif"] < r["rows"][0]["peak_now"]
    r = c.post("/api/whatif", json={"thresholds": {"medium": 5}}).get_json()
    assert r["summary"]["alerts_whatif"] >= r["summary"]["alerts_now"]
    for bad in ({"weights": {"nope": 1}}, {"weights": {"rssi_jump": 11}}, {"weights": {"rssi_jump": True}},
                {"signatures": {"karma": 101}}, {"thresholds": {"medium": 70}},
                {"weights": {k: 0 for k in load_config(CONFIG)["weights"]}}):
        assert c.post("/api/whatif", json=bad).status_code == 400
    assert c.post("/api/whatif", data="x=1", content_type="application/x-www-form-urlencoded").status_code == 415
    # nothing was saved: the configured values are unchanged
    assert c.post("/api/whatif", json={}).get_json()["configured"]["thresholds"] == load_config(CONFIG)["thresholds"]


def test_whatif_refuses_huge_sessions(env, monkeypatch):
    c, db, cfg = env
    with Store(db) as s:
        obs = s.observations()
    monkeypatch.setattr(whatif, "MAX_EVALUATIONS", 10)
    with pytest.raises(whatif.TooLarge):
        whatif.Recording(cfg, obs)


def test_annotations_add_list_delete_and_audit(env):
    c, db, _ = env
    with Store(db) as s:
        t0, t1 = s.conn.execute("SELECT MIN(ts), MAX(ts) FROM observations").fetchone()
    assert c.post("/api/annotations", json={"ts": t0 + 180, "text": "  "}).status_code == 400
    assert c.post("/api/annotations", json={"ts": t0 + 180, "text": "x" * 301}).status_code == 400
    assert c.post("/api/annotations", json={"ts": t1 + 86400, "text": "far away"}).status_code == 400
    assert c.post("/api/annotations", json={"ts": "soon", "text": "x"}).status_code == 400
    aid = c.post("/api/annotations", json={"ts": t0 + 180, "text": " switched on the hotspot "}).get_json()["id"]
    notes = c.get("/api/annotations").get_json()
    assert [(n["id"], n["text"], n["ts"]) for n in notes] == [(aid, "switched on the hotspot", t0 + 180)]
    assert c.get("/api/audit?action=annotation.add").get_json()[0]["target"] == str(aid)
    assert c.post("/api/annotations/{}/delete".format(aid)).status_code == 200
    assert c.post("/api/annotations/{}/delete".format(aid)).status_code == 404
    assert c.get("/api/annotations").get_json() == []


def test_old_database_gets_new_tables(tmp_path):
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, ts REAL NOT NULL, frame_type TEXT NOT NULL, "
                "ssid TEXT NOT NULL, bssid TEXT NOT NULL, oui TEXT, channel INTEGER, security TEXT, rssi INTEGER, "
                "beacon_interval INTEGER, tsf INTEGER, seq INTEGER)")
    con.commit()
    con.close()
    with Store(db) as s:
        tables = {r[0] for r in s.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"layouts", "annotations"} <= tables
        s.add_annotation(1.0, "note", "local", 2.0)
        assert s.annotations()[0]["text"] == "note"
