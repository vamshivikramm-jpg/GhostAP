"""Phase G web: report (F052), bundles (F054), labelling + suggestions (F046, F088),
evaluation runner (F047). Runs in a temporary working directory (data/ and results/)."""
import io
import json
import os
import shutil
import sys
import time
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.sessions import SessionError, SessionStore, import_bundle  # noqa: E402
from ghostap.web import create_app  # noqa: E402

EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_test_pcap.generate(str(tmp_path / "data"))
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    store = SessionStore(str(tmp_path / "data" / "sessions"))
    s = store.create("lab run", "replay", os.path.join("data", "test_capture.pcap"))
    pipe = Pipeline(s.db, cfg, pcap=os.path.join("data", "test_capture.pcap"), speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    app = create_app(s.db, cfg, pipe, sessions=store, current_session=s.id, admin_db=str(tmp_path / "admin.db"),
                     config_path=os.path.join(ROOT, "config.yaml"), monitored_path=str(tmp_path / "m.json"))
    return app.test_client(), store, s


def test_report_is_a_standalone_page(lab):
    c, _, s = lab
    r = c.get("/api/report.html")
    page = r.data.decode()
    assert r.status_code == 200 and r.mimetype == "text/html"
    assert "GhostAP incident report" in page and EVIL in page and "data:image/png;base64," in page
    assert "<script" not in page and "synthetic" in page                  # replay of the synthetic test capture


def test_bundle_round_trip_and_refusals(lab, tmp_path):
    c, store, s = lab
    r = c.get("/api/sessions/{}/bundle.zip".format(s.id))
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.data))
    assert {"session.db", "meta.json", "manifest.json"} <= set(z.namelist())
    path = tmp_path / "b.zip"
    path.write_bytes(r.data)
    new = import_bundle(store, str(path))
    assert new.id != s.id and os.path.getsize(new.db) > 0 and new.meta()["imported_from"] == s.id
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as w:
        w.writestr("manifest.json", json.dumps({"format": "ghostap-session-bundle", "files": {}}))
        w.writestr("session.db", b"x")
        w.writestr("../../escape.txt", b"x")
    with pytest.raises(SessionError, match="unexpected files"):
        import_bundle(store, str(evil))
    broken = tmp_path / "broken.zip"
    with zipfile.ZipFile(broken, "w") as w:
        w.writestr("manifest.json", json.dumps({"format": "ghostap-session-bundle",
                                                 "files": {"session.db": {"sha256": "00"}}}))
        w.writestr("session.db", b"x")
    n = len(store.list())
    with pytest.raises(SessionError, match="checksum"):
        import_bundle(store, str(broken))
    assert len(store.list()) == n                                       # the half-imported folder is removed
    assert c.get("/api/sessions/nope/bundle.zip").status_code == 404


def test_labels_suggest_save_and_export(lab):
    c, _, s = lab
    d = c.get("/api/labels").get_json()
    sug = {a["bssid"]: a["suggestion"] for a in d["aps"]}
    assert sug[EVIL]["label"] == "evil_twin" and sug[EVIL]["confidence"] == "high" and sug[EVIL]["attack_start"]
    assert all(v["label"] == "legit" for b, v in sug.items() if b != EVIL)
    assert c.post("/api/labels", json={"aps": {EVIL: {"label": "evil_twin"}}}).status_code == 400   # needs a start
    assert c.post("/api/labels", json={"aps": {"nope": {"label": "legit"}}}).status_code == 400
    labels = {a["bssid"]: ({"label": "evil_twin", "attack_start": d["capture_start"] + 180} if a["bssid"] == EVIL
                           else {"label": "legit"}) for a in d["aps"]}
    assert c.post("/api/labels", json={"aps": labels, "synthetic": True}).get_json()["saved"] == 4
    saved = json.load(open(os.path.join(s.path, "labels.json")))
    assert saved["aps"][EVIL]["label"] == "evil_twin" and saved["synthetic"] is True
    assert c.post("/api/labels/export", json={"name": "../x"}).status_code == 400
    r = c.post("/api/labels/export", json={"name": "run1"})
    assert r.status_code == 200 and os.path.exists("data/lab/run1.pcap")
    assert c.post("/api/labels/export", json={"name": "run1"}).status_code == 409


def test_evaluation_runner_on_lab_captures(lab):
    c, _, s = lab
    os.makedirs("data/lab", exist_ok=True)
    shutil.copyfile("data/test_capture.pcap", "data/lab/run1.pcap")
    shutil.copyfile("data/test_labels.json", "data/lab/run1.labels.json")
    ds = {d["name"]: d for d in c.get("/api/evaluation/datasets").get_json()}
    assert ds["lab"]["captures"] == 1
    assert c.post("/api/evaluation/run", json={"dataset": "nope"}).status_code == 400
    assert c.post("/api/evaluation/run", json={"dataset": "lab"}).status_code == 200
    for _ in range(300):
        st = c.get("/api/evaluation/status").get_json()
        if st["state"] != "running":
            break
        time.sleep(0.1)
    assert st["state"] == "done", st
    res = c.get("/api/evaluation/result?dataset=lab").get_json()
    g = [m for m in res["metrics"] if m["detector"] == "ghostap"][0]
    assert res["available"] and g["TP"] == "1" and res["extended"]["curves"]["auc"] == 1.0
    assert os.path.exists("results/lab/extended.md")
