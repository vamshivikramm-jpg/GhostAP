"""F089 demo button: replays the synthetic test capture as a new session, never during live capture."""
import os

from ghostap.config import load_config
from ghostap.pipeline import Pipeline
from ghostap.sessions import SessionStore
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config.yaml")


class _LivePipe:
    status = {"mode": "live", "state": "running"}

    def snapshot(self):
        return dict(self.status, source="wlan0mon", frames=0, message="", speed=None, data_version=0)

    def stop(self):
        raise AssertionError("the demo must not stop a live capture")


def _app(tmp_path, pipeline, cfg):
    sessions = SessionStore(str(tmp_path / "sessions"))
    s = sessions.create("first", "replay", "x.pcap")
    return create_app(s.db, cfg, pipeline, sessions=sessions, current_session=s.id,
                      admin_db=str(tmp_path / "admin.db"), config_path=CONFIG,
                      monitored_path=str(tmp_path / "m.json")), s


def test_demo_refused_during_live_capture(tmp_path):
    app, _ = _app(tmp_path, _LivePipe(), load_config(CONFIG))
    r = app.test_client().post("/api/demo/start", json={})
    assert r.status_code == 409 and "live capture" in r.get_json()["error"]


def test_demo_switches_to_a_new_replay_session(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)                       # the demo capture lives in data/
    cfg = load_config(CONFIG)
    app, first = _app(tmp_path, None, cfg)
    c = app.test_client()
    assert c.post("/api/demo/start", json={"speed": 0}).status_code == 400
    r = c.post("/api/demo/start", json={"speed": 100})
    assert r.status_code == 200
    sid = r.get_json()["session"]
    ctx = app.extensions["ghostap"]
    assert ctx.current_session == sid != first.id and isinstance(ctx.pipeline, Pipeline)
    ctx.pipeline.wait(60)
    s = c.get("/api/summary").get_json()
    assert s["status"]["session"] == sid and s["status"]["mode"] == "replay"
    assert s["top_alert"] and s["top_alert"]["ssid"] == "MVSR_WiFi"
    assert c.get("/api/audit?action=demo.start").get_json()[0]["target"] == sid
    ctx.pipeline.stop()
