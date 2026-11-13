"""Phase A: settings validation, sessions, audit, health, saved baselines, retention, logs."""
import copy
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import config as gconfig  # noqa: E402
from ghostap import monitored  # noqa: E402
from ghostap.collector import collect_pcap  # noqa: E402
from ghostap.config import ConfigError, load_config, save_overlay, validate  # noqa: E402
from ghostap.indicators import Analyzer  # noqa: E402
from ghostap.pipeline import IncrementalScorer, Pipeline  # noqa: E402
from ghostap.risk import RiskEngine  # noqa: E402
from ghostap.sessions import SessionError, SessionStore  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture(scope="module")
def obs(tmp_path_factory):
    d = tmp_path_factory.mktemp("f")
    pcap, _, _ = make_test_pcap.generate(str(d))
    with Store(str(d / "a.db")) as s:
        collect_pcap(pcap, s)
        return s.observations()


# ---------------------------------------------------------------- F072 settings validation

def _cfg(**over):
    return gconfig.merge(copy.deepcopy(gconfig.DEFAULT_CONFIG), over)


def test_defaults_and_config_yaml_are_valid():
    assert validate(_cfg())["thresholds"]["high"] == 60
    assert load_config(CONFIG)["weights"]["ie_fingerprint"] == 2.5


@pytest.mark.parametrize("over, msg", [
    ({"thresholds": {"medium": 70, "high": 60}}, "0 < medium < high"),
    ({"weights": {"rssi_jump": -1}}, "cannot be negative"),
    ({"tresholds": {"medium": 1}}, "did you mean 'thresholds'"),
    ({"temporal": {"step_seconds": "ten"}}, "must be a number"),
    ({"known_bssids": ["not-a-mac"]}, "not a MAC address"),
    ({"logging": {"level": "LOUD"}}, "logging.level"),
    ({"temporal": {"smoothing_steps": 0}}, "at least 1"),
])
def test_bad_settings_are_rejected_with_a_clear_message(over, msg):
    with pytest.raises(ConfigError, match=msg):
        validate(_cfg(**over))


def test_config_file_errors_name_the_file(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("thresholds: {medium: 90, high: 60}\n")
    with pytest.raises(ConfigError, match=str(p)):
        load_config(str(p))
    p.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError, match="must contain settings"):
        load_config(str(p))


def test_settings_overlay_is_validated_before_writing(tmp_path):
    overlay = str(tmp_path / "settings.yaml")
    with pytest.raises(ConfigError):
        save_overlay({"thresholds": {"medium": 99}}, overlay=overlay, base_path=CONFIG)
    assert not os.path.exists(overlay)                         # nothing written when invalid
    cfg = save_overlay({"thresholds": {"medium": 25}}, overlay=overlay, base_path=CONFIG)
    assert cfg["thresholds"]["medium"] == 25
    assert load_config(CONFIG, overlay=overlay)["thresholds"]["medium"] == 25
    assert load_config(CONFIG, overlay=None)["thresholds"]["medium"] == 30   # config.yaml untouched


# ---------------------------------------------------------------- F040 sessions

def test_session_lifecycle(tmp_path):
    ss = SessionStore(str(tmp_path / "sessions"))
    a = ss.create("Lab run 1", "replay", "x.pcap", now=1_700_000_000)
    b = ss.create("Lab run 1", "replay", "x.pcap", now=1_700_000_000)   # same second: unique id
    assert a.id != b.id and a.id.endswith("lab-run-1")
    with Store(a.db) as s:
        s.add({"ts": 1.0, "frame_type": "beacon", "ssid": "N", "bssid": "aa:bb:cc:00:00:01"})
        s.update_profiles(s.observations())
    items = ss.list()
    assert {m["id"] for m in items} == {a.id, b.id}
    assert next(m for m in items if m["id"] == a.id)["frames"] == 1
    assert ss.rename(a.id, "Renamed")["name"] == "Renamed"
    ss.delete(b.id)
    assert [m["id"] for m in ss.list()] == [a.id]


@pytest.mark.parametrize("bad", ["../x", "..", "/etc", "20231114-221320-a/../../x", "", "a b", "x" * 300])
def test_session_ids_cannot_escape_the_folder(tmp_path, bad):
    ss = SessionStore(str(tmp_path / "sessions"))
    ss.create("ok", "replay")
    with pytest.raises(SessionError):
        ss.get(bad)


@pytest.fixture()
def web(tmp_path):
    """Two sessions: a finished replay and a 'current' empty one."""
    ss = SessionStore(str(tmp_path / "sessions"))
    old = ss.create("old replay", "replay", "test_capture.pcap")
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    Pipeline(old.db, load_config(CONFIG), pcap=pcap, speed=0, rescore_seconds=0.2).start().wait(60)
    cur = ss.create("current", "live", "wlan1")
    Store(cur.db).close()
    app = create_app(cur.db, load_config(CONFIG), sessions=ss, current_session=cur.id,
                     admin_db=str(tmp_path / "admin.db"))
    return app.test_client(), ss, old, cur


def test_sessions_api_and_viewing_a_past_session(web):
    c, ss, old, cur = web
    lst = c.get("/api/sessions").get_json()
    assert lst["current"] == cur.id and len(lst["sessions"]) == 2
    assert c.get("/api/summary").get_json()["aps"] == 0                      # current: empty
    past = c.get("/api/summary?session=" + old.id).get_json()
    assert past["aps"] == 4 and past["status"]["mode"] == "session"
    assert c.get("/api/alerts?session=" + old.id).get_json()[0]["bssid"] == EVIL
    assert c.get("/api/summary?session=../../etc").status_code == 404


def test_session_rename_delete_and_audit(web):
    c, ss, old, cur = web
    r = c.post("/api/sessions/{}/rename".format(old.id), json={"name": "Lab A"})
    assert r.get_json()["name"] == "Lab A"
    assert c.post("/api/sessions/{}/delete".format(cur.id), json={"confirm": cur.id}).status_code == 409
    assert c.post("/api/sessions/{}/delete".format(old.id), json={}).status_code == 400
    aid = c.get("/api/alerts?session=" + old.id).get_json()[0]["id"]
    assert c.post("/api/alerts/{}/triage?session={}".format(aid, old.id),
                  json={"status": "confirmed", "note": "lab twin"}).status_code == 200
    assert c.post("/api/sessions/{}/delete".format(old.id), json={"confirm": old.id}).status_code == 200
    actions = [a["action"] for a in c.get("/api/audit").get_json()]
    assert actions == ["session.delete", "triage", "session.rename"]       # newest first
    triage = c.get("/api/audit?action=triage").get_json()[0]
    assert triage["detail"]["to"] == "confirmed" and triage["actor"] == "local"


def test_health_endpoint(web):
    c, ss, old, cur = web
    h = c.get("/api/health?session=" + old.id).get_json()
    assert h["database"]["raw_frames"] == 1020 and h["disk"]["free_bytes"] > 0
    assert h["version"] and h["server_uptime_s"] >= 0


# ---------------------------------------------------------------- F014 saved baselines

def test_saved_baseline_roundtrip(obs, tmp_path):
    learned = monitored.learn([o for o in obs if o["bssid"] != EVIL], 2)
    assert set(learned) == {"MVSR_WiFi", "Cafe_Guest"}
    path = str(tmp_path / "monitored.json")
    data = monitored.empty()
    monitored.upsert(data, learned)
    monitored.save(path, data)
    back = monitored.baselines(monitored.load(path))
    assert back["MVSR_WiFi"].bssids == {"a4:2b:b0:11:22:33", "a4:2b:b0:11:22:99"}
    assert back["MVSR_WiFi"].security == "WPA2/PSK" and back["MVSR_WiFi"].saved


def test_saved_baseline_catches_a_twin_running_at_start_up(obs):
    """Without a saved baseline the twin is learned as normal; with one it is caught."""
    legit = [o for o in obs if o["bssid"] != EVIL]
    saved = monitored.baselines({"networks": monitored.learn(legit, 2)})
    shift = 180.0
    twin_from_start = [dict(o, ts=o["ts"] - shift) for o in obs if o["bssid"] == EVIL]
    t0 = min(o["ts"] for o in legit)
    today = sorted(legit + [o for o in twin_from_start if o["ts"] >= t0], key=lambda o: o["ts"])
    cfg = load_config(CONFIG)
    learned_only = RiskEngine(Analyzer(today, 2), cfg).run()
    assert learned_only.alerts == []                               # the blind spot F014 fixes
    an = Analyzer(today, 2, monitored=saved)
    assert an.scoring_start == t0                                  # no learning wait
    rep = RiskEngine(an, cfg).run()
    assert [a["bssid"] for a in rep.alerts] == [EVIL] and rep.alerts[0]["level"] == "HIGH"
    assert rep.alerts[0]["first_ts"] - t0 <= 40


def test_monitored_cli_save_show_remove(obs, tmp_path, capsys):
    db = str(tmp_path / "s.db")
    with Store(db) as s:
        for o in obs:
            s.add(o)
    path = str(tmp_path / "m.json")
    assert monitored.main(["save", "--db", db, "--ssid", "MVSR_WiFi",
                           "--file", path, "--config", CONFIG]) == 0
    assert monitored.main(["show", "--file", path, "--config", CONFIG]) == 0
    assert "MVSR_WiFi" in capsys.readouterr().out
    assert monitored.main(["remove", "--ssid", "MVSR_WiFi", "--file", path, "--config", CONFIG]) == 0
    assert monitored.load(path)["networks"] == {}


def test_accepting_an_ap_into_the_baseline(obs):
    data = monitored.empty()
    monitored.upsert(data, monitored.learn([o for o in obs if o["bssid"] != EVIL], 2))
    monitored.add_ap(data, "MVSR_WiFi", {"bssid": "A4:2B:B0:11:22:C4", "channels": [11],
                                         "security": "WPA2/PSK", "fingerprints": ["fp1"], "rssi_avg": -60})
    net = data["networks"]["MVSR_WiFi"]
    assert "a4:2b:b0:11:22:c4" in net["bssids"] and 11 in net["channels"] and "fp1" in net["fingerprints"]


# ---------------------------------------------------------------- F070 retention

def test_retention_prunes_old_frames_without_changing_results(obs, tmp_path):
    cfg = load_config(CONFIG)
    full = RiskEngine(Analyzer(obs, 2), cfg).run()
    cfg["retention"] = {"raw_hours": 60 / 3600, "check_minutes": 0.25}    # keep 60 s, check every 15 s
    db = str(tmp_path / "r.db")
    sc = IncrementalScorer(db, cfg)
    with Store(db) as s:
        for i in range(0, len(obs), 40):
            for o in obs[i:i + 40]:
                s.add(o)
            s.commit()
            sc.step()
    sc.step(final=True)
    with Store(db) as s:
        remaining = s.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        frames = sum(p["frames"] for p in s.profiles())
        alerts = s.alerts("ghostap")
    assert sc.pruned > 0 and remaining < len(obs)
    assert frames == len(obs)                                       # profiles keep the totals
    assert [(a["bssid"], a["level"]) for a in alerts] == [(a["bssid"], a["level"]) for a in full.alerts]


# ---------------------------------------------------------------- F074 log files

def test_log_file_is_written(tmp_path):
    import logging

    from ghostap.logs import get_logger, setup_logging
    path = str(tmp_path / "logs" / "g.log")
    log = setup_logging({"logging": {"file": path, "level": "INFO"}})
    try:
        get_logger("test").info("hello from the test")
        for h in log.handlers:
            h.flush()
        assert "hello from the test" in open(path).read()
    finally:
        for h in list(log.handlers):
            if isinstance(h, logging.FileHandler):
                log.removeHandler(h)
                h.close()
