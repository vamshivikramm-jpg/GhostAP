"""GhostAP 2.1 (2.0 Phase 2): saved-baseline integrity, versions, approval and contamination checks."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import auth as A  # noqa: E402
from ghostap import baselines as B  # noqa: E402
from ghostap import monitored as mon  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
PW = "Correct-Horse-9"
EVIL = "00:c0:ca:de:ad:01"


@pytest.fixture()
def env(tmp_path):
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    db, admin = str(tmp_path / "s.db"), str(tmp_path / "admin.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    mpath = str(tmp_path / "monitored.json")
    app = create_app(db, cfg, pipe, admin_db=admin, config_path=CONFIG, monitored_path=mpath)
    return app, pipe, mpath, admin


def _login(app, name):
    c = app.test_client()
    assert c.post("/api/login", json={"username": name, "password": PW}).status_code == 200
    return c


def _users(admin, *pairs):
    au = A.Auth(admin)
    for name, role in pairs:
        au.add_user(name, PW, role)
    au._count_cache = (0.0, -1)


# ---------------------------------------------------------------- integrity

def test_signed_file_round_trip_and_tampering(tmp_path):
    path = str(tmp_path / "m.json")
    data = mon.empty()
    data["networks"]["Lab"] = {"bssids": ["a4:2b:b0:00:00:01"]}
    assert mon.save(path, data) == 1 and mon.save(path, data) == 2
    assert mon.signed_version(mon.load(path)) == 2
    raw = json.load(open(path))
    raw["networks"]["Lab"]["bssids"].append(EVIL)                    # edited outside GhostAP
    json.dump(raw, open(path, "w"))
    with pytest.raises(B.IntegrityError, match="changed outside GhostAP"):
        mon.load(path)
    raw["integrity"]["sha256"] = B.digest(B.content_of(raw))          # ... and its checksum
    json.dump(raw, open(path, "w"))
    with pytest.raises(B.IntegrityError, match="signature does not match"):
        mon.load(path)
    assert stat_mode(B.key_path()) == 0o600


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


def test_unsigned_older_file_still_loads_and_gets_signed(tmp_path):
    path = str(tmp_path / "m.json")
    json.dump({"version": 1, "networks": {"Lab": {"bssids": []}}}, open(path, "w"))
    data = mon.load(path)                                            # no integrity block: accepted
    assert mon.signed_version(data) == 0
    assert mon.save(path, data) == 1 and mon.load(path)["integrity"]["version"] == 1


def test_under_sudo_the_key_belongs_to_the_invoking_user(tmp_path, monkeypatch):
    """Live capture runs under sudo with HOME=/root; the key must be the one the same user's
    later non-sudo runs find, and owned by that user."""
    import pwd
    home = tmp_path / "home" / "kali"
    home.mkdir(parents=True)
    monkeypatch.delenv(B.KEY_ENV)
    monkeypatch.setattr("ghostap.ownership.sudo_user", lambda: (4321, 4322))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("P", (), {"pw_dir": str(home)})())
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, u, g, follow_symlinks=True: chowned.append((p, u, g)))
    assert B.key_path() == str(home / ".config" / "ghostap" / "baseline.key")
    assert B.load_key(create=True)
    assert {p for p, _, _ in chowned} == {str(home / ".config" / "ghostap" / "baseline.key"),
                                          str(home / ".config" / "ghostap"), str(home / ".config")}
    assert all((u, g) == (4321, 4322) for _, u, g in chowned)


def test_missing_key_is_reported(tmp_path, monkeypatch):
    path = str(tmp_path / "m.json")
    mon.save(path, mon.empty())
    monkeypatch.setenv(B.KEY_ENV, str(tmp_path / "other" / "key"))
    with pytest.raises(B.IntegrityError, match="signing key"):
        mon.load(path)


def test_tampered_file_is_refused_by_the_api_and_at_start_up(env):
    app, _, mpath, _ = env
    c = app.test_client()
    assert c.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]}).status_code == 200
    raw = json.load(open(mpath))
    raw["networks"]["Cafe_Guest"]["bssids"].append(EVIL)            # someone adds a BSSID by hand
    json.dump(raw, open(mpath, "w"))
    r = c.get("/api/monitored")
    assert r.status_code == 409 and r.get_json()["integrity"] is False
    import logging

    from ghostap import web
    tmp = os.path.dirname(mpath)                      # own config: no writes to the real data/ or logs
    cfg = os.path.join(tmp, "c.yaml")
    with open(cfg, "w") as f:
        f.write(open(CONFIG).read() + "\nsessions_dir: {0}/sessions\nlogging:\n  file: {0}/g.log\n".format(tmp))
    try:
        assert web.main(["--config", cfg, "--db", os.path.join(tmp, "s.db"), "--monitored", mpath,
                         "--port", "0"]) == 2
    finally:
        log = logging.getLogger("ghostap")
        for h in list(log.handlers):
            if isinstance(h, logging.FileHandler):
                log.removeHandler(h)
                h.close()


# ---------------------------------------------------------------- versions, local mode

def test_local_changes_apply_as_versions_and_roll_back(env):
    app, pipe, mpath, admin = env
    c = app.test_client()
    r = c.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]})
    assert r.status_code == 200 and r.get_json()["version"] == 1
    settings = mon.default_settings()
    settings["threshold_medium"] = 45
    r = c.post("/api/monitored/settings", json={"ssid": "Cafe_Guest", "settings": settings})
    assert r.get_json()["version"] == 2
    v = c.get("/api/baselines/versions").get_json()
    assert v["current_version"] == 2 and v["signed"]
    assert [x["status"] for x in v["versions"]] == ["trusted", "superseded"]
    first = v["versions"][1]
    d = c.get("/api/baselines/versions/{}".format(first["id"])).get_json()
    assert d["diff"]["changed"]["Cafe_Guest"]["fields"] == ["settings"]
    r = c.post("/api/baselines/versions/{}/rollback".format(first["id"]), json={})
    assert r.status_code == 200 and r.get_json() == {"restored": 1, "version": 3}
    assert mon.load(mpath)["networks"]["Cafe_Guest"]["settings"]["threshold_medium"] is None
    assert pipe._scorer.analyzer.baseline.ssids["Cafe_Guest"].saved                 # applied live
    with Store(admin) as s:
        actions = [a["action"] for a in s.audit_log()]
    assert "baseline.rollback" in actions and "baseline.settings" in actions


# ---------------------------------------------------------------- approval

def test_analyst_proposes_admin_approves(env):
    app, _, mpath, admin = env
    _users(admin, ("alice", "admin"), ("bob", "analyst"))
    bob, alice = _login(app, "bob"), _login(app, "alice")
    r = bob.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]})
    assert r.status_code == 202 and "admin" in r.get_json()["message"]
    pid = r.get_json()["pending"]
    assert not os.path.exists(mpath)                                   # nothing applied yet
    assert bob.post("/api/baselines/versions/{}/approve".format(pid), json={}).status_code == 403
    lst = alice.get("/api/baselines/versions").get_json()
    assert lst["versions"][0]["status"] == "pending" and lst["versions"][0]["approve_error"] is None
    r = alice.post("/api/baselines/versions/{}/approve".format(pid), json={})
    assert r.status_code == 200 and r.get_json()["version"] == 1
    assert "Cafe_Guest" in mon.load(mpath)["networks"]
    assert alice.post("/api/baselines/versions/{}/approve".format(pid), json={}).status_code == 409


def test_stale_proposal_cannot_be_approved(env):
    app, _, mpath, admin = env
    _users(admin, ("alice", "admin"), ("bob", "analyst"))
    bob, alice = _login(app, "bob"), _login(app, "alice")
    pid = bob.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]}).get_json()["pending"]
    assert alice.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]}).status_code == 200   # v1 meanwhile
    r = alice.post("/api/baselines/versions/{}/approve".format(pid), json={})
    assert r.status_code == 409 and "changed since" in r.get_json()["error"]
    assert alice.post("/api/baselines/versions/{}/reject".format(pid), json={"reason": "stale"}).status_code == 200


def test_two_person_rule_with_two_admins(env):
    app, _, mpath, admin = env
    _users(admin, ("alice", "admin"), ("carol", "admin"))
    alice, carol = _login(app, "alice"), _login(app, "carol")
    r = alice.post("/api/monitored/learn", json={"ssids": ["Cafe_Guest"]})
    assert r.status_code == 202 and "second admin" in r.get_json()["message"]
    pid = r.get_json()["pending"]
    r = alice.post("/api/baselines/versions/{}/approve".format(pid), json={})
    assert r.status_code == 403 and "different admin" in r.get_json()["error"]
    assert carol.post("/api/baselines/versions/{}/approve".format(pid), json={}).get_json()["version"] == 1
    with Store(admin) as s:
        row = B.versions(s.conn)[0]
    assert row["proposed_by"] == "alice" and row["approved_by"] == "carol"


# ---------------------------------------------------------------- contamination

def test_learning_with_the_twin_on_air_needs_explicit_approval(env):
    """The test capture's twin (open, freshly booted) is on the air in the second half: learning
    MVSR_WiFi from the whole session would learn it as normal. Even in local mode (a lone admin),
    the change waits for an explicit approval and says why."""
    app, _, mpath, _ = env
    c = app.test_client()
    r = c.post("/api/monitored/learn", json={"ssids": ["MVSR_WiFi"], "whole": True})
    assert r.status_code == 202
    checks = {(h["check"], h["bssid"]) for h in r.get_json()["checks"]}
    assert ("mixed_security", EVIL) in checks
    assert not os.path.exists(mpath)
    r = c.post("/api/baselines/versions/{}/approve".format(r.get_json()["pending"]), json={})
    assert r.status_code == 200 and EVIL in mon.load(mpath)["networks"]["MVSR_WiFi"]["bssids"]
    # learning only the clean first minutes finds nothing and applies directly
    r = c.post("/api/monitored/learn", json={"ssids": ["MVSR_WiFi"]})
    assert r.status_code == 200 and r.get_json()["checks"] == []


def test_contamination_checks_unit():
    def o(t, bssid, ssid="Lab", sec="WPA2/PSK", tsf=None):
        return {"ts": 1000.0 + t, "frame_type": "beacon", "ssid": ssid, "bssid": bssid, "oui": bssid[:8],
                "channel": 6, "security": sec, "rssi": -50, "beacon_interval": 100,
                "tsf": tsf if tsf is not None else int(9e9 + t * 1e6), "seq": int(t * 10) % 4096,
                "fingerprint": "fp", "rsn": None}
    obs = [o(t, "a4:2b:b0:00:00:01") for t in range(100)]                       # up 2.5 h
    obs += [o(t, "02:00:00:00:00:09", sec="OPN", tsf=int(5e6 + t * 1e6)) for t in range(50, 100)]
    for i, name in enumerate(("Lab", "Free", "Airport")):                          # KARMA-like radio
        obs.append(o(60 + i, "02:00:00:00:00:0a", ssid=name))
    hits = {(h["check"], h["bssid"]) for h in B.contamination(obs, 2, ["Lab"])}
    assert {("mixed_security", "02:00:00:00:00:09"), ("fresh_boot", "02:00:00:00:00:09"),
            ("karma", "02:00:00:00:00:0a")} <= hits
    clean = [x for x in obs if x["bssid"] == "a4:2b:b0:00:00:01"]
    assert B.contamination(clean, 2, ["Lab"]) == []


# ---------------------------------------------------------------- CLI

def test_cli_trust_after_an_outside_edit(tmp_path, capsys):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("sessions_dir: {}/sessions\nmonitored_networks: {}/m.json\n".format(tmp_path, tmp_path))
    path = str(tmp_path / "m.json")
    mon.save(path, {"networks": {"Lab": {"bssids": []}}})
    raw = json.load(open(path))
    raw["networks"]["Lab"]["bssids"] = [EVIL]
    json.dump(raw, open(path, "w"))
    assert mon.main(["show", "--config", str(cfg_path)]) == 2
    assert mon.main(["trust", "--config", str(cfg_path)]) == 1                  # needs --yes
    assert mon.main(["trust", "--config", str(cfg_path), "--yes"]) == 0
    assert mon.load(path)["networks"]["Lab"]["bssids"] == [EVIL]
    assert mon.main(["history", "--config", str(cfg_path)]) == 0
    assert "baseline.trust" in capsys.readouterr().out


def test_old_database_gets_the_versions_table(tmp_path):
    import sqlite3
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 1")
    con.commit()
    con.close()
    with Store(db) as s:
        assert s.schema_version() >= 2
        assert s.conn.execute("SELECT COUNT(*) FROM baseline_versions").fetchone()[0] == 0
