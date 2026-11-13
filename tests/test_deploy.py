"""Phase H: systemd service (F071), Docker files (F073), health check, Settings API (F075)."""
import configparser
import os
import socket
import subprocess
import threading

import yaml

import ghostap.config
from ghostap import healthcheck
from ghostap.config import load_config
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config.yaml")


def test_systemd_unit_is_least_privilege():
    unit = configparser.ConfigParser(strict=False, interpolation=None)
    unit.optionxform = str
    unit.read(os.path.join(ROOT, "deploy", "ghostap.service"))
    svc = unit["Service"]
    assert svc["User"] == "ghostap" and svc["NoNewPrivileges"] == "yes" and svc["ProtectSystem"] == "strict"
    assert set(svc["AmbientCapabilities"].split()) == {"CAP_NET_RAW", "CAP_NET_ADMIN"}
    assert svc["CapabilityBoundingSet"] == svc["AmbientCapabilities"]
    assert svc["ReadWritePaths"] == "/opt/ghostap/data" and svc["UMask"] == "0077"
    assert svc["ExecStartPre"].startswith("+/opt/ghostap/tools/kali_monitor.sh start")
    assert "-m ghostap.web --iface" in svc["ExecStart"] and unit["Install"]["WantedBy"] == "multi-user.target"


def test_install_script_and_env_example():
    assert subprocess.run(["bash", "-n", os.path.join(ROOT, "tools", "install_service.sh")]).returncode == 0
    env = open(os.path.join(ROOT, "deploy", "ghostap.env.example")).read()
    for line in env.splitlines():
        if line.startswith(("GHOSTAP_TOKEN", "GHOSTAP_SMTP_PASSWORD", "GHOSTAP_NTFY_URL")):
            raise AssertionError("the example must not set a secret: " + line)


def test_dockerfile_and_compose():
    df = open(os.path.join(ROOT, "Dockerfile")).read()
    lines = [x.strip() for x in df.splitlines() if x.strip() and not x.strip().startswith("#")]
    assert lines[0].startswith("FROM python:3.12-slim-")                # pinned base image
    user = [i for i, x in enumerate(lines) if x.startswith("USER ")]
    entry = [i for i, x in enumerate(lines) if x.startswith("ENTRYPOINT")]
    assert user and lines[user[-1]] == "USER ghostap" and user[-1] < entry[0]
    assert "ghostap.healthcheck" in df and "ADD http" not in df and "| sh" not in df
    ignore = open(os.path.join(ROOT, ".dockerignore")).read().split()
    assert {"data", ".venv", ".git", "results"} <= set(ignore)
    comp = yaml.safe_load(open(os.path.join(ROOT, "docker-compose.yml")))
    demo, live = comp["services"]["demo"], comp["services"]["live"]
    assert demo["ports"] == ["127.0.0.1:8050:8050"] and demo["cap_drop"] == ["ALL"] and demo["read_only"]
    assert set(live["cap_add"]) == {"NET_RAW", "NET_ADMIN"} and live["cap_drop"] == ["ALL"]
    assert not live.get("privileged") and "no-new-privileges:true" in live["security_opt"]


def test_healthcheck(tmp_path):
    from werkzeug.serving import make_server
    db = str(tmp_path / "s.db")
    app = create_app(db, load_config(CONFIG), admin_db=db + ".a")
    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert healthcheck.alive(srv.server_port)
    finally:
        srv.shutdown()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    assert not healthcheck.alive(free, timeout=1)


def test_settings_api(tmp_path):
    db = str(tmp_path / "s.db")
    cfg = load_config(CONFIG)
    app = create_app(db, cfg, admin_db=db + ".a", config_path=CONFIG)
    c = app.test_client()
    d = c.get("/api/settings").get_json()
    assert d["values"]["thresholds.medium"]["saved"] == 30 and any(s["title"] == "Notifications" for s in d["sections"])
    assert c.post("/api/settings", json={"changes": {"known_bssids": []}}).status_code == 400
    bad = c.post("/api/settings", json={"changes": {"thresholds.medium": 70}})
    assert bad.status_code == 400 and "medium" in bad.get_json()["error"]
    assert not os.path.exists(ghostap.config.SETTINGS_OVERLAY)                   # nothing written when invalid
    r = c.post("/api/settings", json={"changes": {"weights.rssi_jump": 2.5, "retention.raw_hours": 48,
                                                  "logging.level": "DEBUG"}}).get_json()
    assert r["restart_needed"] == ["weights.rssi_jump"]
    assert set(r["applied_now"]) == {"retention.raw_hours", "logging.level"}
    assert cfg["retention"]["raw_hours"] == 48 and cfg["weights"]["rssi_jump"] == 1.5      # running weights unchanged
    assert load_config(CONFIG)["weights"]["rssi_jump"] == 2.5
    assert c.get("/api/audit?action=settings.save").get_json()[0]["detail"]["restart"] == ["weights.rssi_jump"]
    assert c.post("/api/settings/reset", json={}).status_code == 400
    assert c.post("/api/settings/reset", json={"confirm": True}).status_code == 200
    assert load_config(CONFIG)["weights"]["rssi_jump"] == 1.5
    import logging
    logging.getLogger("ghostap").setLevel(logging.INFO)
