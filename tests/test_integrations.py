"""Phase E: notifications (F013, F056-F059), metrics (F060), API keys + OpenAPI (F061).
Every channel is tested against a local fake receiver; nothing leaves this machine."""
import copy
import hashlib
import hmac
import http.server
import json
import os
import socket
import threading

import pytest

from ghostap import apikeys, notify
from ghostap.config import DEFAULT_CONFIG, ConfigError, load_config, validate
from ghostap.pipeline import Pipeline
from ghostap.storage import Store
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config.yaml")
ALERT = {"id": 7, "ssid": "Lab<WiFi>", "bssid": "00:c0:ca:de:ad:01", "level": "MEDIUM", "score": 45.0,
         "detector": "ghostap", "first_ts": 100.0, "high_ts": None, "last_ts": 200.0, "triage_status": "new",
         "reasons": "security_downgrade (+19): advertises OPN; ie_fingerprint (+16): different structure"}


def cfg_with(**notif):
    c = copy.deepcopy(DEFAULT_CONFIG)
    c["notifications"].update(notif)
    return validate(c)


class _Recv(http.server.BaseHTTPRequestHandler):
    got: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Recv.got.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture()
def http_server():
    _Recv.got = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Recv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:{}".format(srv.server_port)
    srv.shutdown()


def test_settings_validation():
    with pytest.raises(ConfigError, match="exactly one of url or url_env"):
        cfg_with(webhooks=[{"format": "json"}])
    with pytest.raises(ConfigError, match="telegram needs chat_id"):
        cfg_with(webhooks=[{"url_env": "X", "format": "telegram"}])
    with pytest.raises(ConfigError, match="unknown setting"):
        cfg_with(webhooks=[{"url": "https://x", "token": "secret"}])
    with pytest.raises(ConfigError, match="email needs host"):
        cfg_with(email=dict(DEFAULT_CONFIG["notifications"]["email"], enabled=True))
    assert load_config(CONFIG)["notifications"]["enabled"] is False          # off by default


def test_decide_raise_escalate_remind_and_skip():
    st = {}
    muted = lambda a: False  # noqa: E731
    assert notify.decide([ALERT], st, muted, "MEDIUM", 1800, 1000, 200) == [("raised", ALERT)]
    assert notify.decide([ALERT], st, muted, "HIGH", 1800, 1000, 200) == []
    assert notify.decide([dict(ALERT, triage_status="false_positive")], st, muted, "MEDIUM", 1800, 1000, 200) == []
    assert notify.decide([ALERT], st, lambda a: True, "MEDIUM", 1800, 1000, 200) == []
    st = {7: {"level": "MEDIUM", "last_sent": 1000}}
    assert notify.decide([dict(ALERT, level="HIGH")], st, muted, "MEDIUM", 1800, 1001, 200)[0][0] == "escalated"
    assert notify.decide([ALERT], st, muted, "MEDIUM", 1800, 2000, 200) == []                  # too soon
    assert notify.decide([ALERT], st, muted, "MEDIUM", 1800, 2800, 200)[0][0] == "reminder"
    assert notify.decide([ALERT], st, muted, "MEDIUM", 1800, 2800, 900) == []                  # no longer active
    assert notify.decide([ALERT], st, muted, "MEDIUM", 0, 99999, 200) == []                    # reminders off


def test_rate_limit_counts_what_it_holds_back():
    rl = notify.RateLimit(2)
    assert [rl.allow("x", t) for t in (0, 1, 2, 3)] == [True, True, False, False]
    assert rl.take_held("x") == 2 and rl.take_held("x") == 0
    assert rl.allow("x", 61)


def test_json_webhook_is_signed(http_server, monkeypatch):
    hook = notify.Webhook({"url": http_server + "/hook", "format": "json", "secret_env": "GA_SECRET"},
                          env={"GA_SECRET": "s3cret"})
    assert hook.send("raised", ALERT, "sess1", "http://kali:8050", 0) == "HTTP 200"
    path, headers, body = _Recv.got[0]
    assert path == "/hook" and json.loads(body)["alert"]["ssid"] == "Lab<WiFi>"
    want = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["x-ghostap-signature"] == want and headers["user-agent"].startswith("GhostAP/")


def test_ntfy_slack_telegram_formats(http_server):
    notify.Webhook({"url": http_server + "/n", "format": "ntfy"}).send("raised", dict(ALERT, ssid="Café"), "s", "", 0)
    notify.Webhook({"url": http_server + "/s", "format": "slack"}).send("raised", ALERT, "s", "", 3)
    notify.Webhook({"url_env": "TG", "format": "telegram", "chat_id": "42"},
                   env={"TG": http_server + "/bot123/sendMessage"}).send("escalated", ALERT, "s", "", 0)
    (_, nh, nb), (_, _, sb), (tp, _, tb) = _Recv.got
    assert nh["title"].isascii() and "Café" in nb.decode() and nh["priority"] == "high"
    assert "&lt;WiFi&gt;" in json.loads(sb)["text"] and "3 more messages" in json.loads(sb)["text"]
    assert tp == "/bot123/sendMessage" and json.loads(tb)["chat_id"] == "42" and "now HIGH" in json.loads(tb)["text"]
    with pytest.raises(ValueError, match="TG2 is not set"):
        notify.Webhook({"url_env": "TG2", "format": "json"}, env={})


def test_email_uses_starttls_and_env_password():
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["addr"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            sent["tls"] = True

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["msg"] = msg

    spec = dict(DEFAULT_CONFIG["notifications"]["email"], enabled=True, host="smtp.lab", sender="g@lab",
                to=["a@lab"], username="g")
    with pytest.raises(ValueError, match="SMTP password"):
        notify.Email(spec, env={})
    notify.Email(spec, env={"GHOSTAP_SMTP_PASSWORD": "pw"}, smtp_class=FakeSMTP).send("raised", ALERT, "s", "", 0)
    assert sent["addr"] == ("smtp.lab", 587) and sent["tls"] and sent["login"] == ("g", "pw")
    assert "MEDIUM" in sent["msg"]["Subject"] and "Lab<WiFi>" in sent["msg"]["Subject"]


def test_syslog_udp_json_and_cef(tmp_path):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(3)
    port = rx.getsockname()[1]
    notify.Syslog({"host": "127.0.0.1", "port": port, "protocol": "udp", "format": "json"}).send(
        "raised", ALERT, "s", "", 0)
    line = rx.recv(9000).decode()
    assert line.startswith("<132>1 ")
    assert json.loads(line.split(" - ALERT - ", 1)[1])["alert"]["bssid"] == ALERT["bssid"]
    notify.Syslog({"host": "127.0.0.1", "port": port, "protocol": "udp", "format": "cef"}).send(
        "raised", dict(ALERT, ssid="a|b=c"), "s", "", 0)
    cef = rx.recv(9000).decode()
    assert "CEF:0|GhostAP|GhostAP|" in cef and "cs1=a|b\\=c" in cef
    rx.close()
    path = tmp_path / "a.jsonl"
    notify.JsonLines({"path": str(path)}).send("raised", ALERT, "s", "", 0)
    assert json.loads(path.read_text())["event"] == "raised"


def test_notifier_sends_once_then_escalates(tmp_path, http_server):
    cfg = cfg_with(enabled=True, webhooks=[{"url": http_server + "/h", "format": "json"}])
    admin = str(tmp_path / "admin.db")
    nt = notify.Notifier(cfg, admin)
    assert len(nt.channels) == 1 and nt.problems == []
    r = nt.tick("s1", [ALERT], lambda a: False, 200, now=1000)
    assert [x["event"] for x in r] == ["raised"] and r[0]["ok"]
    assert nt.tick("s1", [ALERT], lambda a: False, 200, now=1010) == []                 # not sent twice
    up = nt.tick("s1", [dict(ALERT, level="HIGH")], lambda a: False, 200, now=1020)
    assert [x["event"] for x in up] == ["escalated"]
    with Store(admin) as s:
        logrows = s.notification_log()
    assert len(logrows) == 2 and all(x["ok"] for x in logrows)
    assert len(_Recv.got) == 2


def test_metrics_api_keys_and_openapi(tmp_path):
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        import sys
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import make_test_pcap
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    db, admin = str(tmp_path / "s.db"), str(tmp_path / "admin.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    c = create_app(db, cfg, pipe, admin_db=admin, config_path=CONFIG,
                   monitored_path=str(tmp_path / "m.json")).test_client()
    m = c.get("/metrics")
    assert m.status_code == 200 and m.mimetype == "text/plain"
    text = m.data.decode()
    assert 'ghostap_open_alerts{level="HIGH"} 1' in text and "ghostap_access_points 4" in text
    # keys
    made = c.post("/api/keys", json={"name": "grafana", "scope": "read"}).get_json()
    rkey = made["key"]
    wkey = c.post("/api/keys", json={"name": "bot", "scope": "write"}).get_json()["key"]
    assert c.post("/api/keys", json={"name": "x", "scope": "admin"}).status_code == 400
    hdr = lambda k: {"Authorization": "Bearer " + k}  # noqa: E731
    assert c.get("/api/summary", headers=hdr(rkey)).status_code == 200
    aid = c.get("/api/alerts").get_json()[0]["id"]
    url, body = "/api/alerts/{}/triage".format(aid), {"status": "investigating"}
    assert c.post(url, json=body, headers=hdr(rkey)).status_code == 403
    assert c.post(url, json=body, headers=hdr(wkey)).status_code == 200
    assert c.get("/api/audit?action=triage").get_json()[0]["actor"] == "key:bot"
    assert c.get("/api/keys", headers=hdr(wkey)).status_code == 403                    # keys can't manage keys
    assert c.get("/api/summary", headers=hdr("gk_wrong")).status_code == 401
    listed = c.get("/api/keys").get_json()
    assert all("hash" not in k for k in listed) and listed[0]["prefix"] == rkey[:10]
    assert c.post("/api/keys/{}/revoke".format(made["id"])).status_code == 200
    assert c.get("/api/summary", headers=hdr(rkey)).status_code == 401
    with Store(admin) as s:                                                            # only the hash is stored
        assert rkey not in json.dumps([dict(r) for r in s.conn.execute("SELECT * FROM api_keys")])
    spec = c.get("/api/openapi.json").get_json()
    assert spec["openapi"].startswith("3.") and "/api/alerts/{alert_id}/triage" in spec["paths"]
    assert "post" in spec["paths"]["/api/whatif"] and "/metrics" in spec["paths"]
    assert c.post("/api/notifications/test").status_code == 400                       # nothing configured


def test_apikey_cli(tmp_path, monkeypatch, capsys):
    kid, key = apikeys.create(str(tmp_path / "a.db"), "cli", "read")
    assert key.startswith("gk_") and apikeys.check(str(tmp_path / "a.db"), key)["id"] == kid
    assert apikeys.check(str(tmp_path / "a.db"), "nope") is None
    with pytest.raises(ValueError):
        apikeys.create(str(tmp_path / "a.db"), "", "read")


def test_notifier_thread_end_to_end(tmp_path):
    import time as _t
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    db, out = str(tmp_path / "s.db"), tmp_path / "alerts.jsonl"
    cfg = load_config(CONFIG)
    cfg["notifications"].update(enabled=True, jsonl={"enabled": True, "path": str(out)})
    pipe = Pipeline(db, cfg, pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    app = create_app(db, cfg, pipe, admin_db=str(tmp_path / "a.db"), config_path=CONFIG,
                     monitored_path=str(tmp_path / "m.json"))
    ctx = app.extensions["ghostap"]
    ctx.notifier_thread.every = 0.1
    deadline = _t.time() + 10
    while _t.time() < deadline and not (out.exists() and out.read_text().strip()):
        _t.sleep(0.2)
    ctx.notifier_thread.stop_event.set()
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    assert lines and lines[0]["event"] == "raised" and lines[0]["alert"]["bssid"] == "00:c0:ca:de:ad:01"
    status = app.test_client().get("/api/notifications").get_json()
    assert status["channels"][0]["name"] == "jsonl" and status["log"][0]["ok"] == 1
