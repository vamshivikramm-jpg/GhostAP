"""Phase J: capture control (F041), several sensors (F044), rough location (F045)."""
import math
import os
import sys
import threading
import time

import pytest
from scapy.utils import rdpcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import apikeys, collector  # noqa: E402
from ghostap import sensors as S  # noqa: E402
from ghostap.capture import CaptureControl  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.hopper import ChannelHopper  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
PCAP = os.path.join(ROOT, "data", "test_capture.pcap")


def rssi_at(sx, sy, ax, ay, p0=-40.0, n=3.0):
    return p0 - 10 * n * math.log10(max(math.hypot(ax - sx, ay - sy), 0.1))


def test_locate_recovers_a_known_position():
    sensors = [(0, 0), (10, 0), (0, 10), (10, 10)]
    est = S.locate([(x, y, rssi_at(x, y, 3, 4)) for x, y in sensors])
    assert abs(est["x"] - 3) < 0.1 and abs(est["y"] - 4) < 0.1 and est["sensors"] == 4
    noisy = S.locate([(x, y, rssi_at(x, y, 3, 4) + d) for (x, y), d in zip(sensors, (3, -3, 2, -2))])
    assert math.hypot(noisy["x"] - 3, noisy["y"] - 4) < 3 and noisy["radius"] >= 1
    near = S.locate([(0, 0, -50), (10, 0, -70)])
    assert near["method"].startswith("nearest sensor") and (near["x"], near["y"]) == (0.0, 0.0)
    assert S.locate([]) is None


def test_report_validation_and_merge(tmp_path):
    db = str(tmp_path / "a.db")
    S.ensure_schema(db)
    for bad in ({"sensor": "../x", "aps": []}, {"sensor": "a", "aps": [{"ssid": "x", "bssid": "nope"}]},
                {"sensor": "a", "aps": [{"ssid": "x", "bssid": "00:11:22:33:44:55", "rssi": 5}]}):
        with pytest.raises(S.ReportError):
            S.record_report(db, bad, "1.2.3.4")
    for name, (x, y) in {"s1": (0, 0), "s2": (10, 0), "s3": (0, 10)}.items():
        S.record_report(db, {"sensor": name, "aps": [{"ssid": "Lab", "bssid": "00:c0:ca:de:ad:01",
                                                      "rssi": rssi_at(x, y, 6, 2), "level": "HIGH", "score": 70}]}, "")
        with Store(db) as s:
            s.conn.execute("UPDATE sensors SET x=?, y=? WHERE name=?", (x, y, name))
            s.conn.commit()
    m = S.merged(db, -40, 3)
    assert len(m) == 1 and len(m[0]["heard_by"]) == 3 and m[0]["level"] == "HIGH"
    assert abs(m[0]["location"]["x"] - 6) < 0.2 and abs(m[0]["location"]["y"] - 2) < 0.2


def test_sensor_reports_to_central_over_http(tmp_path):
    from werkzeug.serving import make_server
    if not os.path.exists(PCAP):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    cfg = load_config(CONFIG)
    central_admin = str(tmp_path / "central.db")
    central = create_app(str(tmp_path / "c.db"), cfg, admin_db=central_admin)
    srv = make_server("127.0.0.1", 0, central)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _, key = apikeys.create(central_admin, "lab-1 sensor", "write")
    try:
        scfg = load_config(CONFIG)
        scfg["sensors"].update(name="lab-1", report_to="http://127.0.0.1:{}".format(srv.server_port))
        sdb = str(tmp_path / "s.db")
        pipe = Pipeline(sdb, scfg, pcap=PCAP, speed=0, rescore_seconds=0.2).start()
        pipe.wait(60)
        sensor = create_app(sdb, scfg, pipe, admin_db=str(tmp_path / "sa.db"))
        ctx = sensor.extensions["ghostap"]
        rep = S.Reporter(ctx, scfg, key)
        rep.send_once()
        bad = S.Reporter(ctx, scfg, "gk_wrong")
        with pytest.raises(OSError):
            bad.send_once()
    finally:
        srv.shutdown()
    c = central.test_client()
    fleet = c.get("/api/sensors").get_json()["sensors"]
    assert fleet[0]["name"] == "lab-1" and fleet[0]["online"] and fleet[0]["aps"] == 4
    assert any(a["level"] == "HIGH" for a in fleet[0]["status"]["alerts"])
    aps = c.get("/api/sensors/aps").get_json()
    assert aps[0]["bssid"] == "00:c0:ca:de:ad:01" and aps[0]["heard_by"][0]["sensor"] == "lab-1"
    assert c.post("/api/sensors/lab-1/position", json={"x": 1, "y": None}).status_code == 400
    assert c.post("/api/sensors/lab-1/position", json={"x": 1.5, "y": 2}).status_code == 200
    assert c.get("/api/audit?action=sensor.position").get_json()[0]["target"] == "lab-1"


def test_capture_control_pause_and_hop(monkeypatch, tmp_path):
    if not os.path.exists(PCAP):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    pkts = rdpcap(PCAP)[:60]
    ctl = CaptureControl()
    calls = {"n": 0}

    def fake_sniff(iface, prn, lfilter, store, timeout):
        calls["n"] += 1
        if calls["n"] == 2:
            ctl.pause()
        for p in pkts[(calls["n"] - 1) * 20: calls["n"] * 20]:
            if lfilter(p):
                prn(p)
        if calls["n"] == 3:
            stop.set()
    import scapy.sendrecv
    monkeypatch.setattr(scapy.sendrecv, "sniff", fake_sniff)
    stop = threading.Event()
    with Store(str(tmp_path / "x.db")) as st:
        n = collector.collect_live("wlan0mon", None, st, stop=stop, control=ctl)
    assert n == 20 and ctl.dropped_while_paused == 40 and ctl.iface is None
    # hopper reconfiguration (fake channel setter: no radio)
    seen = []
    h = ChannelHopper("wlan0mon", [1, 6, 11], 0.05, setter=lambda i, c: seen.append(c)).start()
    time.sleep(0.2)
    h.reconfigure([36], 0.05)
    time.sleep(0.2)
    h.stop()
    assert {1, 6, 11} & set(seen) and seen[-1] == 36 and h.channels == [36]
    with pytest.raises(RuntimeError):
        CaptureControl().set_hop([6], 0.25)


def test_capture_api_refuses_replay(tmp_path):
    db = str(tmp_path / "s.db")
    app = create_app(db, load_config(CONFIG), admin_db=db + ".a")
    c = app.test_client()
    assert c.get("/api/capture").get_json()["live"] is False
    r = c.post("/api/capture", json={"action": "pause"})
    assert r.status_code == 409 and "live capture" in r.get_json()["error"]
