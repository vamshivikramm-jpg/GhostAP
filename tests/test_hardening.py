"""Robustness on real-world frames, incremental profiles, and dashboard security."""
import os
import struct
import sys
import zlib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402
from scapy.layers.dot11 import Dot11FCS, RadioTap  # noqa: E402
from scapy.utils import RawPcapWriter  # noqa: E402

from ghostap.collector import collect_pcap  # noqa: E402
from ghostap.parser import parse_frame  # noqa: E402
from ghostap.pipeline import IncrementalScorer, Pipeline  # noqa: E402
from ghostap.risk import RiskEngine, load_config  # noqa: E402
from ghostap.indicators import Analyzer  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app, is_loopback  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"
RAW = bytes(make_test_pcap.make_beacon("MVSR_WiFi", "a4:2b:b0:11:22:33", 6, True, -50, 10**9, 7))


def _with_fcs(flags, body):
    fcs = struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
    pkt = RadioTap(bytes(RadioTap(present="Flags+dBm_AntSignal", Flags=flags, dBm_AntSignal=-50)
                         / Dot11FCS(body + fcs)))
    pkt.time = 1.0
    return pkt


# ------------------------------------------------------------------ parser robustness

def test_frames_with_fcs_are_parsed():
    o = parse_frame(_with_fcs("FCS", RAW[9:]))
    assert o["ssid"] == "MVSR_WiFi" and o["security"] == "WPA2/PSK" and o["channel"] == 6


def test_corrupted_frames_are_rejected_and_counted():
    body = bytearray(RAW[9:])
    body[40] ^= 0x5A                                   # radio noise inside the SSID
    stats = {}
    assert parse_frame(_with_fcs("FCS+badFCS", bytes(body)), stats) is None
    assert stats == {"bad_fcs": 1}


def test_truncated_capture_frames_are_rejected(tmp_path):
    path = str(tmp_path / "snap.pcap")
    w = RawPcapWriter(path, linktype=127)
    w.write_header(None)
    w.write_packet(RAW[:100], sec=1, usec=0, caplen=100, wirelen=len(RAW))   # snap length cut
    w.write_packet(RAW, sec=2, usec=0)
    w.close()
    stats = {}
    with Store(str(tmp_path / "t.db")) as s:
        assert collect_pcap(path, s, stats) == 1                          # only the full frame
        assert s.observations()[0]["security"] == "WPA2/PSK"
    assert stats == {"truncated": 1}


def test_malformed_and_garbage_input_never_raises():
    stats = {}
    no_ssid = RadioTap(RAW[:45])                      # beacon without any information element
    no_ssid.time = 1.0
    assert parse_frame(no_ssid, stats) is None
    for junk in (b"", b"\x00" * 8, os.urandom(64), RAW[:12] + os.urandom(80)):
        p = RadioTap(junk)
        p.time = 1.0
        parse_frame(p, stats)                         # must not raise
    assert stats.get("malformed", 0) >= 1


# ------------------------------------------------------------------ incremental profiles

@pytest.fixture(scope="module")
def capture_obs(tmp_path_factory):
    d = tmp_path_factory.mktemp("h")
    pcap, _, _ = make_test_pcap.generate(str(d))
    with Store(str(d / "full.db")) as s:
        collect_pcap(pcap, s)
        return s.observations()


def test_incremental_profiles_equal_full_rebuild(capture_obs, tmp_path):
    with Store(str(tmp_path / "a.db")) as s:
        for o in capture_obs:
            s.add(o)
        s.rebuild_profiles()
        full = {(p["ssid"], p["bssid"]): p for p in s.profiles()}
    with Store(str(tmp_path / "b.db")) as s:
        for i in range(0, len(capture_obs), 97):     # uneven chunks, like live rounds
            s.update_profiles(capture_obs[i:i + 97])
        inc = {(p["ssid"], p["bssid"]): p for p in s.profiles()}
    assert full.keys() == inc.keys()
    for k, f in full.items():
        g = inc[k]
        for col in ("first_seen", "last_seen", "frames", "rssi_min", "rssi_max", "rssi_n"):
            assert f[col] == g[col], (k, col)
        assert f["rssi_avg"] == pytest.approx(g["rssi_avg"])
        assert set(f["channels"].split(",")) == set(g["channels"].split(","))
        assert set(f["securities"].split(",")) == set(g["securities"].split(","))


def test_idle_scoring_round_does_no_work(capture_obs, tmp_path):
    db = str(tmp_path / "idle.db")
    with Store(db) as s:
        for o in capture_obs:
            s.add(o)
    scorer = IncrementalScorer(db, load_config(CONFIG))
    assert scorer.step()["new_frames"] == len(capture_obs)
    assert scorer.step() == {"new_frames": 0, "new_rows": 0, "alerts": None}


def test_alert_peak_time_is_first_time_the_peak_is_reached(capture_obs):
    cfg = load_config(CONFIG)
    rep = RiskEngine(Analyzer(capture_obs, cfg["baseline_minutes"]), cfg).run()
    a = rep.alerts[0]
    evil = [r for r in rep.timeline if r["bssid"] == EVIL]
    first_max = next(r["ts"] for r in evil if r["score"] == a["score"])
    assert a["peak_ts"] == first_max and a["peak_ts"] < evil[-1]["ts"]
    assert a["indicators"]


# ------------------------------------------------------------------ dashboard security

@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("sec") / "sec.db")
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    pipe = Pipeline(db, load_config(CONFIG), pcap=pcap, speed=0, rescore_seconds=0.2).start()
    pipe.wait(timeout=60)
    return db


def test_loopback_detection():
    for h in ("127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.53"):
        assert is_loopback(h), h
    for h in ("0.0.0.0", "192.168.1.5", "evil.example", "::"):
        assert not is_loopback(h), h


def test_dns_rebinding_is_blocked(db_path):
    c = create_app(db_path, load_config(CONFIG)).test_client()
    assert c.get("/api/summary", headers={"Host": "127.0.0.1:8050"}).status_code == 200
    assert c.get("/api/summary", headers={"Host": "localhost:8050"}).status_code == 200
    assert c.get("/api/summary", headers={"Host": "[::1]:8050"}).status_code == 200
    r = c.get("/api/summary", headers={"Host": "attacker.example:8050"})
    assert r.status_code == 403 and b"localhost" in r.data
    assert c.post("/api/alerts/1/triage", json={"status": "confirmed"},
                  headers={"Host": "attacker.example"}).status_code == 403


def test_security_headers(db_path):
    c = create_app(db_path, load_config(CONFIG)).test_client()
    for url in ("/", "/api/summary", "/static/app.js"):
        h = c.get(url).headers
        assert "script-src 'self'" in h["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert c.get("/api/summary").headers["Cache-Control"] == "no-store"


def test_token_login_when_exposed_to_the_network(db_path):
    c = create_app(db_path, load_config(CONFIG), token="s3cret-token", local_only=False).test_client()
    assert c.get("/api/summary").status_code == 401
    page = c.get("/")
    assert page.status_code == 401 and b"token" in page.data
    assert c.get("/?token=wrong").status_code == 401
    r = c.get("/?token=s3cret-token")
    assert r.status_code == 303 and r.headers["Location"].endswith("/")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert c.get("/api/summary").status_code == 200                # cookie now set
    other = create_app(db_path, load_config(CONFIG), token="s3cret-token", local_only=False).test_client()
    assert other.get("/api/aps", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
    assert other.get("/api/aps", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_request_body_size_is_limited(db_path):
    c = create_app(db_path, load_config(CONFIG)).test_client()
    aid = c.get("/api/alerts").get_json()[0]["id"]
    r = c.post("/api/alerts/{}/triage".format(aid), json={"status": "new", "note": "x" * 100_000})
    assert r.status_code == 413


def test_false_positive_triage_clears_the_verdict(db_path):
    c = create_app(db_path, load_config(CONFIG)).test_client()
    before = c.get("/api/summary").get_json()
    assert before["top_alert"]["bssid"] == EVIL and before["alerts"]["HIGH"] == 1
    aid = before["top_alert"]["id"]
    assert c.post("/api/alerts/{}/triage".format(aid), json={"status": "false_positive"}).status_code == 200
    after = c.get("/api/summary").get_json()
    assert after["top_alert"] is None and after["alerts"]["HIGH"] == 0
    assert after["dismissed_alerts"] == 1
    assert after["data_version"] != before["data_version"]           # page knows to refetch
    c.post("/api/alerts/{}/triage".format(aid), json={"status": "new"})
    assert c.get("/api/summary").get_json()["top_alert"]["id"] == aid


def test_summary_counts_come_from_profiles(db_path):
    s = create_app(db_path, load_config(CONFIG)).test_client().get("/api/summary").get_json()
    assert s["frames"] == 1020 and s["aps"] == 4 and s["networks"] == 2
