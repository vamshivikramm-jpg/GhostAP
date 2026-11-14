"""Phase D: beacon diff (F028), vendor names (F029), signal/uptime series (F030),
evidence pcap (F032) and related access points (F033)."""
import io
import os
import sys

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon
from scapy.utils import rdpcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import beacons, vendors  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.parser import beacon_fingerprint, beacon_layout, fingerprint_of  # noqa: E402
from ghostap.pipeline import Pipeline  # noqa: E402
from ghostap.web import create_app  # noqa: E402
from ghostap.web_ap import related_reasons  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = "00:c0:ca:de:ad:01"
PCAP = os.path.join(ROOT, "data", "test_capture.pcap")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    if not os.path.exists(PCAP):
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    tmp = tmp_path_factory.mktemp("apd")
    db = str(tmp / "s.db")
    cfg = load_config(CONFIG)
    pipe = Pipeline(db, cfg, pcap=PCAP, speed=0, rescore_seconds=0.2).start()
    pipe.wait(60)
    return create_app(db, cfg, pipe, admin_db=str(tmp / "a.db"), config_path=CONFIG,
                      monitored_path=str(tmp / "m.json")).test_client()


def test_layout_hashes_to_the_same_fingerprint():
    for pkt in rdpcap(PCAP)[:50]:
        if pkt.haslayer(Dot11Beacon):
            body = pkt[Dot11Beacon]
            assert fingerprint_of(beacon_layout(body)) == beacon_fingerprint(body)


def test_diff_operations_and_names():
    ref = ["cap=0401", "0", "1:82848b96", "3", "45:2c0103", "221:0050f202"]
    mine = ["cap=0401", "0", "1:82848b960c", "3", "221:0050f204", "221:0050f202"]
    rows = beacons.diff(mine, ref)
    ops = {(r["name"], r["op"]) for r in rows}
    assert ("Supported rates", "changed") in ops
    assert ("HT capabilities (Wi-Fi 4)", "only_known") in ops
    assert ("Vendor: WPS (Wi-Fi Protected Setup)", "only_this") in ops
    assert ("Vendor: WMM (quality of service)", "same") in ops
    assert "1 element missing" in beacons.summary(rows)
    assert beacons.summary(beacons.diff(ref, ref)) == "Same elements in the same order."
    assert beacons.describe("255:23:aabbccddeeff")["name"] == "HE capabilities (Wi-Fi 6)"


def test_vendor_lookup_and_import_formats(tmp_path, monkeypatch):
    assert vendors.is_local("02:11:22:33:44:55") and vendors.is_local("da:a1:19:00:00:01")
    assert not vendors.is_local("00:c0:ca:de:ad:01")
    assert vendors.lookup("02:11:22:33:44:55") == {"vendor": None, "local": True, "source": None}
    assert vendors.name(EVIL)                          # Scapy's bundled list knows Alfa
    table = vendors.parse_list("# comment\n00:C0:CA\tAlfa\tAlfa, Inc.\n"
                               "A4-2B-B0   (hex)\t\tTP-LINK TECHNOLOGIES CO.,LTD.\n"
                               "00:1B:C5:00:00:00/36\tShort\tTooSpecific\n")
    assert table == {"00:c0:ca": "Alfa, Inc.", "a4:2b:b0": "TP-LINK TECHNOLOGIES CO.,LTD."}
    src = tmp_path / "manuf"
    src.write_text("00:C0:CA\tX\tLab Override Ltd\n")
    monkeypatch.setattr(vendors, "LOCAL_FILE", str(tmp_path / "oui.txt"))
    vendors._local_table.cache_clear()
    vendors.lookup.cache_clear()
    assert vendors.main(["import", str(src)]) == 0
    assert vendors.lookup(EVIL) == {"vendor": "Lab Override Ltd", "local": False, "source": str(tmp_path / "oui.txt")}
    vendors._local_table.cache_clear()
    vendors.lookup.cache_clear()


def test_related_reasons_rules():
    base = {"ssid": "Lab", "rssi_avg": -40.0, "channels": "6", "first_seen": 200.0}
    me = dict(base, bssid="00:c0:ca:de:ad:01")
    neighbour = dict(base, ssid="Free_WiFi", bssid="00:c0:ca:de:ad:02", first_seen=205.0)
    local_bit = dict(base, ssid="Other", bssid="02:c0:ca:de:ad:01", first_seen=10.0, rssi_avg=-80.0)
    stranger = dict(base, ssid="Cafe", bssid="f0:9f:c2:aa:bb:cc", first_seen=10.0, rssi_avg=-80.0)
    kinds = [k for k, _, _ in related_reasons(me, neighbour, {"f1"}, {"f1"}, b_end=120)]
    assert kinds == ["neighbour", "together", "fingerprint", "signal"]
    assert [k for k, _, _ in related_reasons(me, local_bit, set(), set(), 120)] == ["neighbour"]
    assert related_reasons(me, stranger, {"f1"}, {"f2"}, 120) == []


def test_endpoints_on_the_test_capture(client):
    q = "ssid=MVSR_WiFi&bssid=" + EVIL
    d = client.get("/api/ap/beacon_diff?" + q).get_json()
    assert d["available"] and d["known"]["in_baseline"] and d["fingerprint"] != d["known"]["fingerprint"]
    assert any(r["op"] != "same" for r in d["rows"])
    s = client.get("/api/ap/series?" + q).get_json()
    assert s["series"][0]["bssid"] == EVIL and len(s["series"]) == 2 + 1
    assert all(p[1] is not None for p in s["series"][0]["points"])
    assert client.get("/api/ap/series?ssid=MVSR_WiFi&bssid=11:22:33:44:55:66").status_code == 404
    assert client.get("/api/ap/related?" + q).get_json() == []
    rows = client.get("/api/aps").get_json()
    assert {r["bssid"]: r["vendor"] for r in rows}[EVIL] == vendors.name(EVIL)
    assert client.get("/api/ap?" + q).get_json()["ap"]["vendor"]["vendor"] == vendors.name(EVIL)


def test_evidence_pcap_has_only_that_aps_beacons(client):
    r = client.get("/api/ap/evidence.pcap?ssid=MVSR_WiFi&bssid=" + EVIL)
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    pkts = rdpcap(io.BytesIO(r.data))
    assert len(pkts) == int(r.headers["X-GhostAP-Frames"]) > 0
    assert all(p.haslayer(Dot11Beacon) and p[Dot11].addr3.lower() == EVIL for p in pkts)
    audit = client.get("/api/audit?action=evidence.export").get_json()
    assert audit and audit[0]["detail"]["frames"] == len(pkts)
    assert client.get("/api/ap/evidence.pcap?ssid=MVSR_WiFi&bssid=11:22:33:44:55:66").status_code == 404


def test_live_radar_endpoint(client):
    r = client.get("/api/live?seconds=60").get_json()
    aps = {a["bssid"]: a for a in r["aps"]}
    assert r["seconds"] == 60 and set(r["model"]) == {"p0", "n"} and len(aps) == 4
    twin = aps[EVIL]
    assert twin["level"] == "HIGH" and not twin["known"] and twin["band"] == "2.4" and twin["channel"] == 11
    assert twin["rssi"] > aps["a4:2b:b0:11:22:33"]["rssi"]              # the twin is the strongest signal
    assert 10 <= len(twin["trail"]) <= 13 and all(t <= r["now"] for t, _ in twin["trail"])
    assert all(a["known"] for b, a in aps.items() if b != EVIL)
    assert client.get("/api/live?seconds=5").get_json()["seconds"] == 10   # clamped
    assert client.get("/api/live?seconds=abc").get_json()["seconds"] == 60
    short = client.get("/api/live?seconds=10").get_json()
    assert all(len(a["trail"]) <= 3 for a in short["aps"])
