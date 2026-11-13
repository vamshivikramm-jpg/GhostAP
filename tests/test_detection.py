"""Phase B: signatures, detailed downgrades, signal tracks, beacon rate, clock skew,
deauth / flood detection, hidden-network matching, per-network settings, incidents."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap  # noqa: E402
from scapy.utils import PcapWriter  # noqa: E402

from ghostap.collector import collect_pcap  # noqa: E402
from ghostap.config import load_config  # noqa: E402
from ghostap.indicators import Analyzer  # noqa: E402
from ghostap.parser import parse_event, parse_frame, parse_rsn  # noqa: E402
from ghostap.risk import (  # noqa: E402
    DeauthDetector, FloodDetector, RiskEngine, build_incidents, risk_score,
)
from ghostap.signatures import (  # noqa: E402
    BUILTIN_LIBRARY, library_for, load_library, lookalike_target, normalize_ssid,
)
from ghostap.storage import Store  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
LEGIT = "a4:2b:b0:00:00:01"
ROGUE = "00:c0:ca:66:66:66"


def obs(t, bssid=LEGIT, ssid="Lab", ch=6, sec="WPA2/PSK", rssi=-60, tsf=None, fp="fp-vendor",
        rsn="pw=CCMP;akm=PSK;pmf=none", frame="beacon", bi=100, seq=None):
    return {"ts": 1000.0 + t, "frame_type": frame, "ssid": ssid, "bssid": bssid, "oui": bssid[:8],
            "channel": ch, "security": sec, "rssi": rssi, "beacon_interval": bi,
            "tsf": tsf if tsf is not None else int(5e9 + t * 1e6), "seq": seq if seq is not None else int(t) % 4096,
            "fingerprint": fp, "rsn": rsn}


def by_name(results):
    return {r.name: r for r in results}


def legit_minutes(minutes=5, **kw):
    return [obs(t, **kw) for t in range(minutes * 60)]


# ---------------------------------------------------------------- F001 KARMA
def test_karma_radio_answering_for_many_names():
    o = legit_minutes()
    for i, name in enumerate(["Lab", "HomeWiFi", "Airport_Free", "Starbucks"]):
        o += [obs(200 + t + i * 0.1, bssid=ROGUE, ssid=name, sec="OPN", rsn=None, fp="fp-tool",
                  frame="probe_resp", tsf=int(1000 + t * 1e6)) for t in range(30)]
    an = Analyzer(o, 2, detection=load_config(CONFIG)["detection"])
    r = by_name(an.evaluate("Airport_Free", ROGUE))
    assert r["karma"].value == 1.0 and "4 different network names" in r["karma"].reason
    score, contrib = risk_score(an.evaluate("Airport_Free", ROGUE), load_config(CONFIG)["weights"],
                                load_config(CONFIG)["signatures"])
    assert score >= 70 and any(c["name"] == "karma" and c["contribution"] > 0 for c in contrib)
    assert by_name(an.evaluate("Lab", LEGIT))["karma"].value == 0


# ---------------------------------------------------------------- F002 look-alike names
@pytest.mark.parametrize("fake", ["MVSR-WiFi", "MVSR WiFi", "mvsr_wifi", "MVSR_W1Fi", "MVSR_WіFi"])
def test_lookalike_names_normalize_to_the_real_one(fake):
    assert lookalike_target(fake, ["MVSR_WiFi"])[0] == "MVSR_WiFi"


def test_unrelated_and_identical_names_are_not_lookalikes():
    assert lookalike_target("Cafe_Guest", ["MVSR_WiFi"]) is None
    assert lookalike_target("MVSR_WiFi", ["MVSR_WiFi"]) is None
    assert normalize_ssid("Ｍvsr_Wi-Fi") == normalize_ssid("MVSR WIFI")


def test_lookalike_ap_is_judged_against_the_network_it_imitates():
    o = legit_minutes(ssid="MVSR_WiFi")
    o += [obs(200 + t, bssid=ROGUE, ssid="MVSR-WiFi", sec="OPN", rsn=None, fp="fp-tool", rssi=-35,
              tsf=int(1000 + t * 1e6)) for t in range(60)]
    an = Analyzer(o, 2, detection=load_config(CONFIG)["detection"])
    r = by_name(an.evaluate("MVSR-WiFi", ROGUE))
    assert r["lookalike_ssid"].value == 1.0
    assert r["security_downgrade"].value == 1.0 and "compared with 'MVSR_WiFi'" in r["security_downgrade"].reason
    assert r["ie_fingerprint"].value == 1.0
    rep = RiskEngine(an, load_config(CONFIG)).run()
    assert [(a["ssid"], a["level"]) for a in rep.alerts] == [("MVSR-WiFi", "HIGH")]


def test_a_band_suffix_network_alone_does_not_alert():
    o = legit_minutes(ssid="Campus")
    o += [obs(200 + t, bssid="a4:2b:b0:00:00:09", ssid="Campus5G", ch=36, tsf=int(9e11 + t * 1e6))
          for t in range(60)]
    rep = RiskEngine(Analyzer(o, 2, detection=load_config(CONFIG)["detection"]), load_config(CONFIG)).run()
    assert rep.alerts == []


# ---------------------------------------------------------------- F003 attack-tool library
def test_tool_library_examples_are_off_by_default():
    assert library_for(load_config(CONFIG)) == []                     # examples skipped
    lib = load_library([BUILTIN_LIBRARY], include_examples=True)
    assert {e["name"] for e in lib} >= {"Phone hotspot"} and all(e["example"] for e in lib)


def test_tool_fingerprint_match():
    p = RadioTap(bytes(make_test_pcap.make_beacon("Lab", ROGUE, 6, False, -40, 1000, 1, profile="hostapd")))
    p.time = 1300.0
    twin = parse_frame(p)
    o = legit_minutes() + [dict(twin, ts=1300.0 + i) for i in range(30)]
    an = Analyzer(o, 2, library=load_library([BUILTIN_LIBRARY], include_examples=True))
    r = by_name(an.evaluate("Lab", ROGUE))
    assert r["known_tool"].value == 1.0 and "hostapd" in r["known_tool"].reason
    assert "synthetic example" in r["known_tool"].reason


def test_signatures_cli_adds_a_lab_fingerprint(tmp_path):
    from ghostap import signatures
    db = str(tmp_path / "s.db")
    with Store(db) as s:
        for o in legit_minutes(1, bssid=ROGUE, fp="fp-pineapple"):
            s.add(o)
    lib = str(tmp_path / "tools.json")
    assert signatures.main(["add", "--db", db, "--bssid", ROGUE, "--name", "Lab Pineapple",
                            "--file", lib, "--config", CONFIG]) == 0
    entry = load_library([lib])[0]
    assert entry["name"] == "Lab Pineapple" and entry["fingerprints"] == {"fp-pineapple"} and not entry["example"]


# ---------------------------------------------------------------- F004 detailed security downgrade
def test_rsn_details_are_parsed():
    p = RadioTap(bytes(make_test_pcap.make_beacon("Lab", LEGIT, 6, True, -40, 1000, 1)))
    from scapy.layers.dot11 import Dot11Beacon
    assert parse_rsn(p[Dot11Beacon]) == "pw=CCMP;akm=PSK;pmf=none"


@pytest.mark.parametrize("base_rsn, twin_rsn, value, words", [
    ("pw=CCMP;akm=802.1X;pmf=capable", "pw=CCMP;akm=PSK;pmf=capable", 1.0, "enterprise"),
    ("pw=CCMP;akm=SAE;pmf=required", "pw=CCMP;akm=SAE,PSK;pmf=capable", 0.8, "WPA3 transition"),
    ("pw=CCMP;akm=PSK;pmf=none", "pw=TKIP;akm=PSK;pmf=none", 1.0, "TKIP"),
    ("pw=CCMP;akm=PSK;pmf=required", "pw=CCMP;akm=PSK;pmf=none", 0.8, "protected management frames"),
])
def test_detailed_security_downgrade(base_rsn, twin_rsn, value, words):
    o = legit_minutes(rsn=base_rsn)
    o += [obs(200 + t, bssid="a4:2b:b0:00:00:07", rsn=twin_rsn, tsf=int(8e9 + t * 1e6)) for t in range(30)]
    r = by_name(Analyzer(o, 2).evaluate("Lab", "a4:2b:b0:00:00:07"))["security_downgrade"]
    assert r.value == value and words in r.reason


def test_same_rsn_is_not_a_downgrade():
    o = legit_minutes() + [obs(200 + t, bssid="a4:2b:b0:00:00:07", tsf=int(8e9 + t * 1e6)) for t in range(30)]
    assert by_name(Analyzer(o, 2).evaluate("Lab", "a4:2b:b0:00:00:07"))["security_downgrade"].value == 0


# ---------------------------------------------------------------- F006 two transmitters, one address
def test_two_signal_tracks_on_one_address():
    o = legit_minutes()
    for t in range(200, 260):
        o.append(obs(t + 0.5, rssi=-38, seq=(t * 7) % 4096))          # a second, much louder radio
    r = by_name(Analyzer(o, 2).evaluate("Lab", LEGIT, until=1260, window=60))["bssid_conflict"]
    assert r.value == 1.0 and "two signal levels" in r.reason


def test_normal_signal_variation_is_not_two_tracks():
    o = [obs(t, rssi=-60 + (t % 7) - 3) for t in range(300)]
    assert by_name(Analyzer(o, 2).evaluate("Lab", LEGIT))["bssid_conflict"].value == 0


# ---------------------------------------------------------------- F008 beacon rate
def test_beacon_flood_rate_from_one_ap():
    o = legit_minutes()
    o += [obs(200 + i / 30, bssid="a4:2b:b0:00:00:08", tsf=int(7e9 + i / 30 * 1e6)) for i in range(300)]
    r = by_name(Analyzer(o, 2).evaluate("Lab", "a4:2b:b0:00:00:08"))["beacon_interval_mismatch"]
    assert r.value > 0.5 and "times per second" in r.reason


def test_flood_detector_many_new_radios():
    det = FloodDetector({"flood_new_aps_per_minute": 30}, warmup=120)
    det.update([obs(t) for t in range(150)])
    det.update([obs(200 + i, bssid="02:00:00:00:{:02x}:{:02x}".format(i // 256, i % 256), ssid="free" + str(i))
                for i in range(40)])
    a = det.alerts()[0]
    assert a["level"] == "HIGH" and a["peak"] >= 30


# ---------------------------------------------------------------- F007 clock skew
def test_clock_skew_change_on_a_known_address():
    o = [obs(t, tsf=int(5e9 + t * 1e6)) for t in range(150)]                        # original, 0 ppm
    tsf150 = 5e9 + 150 * 1e6
    o += [obs(t, tsf=int(tsf150 + (t - 150) * 1e6 * 1.0003)) for t in range(150, 600)]  # +300 ppm clone
    r = by_name(Analyzer(o, 2).evaluate("Lab", LEGIT))["tsf_anomaly"]
    assert r.value > 0.5 and "clock drift" in r.reason


def test_capture_jitter_alone_is_not_a_clock_change():
    import random
    rnd = random.Random(3)
    o = [dict(obs(t), ts=1000.0 + t + rnd.uniform(0, 0.1)) for t in range(600)]
    assert by_name(Analyzer(o, 2).evaluate("Lab", LEGIT))["tsf_anomaly"].value == 0


# ---------------------------------------------------------------- F005 deauthentication floods
def _deauth(bssid, client, t, reason=7):
    p = RadioTap(bytes(RadioTap() / Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
                       / Dot11Deauth(reason=reason)))
    p.time = t
    return p


def test_deauth_frames_are_parsed_without_client_addresses(tmp_path):
    client = "3c:22:fb:12:34:56"
    path = str(tmp_path / "d.pcap")
    with PcapWriter(path, linktype=127) as w:
        for i in range(40):
            w.write(_deauth(LEGIT, client if i % 2 else "ff:ff:ff:ff:ff:ff", 2000 + i * 0.1))
    stats = {}
    with Store(str(tmp_path / "d.db")) as s:
        collect_pcap(path, s, stats)
        rows = [tuple(r) for r in s.conn.execute("SELECT * FROM events").fetchall()]
    assert stats["events"] == 40 and len(rows) == 40
    assert not any(client in str(v) for r in rows for v in r)        # privacy: no client address stored
    ev = parse_event(_deauth(LEGIT, client, 1.0))
    assert ev["kind"] == "deauth" and ev["bssid"] == LEGIT and ev["broadcast"] is False and ev["reason"] == 7


def test_deauth_detector_levels():
    det = DeauthDetector({"deauth_window_seconds": 10, "deauth_medium": 10, "deauth_high": 30})
    det.update([{"ts": 100 + i * 0.5, "kind": "deauth", "bssid": LEGIT, "broadcast": False, "reason": 7}
                for i in range(5)])
    assert det.alerts() == []                                          # a few deauths are routine
    det.update([{"ts": 200 + i * 0.1, "kind": "deauth", "bssid": LEGIT, "broadcast": True, "reason": 7}
                for i in range(40)])
    a = det.alerts(lambda b: ["Lab"])[0]
    assert a["level"] == "HIGH" and a["ssid"] == "Lab" and a["high_ts"] is not None


# ---------------------------------------------------------------- F010 hidden networks
def test_hidden_network_gets_its_name_from_a_probe_response():
    o = [obs(t, ssid="<hidden>") for t in range(100)]
    o += [obs(100 + t, ssid="SecretLab", frame="probe_resp") for t in range(5)]
    an = Analyzer(o, 2)
    assert ("<hidden>", LEGIT) not in an.aps() and ("SecretLab", LEGIT) in an.aps()
    assert len(an._by_ap[("SecretLab", LEGIT)]) == 105


# ---------------------------------------------------------------- F011 per-network settings
def test_indicator_switched_off_for_one_network():
    o = legit_minutes() + [obs(200 + t, bssid="a4:2b:b0:00:00:07", sec="OPN", rsn=None,
                               tsf=int(8e9 + t * 1e6)) for t in range(30)]
    an = Analyzer(o, 2, network_settings={"Lab": {"enabled": {"security_downgrade": False}}})
    r = by_name(an.evaluate("Lab", "a4:2b:b0:00:00:07"))["security_downgrade"]
    assert r.value == 0 and r.reason == "turned off for this network"


def test_network_specific_alert_threshold():
    eng = RiskEngine(Analyzer([], 2, network_settings={"Guest": {"threshold_medium": 50}}),
                     load_config(CONFIG))
    assert eng.thresholds_for("Guest")["medium"] == 50 and eng.thresholds_for("Lab")["medium"] == 30


# ---------------------------------------------------------------- F012 incidents
def test_deauth_and_twin_alerts_become_one_incident():
    alerts = [
        {"detector": "deauth", "ssid": "Lab", "bssid": LEGIT, "level": "HIGH", "score": 80, "first_ts": 100,
         "high_ts": 105, "last_ts": 120, "id": 1},
        {"detector": "ghostap", "ssid": "Lab", "bssid": ROGUE, "level": "HIGH", "score": 77, "first_ts": 130,
         "high_ts": 140, "last_ts": 300, "id": 2},
        {"detector": "baseline", "ssid": "Lab", "bssid": LEGIT, "level": "HIGH", "score": 100, "first_ts": 0,
         "last_ts": 300, "id": 3},
        {"detector": "ghostap", "ssid": "Other", "bssid": "02:00:00:00:00:01", "level": "MEDIUM", "score": 40,
         "first_ts": 5000, "last_ts": 5100, "id": 4},
    ]
    inc = build_incidents(alerts)
    assert len(inc) == 2
    top = inc[0]
    assert top["summary"] == "Deauthentication attack and suspicious access point on 'Lab'"
    assert [s["text"].split()[0] for s in top["story"]][:2] == ["deauthentication", "{}".format(LEGIT)]


# ---------------------------------------------------------------- F009 6 GHz hopping
def test_six_ghz_channels_are_tuned_by_frequency(monkeypatch):
    from ghostap import hopper
    chans = hopper.parse_channels("6e")
    assert chans[0] == 5975 and all(5925 <= c <= 7125 for c in chans)
    calls = []
    monkeypatch.setattr(hopper.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    hopper._iw("wlan1", 5975)
    hopper._iw("wlan1", 6)
    assert calls == [["iw", "dev", "wlan1", "set", "freq", "5975"], ["iw", "dev", "wlan1", "set", "channel", "6"]]


def test_six_ghz_band_from_radio_frequency():
    from ghostap.parser import band_of, channel_from_freq
    assert band_of(5975) == "6" and channel_from_freq(5975) == 5
    assert band_of(2437) == "2.4" and channel_from_freq(2437) == 6
    assert band_of(5180) == "5" and channel_from_freq(5180) == 36
