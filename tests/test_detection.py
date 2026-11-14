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
    assert parse_rsn(p[Dot11Beacon]) == "pw=CCMP;akm=PSK;pmf=none;grp=CCMP"


def _rsn_body(raw):
    from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
    # serialise and parse back, like a captured frame (element lengths are filled in)
    return Dot11Beacon(bytes(Dot11Beacon() / Dot11Elt(ID=0, info=b"Lab") / Dot11Elt(ID=48, info=raw)))


def test_group_and_management_ciphers_are_parsed():
    suite = lambda t: b"\x00\x0f\xac" + bytes([t])  # noqa: E731 - IEEE 802.11 OUI + suite type
    # version 1, group TKIP, 1 pairwise CCMP, 1 AKM SAE, caps MFPR+MFPC, 0 PMKIDs, group mgmt BIP-CMAC-128
    raw = (b"\x01\x00" + suite(2) + b"\x01\x00" + suite(4) + b"\x01\x00" + suite(8) + b"\xc0\x00"
           + b"\x00\x00" + suite(6))
    assert parse_rsn(_rsn_body(raw)) == "pw=CCMP;akm=SAE;pmf=required;grp=TKIP;gmgmt=BIP-CMAC-128"
    # OWE (AKM 18), no group management cipher
    raw = b"\x01\x00" + suite(4) + b"\x01\x00" + suite(4) + b"\x01\x00" + suite(18) + b"\x80\x00"
    assert parse_rsn(_rsn_body(raw)) == "pw=CCMP;akm=OWE;pmf=capable;grp=CCMP"
    truncated = parse_rsn(_rsn_body(b"\x01\x00\x00"))                  # must not raise
    assert truncated is None or "grp=" not in truncated

@pytest.mark.parametrize("base_rsn, twin_rsn, value, words", [
    ("pw=CCMP;akm=802.1X;pmf=capable", "pw=CCMP;akm=PSK;pmf=capable", 1.0, "enterprise"),
    ("pw=CCMP;akm=SAE;pmf=required", "pw=CCMP;akm=SAE,PSK;pmf=capable", 0.8, "WPA3 transition"),
    ("pw=CCMP;akm=PSK;pmf=none", "pw=TKIP;akm=PSK;pmf=none", 1.0, "TKIP"),
    ("pw=CCMP;akm=PSK;pmf=required", "pw=CCMP;akm=PSK;pmf=none", 0.8, "protected management frames"),
    ("pw=CCMP;akm=PSK;pmf=none;grp=CCMP", "pw=CCMP;akm=PSK;pmf=none;grp=TKIP", 0.8, "group cipher"),
    ("pw=CCMP;akm=PSK;pmf=none;grp=CCMP", "pw=CCMP;akm=OWE;pmf=capable;grp=CCMP", 0.9, "OWE"),
    ("pw=CCMP;akm=SAE;pmf=required", "pw=CCMP;akm=OWE;pmf=required", 0.9, "OWE"),
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


def _hopping(t, ch=2):
    """Sensor hopping channels 1-13, 0.25 s each: (tuned frequency, dB lost off-channel)."""
    tuned = 1 + int(t / 0.25) % 13
    return 2407 + 5 * tuned, (0 if abs(tuned - ch) <= 2 else 40)


def test_off_channel_reception_while_hopping_is_not_two_transmitters():
    """Found in live testing: a phone hotspot on channel 2, next to the sensor, was heard at
    about -8 dBm while tuned to channels 1-4 and about -48 dBm on channels 7-10. One
    transmitter (sequence numbers steady), but it was reported as two."""
    o = []
    for i in range(1200):                                    # 120 s of beacons, 10 per second
        t = i / 10
        f, loss = _hopping(t)
        o.append(dict(obs(t, ch=2, rssi=-8 - loss, seq=(i * 5) % 4096), freq=f))
    r = by_name(Analyzer(o, 1).evaluate("Lab", LEGIT, until=1120, window=10))["bssid_conflict"]
    assert r.value == 0, r.reason


def test_two_transmitters_are_still_found_while_hopping():
    o = []
    for i in range(1200):
        t = i / 10
        f, loss = _hopping(t)
        o.append(dict(obs(t, ch=2, rssi=-60 - loss, seq=(i * 5) % 4096), freq=f))
        if t >= 90:                                              # a louder clone on the same channel
            o.append(dict(obs(t + 0.05, ch=2, rssi=-25 - loss, seq=(i * 3) % 4096), freq=f))
    r = by_name(Analyzer(o, 1).evaluate("Lab", LEGIT, until=1120, window=20))["bssid_conflict"]
    assert r.value == 1.0 and "two signal levels" in r.reason


def test_channel_flips_with_one_sequence_counter_are_not_a_clone():
    """Live: a neighbour's probe responses said channel 7/8 while its beacons said 4, but the
    sequence counter ran on across every flip (811 -> 812, 981 -> 982): one radio."""
    o = []
    for i in range(300):
        ch = 8 if i % 10 == 5 else 4                      # every 10th frame claims channel 8
        o.append(obs(i / 10, ch=ch, seq=(100 + i * 3) % 4096))
    r = by_name(Analyzer(o, 0.1).evaluate("Lab", LEGIT, until=1030, window=10))["bssid_conflict"]
    assert r.value == 0, r.reason


def test_cloned_bssid_on_another_channel_is_still_a_clone():
    o = []
    for i in range(300):
        o.append(obs(i / 10, ch=4, seq=(100 + i * 3) % 4096))
        if i % 10 == 5:                                    # a clone with its own counter on 8
            o.append(obs(i / 10 + 0.05, ch=8, seq=(3000 + i) % 4096))
    r = by_name(Analyzer(o, 0.1).evaluate("Lab", LEGIT, until=1030, window=10))["bssid_conflict"]
    assert r.value == 1.0 and "alternates between channels" in r.reason


def test_on_channel_rule():
    from ghostap.indicators import _heard_on_channel
    assert _heard_on_channel({"channel": 2, "freq": 2412})          # tuned 1: overlaps channel 2
    assert _heard_on_channel({"channel": 2, "freq": 2427})          # tuned 4
    assert not _heard_on_channel({"channel": 2, "freq": 2442})      # tuned 7
    assert _heard_on_channel({"channel": 36, "freq": 5180})
    assert not _heard_on_channel({"channel": 40, "freq": 5180})     # 5 GHz channels do not overlap
    assert _heard_on_channel({"channel": 6, "freq": None})          # no tuning information: keep
    assert _heard_on_channel({"channel": None, "freq": 2412})


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
NEIGHBOURS = [("Cafe", "10:00:00:00:00:0%d" % i, ppm) for i, ppm in enumerate((-6.0, 2.0, 9.0, -1.5))]


def _air(lab_tsf, sensor=lambda t: 0.0, seconds=600, neighbours=NEIGHBOURS):
    """Lab AP plus neighbour APs, frames every 1 s. lab_tsf(t): the Lab AP's TSF at true
    time t. sensor(t): error of the capture clock in s at true time t (NTP / VM slewing)."""
    o = []
    for t in range(seconds):
        o.append(dict(obs(t, tsf=int(lab_tsf(t))), ts=1000.0 + t + sensor(t)))
        for k, (ssid, b, ppm) in enumerate(neighbours):
            tt = t + 0.1 * (k + 1)                   # heard a little later (channel hopping)
            o.append(dict(obs(tt, bssid=b, ssid=ssid, tsf=int(7e9 + tt * 1e6 * (1 + ppm * 1e-6))),
                          ts=1000.0 + tt + sensor(tt)))
    return o


def _clone_tsf(t):
    """The original radio (0 ppm) until 150 s, then a clone of its address (+300 ppm)."""
    return 5e9 + t * 1e6 if t < 150 else 5e9 + 150e6 + (t - 150) * 1e6 * 1.0003


def _slewed(t):
    """Sensor clock as seen live on a Kali VM: +250 ppm for 120 s, then -110 ppm."""
    return 250e-6 * t if t < 120 else 250e-6 * 120 - 110e-6 * (t - 120)


def test_clock_skew_change_on_a_known_address():
    r = by_name(Analyzer(_air(_clone_tsf), 2).evaluate("Lab", LEGIT))["tsf_anomaly"]
    assert r.value > 0.5 and "clock drift" in r.reason


def test_capture_jitter_alone_is_not_a_clock_change():
    import random
    rnd = random.Random(3)
    o = [dict(x, ts=x["ts"] + rnd.uniform(0, 0.1)) for x in _air(lambda t: 5e9 + t * 1e6)]
    assert by_name(Analyzer(o, 2).evaluate("Lab", LEGIT))["tsf_anomaly"].value == 0


def test_sensor_clock_slewing_is_not_a_clock_change():
    """Found in live testing: the capture (system) clock was slewed by NTP / VMware time
    sync, and every AP 'drifted' +250 ppm in the baseline and -110 ppm later, so the
    drift check called every known network 'different hardware'. Drifts are measured
    against the other APs, so the sensor's clock cancels."""
    o = _air(lambda t: 5e9 + t * 1e6, sensor=_slewed)
    an = Analyzer(o, 2)
    for ssid, b in [("Lab", LEGIT)] + [(s, b) for s, b, _ in NEIGHBOURS]:
        assert by_name(an.evaluate(ssid, b))["tsf_anomaly"].value == 0, b
    # the measurement itself: the Lab AP's crystal is 0 ppm, the neighbours' median +0.25
    ppm, se = an.baseline.get("Lab").bssid_skew[LEGIT]
    assert abs(ppm - -0.25) < 1.0 and se < 1.0


def test_clone_is_still_found_while_the_sensor_clock_slews():
    r = by_name(Analyzer(_air(_clone_tsf, sensor=_slewed), 2).evaluate("Lab", LEGIT))["tsf_anomaly"]
    assert r.value > 0.5 and "clock drift" in r.reason


def test_no_clock_verdict_without_other_aps_to_compare():
    o = _air(_clone_tsf, neighbours=NEIGHBOURS[:2])            # only 2 references: too few
    r = by_name(Analyzer(o, 2).evaluate("Lab", LEGIT))["tsf_anomaly"]
    assert "clock drift" not in r.reason


def test_saved_baselines_from_before_the_clock_fix_ignore_old_drifts():
    from ghostap.indicators import SSIDBaseline
    old = {"bssids": [LEGIT], "bssid_skew": {LEGIT: [252.3, 0.7]}}      # against the sensor clock
    assert SSIDBaseline.from_dict("Lab", old).bssid_skew == {}
    new = SSIDBaseline(ssid="Lab", bssids={LEGIT}, bssid_skew={LEGIT: (-0.5, 0.2)}).to_dict()
    assert SSIDBaseline.from_dict("Lab", new).bssid_skew == {LEGIT: (-0.5, 0.2)}


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


def test_deauth_alert_names_the_reason_code_and_login_failures():
    """Live test: a same-name hotspot with another password made devices fail the 4-way
    handshake (reason 15) again and again. The alert keeps its score and level but says so."""
    det = DeauthDetector({"deauth_window_seconds": 10, "deauth_medium": 10, "deauth_high": 30})
    det.update([{"ts": 100 + i * 0.5, "kind": "deauth", "bssid": LEGIT, "broadcast": False,
                 "reason": 15 if i % 4 else 7} for i in range(16)])
    a = det.alerts()[0]
    assert a["level"] == "MEDIUM"
    assert "reason code 15 (4-way handshake timeout" in a["reasons"]
    assert a["benign_causes"][0].startswith("Devices failing to log in")
    det2 = DeauthDetector({"deauth_window_seconds": 10, "deauth_medium": 10, "deauth_high": 30})
    det2.update([{"ts": 100 + i * 0.1, "kind": "deauth", "bssid": LEGIT, "broadcast": True, "reason": 7}
                 for i in range(16)])
    b = det2.alerts()[0]
    assert b["score"] == a["score"] and "reason code 7" in b["reasons"]
    assert not b["benign_causes"][0].startswith("Devices failing")


def test_leave_reason_burst_is_not_an_attack():
    """Live: one device repeated 'station is leaving' (reason 8) 11 times in 1 s to a
    neighbour's AP and raised a MEDIUM alert. Leave reasons count one third."""
    det = DeauthDetector({"deauth_window_seconds": 10, "deauth_medium": 10, "deauth_high": 30})
    det.update([{"ts": 100 + i * 0.09, "kind": "disassoc", "bssid": LEGIT, "broadcast": False, "reason": 8}
                for i in range(11)])
    assert det.alerts() == []


def test_flood_with_a_faked_leave_reason_still_alerts():
    det = DeauthDetector({"deauth_window_seconds": 10, "deauth_medium": 10, "deauth_high": 30})
    det.update([{"ts": 100 + i * 0.02, "kind": "deauth", "bssid": LEGIT, "broadcast": True, "reason": 3}
                for i in range(200)])
    a = det.alerts()[0]
    assert a["level"] == "HIGH" and a["reasons"].startswith("deauth_flood (+80): 200 deauthentication")


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
