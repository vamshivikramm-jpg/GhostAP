import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.collector import collect_pcap  # noqa: E402
from ghostap.indicators import (  # noqa: E402
    INDICATOR_NAMES, Analyzer, beacon_interval_mismatch, bssid_conflict,
    channel_deviation, tsf_anomaly,
)
from ghostap.storage import Store  # noqa: E402

DATA = os.path.join(ROOT, "data")
PCAP = os.path.join(DATA, "test_capture.pcap")
LABELS = os.path.join(DATA, "test_labels.json")

EVIL = ("MVSR_WiFi", "00:c0:ca:de:ad:01")
LEGIT_SECOND = ("MVSR_WiFi", "a4:2b:b0:11:22:99")
LEGIT_ALL = [("MVSR_WiFi", "a4:2b:b0:11:22:33"), LEGIT_SECOND,
             ("Cafe_Guest", "f0:9f:c2:aa:bb:cc")]


# --------------------------------------------------------------------------- #
# Integration: data/test_capture.pcap
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def analyzer(tmp_path_factory):
    if not (os.path.exists(PCAP) and os.path.exists(LABELS)):
        make_test_pcap.generate(DATA)
    db = str(tmp_path_factory.mktemp("ind") / "ind.db")
    with Store(db) as store:
        collect_pcap(PCAP, store)
    return Analyzer.from_db(db, baseline_minutes=2)


@pytest.fixture(scope="module")
def labels():
    with open(LABELS) as f:
        return json.load(f)


def as_dict(results):
    return {r.name: r for r in results}


def test_every_indicator_reported(analyzer):
    res = analyzer.evaluate(*EVIL)
    assert [r.name for r in res] == list(INDICATOR_NAMES)
    for r in res:
        assert 0.0 <= r.value <= 1.0
        assert isinstance(r.reason, str) and r.reason


def test_evil_twin_scores_high(analyzer):
    r = as_dict(analyzer.evaluate(*EVIL))
    assert r["security_downgrade"].value == 1.0
    assert "OPN" in r["security_downgrade"].reason
    assert r["new_bssid_oui"].value == 1.0
    assert r["channel_deviation"].value == 1.0
    assert r["rssi_jump"].value >= 0.8
    assert r["tsf_anomaly"].value >= 0.9
    assert sum(x.value for x in r.values()) >= 4.5


def test_legit_second_ap_scores_low(analyzer):
    r = analyzer.evaluate(*LEGIT_SECOND)
    assert all(x.value < 0.2 for x in r), [(x.name, x.value) for x in r]
    assert sum(x.value for x in r) < 0.5


@pytest.mark.parametrize("ap", LEGIT_ALL)
def test_all_legit_aps_low(analyzer, ap):
    assert sum(x.value for x in analyzer.evaluate(*ap)) < 0.5


def test_evil_twin_not_present_before_attack(analyzer, labels):
    assert analyzer.evaluate(*EVIL, until=labels["attack_start"] - 1) is None
    assert analyzer.evaluate(*EVIL, until=labels["attack_start"] + 5) is not None


def test_baseline_learned_from_first_minutes(analyzer):
    base = analyzer.baseline.get("MVSR_WiFi")
    assert base.bssids == {"a4:2b:b0:11:22:33", "a4:2b:b0:11:22:99"}
    assert base.channels == {1, 6}
    assert base.security == "WPA2/PSK"
    assert base.beacon_interval == 100


# --------------------------------------------------------------------------- #
# Unit tests for indicators the synthetic capture does not trigger
# --------------------------------------------------------------------------- #

def obs(t, bssid="a4:2b:b0:00:00:01", ssid="Lab", ch=6, tsf=None, seq=None,
        bi=100, rssi=-60, sec="WPA2/PSK"):
    return {"ts": 1000.0 + t, "frame_type": "beacon", "ssid": ssid, "bssid": bssid,
            "oui": bssid[:8], "channel": ch, "security": sec, "rssi": rssi,
            "beacon_interval": bi,
            "tsf": tsf if tsf is not None else int(5e9 + t * 1e6),
            "seq": seq if seq is not None else t % 4096}


def run(observations, bssid="a4:2b:b0:00:00:01", ssid="Lab", minutes=1):
    return as_dict(Analyzer(observations, baseline_minutes=minutes).evaluate(ssid, bssid))


def test_tsf_reset_detected():
    o = [obs(t) for t in range(100)]
    o += [obs(t, tsf=int(2e6 + (t - 100) * 1e6)) for t in range(100, 120)]
    r = run(o)["tsf_anomaly"]
    assert r.value == 1.0 and "reset" in r.reason


def test_same_bssid_two_channels():
    o = [obs(t, ch=6) for t in range(100)]
    o += [obs(t + 0.5, ch=11) for t in range(60, 100)]   # clone beaconing alongside
    r = run(o)["bssid_conflict"]
    assert r.value == 1.0 and "channels" in r.reason


def test_single_channel_change_is_not_a_clone():
    o = [obs(t, ch=6) for t in range(60)] + [obs(t, ch=1) for t in range(60, 100)]
    assert run(o)["bssid_conflict"].value == 0


def test_sequence_number_going_backwards():
    o = []
    for t in range(100):
        o.append(obs(t, seq=100 + t))                 # real AP
        o.append(obs(t + 0.5, seq=3000 + t))          # cloned BSSID, own counter
    r = run(o)["bssid_conflict"]
    assert r.value == 1.0 and "backwards" in r.reason


def test_sequence_wraparound_is_not_flagged():
    o = [obs(t, seq=(4000 + t) % 4096) for t in range(200)]
    assert run(o)["bssid_conflict"].value == 0


def test_beacon_interval_mismatch():
    o = [obs(t) for t in range(60)]
    o += [obs(t, bssid="a4:2b:b0:00:00:02", bi=200) for t in range(60, 100)]
    r = run(o, bssid="a4:2b:b0:00:00:02")["beacon_interval_mismatch"]
    assert r.value == 1.0 and "200" in r.reason


def test_known_bssid_channel_change_is_moderate():
    o = [obs(t, ch=6) for t in range(60)] + [obs(t, ch=1) for t in range(70, 100)]
    r = run(o)["channel_deviation"]
    assert r.value == 0.5 and "auto channel" in r.reason


def test_new_ap_same_vendor_is_low():
    o = [obs(t) for t in range(60)]
    o += [obs(t, bssid="a4:2b:b0:00:00:02") for t in range(60, 100)]
    r = run(o, bssid="a4:2b:b0:00:00:02")
    assert r["new_bssid_oui"].value == 0.3
    assert r["security_downgrade"].value == 0
    assert r["channel_deviation"].value == 0
