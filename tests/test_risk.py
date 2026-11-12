import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.collector import collect_pcap  # noqa: E402
from ghostap.indicators import INDICATOR_NAMES, Analyzer, IndicatorResult  # noqa: E402
from ghostap.risk import (  # noqa: E402
    HIGH, LOW, MEDIUM, RiskEngine, duplicate_ssid_detector, level_for,
    load_config, main, risk_score,
)
from ghostap.storage import Store  # noqa: E402

DATA = os.path.join(ROOT, "data")
PCAP = os.path.join(DATA, "test_capture.pcap")
LABELS = os.path.join(DATA, "test_labels.json")
CONFIG = os.path.join(ROOT, "config.yaml")

EVIL = ("MVSR_WiFi", "00:c0:ca:de:ad:01")


# --------------------------------------------------------------------------- #
# Formula, levels, config
# --------------------------------------------------------------------------- #

def results(**values):
    return [IndicatorResult(n, values.get(n, 0.0), "r") for n in INDICATOR_NAMES]


def test_risk_score_formula():
    w = load_config(CONFIG)["weights"]
    assert risk_score(results(), w)[0] == 0
    assert risk_score(results(**{n: 1.0 for n in INDICATOR_NAMES}), w)[0] == pytest.approx(100, abs=0.05)
    score, contrib = risk_score(results(security_downgrade=1.0, rssi_jump=0.5), w)
    expected = (w["security_downgrade"] * 1.0 + w["rssi_jump"] * 0.5) / sum(w.values()) * 100
    assert score == pytest.approx(expected, abs=0.05)
    assert {c["name"] for c in contrib} == set(INDICATOR_NAMES)


def test_levels():
    th = {"medium": 30, "high": 60}
    assert level_for(29.9, th) == LOW
    assert level_for(30, th) == MEDIUM
    assert level_for(60, th) == HIGH


def test_config_yaml_is_loaded():
    cfg = load_config(CONFIG)
    assert set(cfg["weights"]) == set(INDICATOR_NAMES)
    assert cfg["temporal"]["smoothing_steps"] >= 2
    assert load_config("does-not-exist.yaml")["thresholds"]["high"] == 60


# --------------------------------------------------------------------------- #
# Synthetic capture
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def db(tmp_path_factory):
    if not (os.path.exists(PCAP) and os.path.exists(LABELS)):
        make_test_pcap.generate(DATA)
    path = str(tmp_path_factory.mktemp("risk") / "risk.db")
    with Store(path) as store:
        collect_pcap(PCAP, store)
    return path


@pytest.fixture(scope="module")
def labels():
    with open(LABELS) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def report(db):
    return RiskEngine.from_db(db, load_config(CONFIG)).run()


def test_only_evil_twin_alerts(report):
    assert [(a["ssid"], a["bssid"]) for a in report.alerts] == [EVIL]
    assert report.alerts[0]["level"] == HIGH


def test_detection_latency(report, labels):
    a = report.alerts[0]
    assert labels["attack_start"] <= a["first_ts"] <= labels["attack_start"] + 60
    assert a["high_ts"] is not None and a["high_ts"] >= a["first_ts"]


def test_alert_is_explained(report):
    a = report.alerts[0]
    top = max(a["indicators"], key=lambda c: c["contribution"])
    assert top["name"] == "security_downgrade"
    assert "OPN" in a["reasons"]
    assert any("reboot" in c for c in a["benign_causes"])
    total = sum(c["contribution"] for c in a["indicators"])
    assert total == pytest.approx(a["score"], abs=0.1)


def test_legit_aps_stay_low(report):
    legit = [r for r in report.timeline if (r["ssid"], r["bssid"]) != EVIL]
    assert legit and all(r["level"] == LOW for r in legit)
    assert max(r["score"] for r in legit) < 10


def test_baseline_flags_every_duplicate_ssid(db, labels):
    alerts = duplicate_ssid_detector(Analyzer.from_db(db).obs)
    flagged = {a["bssid"] for a in alerts}
    assert flagged == {"a4:2b:b0:11:22:33", "a4:2b:b0:11:22:99", "00:c0:ca:de:ad:01"}
    evil = next(a for a in alerts if a["bssid"] == EVIL[1])
    assert evil["first_ts"] >= labels["attack_start"]


def test_cli_saves_alerts_and_timeline(db, capsys):
    assert main(["--db", db, "--config", CONFIG]) == 0
    assert "GhostAP alerts (1)" in capsys.readouterr().out
    with Store(db) as store:
        ghost = store.alerts("ghostap")
        base = store.alerts("baseline")
        tl = store.timeline(*EVIL)
    assert len(ghost) == 1 and ghost[0]["bssid"] == EVIL[1]
    assert isinstance(ghost[0]["indicators"], list) and ghost[0]["benign_causes"]
    assert len(base) == 3
    assert tl and tl[-1]["level"] == HIGH


# --------------------------------------------------------------------------- #
# Temporal smoothing
# --------------------------------------------------------------------------- #

def obs(t, bssid="a4:2b:b0:00:00:01", ch=6, sec="WPA2/PSK", rssi=-60, tsf=None, fp="fp-vendor"):
    return {"ts": 1000.0 + t, "frame_type": "beacon", "ssid": "Lab", "bssid": bssid,
            "oui": bssid[:8], "channel": ch, "security": sec, "rssi": rssi,
            "beacon_interval": 100, "tsf": tsf if tsf is not None else int(5e9 + t * 1e6),
            "seq": t % 4096, "fingerprint": fp}


ROGUE = "00:c0:ca:00:00:66"


def engine_for(observations):
    cfg = load_config(CONFIG)
    return RiskEngine(Analyzer(observations, cfg["baseline_minutes"]), cfg)


def test_one_off_spike_does_not_alert():
    o = [obs(t) for t in range(300)]
    o.append(obs(200.5, bssid=ROGUE, sec="OPN", rssi=-30, tsf=500, fp="fp-hostapd"))  # one odd beacon
    rep = engine_for(o).run()
    rogue = [r for r in rep.timeline if r["bssid"] == ROGUE]
    assert max(r["raw_score"] for r in rogue) >= 60    # the spike itself is high...
    assert rep.alerts == []                             # ...but smoothing suppresses it


def test_persistent_rogue_alerts():
    o = [obs(t) for t in range(300)]
    o += [obs(t + 0.5, bssid=ROGUE, sec="OPN", rssi=-30, tsf=int(500 + (t - 200) * 1e6),
              fp="fp-hostapd") for t in range(200, 300)]
    rep = engine_for(o).run()
    assert [a["bssid"] for a in rep.alerts] == [ROGUE]
    assert rep.alerts[0]["level"] == HIGH
