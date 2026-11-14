"""Channel hopping, live pcap recording, incremental scoring, allow-list, DB migration."""
import os
import sqlite3
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap import collector  # noqa: E402
from ghostap.collector import collect_live, collect_pcap  # noqa: E402
from ghostap.hopper import ChannelHopper, parse_channels  # noqa: E402
from ghostap.indicators import Analyzer  # noqa: E402
from ghostap.pipeline import IncrementalScorer  # noqa: E402
from ghostap.risk import RiskEngine, load_config  # noqa: E402
from ghostap.storage import Store  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")
EVIL = ("MVSR_WiFi", "00:c0:ca:de:ad:01")


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    d = tmp_path_factory.mktemp("cap")
    pcap, labels, _ = make_test_pcap.generate(str(d))
    with Store(str(d / "full.db")) as s:
        collect_pcap(pcap, s)
        obs = s.observations()
    return pcap, obs


# --------------------------------------------------------------------- hopping

def test_parse_channels():
    assert parse_channels("1,6,11") == [1, 6, 11]
    assert parse_channels("1-3,6") == [1, 2, 3, 6]
    assert parse_channels("2.4")[:3] == [1, 2, 3] and len(parse_channels("2.4")) == 13
    assert 36 in parse_channels("5") and 1 not in parse_channels("5")
    assert parse_channels("6,6,6") == [6]
    for bad in ("", "0", "11-1", "abc"):
        with pytest.raises(ValueError):
            parse_channels(bad)


def test_hopper_cycles_and_drops_unsupported_channels():
    calls, done = [], threading.Event()

    def setter(iface, ch):
        if ch == 36:
            raise RuntimeError("Invalid argument")      # 2.4 GHz-only adapter
        calls.append(ch)
        if len(calls) >= 6:
            done.set()

    h = ChannelHopper("wlan1", [1, 36, 6, 11], dwell=0.01, setter=setter).start()
    assert done.wait(5)
    h.stop()
    assert set(calls) == {1, 6, 11} and h.dropped == [36]
    assert "unsupported: 36" in h.describe()


def test_hopper_without_iw_reports_error():
    def setter(iface, ch):
        raise FileNotFoundError("iw")
    h = ChannelHopper("wlan1", [1, 6], dwell=0.01, setter=setter).start()
    h._thread.join(5)
    assert "iw" in h.error and h.describe().startswith("hopping stopped")


# ---------------------------------------------------------- live + save pcap

def test_live_capture_saves_pcap_and_hops(capture, tmp_path, monkeypatch):
    """Simulate `sniff` with frames from the synthetic capture (no root needed)."""
    from scapy.utils import rdpcap
    pkts = rdpcap(capture[0])[:40]
    calls = {"n": 0}

    def fake_sniff(iface, prn, lfilter, store, timeout):
        if calls["n"] == 0:
            for p in pkts:
                if lfilter(p):
                    prn(p)
        calls["n"] += 1

    import scapy.sendrecv
    monkeypatch.setattr(scapy.sendrecv, "sniff", fake_sniff)
    hops = []
    monkeypatch.setattr("ghostap.hopper._iw", lambda iface, ch: hops.append(ch))
    out = str(tmp_path / "rec" / "live.pcap")
    with Store(str(tmp_path / "live.db")) as s:
        n = collect_live("wlan1", 0.5, s, hop=[1, 6, 11], dwell=0.01, save_pcap=out)
        assert n == 40 and len(s.observations()) == 40
    assert len(rdpcap(out)) == 40                      # replayable / labelable later
    assert set(hops) <= {1, 6, 11} and hops


# ----------------------------------------------------- incremental scoring

def test_incremental_engine_matches_one_shot(capture):
    _, obs = capture
    cfg = load_config(CONFIG)
    one = RiskEngine(Analyzer(obs, cfg["baseline_minutes"]), cfg).run()

    an = Analyzer((), cfg["baseline_minutes"])
    eng = RiskEngine(an, cfg)
    rows, alerts = [], None
    for i in range(0, len(obs), 37):                  # feed in uneven chunks
        an.add(obs[i:i + 37])
        rep = eng.run(final=False)
        rows += rep.timeline
        alerts = rep.alerts
    rep = eng.run(final=True)
    rows += rep.timeline
    alerts = rep.alerts

    key = lambda r: (r["ts"], r["ssid"], r["bssid"])  # noqa: E731
    assert sorted(rows, key=key) == sorted(one.timeline, key=key)
    assert [(a["bssid"], a["level"], a["first_ts"]) for a in alerts] == \
           [(a["bssid"], a["level"], a["first_ts"]) for a in one.alerts]


def test_incremental_scorer_on_database(capture, tmp_path):
    _, obs = capture
    db = str(tmp_path / "inc.db")
    cfg = load_config(CONFIG)
    scorer = IncrementalScorer(db, cfg)
    with Store(db) as s:
        for o in obs[:500]:
            s.add(o)
    scorer.step()
    with Store(db) as s:
        for o in obs[500:]:
            s.add(o)
    out = scorer.step(final=True)
    assert out["new_frames"] == len(obs) - 500
    with Store(db) as s:
        assert [a["bssid"] for a in s.alerts("ghostap")] == [EVIL[1]]
        assert len(s.alerts("baseline")) == 3


def test_out_of_order_batch_is_merged(capture):
    _, obs = capture
    an = Analyzer(obs[200:], 2)
    an.add(obs[:200])                                  # older frames arrive late
    ref = Analyzer(obs, 2)
    assert [o["ts"] for o in an.obs] == [o["ts"] for o in ref.obs]
    assert an.evaluate(*EVIL)[0].value == ref.evaluate(*EVIL)[0].value


# ----------------------------------------------------------------- allow-list

def test_allowlist_suppresses_new_bssid_but_not_other_evidence(capture):
    _, obs = capture
    plain = {r.name: r for r in Analyzer(obs, 2).evaluate(*EVIL)}
    allowed = {r.name: r for r in Analyzer(obs, 2, allowlist=[EVIL[1].upper()]).evaluate(*EVIL)}
    assert plain["new_bssid_oui"].value == 1.0 and allowed["new_bssid_oui"].value == 0
    assert "allow-list" in allowed["new_bssid_oui"].reason
    assert allowed["channel_deviation"].value == 0
    assert allowed["security_downgrade"].value == 1.0      # still caught
    assert allowed["ie_fingerprint"].value == 1.0


# ------------------------------------------------------------------- storage

def test_old_database_is_migrated(tmp_path):
    db = str(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, "
                 "frame_type TEXT NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL, oui TEXT, "
                 "channel INTEGER, security TEXT, rssi INTEGER, beacon_interval INTEGER, tsf INTEGER, "
                 "seq INTEGER)")
    conn.execute("INSERT INTO observations (ts, frame_type, ssid, bssid) VALUES (1, 'beacon', 'A', 'b')")
    conn.commit()
    conn.close()
    with Store(db) as s:
        o = s.observations()
        assert o[0]["fingerprint"] is None and o[0]["ssid"] == "A"
        rows, last = s.observations_after(0)
        assert len(rows) == 1 and last == 1 and s.observations_after(last) == ([], 1)


def test_collector_cli_rejects_bad_hop(capsys):
    with pytest.raises(SystemExit):
        collector.main(["--iface", "wlan1", "--hop", "99-1"])


# ------------------------------------------------------------ labelling tool

def test_label_capture_roundtrip(capture, tmp_path, capsys):
    import json
    import shutil
    import label_capture
    from ghostap.evaluate import load_labels
    pcap = str(tmp_path / "lab1.pcap")
    shutil.copy(capture[0], pcap)
    assert label_capture.main([pcap]) == 0                      # listing mode
    assert EVIL[1] in capsys.readouterr().out
    assert label_capture.main([pcap, "--evil", EVIL[1].upper()]) == 0
    labels = load_labels(str(tmp_path / "lab1.labels.json"))["aps"]
    assert labels[EVIL[1]]["label"] == "evil_twin"
    assert sum(v["label"] == "legit" for v in labels.values()) == 3
    raw = json.load(open(tmp_path / "lab1.labels.json"))
    assert 179 < labels[EVIL[1]]["attack_start"] - raw["capture_start"] < 181
    assert label_capture.main([pcap, "--evil", "02:00:00:00:00:00"]) == 1
    # a run without a twin (false-positive measurement) also gets a labels file
    assert label_capture.main([pcap, "--no-twin", "--out", str(tmp_path / "none.labels.json")]) == 0
    labels = load_labels(str(tmp_path / "none.labels.json"))["aps"]
    assert len(labels) == 4 and all(v["label"] == "legit" for v in labels.values())


def test_old_alerts_table_gets_triage_columns(tmp_path):
    db = str(tmp_path / "old_alerts.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, detector TEXT NOT NULL, "
                 "ssid TEXT NOT NULL, bssid TEXT NOT NULL, level TEXT NOT NULL, score REAL NOT NULL, "
                 "first_ts REAL NOT NULL, high_ts REAL, peak_ts REAL, last_ts REAL, indicators TEXT, "
                 "reasons TEXT, benign_causes TEXT, UNIQUE (detector, ssid, bssid))")
    conn.execute("INSERT INTO alerts (detector, ssid, bssid, level, score, first_ts) "
                 "VALUES ('ghostap', 'A', 'b', 'HIGH', 70, 1)")
    conn.commit()
    conn.close()
    with Store(db) as s:
        a = s.alerts()[0]
        assert a["triage_status"] == "new"
        assert s.set_triage(a["id"], "confirmed", "seen", 5.0)
        assert s.alert(a["id"])["triage_status"] == "confirmed"
        # rescoring (upsert) keeps the analyst's triage
        s.save_alerts("ghostap", [dict(a, score=80.0, indicators=[], benign_causes=[])])
        assert s.alert(a["id"])["triage_status"] == "confirmed"
