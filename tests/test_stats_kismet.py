"""Phase G: statistics (F048, F049, F084, F085) and the Kismet reader (F050)."""
import json
import math
import os
import sqlite3

import numpy as np
import pytest

from ghostap import kismet, stats

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_wilson_matches_known_values():
    lo, hi = stats.wilson(5, 6)
    assert abs(lo - 0.4365) < 1e-3 and abs(hi - 0.9699) < 1e-3
    assert stats.wilson(0, 10)[0] == 0.0 and abs(stats.wilson(10, 10)[1] - 1.0) < 1e-12
    assert stats.wilson(0, 0) == (None, None)


def test_bootstrap_resamples_captures():
    rows = [{"scenario": "a", "v": 1}, {"scenario": "a", "v": 1}, {"scenario": "b", "v": 0}]
    lo, hi = stats.bootstrap(rows, lambda sub: sum(r["v"] for r in sub) / len(sub), b=500)
    assert 0 <= lo <= hi <= 1 and lo == 0.0 and hi == 1.0
    assert stats.bootstrap(rows[:2], lambda s: 1.0) == (None, None)        # one capture: no interval


def test_split_is_stable_and_complete():
    names = ["s{:02d}".format(i) for i in range(40)]
    a, b = stats.split(names), stats.split(list(reversed(names)))
    assert a == b and set(a.values()) == {"tune", "test"}
    assert 10 < sum(v == "test" for v in a.values()) < 30


def test_roc_and_pr():
    pts, auc = stats.roc([0.9, 0.8, 0.3, 0.1], [1, 1, 0, 0])
    assert auc == 1.0 and pts[0][1:] == (0.0, 0.0) and pts[-1][1:] == (1.0, 1.0)
    assert stats.roc([0.5, 0.5], [1, 0])[1] == 0.5                       # ties count half
    _, ap = stats.pr([0.9, 0.8, 0.3, 0.1], [1, 0, 1, 0])
    assert abs(ap - (0.5 * 1 + 0.5 * 2 / 3)) < 1e-9
    assert stats.roc([1, 2], [1, 1]) == ([], None)


def test_learned_weights_favour_the_informative_feature():
    rng = np.random.default_rng(0)
    y = np.array([1.0] * 20 + [0.0] * 60)
    x = np.column_stack([y * 0.9 + rng.uniform(0, 0.1, 80), rng.uniform(0, 1, 80)])
    w = stats.learn_weights(x, y, ["good", "noise"], total=10)
    assert w["good"] > 3 * w["noise"] and abs(sum(w.values()) - 10) < 0.05
    assert stats.static_score({"good": 1.0}, {"good": 2.0, "noise": 2.0}) == 50.0


def test_anomaly_scores_the_outlier_highest():
    rng = np.random.default_rng(1)
    bulk = rng.normal(0, 0.05, size=(50, 3)).clip(0, 1)
    model = stats.Anomaly(bulk)
    s = model.score(np.vstack([bulk[:5], [[0.9, 0.8, 0.9]]]))
    assert s.argmax() == 5 and math.isfinite(float(s.max()))


def _kismet_db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE alerts (ts_sec INT, ts_usec INT, phyname TEXT, devmac TEXT, lat REAL, lon REAL, "
                "header TEXT, json BLOB)")
    rows = [(1700000200, 500000, "IEEE802.11", "00:C0:CA:DE:AD:01", 0, 0, "CRYPTODROP",
             json.dumps({"kismet.alert.text": "network MVSR_WiFi changed from WPA2 to open",
                         "kismet.alert.transmitter_mac": "00:c0:ca:de:ad:01"})),
            (1700000190, 0, "IEEE802.11", "00:00:00:00:00:00", 0, 0, "BSSTIMESTAMP",
             json.dumps({"kismet.alert.source_mac": "00:c0:ca:de:ad:01"})),
            (1700000100, 0, "IEEE802.11", "aa:bb:cc:dd:ee:ff", 0, 0, "PROBECHAN", "{}")]
    con.executemany("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    con.commit()
    con.close()


def test_kismet_reader(tmp_path, capsys):
    db = str(tmp_path / "run1.kismet")
    _kismet_db(db)
    alerts = kismet.read_alerts(db)
    assert [a["header"] for a in alerts] == ["PROBECHAN", "BSSTIMESTAMP", "CRYPTODROP"]
    first = kismet.first_alerts(db)
    assert first == {"00:c0:ca:de:ad:01": 1700000190.0}                  # PROBECHAN is not a twin alert
    assert kismet.main([db]) == 0 and "CRYPTODROP" in capsys.readouterr().out
    bad = tmp_path / "x.kismet"
    sqlite3.connect(bad).execute("CREATE TABLE devices (x INT)").connection.close()
    with pytest.raises(ValueError):
        kismet.read_alerts(str(bad))


def test_replayed_kismet_log_gives_who_but_not_when(tmp_path):
    """Real Kismet 2023-07 logs of a replayed pcap: packets keep their capture times, alerts get
    the time Kismet processed the file (hours later). Latency must not be computed from them."""
    from ghostap.evaluate import compute_metrics
    live, replay = str(tmp_path / "live.kismet"), str(tmp_path / "replay.kismet")
    for path, packet_ts in ((live, 1700000150), (replay, 1699990000)):
        _kismet_db(path)
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE packets (ts_sec INT, ts_usec INT)")
        con.execute("INSERT INTO packets VALUES (?, 0)", (packet_ts,))
        con.commit()
        con.close()
    assert not kismet.replayed(live) and kismet.replayed(replay)
    row = {"label": "evil_twin", "attack_start": 1699990100.0, "kismet_first": 1700000190.0, "kismet_timed": False}
    m = compute_metrics([row], "kismet", 30)
    assert m["TP"] == 1 and m["latency_mean"] is None                   # detected, latency unknown
    m = compute_metrics([dict(row, kismet_timed=True)], "kismet", 30)
    assert m["latency_mean"] == 10090.0


def test_extended_evaluation_with_kismet(tmp_path):
    import sys
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import make_test_pcap

    from ghostap.config import load_config
    from ghostap.evaluate import evaluate
    from ghostap.evaluate_extended import extended
    make_test_pcap.generate(str(tmp_path))
    os.rename(tmp_path / "test_capture.pcap", tmp_path / "run1.pcap")
    labels = json.load(open(tmp_path / "test_labels.json"))
    json.dump(labels, open(tmp_path / "run1.labels.json", "w"))
    _kismet_db(str(tmp_path / "run1.kismet"))
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    rows, *_ = evaluate([("run1", str(tmp_path / "run1.pcap"), str(tmp_path / "run1.labels.json"))], cfg)
    twin = [r for r in rows if r["label"] == "evil_twin"][0]
    assert twin["kismet_first"] == 1700000190.0 and twin["indicators"]["security_downgrade"] == 1.0
    res = extended(rows, cfg, str(tmp_path / "out"), charts=False)
    assert res["kismet"] and [c["detector"] for c in res["ci"]] == ["ghostap", "baseline", "kismet"]
    assert not res["split_results"]["usable"]                              # one capture cannot be split
    assert os.path.exists(tmp_path / "out" / "extended.md") and os.path.exists(tmp_path / "out" / "roc.csv")


def test_scenario_builder_and_sync_numbers(tmp_path):
    import shutil
    import subprocess
    import sys
    tools = os.path.join(ROOT, "tools")
    sys.path.insert(0, tools)
    import build_scenario
    import sync_numbers
    with pytest.raises(build_scenario.SpecError):
        build_scenario.build({"name": "../x", "aps": []}, str(tmp_path))
    with pytest.raises(build_scenario.SpecError):
        build_scenario.build({"name": "bad", "aps": [{"ssid": "A", "bssid": "zz"}]}, str(tmp_path))
    r = build_scenario.build({"name": "c1", "aps": [{"ssid": "MVSR_WiFi", "bssid": "00:c0:ca:de:ad:09",
                                                     "channel": 11, "security": "open", "start": 180,
                                                     "label": "evil_twin", "profile": "hostapd"}]}, str(tmp_path))
    lab = json.load(open(tmp_path / "c1.labels.json"))
    assert r["twins"] == 1 and lab["synthetic"] and lab["custom"] and "build_scenario" in lab["description"]
    # sync: in step with the committed results, and a stale number is found and fixed
    root = tmp_path / "repo"
    for f in ("README.md", "CLAUDE.md", "docs/REPORT.md", "docs/DEMO.md"):
        (root / os.path.dirname(f)).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, f), root / f)
    (root / "docs" / "figures").mkdir()
    results = os.path.join(ROOT, "results")
    if not os.path.exists(os.path.join(results, "metrics.csv")):
        pytest.skip("run the evaluation first")
    assert sync_numbers.main(["--results", results, "--root", str(root)]) == 0
    readme = (root / "README.md").read_text().replace("| GhostAP | 1.00 | 0.83 | 0.91 |",
                                                     "| GhostAP | 1.00 | 0.83 | 0.99 |")
    (root / "README.md").write_text(readme)
    assert sync_numbers.main(["--results", results, "--root", str(root)]) == 1
    assert sync_numbers.main(["--results", results, "--root", str(root), "--write"]) == 0
    assert "| 0.91 |" in (root / "README.md").read_text()
    assert subprocess.run([sys.executable, os.path.join(tools, "sync_numbers.py"), "--results", results, "--root",
                           str(root)], capture_output=True).returncode == 0
