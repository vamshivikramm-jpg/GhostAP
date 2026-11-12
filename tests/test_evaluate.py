import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_eval_set  # noqa: E402
import make_test_pcap  # noqa: E402

from ghostap.evaluate import (  # noqa: E402
    compute_metrics, evaluate, find_dataset, load_labels, main, threshold_sweep,
)
from ghostap.risk import load_config  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")


# --------------------------------------------------------------------------- #
# Metric arithmetic on hand-made rows
# --------------------------------------------------------------------------- #

def row(label, peak_at=None, score=80.0, attack=100.0, baseline=None):
    series = [(90.0, 0.0), (peak_at, score)] if peak_at is not None else [(90.0, 0.0)]
    return {"scenario": "x", "description": "", "label": label,
            "attack_start": attack if label == "evil_twin" else None,
            "ghostap_series": series, "baseline_first": baseline}


def test_metrics_counts_and_ratios():
    rows = [
        row("evil_twin", peak_at=120.0),          # TP, latency 20
        row("evil_twin"),                         # FN
        row("legit", peak_at=130.0),              # FP
        row("legit"), row("legit"), row("legit"),  # TN x3
    ]
    m = compute_metrics(rows, "ghostap", 30)
    assert (m["TP"], m["FP"], m["TN"], m["FN"]) == (1, 1, 3, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5
    assert m["fpr"] == pytest.approx(0.25)
    assert m["latency_mean"] == 20.0


def test_latency_floored_at_zero_and_no_predictions():
    rows = [row("evil_twin", baseline=50.0), row("legit")]
    m = compute_metrics(rows, "baseline", 30)
    assert m["TP"] == 1 and m["latency_max"] == 0.0
    none = compute_metrics([row("legit")], "ghostap", 30)
    assert none["precision"] is None and none["recall"] is None and none["fpr"] == 0.0


def test_threshold_sweep_is_monotonic_in_alerts():
    rows = [row("evil_twin", peak_at=120.0, score=45.0), row("legit", peak_at=120.0, score=25.0)]
    sweep = threshold_sweep(rows, [20, 30, 50])
    assert [(m["TP"], m["FP"]) for m in sweep] == [(1, 1), (1, 0), (0, 0)]


def test_load_labels_both_formats(tmp_path):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"attack_start": 5.0, "aps": {"AA:BB:CC:00:00:01": "evil_twin",
                                                            "aa:bb:cc:00:00:02": "legit"}}))
    new = tmp_path / "new.json"
    new.write_text(json.dumps({"aps": {"aa:bb:cc:00:00:01": {"label": "evil_twin", "attack_start": 7.0}}}))
    a = load_labels(str(old))["aps"]
    assert a["aa:bb:cc:00:00:01"] == {"label": "evil_twin", "attack_start": 5.0}
    assert a["aa:bb:cc:00:00:02"]["attack_start"] is None
    assert load_labels(str(new))["aps"]["aa:bb:cc:00:00:01"]["attack_start"] == 7.0


# --------------------------------------------------------------------------- #
# End to end on generated scenarios
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def eval_dir(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("eval"))
    make_eval_set.generate(d)
    return d


def test_dataset_discovery(eval_dir):
    pairs = find_dataset(eval_dir)
    assert len(pairs) == len(make_eval_set.SCENARIOS)
    assert all(p.endswith(".pcap") and l.endswith(".labels.json") for _, p, l in pairs)


def test_ghostap_beats_baseline_on_precision_and_fpr(eval_dir):
    pick = {"s01_classic_open_twin", "s04_stealth_wpa2_twin", "s06_benign_new_ap",
            "s08_benign_enterprise", "s11_fingerprint_clone_twin"}
    pairs = [p for p in find_dataset(eval_dir) if p[0] in pick]
    rows, metrics, sweep, scen = evaluate(pairs, load_config(CONFIG))
    g, b = metrics
    assert g["detector"] == "ghostap" and b["detector"] == "baseline"
    assert b["recall"] == 1.0                     # baseline flags every duplicate SSID...
    assert b["fpr"] > 0.5                         # ...including most legit APs
    assert g["FP"] == 0 and g["fpr"] == 0.0
    assert g["precision"] > b["precision"]
    by = {e["scenario"]: e for e in scen}
    assert by["s01_classic_open_twin"]["ghostap_TP"] == 1
    assert by["s04_stealth_wpa2_twin"]["ghostap_TP"] == 1   # caught by the beacon fingerprint
    assert by["s06_benign_new_ap"]["ghostap_FP"] == 0       # same hardware: no fingerprint hit
    assert by["s11_fingerprint_clone_twin"]["ghostap_FN"] == 1   # known limitation
    assert 0 <= g["latency_max"] <= 60


def test_cli_writes_results(eval_dir, tmp_path):
    out = str(tmp_path / "results")
    # also include the Phase-1 capture through --pcap/--labels (old labels format)
    pcap, labels, _ = make_test_pcap.generate(str(tmp_path / "p1"))
    assert main(["--dataset", eval_dir, "--pcap", pcap, "--labels", labels,
                 "--config", CONFIG, "--out", out]) == 0
    for f in ("summary.md", "metrics.csv", "per_ap.csv", "per_scenario.csv", "threshold_sweep.csv",
              "metrics_comparison.png", "latency.png", "threshold_sweep.png", "risk_timelines.png"):
        assert os.path.getsize(os.path.join(out, f)) > 0, f
    summary = open(os.path.join(out, "summary.md")).read()
    assert "test_capture" in summary and "synthetic" in summary


def test_cli_without_data(tmp_path, capsys):
    assert main(["--dataset", str(tmp_path / "empty"), "--out", str(tmp_path / "r")]) == 1
    assert "make_eval_set.py" in capsys.readouterr().err
