import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_test_pcap  # noqa: E402

from ghostap.storage import Store  # noqa: E402

EVIL = "00:c0:ca:de:ad:01"
LEGIT = ("a4:2b:b0:11:22:33", "a4:2b:b0:11:22:99", "f0:9f:c2:aa:bb:cc")


def test_pipeline(tmp_path):
    pcap, labels_path, _ = make_test_pcap.generate(str(tmp_path))
    db = str(tmp_path / "test.db")

    # Run the real CLI entry point.
    res = subprocess.run(
        [sys.executable, "-m", "ghostap.collector", "--pcap", pcap, "--db", db],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "BSSID" in res.stdout

    store = Store(db)
    profiles = {p["bssid"]: p for p in store.profiles()}
    store.close()

    assert len(profiles) == 4

    evil = profiles[EVIL]
    assert evil["ssid"] == "MVSR_WiFi"
    assert evil["securities"] == "OPN"
    assert evil["channels"] == "11"
    assert evil["frames"] == 120

    for bssid in LEGIT:
        assert profiles[bssid]["frames"] == 300

    labels = json.load(open(labels_path))
    assert labels["aps"][EVIL] == "evil_twin"
    assert all(labels["aps"][b] == "legit" for b in LEGIT)
    assert evil["first_seen"] >= labels["attack_start"]
