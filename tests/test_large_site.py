"""F038: the timeline stays bounded on large sites, without hiding any alert or peak."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import bench_large_site  # noqa: E402

from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import rescore  # noqa: E402
from ghostap.web import _downsample, create_app  # noqa: E402

CONFIG = os.path.join(ROOT, "config.yaml")


def test_downsample_keeps_every_bucket_peak():
    n = 1000
    s = {"ts": list(range(n)), "score": [0.0] * n, "raw": [0.0] * n, "level": ["LOW"] * n}
    s["score"][777] = 99.0
    out = _downsample(s, 100)
    assert len(out["ts"]) == 100 and out["downsampled_from"] == n
    assert 99.0 in out["score"] and out["ts"][out["score"].index(99.0)] == 777
    assert _downsample(s, 5000) is s


def test_timeline_limits_lines_but_keeps_alerts(tmp_path):
    db = str(tmp_path / "big.db")
    info = bench_large_site.build(db, n_aps=60, minutes=4)
    cfg = load_config(CONFIG)
    assert rescore(db, cfg)["alerts"] >= info["twins"]
    c = create_app(db, cfg, admin_db=db + ".a").test_client()
    full = c.get("/api/timeline?top=500").get_json()
    assert len(full) == info["aps"] and not any(r.get("aggregate") for r in full)
    r = c.get("/api/timeline?top=3")
    lines = r.get_json()
    agg = [x for x in lines if x.get("aggregate")]
    named = [x for x in lines if not x.get("aggregate")]
    alerting = {(x["ssid"], x["bssid"]) for x in full if x["peak"] >= cfg["thresholds"]["medium"]}
    assert alerting <= {(x["ssid"], x["bssid"]) for x in named}         # no alert is folded away
    assert len(named) == max(3, len(alerting)) and agg[0]["aggregate"] == info["aps"] - len(named)
    rest_peak = max(x["peak"] for x in full if (x["ssid"], x["bssid"]) not in {(y["ssid"], y["bssid"]) for y in named})
    assert agg[0]["peak"] == rest_peak
    assert r.headers["X-GhostAP-Lines"] == "{} of {}".format(len(named), info["aps"])
    assert c.get("/api/timeline?top=abc").status_code == 200                 # bad numbers fall back
