"""GhostAP 2.0 Phase 0 (P1): the live detector's memory stays bounded, and scores do not change."""
import copy
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import bench_large_site  # noqa: E402

from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import IncrementalScorer  # noqa: E402
from ghostap.storage import Store  # noqa: E402


def _run(tmp_path, name, obs, memory_minutes):
    cfg = copy.deepcopy(load_config(os.path.join(ROOT, "config.yaml")))
    cfg["retention"].update(memory_minutes=memory_minutes, check_minutes=1)
    db = str(tmp_path / (name + ".db"))
    sc = IncrementalScorer(db, cfg)
    peak = 0
    start = obs[0]["ts"]
    i = 0
    while i < len(obs):                                  # 30 s of frames at a time, like live capture
        end = start + 30
        with Store(db) as s:
            while i < len(obs) and obs[i]["ts"] < end:
                s.add(obs[i])
                i += 1
            s.commit()
        sc.step()
        peak = max(peak, len(sc.analyzer.obs))
        start = end
    sc.step(final=True)
    with Store(db) as s:
        tl = [(r["ts"], r["ssid"], r["bssid"], r["score"], r["level"]) for r in s.timeline()]
        alerts = [(a["ssid"], a["bssid"], a["level"], a["score"], a["first_ts"]) for a in s.alerts("ghostap")]
    return tl, alerts, peak, sc.forgotten


def test_bounded_memory_gives_identical_scores(tmp_path):
    src = str(tmp_path / "site.db")
    bench_large_site.build(src, n_aps=20, minutes=40)      # SYNTHETIC: 20 APs + a twin at 20 min
    with Store(src) as s:
        obs = s.observations()
    full_tl, full_alerts, full_peak, _ = _run(tmp_path, "full", obs, 0)
    tl, alerts, peak, forgotten = _run(tmp_path, "bounded", obs, 5)
    assert full_alerts and alerts == full_alerts
    assert tl == full_tl
    assert forgotten > 0 and peak < 0.35 * full_peak        # ~5 of 40 minutes kept (+ heads)
    with Store(str(tmp_path / "bounded.db")) as s:          # the database still has every frame
        assert s.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == len(obs)


def test_late_frame_after_pruning_does_not_relearn(tmp_path):
    from ghostap.risk import analyzer_for
    src = str(tmp_path / "s.db")
    bench_large_site.build(src, n_aps=5, minutes=12)
    with Store(src) as s:
        obs = s.observations()
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    an = analyzer_for(cfg, obs[: len(obs) * 3 // 4])
    base = an.baseline
    assert an.prune(obs[len(obs) // 2]["ts"]) > 0
    late = dict(obs[len(obs) * 3 // 4 - 1], ts=obs[len(obs) * 3 // 4 - 1]["ts"] - 1)
    an.add([late] + obs[len(obs) * 3 // 4:])
    assert an.baseline is base                                # not rebuilt from partial data
    assert all(a <= b for a, b in zip(an._ts[(late["ssid"], late["bssid"])], an._ts[(late["ssid"], late["bssid"])][1:]))
