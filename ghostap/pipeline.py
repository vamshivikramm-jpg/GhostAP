"""Background pipeline for the dashboard: ingest frames and keep the risk scores fresh.

Sources:
  * replay   - read a pcap and insert frames paced by their capture timestamps
               (speed 10 = ten times real time, 0 = as fast as possible)
  * live     - sniff beacons / probe responses on a monitor-mode interface (Linux,
               root), optionally hopping channels and saving a pcap
  * database - score what is already in the database once

A second thread scores incrementally every `rescore_seconds`: it reads only the
observations added since the last round, feeds them to a long-lived Analyzer and
RiskEngine, and appends the new risk-timeline rows. The cost of a round therefore
depends on how much new data arrived, not on how long the capture has been running.
"""
from __future__ import annotations

import threading
import time
from typing import List, Optional

from .collector import LIVE_HELP, collect_live
from .logs import get_logger
from .indicators import Analyzer
from .parser import parse_frame
from .risk import DuplicateSSIDDetector, RiskEngine, duplicate_ssid_detector, load_config
from .storage import Store

log = get_logger("pipeline")


def rescore(db: str, config: dict) -> dict:
    """Score a whole database from scratch (rebuild profiles, GhostAP, baseline detector)."""
    with Store(db) as store:
        store.rebuild_profiles()
        obs = store.observations()
    an = Analyzer(obs, config["baseline_minutes"], config.get("known_bssids") or ())
    report = RiskEngine(an, config).run()
    base = duplicate_ssid_detector(obs)
    with Store(db) as store:
        store.save_timeline(report.timeline)
        store.save_latest(report.latest)
        store.save_alerts("ghostap", report.alerts)
        store.save_alerts("baseline", base)
    return {"frames": len(obs), "alerts": len(report.alerts), "baseline_alerts": len(base)}


class IncrementalScorer:
    """Keeps an Analyzer / RiskEngine alive and feeds it only new database rows."""

    def __init__(self, db: str, config: dict, monitored: Optional[dict] = None):
        self.db = db
        self.config = config
        self.analyzer = Analyzer((), config["baseline_minutes"], config.get("known_bssids") or (),
                                 monitored=monitored)
        self.engine = RiskEngine(self.analyzer, config)
        self.duplicates = DuplicateSSIDDetector()
        self.last_id = 0
        self._last_prune_ts: Optional[float] = None
        self.pruned = 0

    def step(self, final: bool = False) -> dict:
        with Store(self.db) as store:
            first_round = self.last_id == 0
            new, self.last_id = store.observations_after(self.last_id)
            if not new and not final:
                return {"new_frames": 0, "new_rows": 0, "alerts": None}   # idle: nothing to do
            if first_round:
                store.clear_profiles()           # profiles are rebuilt from what we read
            self.analyzer.add(new)
            self.duplicates.update(new)
            report = self.engine.run(final=final)
            store.update_profiles(new)
            store.append_timeline(report.timeline)
            store.save_latest(report.latest)
            store.save_alerts("ghostap", report.alerts)
            store.save_alerts("baseline", self.duplicates.alerts())
            self._retention(store)
        return {"new_frames": len(new), "new_rows": len(report.timeline),
                "alerts": len(report.alerts)}

    def _retention(self, store: Store) -> None:
        """F070: drop raw frames older than retention.raw_hours (capture time)."""
        r = self.config.get("retention", {})
        keep_h = float(r.get("raw_hours") or 0)
        if keep_h <= 0 or not self.analyzer.obs:
            return
        now = self.analyzer.obs[-1]["ts"]
        every = float(r.get("check_minutes", 10)) * 60
        if self._last_prune_ts is not None and now - self._last_prune_ts < every:
            return
        self._last_prune_ts = now
        cutoff = now - keep_h * 3600
        n = store.prune_observations(cutoff)
        self.analyzer.prune(cutoff)
        if n:
            self.pruned += n
            log.info("retention: removed %d raw frames older than %.1f h", n, keep_h)


class Pipeline:
    def __init__(self, db: str, config: Optional[dict] = None, pcap: Optional[str] = None,
                 iface: Optional[str] = None, speed: float = 10.0,
                 duration: Optional[float] = None, rescore_seconds: float = 2.0,
                 reset: bool = True, hop: Optional[List[int]] = None, dwell: float = 0.25,
                 save_pcap: Optional[str] = None, monitored: Optional[dict] = None,
                 on_finish=None):
        """monitored: saved baselines (F014) to use from the first frame.
        on_finish(status): called once ingest and the final scoring round are done."""
        self.monitored = monitored
        self.on_finish = on_finish
        if pcap and iface:
            raise ValueError("use either pcap or iface, not both")
        self.db = db
        self.config = config or load_config(None)
        self.pcap, self.iface = pcap, iface
        self.speed = speed
        self.duration = duration
        self.rescore_seconds = rescore_seconds
        self.reset = reset
        self.hop, self.dwell, self.save_pcap = hop, dwell, save_pcap
        self._stop = threading.Event()
        self._ingest_done = threading.Event()
        self._lock = threading.Lock()
        self._threads = []
        mode = "replay" if pcap else "live" if iface else "database"
        self.status = {
            "mode": mode,
            "source": pcap or iface or db,
            "state": "idle",
            "frames": 0,
            "message": "",
            "speed": speed if pcap else None,
            "hopping": None,
            "save_pcap": save_pcap if iface else None,
            "started_at": None,
            "last_scored_at": None,
            "score_seconds": None,
            "last_frame_ts": None,
            "rejected": {},       # damaged frames skipped, by reason
            "data_version": 0,    # bumped whenever scores / alerts change
        }
        self._rejected: dict = {}

    # -- control ------------------------------------------------------------ #

    def start(self) -> "Pipeline":
        with Store(self.db) as store:
            if self.reset and self.status["mode"] != "database":
                store.reset()
            else:
                store.save_timeline([])     # scored again from scratch below
        self._set(state="running", started_at=time.time())
        if self.status["mode"] == "database":
            self._ingest_done.set()
        else:
            target = self._ingest_replay if self.pcap else self._ingest_live
            self._spawn(target)
        self._spawn(self._score_loop)
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        if self.status["state"] == "running":
            self._set(state="stopped")

    def wait(self, timeout: Optional[float] = None) -> None:
        """Block until ingest and the final rescore have finished (used by tests)."""
        deadline = None if timeout is None else time.time() + timeout
        for t in self._threads:
            t.join(None if deadline is None else max(0, deadline - time.time()))

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.status)

    # -- internals ---------------------------------------------------------- #

    def _damaged(self) -> dict:
        return {k: v for k, v in self._rejected.items() if k != "not_beacon" and v}

    def _set(self, **kw) -> None:
        with self._lock:
            self.status.update(kw)

    def _spawn(self, target) -> None:
        t = threading.Thread(target=target, daemon=True, name=target.__name__)
        self._threads.append(t)
        t.start()

    def _ingest_replay(self) -> None:
        from scapy.utils import PcapReader

        try:
            store = Store(self.db)
            n, ts0, last_ts, wall0, last_commit = 0, None, None, time.time(), time.time()
            with PcapReader(self.pcap) as reader:
                for pkt in reader:
                    if self._stop.is_set():
                        break
                    obs = parse_frame(pkt, self._rejected)
                    if not obs:
                        continue
                    if ts0 is None:
                        ts0 = obs["ts"]
                    if self.speed > 0:
                        delay = wall0 + (obs["ts"] - ts0) / self.speed - time.time()
                        if delay > 0:
                            store.commit()
                            if self._stop.wait(delay):
                                break
                    store.add(obs)
                    n += 1
                    last_ts = obs["ts"]
                    if time.time() - last_commit > 0.5:
                        store.commit()
                        last_commit = time.time()
                        self._set(frames=n, last_frame_ts=last_ts, rejected=self._damaged())
            store.close()
            self._set(frames=n, last_frame_ts=last_ts, rejected=self._damaged(),
                      message="replay finished ({} frames)".format(n))
        except FileNotFoundError:
            self._set(state="error", message="pcap not found: {}".format(self.pcap))
        except Exception as e:  # malformed pcap etc.
            self._set(state="error", message="replay failed: {}: {}".format(type(e).__name__, e))
        finally:
            self._ingest_done.set()

    def _ingest_live(self) -> None:
        store = Store(self.db)
        counter = {"n": 0}

        def on_frame(obs):
            counter["n"] += 1
            self._set(frames=counter["n"], last_frame_ts=obs["ts"], rejected=self._damaged())

        try:
            n = collect_live(self.iface, self.duration, store, hop=self.hop, dwell=self.dwell,
                             save_pcap=self.save_pcap, stop=self._stop, on_frame=on_frame,
                             on_status=lambda m: self._set(hopping=m, rejected=self._damaged()),
                             stats=self._rejected)
            msg = "live capture finished ({} frames)".format(n)
            if self.save_pcap:
                msg += "; saved to {}".format(self.save_pcap)
            self._set(message=msg)
        except Exception as e:  # no root, no monitor mode, no such interface ...
            msg = LIVE_HELP.format(err="{}: {}".format(type(e).__name__, e))
            self._set(state="error", message=msg)
        finally:
            store.close()
            self._ingest_done.set()

    def _score_loop(self) -> None:
        scorer = IncrementalScorer(self.db, self.config, self.monitored)
        log.info("scoring started (%s: %s)%s", self.status["mode"], self.status["source"],
                 " with %d monitored network(s)" % len(self.monitored) if self.monitored else "")
        while True:
            finished = self._ingest_done.wait(self.rescore_seconds)
            try:
                t0 = time.time()
                out = scorer.step(final=finished)
                kw = {"last_scored_at": time.time(), "score_seconds": round(time.time() - t0, 3)}
                if out["new_frames"] or out["new_rows"] or finished:
                    kw["data_version"] = self.status["data_version"] + 1
                self._set(**kw)
            except Exception as e:
                log.exception("rescoring failed")
                self._set(message="rescoring failed: {}: {}".format(type(e).__name__, e))
            if finished or self._stop.is_set():
                break
        if self.status["state"] == "running":
            self._set(state="done" if not self._stop.is_set() else "stopped")
        self._set(pruned_frames=scorer.pruned)
        log.info("scoring finished: %s, %s frames", self.status["state"], self.status["frames"])
        if self.on_finish:
            try:
                self.on_finish(self.snapshot())
            except Exception:
                log.exception("on_finish callback failed")
