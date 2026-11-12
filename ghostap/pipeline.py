"""Background pipeline for the dashboard: ingest frames and keep the risk scores fresh.

Sources:
  * replay - read a pcap and insert frames paced by their capture timestamps
             (speed 10 = ten times real time, 0 = as fast as possible)
  * live   - sniff beacons / probe responses on a monitor-mode interface (Linux, root)

A second thread re-runs the risk engine and the baseline detector every
`rescore_seconds`, writing alerts and the risk timeline to the database that the
Flask API reads.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from .collector import LIVE_HELP, _is_beacon_or_probe_resp
from .indicators import Analyzer
from .parser import parse_frame
from .risk import RiskEngine, duplicate_ssid_detector, load_config
from .storage import Store


def rescore(db: str, config: dict) -> dict:
    """Rebuild profiles, rerun GhostAP + baseline detector, save the results."""
    with Store(db) as store:
        store.rebuild_profiles()
        obs = store.observations()
    an = Analyzer(obs, config["baseline_minutes"])
    report = RiskEngine(an, config).run()
    base = duplicate_ssid_detector(obs)
    with Store(db) as store:
        store.save_timeline(report.timeline)
        store.save_alerts("ghostap", report.alerts)
        store.save_alerts("baseline", base)
    return {"frames": len(obs), "alerts": len(report.alerts), "baseline_alerts": len(base)}


class Pipeline:
    def __init__(self, db: str, config: Optional[dict] = None, pcap: Optional[str] = None,
                 iface: Optional[str] = None, speed: float = 10.0,
                 duration: Optional[float] = None, rescore_seconds: float = 2.0,
                 reset: bool = True):
        if pcap and iface:
            raise ValueError("use either pcap or iface, not both")
        self.db = db
        self.config = config or load_config(None)
        self.pcap, self.iface = pcap, iface
        self.speed = speed
        self.duration = duration
        self.rescore_seconds = rescore_seconds
        self.reset = reset
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
            "started_at": None,
            "last_scored_at": None,
            "last_frame_ts": None,
        }

    # -- control ------------------------------------------------------------ #

    def start(self) -> "Pipeline":
        if self.reset and self.status["mode"] != "database":
            with Store(self.db) as store:
                store.reset()
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
                    obs = parse_frame(pkt)
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
                        self._set(frames=n, last_frame_ts=last_ts)
            store.close()
            self._set(frames=n, last_frame_ts=last_ts,
                      message="replay finished ({} frames)".format(n))
        except FileNotFoundError:
            self._set(state="error", message="pcap not found: {}".format(self.pcap))
        except Exception as e:  # malformed pcap etc.
            self._set(state="error", message="replay failed: {}: {}".format(type(e).__name__, e))
        finally:
            self._ingest_done.set()

    def _ingest_live(self) -> None:
        from scapy.sendrecv import sniff

        store = Store(self.db)
        counter = {"n": 0}

        def handle(pkt):
            obs = parse_frame(pkt)
            if obs:
                store.add(obs)
                counter["n"] += 1
                self._set(frames=counter["n"], last_frame_ts=obs["ts"])

        start = time.time()
        try:
            while not self._stop.is_set():
                if self.duration and time.time() - start >= self.duration:
                    break
                sniff(iface=self.iface, prn=handle, lfilter=_is_beacon_or_probe_resp,
                      store=False, timeout=1)
                store.commit()
            self._set(message="live capture finished ({} frames)".format(counter["n"]))
        except Exception as e:  # no root, no monitor mode, no such interface ...
            msg = LIVE_HELP.format(err="{}: {}".format(type(e).__name__, e))
            self._set(state="error", message=msg)
        finally:
            store.close()
            self._ingest_done.set()

    def _score_loop(self) -> None:
        while True:
            finished = self._ingest_done.wait(self.rescore_seconds)
            try:
                rescore(self.db, self.config)
                self._set(last_scored_at=time.time())
            except Exception as e:
                self._set(message="rescoring failed: {}: {}".format(type(e).__name__, e))
            if finished or self._stop.is_set():
                break
        if self.status["state"] == "running":
            self._set(state="done" if not self._stop.is_set() else "stopped")
