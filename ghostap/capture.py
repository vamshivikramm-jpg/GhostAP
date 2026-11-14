"""Capture control (F041): pause / resume and channel changes while a live capture runs.

The pipeline creates one CaptureControl and hands it to collect_live(); the dashboard
changes it. Pausing drops frames (it does not stop the radio), and both pause and resume
are written to the timeline as notes, so a gap in the data always has an explanation.
"""
from __future__ import annotations

import threading
import time
from typing import List, Optional


class CaptureControl:
    def __init__(self):
        self._paused = threading.Event()
        self.paused_since: Optional[float] = None
        self.dropped_while_paused = 0
        self.hopper = None                 # the running ChannelHopper, if any
        self.iface: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    def pause(self) -> bool:
        if self.paused:
            return False
        self.paused_since = time.time()
        self._paused.set()
        return True

    def resume(self) -> bool:
        if not self.paused:
            return False
        self._paused.clear()
        self.paused_since = None
        return True

    def drop(self) -> bool:
        """Called for every frame: True = discard it (paused)."""
        if self._paused.is_set():
            self.dropped_while_paused += 1
            return True
        return False

    def set_hop(self, channels: List[int], dwell: float) -> str:
        """Change the channel plan of a running capture (one channel = park on it)."""
        from .hopper import ChannelHopper
        if not channels:
            raise ValueError("give at least one channel")
        if not 0.05 <= dwell <= 10:
            raise ValueError("dwell must be 0.05 to 10 seconds")
        with self._lock:
            if self.iface is None:
                raise RuntimeError("no live capture is running")
            if self.hopper is None:
                self.hopper = ChannelHopper(self.iface, channels, dwell).start()
            else:
                self.hopper.reconfigure(channels, dwell)
            return self.hopper.describe()

    def snapshot(self) -> dict:
        h = self.hopper
        return {"paused": self.paused, "paused_since": self.paused_since,
                "dropped_while_paused": self.dropped_while_paused, "iface": self.iface,
                "channels": list(h.channels) if h else None, "dwell": h.dwell if h else None,
                "hopping": h.describe() if h else "parked on the adapter's current channel"}
