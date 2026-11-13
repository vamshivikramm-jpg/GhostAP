"""Channel hopping for live capture.

A monitor-mode adapter hears one channel at a time. An evil twin is often on a
different channel from the real AP, so a monitor parked on one channel can miss
it completely. The hopper cycles the adapter through a channel list with
`iw dev <iface> set channel <n>`.

Channel lists:  "1,6,11"   "1-13"   "2.4" (1-13)   "5" (common 5 GHz)   "6e" (6 GHz
preferred-scanning channels)   "all" (2.4 + 5 GHz). 6 GHz entries are kept as frequencies
in MHz (5975, 6055, ...) because 6 GHz channel numbers overlap 2.4 GHz ones; they are
tuned with `iw dev <iface> set freq`.
"""
from __future__ import annotations

import subprocess
import threading
from typing import Callable, Dict, List, Optional

BAND_24 = list(range(1, 14))
BAND_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
          132, 136, 140, 144, 149, 153, 157, 161, 165]
# 6 GHz preferred scanning channels (PSC), as frequencies in MHz: 5950 + 5 * channel
BAND_6E = [5950 + 5 * c for c in (5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229)]


def parse_channels(spec: str) -> List[int]:
    """'1,6,11' / '1-13' / '2.4' / '5' / 'all' (combinable with commas) -> channel list."""
    out: List[int] = []
    for part in (p.strip().lower() for p in spec.split(",")):
        if not part:
            continue
        if part in ("2.4", "2.4ghz", "24"):
            chans = BAND_24
        elif part in ("5", "5ghz"):
            chans = BAND_5
        elif part in ("6e", "6ghz", "6g"):
            chans = BAND_6E
        elif part == "all":
            chans = BAND_24 + BAND_5
        elif "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                raise ValueError("bad channel range: {}".format(part))
            chans = list(range(lo, hi + 1))
        else:
            chans = [int(part)]
        for c in chans:
            if not (0 < c <= 196 or 5925 <= c <= 7125):
                raise ValueError("bad channel: {}".format(c))
            if c not in out:
                out.append(c)
    if not out:
        raise ValueError("empty channel list")
    return out


def _iw(iface: str, channel: int) -> None:
    """Tune to a channel number, or to a frequency in MHz for 6 GHz entries."""
    what = "freq" if channel >= 5925 else "channel"
    subprocess.run(["iw", "dev", iface, "set", what, str(channel)],
                   check=True, capture_output=True, timeout=5)


class ChannelHopper:
    """Cycle `iface` through `channels`, staying `dwell` seconds on each.

    Channels the adapter rejects are dropped (e.g. 5 GHz on a 2.4 GHz-only
    adapter). If every channel fails, hopping stops and `error` explains why.
    """

    def __init__(self, iface: str, channels: List[int], dwell: float = 0.25,
                 setter: Optional[Callable[[str, int], None]] = None,
                 focus: Optional[Dict[int, float]] = None):
        """focus (F043): dwell multiplier per channel, e.g. {6: 3.0} stays 3x longer on 6."""
        self.iface = iface
        self.channels = list(channels)
        self.dwell = dwell
        self.focus = {int(k): float(v) for k, v in (focus or {}).items() if int(k) in self.channels}
        self._set = setter or _iw
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.current: Optional[int] = None
        self.dropped: List[int] = []
        self.error: Optional[str] = None
        self.hops = 0

    def start(self) -> "ChannelHopper":
        self._thread = threading.Thread(target=self._run, daemon=True, name="channel-hopper")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set() and self.channels:
            ch = self.channels[i % len(self.channels)]
            try:
                self._set(self.iface, ch)
                self.current = ch
                self.hops += 1
                i += 1
            except FileNotFoundError:
                self.error = "channel hopping needs the 'iw' tool (sudo apt install iw)"
                return
            except Exception as e:  # channel not supported by this adapter / regulatory domain
                self.dropped.append(ch)
                self.channels.remove(ch)
                if not self.channels:
                    self.error = "the adapter accepted none of the channels ({}: {})".format(
                        type(e).__name__, e)
                    return
                continue
            self._stop.wait(self.dwell * self.focus.get(ch, 1.0))

    def describe(self) -> str:
        if self.error:
            return "hopping stopped: " + self.error
        s = "hopping {} channel(s), {:g} s each".format(len(self.channels), self.dwell)
        if self.focus:
            s += ", focus on {}".format(",".join(str(c) for c in sorted(self.focus)))
        if self.current is not None:
            s += ", now on {}".format(self.current)
        if self.dropped:
            s += " (unsupported: {})".format(",".join(map(str, self.dropped)))
        return s
