# GhostAP — Passive Evil Twin Access Point Detector

GhostAP is a college cybersecurity project that detects **Evil Twin** Wi-Fi access
points by **passively** listening to 802.11 beacon and probe-response frames.

- No packet injection, no deauthentication, no capture of user traffic.
- Only use it on networks you own or have written permission to monitor.

Pipeline: capture beacons → parse metadata → store in SQLite → per-AP profiles →
multi-indicator weighted risk score (0–100) with temporal analysis → explainable
alerts → Flask + Plotly dashboard → evaluation (precision, recall, F1, false-positive
rate, detection latency) against a baseline that only flags duplicate SSIDs.

## Phases

| # | Phase | Status |
|---|-------|--------|
| 0 | Setup & hardware (Linux + monitor-mode adapter) | manual |
| 1 | Collector + storage + synthetic test data | ✅ done |
| 2 | Labelled lab dataset (real captures) | todo |
| 3 | Indicators | todo |
| 4 | Risk engine | todo |
| 5 | Dashboard | todo |
| 6 | Evaluation | todo |
| 7 | Report & demo | todo |

## Layout

```
ghostap/parser.py      frame -> observation dict
ghostap/storage.py     SQLite store (observations + ap_profiles)
ghostap/collector.py   CLI entry point (offline pcap or live sniff)
tools/make_test_pcap.py synthetic capture with one evil twin
tests/                 pytest suite
data/                  captures and databases (gitignored)
```

## Setup

Requires Python 3.10+ (developed on 3.12; on macOS: `brew install python@3.12`).

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run offline (any OS, including macOS)

```bash
python tools/make_test_pcap.py                       # writes data/test_capture.pcap + data/test_labels.json
python -m ghostap.collector --pcap data/test_capture.pcap
pytest -q
```

The collector appends to the database. Add `--reset` to clear it first, or `--db`
to use a different file.

The synthetic capture contains 300 s of beacons from four APs:

| SSID | BSSID | CH | Security | RSSI | Label |
|------|-------|----|----------|------|-------|
| MVSR_WiFi | a4:2b:b0:11:22:33 | 6 | WPA2 | ~-55 | legit |
| MVSR_WiFi | a4:2b:b0:11:22:99 | 1 | WPA2 | ~-70 | legit (second AP, must not be flagged) |
| Cafe_Guest | f0:9f:c2:aa:bb:cc | 11 | Open | ~-75 | legit |
| MVSR_WiFi | 00:c0:ca:de:ad:01 | 11 | Open | ~-38 | **evil twin**, appears at t=180 s |

## Run live (Linux only)

Requires root and a Wi-Fi adapter that supports monitor mode.

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
sudo .venv/bin/python -m ghostap.collector --iface wlan0 --duration 120
```

Options: `--duration` (seconds, default 60, live only), `--db` (default
`data/ghostap.db`), `--reset`.

## macOS note

macOS cannot put USB Wi-Fi adapters into monitor mode for this kind of capture, so on
a Mac use offline mode (`--pcap`) with the synthetic capture or pcaps recorded on Linux.
