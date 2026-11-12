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
| 3 | Indicators | ✅ done |
| 4 | Risk engine | todo |
| 5 | Dashboard | todo |
| 6 | Evaluation | todo |
| 7 | Report & demo | todo |

## Layout

```
ghostap/parser.py      frame -> observation dict
ghostap/storage.py     SQLite store (observations + ap_profiles)
ghostap/collector.py   CLI entry point (offline pcap or live sniff)
ghostap/indicators.py  baseline learning + 7 Evil Twin indicators
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

## Indicators (Phase 3)

```bash
python -m ghostap.indicators --db data/ghostap.db --baseline-minutes 2
```

The first N minutes of the capture are the **baseline** (what each SSID normally looks
like). Every AP then gets seven indicator values in [0, 1], each with a reason:

| Short | Indicator | Fires when |
|-------|-----------|------------|
| SEC | `security_downgrade` | weaker security than the SSID's baseline (WPA2 → WPA 0.5, → WEP/open 1.0) |
| OUI | `new_bssid_oui` | BSSID not in baseline: same vendor 0.3, different vendor or random MAC 1.0 |
| CH | `channel_deviation` | new BSSID on a channel the SSID never used 1.0; known BSSID changed channel 0.5 |
| RSSI | `rssi_jump` | signal more than 6 dB above baseline, reaching 1.0 at 16 dB above |
| TSF | `tsf_anomaly` | TSF counter reset, or uptime far below sibling APs (log-scale ratio) |
| CLONE | `bssid_conflict` | same BSSID alternating between channels, or sequence numbers going backwards |
| BI | `beacon_interval_mismatch` | beacon interval differs from the SSID's baseline |

Hidden SSIDs are not compared with each other. The baseline must not contain the
attack itself, so in lab captures start the evil twin after the baseline window.

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
