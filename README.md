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
| 4 | Risk engine | ✅ done |
| 5 | Dashboard | ✅ done |
| 6 | Evaluation | ✅ done (synthetic set; rerun on Phase 2 captures) |
| 7 | Report & demo | ✅ draft: [docs/REPORT.md](docs/REPORT.md), [docs/DEMO.md](docs/DEMO.md) |

## Layout

```
ghostap/parser.py      frame -> observation dict
ghostap/storage.py     SQLite store (observations + ap_profiles)
ghostap/collector.py   CLI entry point (offline pcap or live sniff)
ghostap/indicators.py  baseline learning + 7 Evil Twin indicators
ghostap/risk.py        weighted risk score, temporal smoothing, alerts, baseline detector
config.yaml            indicator weights, thresholds, timing
ghostap/pipeline.py    background replay / live ingest + periodic rescoring
ghostap/web.py         Flask API + dashboard server
ghostap/static/        dashboard front end (HTML/CSS/JS, Plotly)
tools/make_test_pcap.py synthetic capture with one evil twin
tools/make_eval_set.py  10 labelled synthetic scenarios for evaluation
tools/demo.py          guided end-to-end demo (opens the dashboard)
docs/                  project report, demo runbook, figures
ghostap/evaluate.py    Phase 6 evaluation (also: python evaluate.py)
tests/                 pytest suite
data/                  captures and databases (gitignored)
```

## Quick demo

```bash
python tools/demo.py          # step-by-step demo; ends with the live dashboard
```

The project report is in [docs/REPORT.md](docs/REPORT.md), and the presenter
runbook with likely questions is in [docs/DEMO.md](docs/DEMO.md).

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

## Risk engine (Phase 4)

```bash
python -m ghostap.risk --db data/ghostap.db --config config.yaml
```

- **Score:** `R = Σ wᵢxᵢ / Σ wᵢ × 100`, with the weights set in `config.yaml`.
- **Temporal analysis:** every `step_seconds` (10 s) each AP is scored using only its
  frames from the last `window_seconds`. The smoothed score is the mean of the last
  `smoothing_steps` (3) raw scores, counting 0 while the AP is silent. So a single odd
  beacon adds at most a third of its score and cannot raise an alert by itself.
- **Levels** on the smoothed score: LOW < 30 ≤ MEDIUM < 60 ≤ HIGH. An alert is raised at MEDIUM.
- **`alerts` table:** one row per AP, with the level, peak score, when it first fired,
  when it reached HIGH, each indicator's value, weight, contribution and reason, and
  possible benign causes. `risk_timeline` stores every AP's score at every step, for the dashboard.
- **Baseline detector** (`detector='baseline'`): flags every BSSID whose SSID is
  advertised by more than one BSSID. Phase 6 compares GhostAP against this.

On the synthetic capture, GhostAP raises one alert: the evil twin, MEDIUM 20 s and
HIGH 30 s after it appears, with a peak score of 73. The baseline detector flags all
three `MVSR_WiFi` BSSIDs, so two of its three alerts are false positives.

## Dashboard (Phase 5)

```bash
# replay a pcap at 10x speed and watch alerts appear (fresh data/replay.db)
python -m ghostap.web --pcap data/test_capture.pcap --speed 10

# browse an existing database (after running the collector and risk engine)
python -m ghostap.web --db data/ghostap.db

# live capture (Linux, root, monitor mode), writes data/live.db
sudo .venv/bin/python -m ghostap.web --iface wlan0
```

Open <http://127.0.0.1:8050>. Port 5000 is avoided because macOS uses it for AirPlay.

- **Status bar and tiles:** mode (replay / live / database), capture clock, AP and
  frame counts, HIGH and MEDIUM alerts, baseline-detector alerts, and baseline-learning progress.
- **Alert list:** ranked by risk, with a tab to switch to the duplicate-SSID baseline detector.
- **Alert detail:** each indicator's contribution (bar chart and table, with reasons), the
  AP's raw and smoothed risk over time against the thresholds, and possible benign causes.
- **Risk timeline:** smoothed score of every AP over capture time, with the baseline window
  shaded and alert / escalation markers, plus an event list.
- **AP table:** profile and current/peak risk for every AP.

During a replay or live capture, a background thread re-runs the risk engine every
2 s, and the page polls the API every 2 s. API: `/api/summary`, `/api/aps`,
`/api/alerts?detector=ghostap|baseline|all`, `/api/alerts/<id>`, `/api/timeline`,
`/api/events`. Plotly is served from the installed `plotly` package, so the dashboard
works offline. SSIDs come from the air and can be chosen by an attacker, so the front
end escapes every value it displays.

Each rescore re-analyses the whole database. That is fine for lab captures of a few
minutes, but would need incremental scoring for captures running for hours.

## Evaluation (Phase 6)

```bash
python tools/make_eval_set.py              # writes data/eval/<scenario>.pcap + .labels.json
python evaluate.py --dataset data/eval --out results
```

GhostAP and the duplicate-SSID baseline run on every labelled capture. The unit of
evaluation is one AP (SSID + BSSID) per capture. A detector flags an AP if it ever
alerts on it. The evaluator reports precision, recall, F1, false-positive rate
(FP / (FP + TN)) and detection latency (first alert − attack start). `results/` gets:

- `summary.md`: overall table, per-scenario table, threshold sweep, caveats
- `metrics.csv`, `per_scenario.csv`, `per_ap.csv`, `threshold_sweep.csv`
- `metrics_comparison.png`, `latency.png`, `threshold_sweep.png`, `risk_timelines.png`

Labels for `X.pcap` go in `X.labels.json` next to it:
`{"aps": {"<bssid>": {"label": "evil_twin", "attack_start": <epoch>}, "<bssid>": {"label": "legit"}}}`.
APs missing from the labels count as legit (`--unlabelled ignore` to skip them).
Extra captures can be added with `--pcap X --labels Y`.

Results on the **synthetic** set (5 attacks, 5 benign look-alikes; 39 APs in total):

| Detector | Precision | Recall | F1 | FPR | Latency mean / max |
|---|---|---|---|---|---|
| GhostAP | 1.00 | 0.80 | 0.89 | 0.00 | 17.5 s / 30 s |
| Baseline (duplicate SSID) | 0.17 | 1.00 | 0.29 | 0.74 | 0 s / 0 s |

GhostAP misses `s04_stealth_wpa2_twin`, a WPA2 twin with a spoofed vendor OUI on the
legit channel. Only its TSF gives it away, so its risk score of 20 stays under the
threshold of 30. The hardest benign case, a new same-vendor AP that has just
booted, scores 28. These synthetic numbers check the logic; the real results come
from rerunning on the Phase 2 lab captures.

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
