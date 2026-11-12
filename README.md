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
| 7 | Report & demo | ✅ draft: [docs/REPORT.md](docs/REPORT.md) (Word: docs/REPORT.docx), [docs/DEMO.md](docs/DEMO.md) |

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
tools/make_eval_set.py  11 labelled synthetic scenarios for evaluation
tools/label_capture.py  list APs in a real capture and write its labels file (Phase 2)
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
like). Every AP then gets eight indicator values in [0, 1], each with a reason:

| Short | Indicator | Fires when |
|-------|-----------|------------|
| SEC | `security_downgrade` | weaker security than the SSID's baseline (WPA2 → WPA 0.5, → WEP/open 1.0) |
| OUI | `new_bssid_oui` | BSSID not in baseline: same vendor 0.3, different vendor or random MAC 1.0 |
| CH | `channel_deviation` | new BSSID on a channel the SSID never used 1.0; known BSSID changed channel 0.5 |
| RSSI | `rssi_jump` | signal more than 6 dB above baseline, reaching 1.0 at 16 dB above |
| TSF | `tsf_anomaly` | TSF counter reset, or uptime far below sibling APs (log-scale ratio) |
| FP | `ie_fingerprint` | beacon structure (element order, rates, capabilities, vendor elements) unlike any baseline AP of the SSID 1.0; known BSSID whose structure changed 0.6 |
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
HIGH 30 s after it appears, with a peak score of 77. The baseline detector flags all
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

- **Verdict banner:** one plain-language sentence, e.g. "Evil twin suspected on MVSR_WiFi"
  with the main reasons, "All clear", or "Learning what normal looks like" with a progress bar.
- **Tiles:** networks, access points, HIGH / MEDIUM alerts, and how many alarms a name-only
  check would raise. Click a tile to jump to that list.
- **Alerts / Networks / Name-only tabs:** alerts ranked by risk; every network with its
  access points underneath (a twin shows up as an extra entry with a red risk bar); and
  the duplicate-name detector's flags, marked "GhostAP agrees" or "GhostAP: normal".
- **Access point detail:** opens for *any* AP, not just alerting ones.
  - a verdict, a 0–100 risk gauge, and the top reasons;
  - a **side-by-side comparison** with the network's known APs (vendor, channel, security,
    signal, uptime, beacon fingerprint, interval), marking every difference with ≠;
  - expandable explanations of all eight indicators, with value × weight = points;
  - the AP's raw and smoothed risk over time.
- **Triage:** mark an alert New / Investigating / Confirmed attack / False positive with a
  note, saved on the server. A checklist tracks which innocent explanations you have ruled
  out.
- **Risk timeline:** click a line to inspect that AP, switch Smoothed / Raw, show only
  suspicious APs, drag to zoom. Events can be filtered and clicked.
- **AP table:** searchable (`/`) and sortable by any column.
- **Also:** notifications for new or escalated alerts, light / dark toggle, a "How it
  works" guide (`?`), links to a selected AP (`#ap=…`), and `j` / `k` to step through the
  list.

During a replay or live capture, a background thread re-runs the risk engine every
2 s, and the page polls the API every 2 s. API: `/api/summary`, `/api/aps`, `/api/networks`,
`/api/ap?ssid=…&bssid=…`, `POST /api/alerts/<id>/triage` (JSON only),
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

Results on the **synthetic** set (6 attacks, 5 benign look-alikes; 43 APs in total):

| Detector | Precision | Recall | F1 | FPR | Latency mean / max |
|---|---|---|---|---|---|
| GhostAP | 1.00 | 0.83 | 0.91 | 0.00 | 16 s / 20 s |
| Baseline (duplicate SSID) | 0.18 | 1.00 | 0.31 | 0.73 | 0 s / 0 s |

The beacon fingerprint catches `s04_stealth_wpa2_twin` (score 32.9), a WPA2 twin with
a spoofed vendor OUI on the legit channel running from a phone hotspot. The hardest
benign case, a new same-vendor AP that has just booted, stays at 23.2. GhostAP misses
`s11_fingerprint_clone_twin` (16.8), an adaptive twin that also copies the real AP's
beacon structure, so only its TSF differs. The beacon profiles in this set were designed
by us, so these synthetic numbers check the logic; the real results come from rerunning
on the Phase 2 lab captures.

## Run live (Linux only)

Requires root, `iw`, and a Wi-Fi adapter that supports monitor mode.

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
sudo .venv/bin/python -m ghostap.collector --iface wlan0 --duration 120
```

Options: `--duration` (seconds, default 60, live only), `--db` (default
`data/ghostap.db`), `--reset`.

Live options (collector and dashboard):

- `--hop 1,6,11`: hop channels (`1-13`, `2.4`, `5`, `all` also work); `--dwell 0.25` sets
  the seconds spent on each channel. Without hopping you only hear one channel, and a
  twin on another channel is invisible.
- `--save-pcap lab1.pcap`: record the beacons and probe responses, so the session can be
  labelled and evaluated later.

```bash
sudo .venv/bin/python -m ghostap.web --iface wlan0 --hop 1,6,11 --save-pcap data/lab1.pcap
python tools/label_capture.py data/lab1.pcap                       # list APs, find your twin
python tools/label_capture.py data/lab1.pcap --evil <twin-bssid>   # writes lab1.labels.json
python evaluate.py --dataset data                                  # metrics on real captures
```

`config.yaml` → `known_bssids` is an allow-list of your own APs. An allow-listed AP that
appears later is not flagged as new, but cloning it is still detected. Scoring is
incremental, so a 20-minute capture rescores in about 0.7 s instead of 70 s.

## macOS note

macOS cannot put USB Wi-Fi adapters into monitor mode for this kind of capture, so on
a Mac use offline mode (`--pcap`) with the synthetic capture or pcaps recorded on Linux.
