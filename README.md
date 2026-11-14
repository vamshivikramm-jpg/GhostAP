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
| 2 | Labelled lab dataset (real captures) | in progress: first live runs, see [docs/testing/live-kali-validation.md](docs/testing/live-kali-validation.md) |
| 3 | Indicators | ✅ done |
| 4 | Risk engine | ✅ done |
| 5 | Dashboard | ✅ done |
| 6 | Evaluation | ✅ done (synthetic set; rerun on Phase 2 captures) |
| 7 | Report & demo | ✅ draft: [docs/REPORT.md](docs/REPORT.md) (Word: docs/REPORT.docx), [docs/DEMO.md](docs/DEMO.md) |
| + | Feature expansion F001–F091 | ✅ built ([docs/ROADMAP.md](docs/ROADMAP.md)) |

## Beyond the core (features F001–F091)

All 91 features of the expansion catalogue are built; [docs/ROADMAP.md](docs/ROADMAP.md)
lists each one and marks those that still need real hardware, your credentials or Phase 2
captures to confirm (`done*`). Highlights:

| Area | What you get | Docs |
|---|---|---|
| Detection | KARMA/MANA, look-alike names, attack-tool fingerprints, detailed security downgrade, deauth floods, two transmitters on one address, clock skew, beacon rate, Wi-Fi 6/6E, hidden networks, per-network sensitivity, incidents | `config.yaml` |
| Saved baselines | Monitored networks page, baseline wizard, accept a change, new-network inbox, allow-list, network health | Monitored page |
| Dashboard | incident story, filters and bulk triage, mutes, history, beacon diff, vendors, signal/uptime charts, evidence pcap, related APs, what-if weights, notes, clock time, CSV export, layout, tour, glossary, command palette (Ctrl/⌘K), colour-blind and high-contrast modes, Hindi/Telugu drafts, shareable links, demo + presentation mode | [docs/ACCESSIBILITY.md](docs/ACCESSIBILITY.md), [docs/PERFORMANCE.md](docs/PERFORMANCE.md) |
| Sessions and lab | sessions, labelling page with suggestions, evaluation page (confidence intervals, ROC/PR, tune/test split, learned weights, anomaly model, Kismet), scenario builder, session report and bundles, number sync | `python evaluate.py --extended` |
| Hardware | the planned sensor adapter, a checklist to verify monitor mode, what is actually tested | [docs/HARDWARE.md](docs/HARDWARE.md) |
| Operations | notifications (webhooks, ntfy, Telegram, Slack, e-mail, syslog/CEF), Prometheus metrics, API keys, accounts with roles and two-factor sign-in, viewer links, HTTPS, systemd service, Docker, settings page, several sensors with rough location, capture control | [docs/API.md](docs/API.md), [docs/DEPLOY.md](docs/DEPLOY.md) |
| Opt-in AI | alert explainer and “Ask GhostAP” through the Claude API, off by default, names hidden from the model | `ai:` in `config.yaml` |

## Layout

```
ghostap/parser.py, storage.py, collector.py, hopper.py, capture.py   capture and storage
ghostap/indicators.py, signatures.py, risk.py, pipeline.py          detection and scoring
ghostap/monitored.py, sessions.py, config.py, logs.py              baselines, sessions, settings
ghostap/web*.py, auth.py, apikeys.py, users.py, tls.py              dashboard API, sign-in, HTTPS
ghostap/notify.py, sensors.py, ai.py, vendors.py, beacons.py         integrations
ghostap/evaluate.py, evaluate_extended.py, stats.py, kismet.py, whatif.py   evaluation
ghostap/static/                dashboard (app.js + views/*.js, no inline scripts)
tools/                         test data, scenarios, labelling, demo, benchmarks, screenshots,
                               number sync, monitor mode, service install
deploy/, Dockerfile            systemd unit and container
docs/                          report, demo runbook, roadmap, API, deployment, figures
tests/                         pytest suite
data/, results/                captures, databases, evaluation output (gitignored)
```

## Quick demo

```bash
python tools/demo.py          # step-by-step demo; ends with the live dashboard
```

The project report is in [docs/REPORT.md](docs/REPORT.md), and the presenter
runbook with likely questions is in [docs/DEMO.md](docs/DEMO.md).

## Setup

Requires Python 3.11+ (tested on 3.11, 3.12 and 3.13; on macOS: `brew install python@3.12`).

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
works offline. The page polls a small summary every 2 s and refetches the heavy lists
only when the server's data version changes. The **Export report** button on any AP
downloads a Markdown write-up (facts, comparison, indicators, triage) for notes or the
report.

**Security model.**
- **Inputs from the air are untrusted:** SSIDs, reasons and analyst notes are
  HTML-escaped everywhere they are displayed.
- **Strict headers:** a Content Security Policy (`script-src 'self'`), plus
  anti-framing and nosniff headers.
- **Default (127.0.0.1):** only requests addressed to localhost are answered, which
  blocks DNS-rebinding attacks from websites you visit.
- **`--host 0.0.0.0`:** token login is required. The link is printed at start-up, or
  set your own with `GHOSTAP_TOKEN`.
- **Triage endpoint:** accepts small JSON bodies only.
- **Server:** the dashboard runs on `waitress`, a production WSGI server.

**Damaged frames.** Frames the driver flags with a bad checksum, frames truncated by
the capture, and malformed frames are skipped and counted rather than guessed at. A
corrupted beacon can otherwise invent networks or make a WPA2 AP look open. The status
bar shows how many were skipped.

Scoring is incremental: each round reads only new frames and updates AP profiles in
place. An idle round, when nothing new arrived, does no work at all.

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

**Step-by-step guide for Kali Linux: [docs/KALI_SETUP.md](docs/KALI_SETUP.md)**. It covers
adapters, VMs, monitor mode, a lab evil twin, recording and labelling captures for
Phase 2, and troubleshooting. `sudo tools/kali_monitor.sh start wlan1` puts an adapter
into monitor mode, and `stop` gives it back.

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
