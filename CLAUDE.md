# GhostAP: notes for Claude

College cybersecurity project: a **passive** Evil Twin Wi-Fi access-point detector.
It listens only to 802.11 beacon and probe-response frames, scores every AP against a
learned baseline, raises explainable alerts, and shows them on a Flask + Plotly
dashboard. The README has user-facing docs; this file is the working context.

## Hard rules

- **Passive only.** Never add packet injection, deauthentication, client-traffic capture
  or decryption. Monitor mode receives; GhostAP never transmits.
- Lab evil twins (phone hotspot / hostapd) run only on the user's own equipment and
  network. Never target real networks or users.
- **The user runs `sudo` commands themselves** in their own terminal: monitor mode
  (`tools/kali_monitor.sh`), and live capture (`sudo .venv/bin/python -m ghostap.web --iface …`).
  Do not run sudo or ask for the password. Read their output / errors and help from there.
- Never put credentials or tokens in the repo or in commands. Pushing uses the user's
  own git credentials.

## Status (phases)

| Phase | State |
|---|---|
| 1 collector + storage + synthetic data | done |
| 2 labelled **real** lab captures | **next: needs Kali + monitor-mode adapter** (see `docs/KALI_SETUP.md` §7–8) |
| 3 indicators (8) / 4 risk engine / 5 dashboard / 6 evaluation | done |
| 7 report + demo | drafted: `docs/REPORT.md`, `docs/REPORT.docx`, `docs/DEMO.md` |

Open items in the report (marked `_[…]_`, yellow in the .docx): team names / guide /
college, a dashboard screenshot (`docs/figures/dashboard.png`), **Section 7.4 real-capture
results**, and academic references (do not invent citations; ask the user for theirs).

## Layout

```
ghostap/parser.py       frame -> observation dict (incl. beacon fingerprint hash)
ghostap/storage.py      SQLite: observations, ap_profiles, alerts (+triage), risk_timeline, ap_latest;
                        migrations in Store._migrate()
ghostap/collector.py    CLI; collect_pcap / collect_live (--hop, --save-pcap)
ghostap/hopper.py       channel hopping via `iw`
ghostap/indicators.py   Baseline + 8 indicators + Analyzer (incremental add(), bisect windows)
ghostap/risk.py         weighted score, smoothing, levels, alerts, benign causes,
                        RiskEngine (resumable run()), duplicate-SSID baseline detector
ghostap/pipeline.py     background replay / live ingest + IncrementalScorer
ghostap/web.py          Flask API; ghostap/static/{index.html,style.css,app.js} dashboard
ghostap/evaluate.py     metrics, threshold sweep, charts (also ./evaluate.py)
tools/                  make_test_pcap.py, make_eval_set.py (11 scenarios), label_capture.py,
                        demo.py, kali_monitor.sh, make_architecture_figure.py
config.yaml             weights, thresholds, timing, known_bssids allow-list
tests/                  pytest (82 tests); CI: .github/workflows/tests.yml (Py 3.11, 3.12, 3.13:
                        ruff lint incl. security rules, pip-audit, tests, evaluation smoke test)
pyproject.toml          ruff + pytest config (lint: `ruff check .`)
```

## Commands

```bash
source .venv/bin/activate
pytest -q                                            # must stay green
python tools/demo.py --no-pause --no-dashboard       # whole pipeline on synthetic data
python tools/make_eval_set.py && python evaluate.py  # results/ (gitignored)
python -m ghostap.web --pcap data/test_capture.pcap --speed 10   # dashboard replay :8050
python -m ghostap.web --db data/live.db              # browse a recorded live session
python tools/label_capture.py data/lab/run1.pcap [--evil <bssid>] [--attack-start +SECONDS]
python evaluate.py --dataset data/lab --out results/lab [--unlabelled ignore]
```

`data/` and `results/` are gitignored. Captures and databases stay local.

## How the detector works (keep consistent)

- Baseline = first `baseline_minutes` (default 2) of a capture. An attack inside the
  baseline is learned as normal (label_capture.py warns about it).
- Indicators return value 0–1 + reason: security_downgrade, new_bssid_oui,
  channel_deviation, rssi_jump, tsf_anomaly, ie_fingerprint, bssid_conflict,
  beacon_interval_mismatch.
- R = Σwᵢxᵢ/Σwᵢ×100 (Σw = 15.5). Every 10 s, scored on the last 10 s of frames; the
  smoothed score is the mean of the last 3 raw scores. MEDIUM ≥ 30 (alert), HIGH ≥ 60.
- tsf_anomaly uses the AP's first frames and its full reset history, not the window.
- Unit of evaluation = one (SSID, BSSID) per capture.

## Conventions

- Python 3.11+ (developed on 3.12; Kali ships 3.13). 3.10 was dropped because the
  Pillow release with current security fixes (13.0) no longer supports it.
- Everything shown in the dashboard that came from the air (SSIDs, reasons, notes) goes
  through `esc()` in app.js, including Plotly legend names. The triage endpoint accepts
  JSON only (this blocks cross-site form posts). Keep both.
- Static files are served with `max_age=0`. Keep it, or users see stale dashboards.
- Web security (keep): Host-header check when bound to localhost (DNS rebinding), token
  login when bound elsewhere, strict CSP (no inline scripts: keep all JS in app.js),
  64 KB request limit, waitress server. See the docstring at the top of ghostap/web.py.
- `parse_frame()` rejects bad-FCS, truncated (caplen < wirelen) and malformed frames
  and counts them by reason. Never "repair" a damaged frame: it creates fake networks or
  makes WPA2 look open.
- AP profiles are maintained incrementally (`Store.update_profiles`); a test checks they
  equal a full `rebuild_profiles()`. The summary endpoint reads counts from ap_profiles.
- The dashboard refetches its heavy lists only when `/api/summary`'s `data_version`
  changes. Bump the pipeline's data_version if you add new state that the page shows.
- Schema changes need a migration in `Store._migrate()` plus a test with an old-schema DB.
- `RiskEngine` is incremental. A test checks that incremental scoring equals a one-shot
  run (`tests/test_live_and_incremental.py`). Keep it passing.
- Scenario generation uses byte templates. If `make_beacon()` changes, check that
  `_Template.frame()` output still equals `bytes(make_beacon(...))`.

## Honesty rules for results and the report

- The 11 evaluation scenarios **and the 4 beacon-structure profiles are synthetic and
  author-designed**. Always say so. Real numbers come from Phase 2.
- Don't tune the alert threshold (or weights) on the data used to report results. The
  sweep says 15 gives a higher F1 on the synthetic set; the configured 30 is kept deliberately.
- Keep the known limitation visible: s11 (twin that also copies the beacon structure) is missed.
- If results change, update every place that quotes them: README.md, docs/REPORT.md,
  docs/DEMO.md, tools/demo.py banner text, docs/figures/*.png (copy from results/).
  Current synthetic results: GhostAP P 1.00 / R 0.83 / F1 0.91 / FPR 0.00, latency mean 16 s;
  baseline P 0.18 / R 1.00 / F1 0.31 / FPR 0.73; s01 twin peak 77.4.

## Report files

`docs/REPORT.md` is the source text. `docs/REPORT.docx` was generated from it with a
docx-js script that is **not** in the repo. The user may edit the .docx directly. Check
`git diff docs/REPORT.docx` before regenerating it, and never overwrite their edits.
