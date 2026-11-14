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
| 2 labelled **real** lab captures | **started 2026-11-14**: 3 live runs (data/lab_eval, gitignored), report `docs/testing/live-kali-validation.md`; more runs needed (5 GHz, longer, other twins) |
| 3 indicators (8) / 4 risk engine / 5 dashboard / 6 evaluation | done |
| 7 report + demo | drafted: `docs/REPORT.md`, `docs/REPORT.docx`, `docs/DEMO.md` |
| Feature expansion F001–F091 (phases A–J) | built; per-feature status in `docs/ROADMAP.md` (`done*` = needs hardware, credentials or Phase 2 data to confirm) |
| GhostAP 2.0 (`docs/PLAN_2.0.md`) | Phase 0 done; dashboard simplified; Live radar page; next: Phase 1 real captures, then Phase 2 Integrity |

User decisions for 2.0 (keep): **one sensor only** (TP-Link Archer T2U Plus, RTL8821AU, 2.4/5 GHz,
no 6 GHz: no multi-sensor lab tests or 6 GHz validation on own hardware); **PDF report last**, not now;
**no deadline**; the public **AWID3** dataset may be used for the ML phase. Not answered yet: team size
(two-person baseline approval?) and CI status. Commit locally, then ask before pushing.

Open items in the report (marked `_[…]_`, yellow in the .docx): team names / guide /
college, **Section 7.4 real-capture results**, and academic references (do not invent
citations; ask the user for theirs). REPORT.md is ahead of REPORT.docx (screenshot,
section 7.3, appendix B): regenerate the .docx only after checking `git diff docs/REPORT.docx`.

## Layout

```
ghostap/parser.py        frame -> observation dict (fingerprint + layout, rsn, freq); deauth events
ghostap/storage.py       SQLite; tables incl. events, layouts, annotations, audit, mutes, notify_*,
                         api_keys; migrations in Store._migrate()
ghostap/collector.py, hopper.py, capture.py   pcap / live capture, channel hopping, pause + hop control
ghostap/indicators.py    Baseline (+ saved baselines) + 8 indicators + Analyzer
ghostap/signatures.py    KARMA, look-alike names, attack-tool library (score floors, not weights)
ghostap/risk.py          score, smoothing, alerts, deauth/flood detectors, incidents, RiskEngine
ghostap/pipeline.py      replay / live ingest + IncrementalScorer; Pipeline.control (capture.py)
ghostap/config.py        defaults, validation, settings overlay data/settings.yaml (never edits config.yaml)
ghostap/sessions.py      data/sessions/<id>/ (session.db, meta.json, capture.pcap, labels.json); bundles
ghostap/monitored.py     saved baselines data/monitored.json
ghostap/web.py           create_app + main (HTTP: waitress, HTTPS: cheroot); ctx holds db/pipeline/session
ghostap/web_*.py         admin, monitored, ap, tools (what-if, notes), demo, integrations (notify,
                         metrics, keys, OpenAPI), auth (Gate: keys, viewer links, accounts, token),
                         lab (report, bundle, labels, evaluation runner), settings, ai, sensors
ghostap/auth.py, users.py, apikeys.py, tls.py    accounts/2FA/sessions, CLIs, certificates
ghostap/ownership.py     files made under sudo (live capture) go back to the SUDO_UID user
ghostap/notify.py, sensors.py, ai.py             notifications, multi-sensor + location, opt-in AI
ghostap/evaluate.py (+ evaluate_extended.py, stats.py, kismet.py, whatif.py)
ghostap/static/          index.html, app.js (core, window.GA), ux.js, present.js, i18n.js, login.*,
                         views/*.js (one page each, registered with GA.register)
tools/                   make_test_pcap, make_eval_set (11 scenarios), build_scenario, label_capture,
                         demo, sync_numbers, bench_large_site, screenshot_dashboard, kali_monitor.sh,
                         install_service.sh
deploy/, Dockerfile, docker-compose.yml          systemd unit, container (not built here)
tests/                   pytest (247 tests); CI: .github/workflows/tests.yml (Py 3.11-3.13: ruff,
                         pip-audit, tests, evaluation smoke test, sync_numbers check)
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
python evaluate.py --dataset data/lab --out results/lab [--unlabelled ignore] [--extended]
python tools/sync_numbers.py [--write]               # docs quote the numbers in results/?
python tools/build_scenario.py NAME --open --oui same   # custom synthetic scenario
python -m ghostap.users add NAME --role admin        # first account turns sign-in on (prompts)
python -m ghostap.apikeys create --name X --scope read
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
  Its clock-drift check (F007) measures each AP's TSF against the TSF of up to 15 other APs
  over the same span (`relative_clock_skew_ppm`), never against the sensor clock: a Kali VM's
  clock was slewed by ~250 ppm live. Saved baselines carry `bssid_skew_kind: relative`;
  older files' drifts are ignored.
- bssid_conflict's signal-track check (F006) uses only frames heard on or within two
  channels (2.4 GHz) of the AP's own channel (`_heard_on_channel`): a hopping sensor hears
  a strong AP faintly on far channels.
- Unit of evaluation = one (SSID, BSSID) per capture.

## Conventions

- Python 3.11+ (developed on 3.12; Kali ships 3.13). 3.10 was dropped because the
  Pillow release with current security fixes (13.0) no longer supports it.
- Everything shown in the dashboard that came from the air (SSIDs, reasons, notes) goes
  through `esc()` in app.js, including Plotly legend names. The triage endpoint accepts
  JSON only (this blocks cross-site form posts). Keep both.
- Static files are served with `max_age=0`. Keep it, or users see stale dashboards.
- Every POST must be JSON (send `{}` when there is nothing to send) and same-origin:
  `cross_site_block()` in web.py refuses `Sec-Fetch-Site: cross-site/same-site` and foreign
  `Origin`s (local mode trusts localhost, so this is the CSRF defence). Keep it.
- Database changes: add a `(version, function)` to `MIGRATIONS` in storage.py (never edit a
  released one) plus a test; `PRAGMA user_version` tracks it; newer databases are refused.
- Live detector memory is capped by `retention.memory_minutes` (prunes the Analyzer only;
  `tests/test_memory_bound.py` checks scores are identical). Indicators may only look at the
  scoring window, each AP's first `Analyzer.HEAD` frames and TSF resets.
- Sensor hardware: one TP-Link Archer T2U Plus (RTL8821AU, 2.4/5 GHz, no 6 GHz); see
  docs/HARDWARE.md. GhostAP 2.0 plan and phase status: docs/PLAN_2.0.md.
- Dashboard UI: simple by default (primary nav Dashboard, Live radar, Protected networks, Sessions,
  System; the rest under More; extra controls only in Advanced view via `.adv`). Live radar
  (views/radar.js, `GET /api/live`): distance = signal strength, angle is a stable hash of the SSID
  (direction is not measured with one antenna). Page headings must match their menu names.
- Web security (keep): Host-header check when bound to localhost (DNS rebinding); the Gate
  in web_auth.py (API keys, viewer links, accounts, start-up token; role rules in
  ADMIN_ONLY / allowed()); strict CSP (no inline scripts: all JS in static files);
  JSON-only POSTs; 64 KB request limit. New admin-only endpoints go into ADMIN_ONLY.
- Off by default and secrets only from environment variables: notifications, AI help
  (ai.redact hides names from the model), sensor reporting. Tests use fake receivers /
  a fake Claude client; nothing leaves the machine in tests.
- Evaluation default outputs (results/per_ap.csv, metrics.csv) must stay byte-identical
  when detection code changes unless results are meant to change; extras go behind
  `--extended`. Signatures are score floors so they cannot shift these numbers.
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
  author-designed**. Always say so. Real numbers come from Phase 2. The first live results
  (3 runs, 3 twins, one lab, one phone) are too few to generalise; say that with them.
- Don't tune the alert threshold (or weights) on the data used to report results. The
  sweep says 15 gives a higher F1 on the synthetic set; the configured 30 is kept deliberately.
- Keep the known limitation visible: s11 (twin that also copies the beacon structure) is missed.
- If results change, run `python tools/sync_numbers.py --write` (README, REPORT.md, DEMO.md,
  CLAUDE.md, figures; CI fails otherwise), then check the s01 breakdown and sweep text in
  REPORT.md by hand and the tools/demo.py banner.
  Current synthetic results: GhostAP P 1.00 / R 0.83 / F1 0.91 / FPR 0.00, latency mean 16 s;
  baseline P 0.18 / R 1.00 / F1 0.31 / FPR 0.73; s01 twin peak 77.4.

## Report files

`docs/REPORT.md` is the source text. `docs/REPORT.docx` was generated from it with a
docx-js script that is **not** in the repo. The user may edit the .docx directly. Check
`git diff docs/REPORT.docx` before regenerating it, and never overwrite their edits.
