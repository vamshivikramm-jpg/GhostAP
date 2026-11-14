# Live validation on Kali Linux (14 Nov 2026)

GhostAP was run against **real 802.11 traffic** from the project's sensor adapter, with a
controlled evil twin made from the owner's own phone hotspot. This file records what was
run, what was observed, the bugs the test exposed and how they were fixed.

Only the owner's router and phone were used as test devices. GhostAP only listened. Nothing
was transmitted, injected or connected to. Neighbouring networks appear in the captures
because their beacons are broadcast; they are not named here. Raw captures, session databases
and labels stay in the gitignored `data/` folder and are not part of the repository.

Live results below are **one lab, one phone, three twins**: enough to find bugs and to show
the detector works on real radio traffic, not enough to generalise accuracy. The synthetic
results in the README are a separate, author-designed set.

## 1. Environment

| Item | Value |
|---|---|
| OS | Kali GNU/Linux Rolling 2024.3, kernel 6.8.11-arm64, in a VMware VM (USB pass-through) |
| Python / key packages | 3.11.9; scapy 2.8.0, Flask 3.1.3, waitress 3.0.2, plotly 7.1.0 |
| Repository | `main`, starting at commit `9c98eb8`; working tree clean before the test |
| Privileges | GhostAP ran as **root** (the project lives in `/root`; owner's decision for this test) |
| Clock | systemd-timesyncd active **and** VMware Tools time sync enabled (both adjust the system clock) |

## 2. Hardware

| Item | Value |
|---|---|
| Adapter | TP-Link Archer T2U Plus, USB ID `2357:0120` |
| Chipset / driver | Realtek RTL8821AU, out-of-tree `88XXau` |
| Interface | `wlan0`, switched to monitor mode with `tools/kali_monitor.sh start wlan0` |
| Interface modes | managed, AP, monitor, IBSS, P2P |
| Channels offered | 2.4 GHz 1–14; 5 GHz 36–144 (regulatory domain `00`, world) |
| Channels used | run1: hop 1, 6, 11; run2 and run3: hop 1–13, 0.25 s each |
| Not tested | 5 GHz capture, 6 GHz (the adapter has none), a second sensor |

A first 8-second sniff on channel 6 heard 7 networks (plus 591 frames that were not beacons or probe responses),
with zero damaged frames, before GhostAP was started.

## 3. Method

1. Monitor mode on `wlan0`; `python -m ghostap.web --iface wlan0 --hop … --save-pcap data/lab/runN.pcap`.
2. Default 2-minute learning period. It was never shortened or extended.
3. **Test A:** the owner's router alone (WPA2/PSK, channel 2, about −29 dBm at the sensor).
4. **Test B:** owner's phone hotspot with **the same network name**, WPA2 with another password, 2.4 GHz.
5. **Test B2:** the same hotspot switched to **open** (no password).
6. **Test D:** hotspot switched off, then on again (rediscovery), then off.
7. **Test C** (second legitimate AP with the same name): **not tested**. The owner has none.
8. Recordings labelled with `tools/label_capture.py` and scored with `evaluate.py`
   (the same tools as Phase 2).

| Run | UTC | Duration | Code | Frames (beacon / probe resp.) | Radios | Twin |
|---|---|---|---|---|---|---|
| run1 | 07:53–08:21 | 27.7 min | before the fixes | 74,359 (67,927 / 6,432) | 52 | none |
| run2 | 08:21–08:42 | 21.4 min | clock fix only | 36,033 (31,564 / 4,469) | 48 | WPA2 hotspot |
| run3 | 08:43–09:13 | 30.5 min | all fixes | 58,238 (51,601 / 6,637) | 51 | WPA2, then open hotspot |

Rejected (damaged) frames: run1 one truncated frame; run2 and run3 none. Every frame had a
signal value, a channel from the beacon and the tuned frequency from radiotap.

## 4. Results of the controlled tests

| Test | Result | Details |
|---|---|---|
| A. Router alone | **PASS** | Baseline stored the BSSID, name, WPA2/PSK, channel 2, beacon fingerprint, interval 100 TU, average signal −29 dBm. Score **0.0** (it was 12.9 before the clock fix, see bug 1). No alert. |
| B. WPA2 twin (run2, old bssid_conflict code) | **PARTIAL** | MEDIUM alert **22 s** after the first frame, score 42–50. Three correct reasons, one wrong ("two transmitters share this address", bug 2). |
| B. WPA2 twin (run3, fixed) | **PASS** | MEDIUM alert **22 s** after the first frame, score 29.3–30.9. Reasons: new randomised BSSID (+12.9), different beacon structure (+16.1), slightly stronger (+0.7). `bssid_conflict` 0, "sequence numbers consistent". |
| B2. Open twin (run3) | **PASS** | MEDIUM alert at its **first scoring round** (11 s), score 55–59. security downgrade (+19.4), beacon structure (+16.1), new BSSID (+12.9), signal +13 dB (+6.7), channel 11 vs 2 (+6.5). Never HIGH (60). |
| C. Second legitimate AP | **NOT TESTED** | No second AP with the same name available. Covered only by synthetic scenario s08. |
| D. Twin switched off | **PASS** | Live score drops to 0 within one window; the peak and all frames are kept; the alert stays open (triage "new") for a person to review; the router's baseline is unchanged; deauthentication activity stopped. |
| D. Rediscovery | **PASS** | When switched on again the phone used a **new random BSSID**; it was alerted again within 22 s. Its beacon fingerprint was identical every time (`ede3…`), so the fingerprint recognises the device across address changes. |
| Router during all twin tests | **PASS** | Score 0.0–0.27, never alerted by GhostAP. |

Classification behaviour: a new same-name AP is never called a confirmed attacker. GhostAP
raises an explained MEDIUM alert; "confirmed" is only set by a person in triage. The naive
duplicate-name detector (shown on the dashboard only "for comparison") flagged the router
itself as HIGH 100 every time a twin appeared, which is why GhostAP does not rely on it.

### Labelled evaluation of the three recordings (fixed code)

`evaluate.py --dataset data/lab_eval`, neighbours labelled legit, unit = (SSID, BSSID) per capture:

| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Latency mean / max |
|---|---|---|---|---|---|---|---|---|---|
| GhostAP | 3 | 0 | 141 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 18.4 s / 22.2 s |
| Baseline (duplicate SSID) | 3 | 2 | 139 | 0 | 0.60 | 1.00 | 0.75 | 0.01 | 0 s |

Twin peak scores: 38.1 (run2 WPA2), 31.5 (run3 WPA2), 59.2 (run3 open). Legitimate APs:
mean peak 2.4, highest 16.0 (after the 2.1 channel-flip fix below; 2.7 / 19.4 before it). Same recordings with the code from before the fixes: the same
verdicts, but legitimate APs' mean peak was 8.5 (highest 23.6) and the WPA2 twins scored
50.0 and 36.5, partly from false evidence. The threshold sweep prefers 20 on these 3
captures; the configured 30 is kept (thresholds are not tuned on reporting data).

## 5. Indicators on live traffic

| Indicator | Evaluated live | Observed | Correct? |
|---|---|---|---|
| security_downgrade | yes | OPN twin vs WPA2 baseline → 1.0; WPA2 twin → 0 | **PASS** |
| new_bssid_oui | yes | randomised (locally administered) BSSIDs → 1.0 each time | **PASS** |
| channel_deviation | yes | twin on 11 vs baseline 2 → 1.0; same channel → 0 | **PASS** |
| rssi_jump | yes | twin 7–13 dB stronger → 0.07–0.69 | **PASS** (needs a weaker-twin case too) |
| tsf_anomaly (uptime / resets) | yes | one neighbour's real reboot (TSF reset) caught; the phone showed 2.8 days uptime, so no "freshly booted" | **PASS**; a phone twin is not caught by it |
| tsf_anomaly (clock drift, F007) | yes | **bug 1**, fixed; afterwards stable per-AP drifts within about 2 ppm across windows | **PASS after fix**; a cloned-BSSID twin not tested live |
| ie_fingerprint | yes | phone structure differs from the router's → 1.0; router unchanged → 0 | **PASS** |
| bssid_conflict | yes | **bug 2** (signal tracks), fixed; channel-flip rule fired on one neighbour, see finding 3 | **PARTIAL** |
| beacon_interval_mismatch | yes | 100 TU everywhere; no flood | **PASS** (no anomaly to see) |
| KARMA / MANA | data only | no radio used several names; not provoked | not validated live |
| look-alike names | yes | flags dual-band pairs like "X" / "X_5G" from one router (score floor 16, below the alert line) | **PARTIAL**, finding 4 |
| attack-tool library | no | the library is empty in live mode (0 entries) | not validated live |
| deauth / disassoc (F005) | yes | real bursts caused by the twin (reason 15 / 3); one benign neighbour burst (reason 8) | **PASS** with finding 5 |
| beacon flood | data only | no flood alerts in 80 min; channel hopping did not trigger it | not provoked |
| alert / session management | yes | alerts kept after the twin left; three sessions with pcaps; dashboard showed live data | **PASS** |

Indicators that cannot be triggered safely with ordinary traffic (KARMA, attack tools,
beacon floods, a cloned BSSID) should be validated with fixture-based or hostapd lab
tests on the owner's equipment, not by provoking them over the air.

## 6. Bugs found and fixed

**Bug 1: the clock-drift check blamed every network for the sensor's clock (F007).**
The drift was a straight-line fit of each AP's TSF against GhostAP's capture time, which is
the system clock. This VM's clock was slewed: every one of 19 busy APs "drifted" +250 ppm
during the learning period, about −110 ppm a few minutes later and 0 after that. The check
then reported "different hardware using this address?" on 18 of 22 networks
(+12.9 to +16 each, all the time). *Fix:* `relative_clock_skew_ppm` compares the AP's TSF with
the TSF of up to 15 other APs at the same capture moments. The sensor's clock error cancels,
and the median is robust against a twin among the references. On the real data, per-AP drift
became stable to about 2 ppm (raw: swings of 370 ppm). Saved baselines now mark
`bssid_skew_kind: relative`; older files' drifts are ignored. Needs 3 other APs; with fewer, no
drift verdict is given.

**Bug 2: off-channel reception reported as "two transmitters" (F006).** While hopping,
the phone hotspot on channel 2, next to the sensor, was heard at about −8 dBm while tuned
to channels 1–4 and about −48 dBm on channels 7–10. Its sequence numbers were continuous
(one device), but the two signal levels were reported as two transmitters sharing one address.
The router got the same false hit. *Fix:* `_heard_on_channel` keeps only frames received on
the AP's own channel or, on 2.4 GHz, within two channels of it (5 GHz: exact). Frames without
tuning information (synthetic data, old pcaps) are kept as before. This also restores detection
of a real clone while hopping 1–13, which the off-channel spread had been hiding (test added).

**Bug 3: the deauth alert did not say why the frames were sent.** The detector counted
reason codes but never showed them, and always said "often used to push clients onto an
evil twin". Live, a WPA2 twin caused bursts of reason 15 (4-way handshake timeout): the
owner's devices tried the router's saved password on the twin and failed. *Fix:* the alert
names the most common reason code; when most frames are login failures (15, 16, 23), the
first benign cause says so. Score and level are unchanged, so no alert is suppressed.

**Bug 4: no way to label a run without a twin.** KALI_SETUP §8 asks for false-positive runs,
but `label_capture.py` only wrote labels with `--evil`, and `evaluate.py` skips pcaps
without labels. *Fix:* `--no-twin` labels every AP legit.

**Earlier the same day:** files created by a `sudo` live run were owned by root, so the
non-root labelling step failed (`ghostap/ownership.py`, commit `9c98eb8`).

Each fix has regression tests that fail on the old code. The synthetic evaluation outputs
(`per_ap.csv`, `metrics.csv`, `per_scenario.csv`, `threshold_sweep.csv`) are byte-identical
before and after.

## 7. Findings not changed (recommendations)

1. **The WPA2 twin margin is thin.** A same-security, same-channel twin scores about 30–38.
   It is caught by its beacon structure and its new address only. An attacker that copies the
   beacon structure (synthetic scenario s11) and the security would be missed, as documented.
2. **Phone twins never look "freshly booted"**, unlike the synthetic twins. The synthetic s01
   peak of 77 comes partly from that; real phone twins peaked at 59. Treat the synthetic
   scores as optimistic for this attack.
3. **Channel-flip rule (bssid_conflict) on a neighbour:** probe responses from one radio carried
   channel 7/8 while its beacons said 4. The sequence numbers were continuous, so it was one
   device (most likely automatic channel selection or a stale channel field). **Fixed in 2.1:**
   channel flips whose sequence counter continues across every flip (forward step < 256) are one
   radio, not a clone (`_one_counter`); that neighbour's peak fell from 19.4 to 3.2.
4. **Look-alike names:** "X" and "X_5G" from one router (BSSIDs differing in the last digit)
   flag each other (floor 16). Exempting near-identical BSSIDs would also let an attacker evade
   the check, so it needs a design decision.
5. **Deauth threshold:** one benign burst of 11 "station is leaving" (reason 8) frames to a
   neighbour's AP raised a MEDIUM deauth alert. **Fixed in 2.1:** leave reasons (3, 8) count one
   third towards the burst thresholds (a flood of 200 faked-reason-3 frames still raises HIGH).
   Replayed over the live events: the twin's reason-15 alert remains; the benign reason-8 burst and
   the router's reason-3 departures (clients leaving it for the twin) no longer alert.
6. **Signal statistics include off-channel frames** (e.g. the router: average −29 dBm, minimum
   −84 dBm while hopping). rssi_jump still worked; using on-channel frames there too would
   make it more sensitive.
7. **Vendor names** were empty for most real BSSIDs (small built-in OUI list).
8. **No 5 GHz, no long run:** the longest run was 30 minutes; memory stayed at 113–128 MB.
   A multi-hour run and 5 GHz hopping are the next tests.

### Follow-up live check (release 2.1, same day)

75 s with `python -m ghostap.collector --iface wlan0 --hop 1,6,11,36,40,44,48,149,153,157,161`:
- **Persistent capture socket:** the kernel log gained **2** "promiscuous mode" lines for the
  whole run (one open, one close). Before the fix it gained about 2 per second (about 10,000
  over the first test).
- **5 GHz receive works:** 417 frames from 14 radios on 5 GHz (36–48, 149–157), 22 frames/s overall.
- **Driver quirk:** 0.5 % of frames carried the frequency of the *next* channel (first frame
  after a hop); harmless for detection, documented in HARDWARE.md.
- `tools/kali_monitor.sh stop` now restores Wi-Fi by itself (wpa_supplicant restarted).

## 8. Performance (measured live)

60-second sample in run3 (about 10 minutes in, about 40 networks, hotspot on):

| Measure | Value |
|---|---|
| CPU | 14.7 % of one core (ARM64 VM) |
| Memory | 113 MB resident (peak 113 MB); run1 was 128 MB after 12 min, 32k frames |
| Threads | 12 |
| Frames stored | 31.8 per second (1,968 in the last minute), 0 rejected |
| Scoring delay | newest score 0.9 s old, newest frame 0.0 s old |
| API response | 1–3 ms for `/api/summary`, `/api/aps`, `/api/alerts`, `/api/live` |
| Detection latency | 18.4 s mean, 22.2 s max (labelled evaluation) |
| Session database after 30 min | about 5 MB plus write-ahead log |
| Log | no tracebacks or exceptions across the three runs |

Database write latency was not measured separately. No SQLite locking errors, no
interruptions and no unhandled exceptions were seen. Longer runs are needed for memory-leak
conclusions.

## 9. Regression tests

`pytest -q`: 247 passed; `ruff check .` clean; the synthetic
evaluation is byte-identical; dashboard start-up, live collector start-up, pcap recording and
`evaluate.py` on the real recordings were all exercised during this test.

New tests: sensor clock slewing is not a clock change; a clone is still found while the sensor
clock slews; no drift verdict without enough reference APs; old saved-baseline drifts are
ignored; off-channel reception while hopping is not two transmitters; two real transmitters are
still found while hopping; the on-channel rule; deauth reason codes and the login-failure cause;
`label_capture.py --no-twin`.

## 10. Remaining limitations

- One lab, one phone, three twins, one sensor, 2.4 GHz only, runs of 21–31 minutes.
- Not tested live: a second legitimate AP with the same name (Test C), a cloned-BSSID twin, a
  twin that copies the beacon structure, KARMA, beacon floods, attack-tool fingerprints, 5 GHz.
- GhostAP ran as root for this test.
