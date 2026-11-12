# GhostAP demo runbook

A 7–8 minute live demo, plus backups and likely questions. Everything runs on synthetic
data, so it works on a laptop with no Wi-Fi adapter and no internet.

## Before you present (10 minutes before)

```bash
cd GhostAP && source .venv/bin/activate
pytest -q                               # expect: 62 passed
python tools/demo.py --no-pause --no-dashboard   # warms caches, regenerates results/
```

- Close anything using port 8050, or add `--port 8051` to the demo command.
- Open `results/summary.md` and the four PNGs in `results/` in separate tabs, as a backup.
- Increase the terminal font size; use a light theme if the projector is dim.

## The demo

Start it with:

```bash
python tools/demo.py
```

It pauses after each step; press Enter to continue.

| Time | Step | What to show | What to say |
|---|---|---|---|
| 0:00 | Intro | – | "Evil twins copy a Wi-Fi network's name. Big networks legitimately have many APs with the same name, so 'duplicate name' alone is useless. GhostAP looks at *how* an AP differs, passively, from beacons only." |
| 0:45 | 1 Generate | 4 APs, twin appears at t=180 s | "Two real MVSR_WiFi APs, one café hotspot, and an open twin of MVSR_WiFi from another vendor, booted a millisecond ago." |
| 1:15 | 2 Collect | profile table | "Only beacons and probe responses: no traffic, no injection. The twin is the only OPN entry for MVSR_WiFi, on channel 11, at −38 dBm." |
| 2:00 | 3 Indicators | indicator matrix + reasons | Point at the twin's row of 1.00s, then at the second real AP (`…22:99`), which stays at about 0 even though it has the same name. "That's the false alarm the baseline would raise." |
| 3:00 | 4 Risk | alert + contributions + benign causes | "Weighted score of 77: the downgrade gives 19 points, the beacon fingerprint 16 (it's built by different software than the real APs), the unknown vendor 13, the fresh TSF 13, the signal 10, the channel 6. Each alert also lists innocent explanations to rule out." Then: "The baseline flagged all three MVSR APs; two are false alarms." |
| 4:00 | 5 Evaluation | metrics table | "Eleven scenarios: six attacks, five benign look-alikes. GhostAP: precision 1.0, F1 0.91, zero false alarms. Baseline: precision 0.18, 73% false-alarm rate. The beacon fingerprint even catches a twin that knows the WPA2 password and copies the vendor and channel. We miss one: an attacker who also copies the beacon structure." |
| 5:00 | 6 Dashboard | browser opens | "This replays the same capture at 10× speed. For the first 12 s it's learning the baseline…" |
| 5:30 | | alert appears (~t+200 s) | "…the twin is flagged MEDIUM at t+200 s, 20 s after it appeared, and HIGH 10 s later. The delay is deliberate: we average 3 scoring steps so one odd frame can't trigger an alarm." |
| 6:15 | | click the alert | Walk through the bar chart of contributions and the reasons table. "Every number on the screen can be traced back to a field in a beacon." |
| 6:45 | | Baseline tab | "Same capture, baseline detector: three alerts, two of them on legitimate APs." |
| 7:15 | Close | `docs/figures/risk_timelines.png` | "Blue lines cross the threshold, grey ones don't, except the stealth WPA2 twin, which is our honest limitation." |

## If something goes wrong

| Problem | Fix |
|---|---|
| Port 8050 in use | `python tools/demo.py --port 8051` |
| Browser doesn't open | open <http://127.0.0.1:8050> by hand |
| Replay finished before you got there | refresh: the finished state still shows all alerts; or restart with `--speed 5` |
| Dashboard won't start at all | show `results/*.png` and `results/summary.md` |
| Asked for a live capture | macOS can't do monitor mode with USB adapters; live capture needs Linux. Show the clear error: `python -m ghostap.collector --iface en0` |

## Live capture (only if you have the Linux laptop and adapter)

```bash
sudo ip link set wlan0 down && sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
sudo .venv/bin/python -m ghostap.web --iface wlan0
```

Wait two minutes for the baseline, then switch on your own lab twin (same SSID, open,
on equipment you own). Never demo against networks you don't control.

## Likely questions

**Why not just flag duplicate SSIDs?**
Every enterprise network has them. In our evaluation that approach flagged 74% of
legitimate APs.

**Isn't this just a blacklist / allow-list?**
No. Nothing has to be configured in advance. GhostAP learns each network's normal
state from the first minutes, then scores deviations from it.

**How did you pick the weights?**
By judgement: how hard each signal is to explain innocently. They're in `config.yaml`.
Learning them from labelled real captures is future work. We did *not* tune the
threshold on the evaluation data: the sweep shows 20 would score higher, but that would
be fitting to the test set.

**What's TSF and why does it matter?**
A 64-bit microsecond counter in every beacon that starts at zero when the AP boots. A
twin is usually started just before the attack, so its uptime is seconds while the real
APs have been up for hours or days. Reboots also reset it, which is why that indicator
alone can't trigger an alert.

**Can an attacker evade it?**
Yes, partly. With the real password, a copied vendor prefix, the same channel and
modest transmit power, the beacon fingerprint still catches it if it runs on different hardware (s04). If it also copies the beacon structure, only the TSF differs and our s11 scenario is missed. A careful
attacker could even let the twin run for days first. Fingerprinting beacon contents
(information-element order, capabilities) is the next step.

**Why is detection 10–30 s and not instant?**
By design: 10 s scoring steps averaged over 3. Faster settings are possible in
`config.yaml`, but they let single glitches raise alarms.

**Is it legal / ethical?**
It only receives broadcast management frames that every phone already receives when it
scans for networks. It never transmits or decrypts anything. We only run attacks on our
own equipment.

**Are the results real?**
The evaluation in this demo uses synthetic captures we generated, which tests the
logic. The lab captures (Phase 2) give the real-world numbers. The evaluation command
is the same: `python evaluate.py --dataset <dir>`.
