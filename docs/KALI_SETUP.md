# Running GhostAP on Kali Linux

This guide takes you from a fresh Kali install to GhostAP detecting a lab evil twin
live, then recording and evaluating real captures (Phase 2).

> **Legal and ethical:** GhostAP only *listens* to broadcast beacon frames. The lab evil
> twin in section 7, however, is something *you* run. Only do that with your own
> equipment, on a network you own or have written permission to test, and never with
> real users connecting to it.

---

## 0. What you need

| Item | Notes |
|---|---|
| Kali Linux | Installed on a laptop, a live USB with persistence, or a VM. Kali 2024 / 2025 releases work. |
| A USB Wi-Fi adapter that supports **monitor mode** | Built-in laptop Wi-Fi usually can't. See the table below. |
| A second device to act as the lab evil twin | A phone hotspot is enough. |
| Your own access point / router | The "real" network to protect. |

**Adapters that work out of the box on Kali** (drivers built into the kernel):

| Chipset | Example adapters | Bands |
|---|---|---|
| Atheros AR9271 | Alfa AWUS036NHA, TP-Link TL-WN722N **v1 only** | 2.4 GHz |
| MediaTek MT7612U | Alfa AWUS036ACM | 2.4 + 5 GHz |
| MediaTek MT7921AU | Alfa AWUS036AXML, Netgear A8000 | 2.4 + 5 + 6 GHz |
| MediaTek MT7610U | Alfa AWUS036ACHM | 2.4 + 5 GHz |

Realtek RTL8812AU adapters (e.g. Alfa AWUS036ACH) also work, but they need an extra
driver: `sudo apt install realtek-rtl88xxau-dkms`, then reboot. TP-Link TL-WN722N v2 and
v3 do **not** do monitor mode reliably.

### Running Kali in a virtual machine?

The VM needs the **USB adapter passed through** to it. A VM's own "network adapter" is
virtual and cannot do monitor mode.

- **VirtualBox:** install the Extension Pack. Then *Devices → USB* and tick the adapter
  (or add a USB filter so it attaches automatically).
- **VMware:** *VM → Removable Devices → (adapter) → Connect*.
- **UTM on an Apple Silicon Mac:** use the Kali ARM64 image, then the USB icon in the
  toolbar → select the adapter.

After passing it through, the adapter should appear in `lsusb` inside Kali.

---

## 1. Install system packages

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip iw aircrack-ng tcpdump
```

`iw` controls the adapter, `aircrack-ng` provides `airmon-ng` (used to stop services
that interfere), and `tcpdump` is for a quick sanity check. GhostAP itself only needs
Python.

## 2. Get GhostAP

```bash
cd ~
git clone https://github.com/vamshivikramm-jpg/GhostAP.git
cd GhostAP
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the repository is private, GitHub asks for your username and a **personal access
token** as the password: GitHub → Settings → Developer settings → Personal access tokens.

Check everything installed correctly. This needs no adapter:

```bash
pytest -q
```

All tests should pass (83 at the time of writing).

## 3. Quick check without any hardware

Run the synthetic demo first, so you know the software works before touching radios:

```bash
python tools/demo.py
```

It ends by opening the dashboard on a 10× replay at <http://127.0.0.1:8050>. Press
`Ctrl-C` to stop it.

---

## 4. Put the adapter into monitor mode

Plug in the adapter and find its name:

```bash
sudo tools/kali_monitor.sh check
```

You will see something like `wlan1 (managed)` and `phy1: monitor mode SUPPORTED`. The
built-in Wi-Fi is often `wlan0`, and the USB adapter `wlan1`. Use **the USB adapter's
name** everywhere below. This guide writes `wlan1`.

```bash
sudo tools/kali_monitor.sh start wlan1
```

This stops NetworkManager and wpa_supplicant, which would otherwise switch the adapter
back. It then sets monitor mode, parks the adapter on channel 6, and checks that it worked.

> NetworkManager is stopped, so **normal Wi-Fi on this machine is off** until you run
> `sudo tools/kali_monitor.sh stop wlan1`. Use Ethernet or the built-in card if you need
> internet at the same time (start it again with `sudo systemctl start NetworkManager`
> after switching, and leave the USB adapter alone).

<details>
<summary>Doing it by hand instead (same result)</summary>

```bash
sudo airmon-ng check kill
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel 6
iw dev wlan1 info          # must show "type monitor"
```

`sudo airmon-ng start wlan1` also works, but it may rename the interface to `wlan1mon`.
In that case, use `wlan1mon` in the GhostAP commands.
</details>

**Sanity check: can you hear beacons?**

```bash
sudo tcpdump -i wlan1 -c 5 -e 'type mgt subtype beacon'
```

Five lines naming nearby networks means monitor mode works. If nothing appears within a
few seconds, see Troubleshooting.

**5 GHz:** set your country, so the adapter is allowed on 5 GHz channels (India shown):

```bash
sudo iw reg set IN
```

---

## 5. Run GhostAP live

```bash
cd ~/GhostAP
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11 --save-pcap data/live1.pcap
```

Then open <http://127.0.0.1:8050> in Firefox on the Kali machine.

- **Always use `sudo .venv/bin/python`.** Plain `sudo python` uses the system Python,
  which doesn't have GhostAP's packages.
- **`--hop 1,6,11`** cycles through the three main 2.4 GHz channels. Without it, GhostAP
  only hears the channel the adapter is parked on, and a twin on another channel is
  invisible. Other options: `--hop 2.4` (channels 1–13), `--hop 1,6,11,36,40,44,48`
  (adds 5 GHz), `--hop all`. Channels the adapter rejects are dropped automatically, and
  the status bar shows what it is hopping.
- **`--save-pcap`** records every beacon. You need these recordings for Phase 2.
- **The first 2 minutes are the learning period.** Don't switch on the twin yet. To learn
  for longer, set `baseline_minutes: 5` in `config.yaml`, which is better for real
  environments where signal strength varies.
- Stop with `Ctrl-C`. The data stays in `data/live.db`, and you can browse it again later
  without the adapter: `python -m ghostap.web --db data/live.db`.

**Opening the dashboard from another computer** (e.g. the host, when Kali runs in a VM):

```bash
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11 --host 0.0.0.0
```

Because the dashboard is now reachable from the network, GhostAP switches on **token
login**. It prints a private link like `http://<this-machine-ip>:8050/?token=…`. Replace
the placeholder with Kali's IP (`ip -4 addr` shows it) and open the link on the host.
Opening it sets a login cookie and removes the token from the address bar. Without the
link you only get a "sign-in needed" page. To set your own token instead of a random one:
`sudo GHOSTAP_TOKEN=some-long-secret .venv/bin/python -m ghostap.web …`. Keep the link
private, and use this only on a private or lab network.

**Without the dashboard** (collector only, prints a table at the end):

```bash
sudo .venv/bin/python -m ghostap.collector --iface wlan1 --hop 1,6,11 --duration 300 --save-pcap data/run1.pcap
```

---

## 6. Tell GhostAP which access points are yours (optional)

Edit `config.yaml` and list your real access points' BSSIDs, in lower case:

```yaml
known_bssids:
  - a4:2b:b0:11:22:33
  - a4:2b:b0:11:22:99
```

An allow-listed AP that switches on *after* the learning period is then not flagged as
new. A device cloning one of these addresses is still detected (security downgrade,
fingerprint, TSF and cloning checks still apply). Your router's BSSID is shown in the
dashboard's AP table, or by `iw dev wlan0 link` on a laptop connected to it.

---

## 7. Create a lab evil twin to test against

Start GhostAP first and wait until the banner says the learning period is over. Then turn
on one of these.

**Option A: phone hotspot (simplest).** Rename your phone's hotspot to exactly your lab
router's network name (same capitalisation) and set it to **no password**. Expected on
the dashboard within about 30 s:
- security downgrade (open vs. WPA2);
- new radio from another vendor;
- freshly booted;
- a different beacon fingerprint;
- probably a stronger signal.

**Option B: a second adapter running hostapd** (closer to a real attack tool). The
following broadcasts an open network called `MyLabWiFi` on channel 11. It hands out no
addresses and forwards no traffic, so it is just beacons.

```bash
sudo apt install -y hostapd
cat > /tmp/twin.conf <<'EOF'
interface=wlan2
driver=nl80211
ssid=MyLabWiFi
hw_mode=g
channel=11
EOF
sudo hostapd /tmp/twin.conf      # Ctrl-C to switch the twin off
```

Use your lab router's SSID in `ssid=`, and a **different** adapter (`wlan2`) from the
one GhostAP listens on. Write down when you switched it on: `date +%s`.

---

## 8. Phase 2: record, label and evaluate real captures

1. **Record.** Run section 5 with `--save-pcap data/lab/run1.pcap`. Leave at least
   2–3 clean minutes, then switch the twin on (section 7) for a few minutes. Repeat with
   variations: twin on another channel, twin with a password, a run with no twin at all
   (this measures false positives), a reboot of your real router, and so on.
2. **Find the twin's BSSID:**
   ```bash
   python tools/label_capture.py data/lab/run1.pcap
   ```
3. **Write the labels file** (`data/lab/run1.labels.json`):
   ```bash
   python tools/label_capture.py data/lab/run1.pcap --evil <twin-bssid>
   ```
   If the twin **cloned** your router's BSSID, give the start time explicitly:
   `--attack-start +180` (seconds into the capture) or `--attack-start <epoch>`.
4. **Evaluate everything in the folder:**
   ```bash
   python evaluate.py --dataset data/lab --out results/lab
   ```
   This produces `results/lab/summary.md` and the charts. Put them in Section 7.4 of
   the report.

Neighbours' networks that appear in your captures are labelled `legit` automatically. If
you don't want them in the numbers, add `--unlabelled ignore` to `evaluate.py` and only
label your own APs. Remove the BSSIDs you don't want counted from the labels file.

---

## 9. Give the adapter back

```bash
sudo tools/kali_monitor.sh stop wlan1
```

This returns the adapter to normal (managed) mode and restarts NetworkManager.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Operation not permitted` / dashboard banner says *needs root* | Run with `sudo .venv/bin/python …` |
| `No such device` | Wrong interface name. Run `sudo tools/kali_monitor.sh check`; after `airmon-ng start` it may be `wlan1mon` |
| `ModuleNotFoundError: scapy` with sudo | You used `sudo python`. Use `sudo .venv/bin/python` |
| `kali_monitor.sh` says monitor mode is not supported | That adapter / driver can't do it (common with built-in cards and TL-WN722N v2/v3). Use one from the table in section 0 |
| Monitor mode set, but 0 frames | NetworkManager switched it back: re-run `start`. Also check `iw dev wlan1 info` shows `type monitor`, and that you're near an AP on the channels you hop |
| Status bar says *skipped N damaged frames* | Normal on a real radio. Frames that fail their checksum, are truncated or malformed are dropped, so they can't create fake networks or false alarms. A very high number means a weak signal or a busy channel: move closer or check the antenna |
| Browser shows *GhostAP only answers requests addressed to localhost* | You opened it via a hostname or IP while GhostAP listens on 127.0.0.1. Use `http://127.0.0.1:8050`, or start it with `--host 0.0.0.0` (token login) |
| Frames arrive, but your network never appears | It is on a channel you aren't hopping (5 GHz?). Use `--hop all` and `sudo iw reg set <country>` |
| `Device or resource busy` | Another process is using the adapter: `sudo airmon-ng check kill` |
| Status bar: *hopping stopped: needs the 'iw' tool* | `sudo apt install -y iw` |
| Status bar: *unsupported: 36,40…* | The adapter is 2.4 GHz only, or 5 GHz is not allowed in the current regulatory domain. Harmless; those channels are skipped |
| The twin is never flagged | It was switched on during the 2-minute learning period, so it was learned as normal. Restart GhostAP and switch the twin on afterwards. Also check it uses *exactly* the same SSID |
| Everything is flagged MEDIUM | The learning period was too short for a busy place. Set `baseline_minutes: 5` in `config.yaml` |
| No internet after testing | `sudo tools/kali_monitor.sh stop wlan1` (or `sudo systemctl start NetworkManager`) |
| `git clone` asks for a password | Use a GitHub personal access token, not your GitHub password |
| VM: no `wlan1` at all | The USB adapter isn't passed through to the VM (see section 0). Check with `lsusb` |

## Command cheat-sheet

```bash
sudo tools/kali_monitor.sh check                     # which adapter, supports monitor mode?
sudo tools/kali_monitor.sh start wlan1               # monitor mode
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11 --save-pcap data/lab/run1.pcap
python tools/label_capture.py data/lab/run1.pcap --evil <twin-bssid>
python evaluate.py --dataset data/lab --out results/lab
sudo tools/kali_monitor.sh stop wlan1                # normal Wi-Fi back
```
