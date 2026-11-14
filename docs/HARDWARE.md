# Hardware

Only hardware listed under **Tested** has been run with GhostAP. Everything else is what
public sources report and must be checked on your machine.

## Tested

| Adapter | Chipset / USB ID | Driver | Kernel / distribution | Bands verified | Date |
|---|---|---|---|---|---|
| TP-Link Archer T2U Plus | RTL8821AU, `2357:0120` | out-of-tree `88XXau` (`rtl88XXau`) | 6.8.11-arm64, Kali Rolling 2024.3, VMware VM with USB pass-through | **2.4 GHz only** (channels 1–13 hopping) | 2026-11-14 |

What worked live: monitor mode via `tools/kali_monitor.sh`, channel hopping with `iw`,
signal strength (dBm) on every frame, the tuned frequency in radiotap, FCS-flagged frames,
about 30 stored frames per second from about 45 networks, zero damaged frames rejected in
the last run. `iw` lists the 5 GHz channels 36–144, but **5 GHz capture was not tested**.
Details: [testing/live-kali-validation.md](testing/live-kali-validation.md).

Two effects of this setup that GhostAP now handles (both found in that test):
- **The VM's clock is adjusted** (systemd-timesyncd and VMware Tools time sync). Capture
  timestamps drift by up to about 250 ppm, so clock drift is measured between access
  points, not against the sensor's clock.
- **A strong nearby AP is also heard several channels away** while hopping (−8 dBm on its
  own channel, about −50 dBm seven channels off). Signal-level comparisons use only frames
  received on or next to the AP's own channel.

## Sensor: TP-Link Archer T2U Plus (AC600 High Gain, V1)

| Item | Value |
|---|---|
| Chipset | Realtek RTL8821AU (802.11ac, 1×1) |
| USB ID | `2357:0120` (as reported by `lsusb`) |
| Bands | 2.4 GHz and 5 GHz. **No 6 GHz**, so GhostAP's Wi-Fi 6E / Wi-Fi 7 checks cannot be validated with it |
| GhostAP needs | monitor mode (receive only) and channel changes; never injection |

**Drivers.** These come from public sources and have not been tested here:
- **Linux 6.14 or newer:** the in-kernel `rtw88` driver covers this chip family. The out-of-tree driver's
  author recommends it from that kernel on, and removing the out-of-tree driver first. Some
  distributions ship it disabled.
- **Older kernels:** the out-of-tree `8821au` driver (morrownr, and a fork listing the T2U Plus V1 with
  monitor mode) is the usual route.
- **Known problems:** users have reported monitor-mode problems with this adapter on some kernels. One
  report is a Raspberry Pi 5 showing no data in monitor mode; another is a DKMS build failure on 6.12-era
  kernels.

So check before relying on it.

## Checklist (run on the sensor, in your own terminal)

```bash
uname -r                                   # kernel version (6.14+ = in-kernel rtw88 should be used)
lsusb | grep -i 2357:0120                  # adapter present
sudo tools/kali_monitor.sh check           # interfaces, drivers, whether "monitor" is supported
sudo tools/kali_monitor.sh start wlan1 6   # monitor mode on channel 6 (use your interface name)
iw dev                                     # the interface should show "type monitor"
```

Then start GhostAP on it for a few minutes:

```bash
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11,36,40,44,48 --name hw-test
```

On the dashboard's **System** page, confirm three things:

- **Beacons last minute** is above zero and **Channels heard** lists both 2.4 GHz and 5 GHz channels.
- **Beacons heard per access point** shows your own AP; a low share there is normal while hopping.
- Access points show a **Signal** value. If every signal is empty, the driver does not report it, and the
  signal-jump indicator cannot work.

Record the result in **Tested** above. If monitor mode or 5 GHz fails, the out-of-tree
author's recommended alternatives for monitor mode include MT7921AU (also 6 GHz), MT7612U and
MT7610U.

Sources:
[morrownr/8821au-20210708](https://github.com/morrownr/8821au-20210708),
[rabidcopy/rtl8821au](https://github.com/rabidcopy/rtl8821au),
[AUR rtl88xxau-aircrack-dkms-git](https://aur.archlinux.org/packages/rtl88xxau-aircrack-dkms-git?O=10),
[morrownr/8821au issue 167](https://github.onedrive11.workers.dev/morrownr/8821au-20210708/issues/167) (checked 14 Nov 2026).
