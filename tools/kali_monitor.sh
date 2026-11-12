#!/usr/bin/env bash
# Put a Wi-Fi adapter into monitor mode for GhostAP, or give it back to the system.
#
#   sudo tools/kali_monitor.sh check            list adapters and whether they support monitor mode
#   sudo tools/kali_monitor.sh start wlan1      monitor mode on wlan1 (channel 6)
#   sudo tools/kali_monitor.sh start wlan1 11   ... parked on channel 11
#   sudo tools/kali_monitor.sh stop  wlan1      back to normal (managed) mode, NetworkManager restarted
#
# GhostAP only listens. Monitor mode receives frames; it does not transmit anything.
set -euo pipefail

die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[+] $*"; }

[[ $(uname -s) == Linux ]] || die "monitor mode needs Linux (Kali). macOS cannot do this with USB adapters."
[[ $EUID -eq 0 ]] || die "run with sudo:  sudo $0 $*"
command -v iw >/dev/null || die "'iw' is missing:  sudo apt install -y iw"

cmd=${1:-check}
iface=${2:-}
channel=${3:-6}

iface_type() { iw dev "$1" info 2>/dev/null | awk '/type/ {print $2}'; }

phy_of() {
    # phy name (e.g. phy0) for an interface
    local idx
    idx=$(iw dev "$1" info 2>/dev/null | awk '/wiphy/ {print $2}')
    [[ -n $idx ]] && echo "phy$idx"
}

case $cmd in
  check)
    info "wireless interfaces:"
    iw dev | awk '/Interface/ {i=$2} /type/ {print "    " i "  (" $2 ")"}'
    for p in $(iw dev | awk '/^phy#/ {sub("#",""); print}'); do
        if iw phy "$p" info | sed -n '/Supported interface modes/,/Band/p' | grep -q '\* monitor'; then
            echo "    $p: monitor mode SUPPORTED"
        else
            echo "    $p: monitor mode not listed (this adapter / driver cannot be used)"
        fi
    done
    if command -v airmon-ng >/dev/null; then
        echo; info "processes that may fight over the adapter (stop them with: start):"
        airmon-ng check || true
    fi
    ;;

  start)
    [[ -n $iface ]] || die "usage: sudo $0 start <iface> [channel]"
    iw dev "$iface" info >/dev/null 2>&1 || die "no interface '$iface' (see: sudo $0 check)"
    phy=$(phy_of "$iface")
    if ! iw phy "$phy" info | sed -n '/Supported interface modes/,/Band/p' | grep -q '\* monitor'; then
        die "$iface ($phy) does not support monitor mode. Use an adapter such as AR9271 / MT7612U / MT7921AU."
    fi
    if command -v airmon-ng >/dev/null; then
        info "stopping NetworkManager / wpa_supplicant so they do not switch the adapter back"
        airmon-ng check kill >/dev/null || true
    else
        systemctl stop NetworkManager wpa_supplicant 2>/dev/null || true
    fi
    ip link set "$iface" down
    iw dev "$iface" set type monitor
    ip link set "$iface" up
    iw dev "$iface" set channel "$channel" || echo "[!] could not set channel $channel (allowed in your country? try: sudo iw reg set IN)"
    [[ $(iface_type "$iface") == monitor ]] || die "$iface did not switch to monitor mode"
    info "$iface is in monitor mode on channel $channel"
    echo "    next:  sudo .venv/bin/python -m ghostap.web --iface $iface --hop 1,6,11"
    echo "    undo:  sudo $0 stop $iface   (gives you normal Wi-Fi back)"
    ;;

  stop)
    [[ -n $iface ]] || die "usage: sudo $0 stop <iface>"
    ip link set "$iface" down || true
    iw dev "$iface" set type managed || true
    ip link set "$iface" up || true
    systemctl start NetworkManager 2>/dev/null || service NetworkManager start 2>/dev/null || true
    info "$iface is back in managed mode; NetworkManager restarted (Wi-Fi may take a few seconds)"
    ;;

  *)
    die "unknown command '$cmd' (use: check | start <iface> [channel] | stop <iface>)"
    ;;
esac
