#!/usr/bin/env bash
# ghostap: start GhostAP and open the dashboard in the browser as soon as it answers.
#
#   ghostap                 live capture on wlan0 (monitor mode on, normal Wi-Fi back on Ctrl-C)
#   ghostap live wlan1      live capture on another adapter
#   ghostap demo            replay the bundled synthetic capture (no adapter, no root)
#   ghostap view            browse the latest recorded session
#   ghostap open            only open the dashboard (GhostAP already running)
#   ghostap stop            stop GhostAP and give the adapter back to normal Wi-Fi
#
# Install the shortcut once:  sudo ln -sf "$PWD/tools/ghostap.sh" /usr/local/bin/ghostap
# Port: GHOSTAP_PORT (default 8050). Channels for live capture: GHOSTAP_HOP (default 2.4 + 5 GHz).
# GhostAP only listens: monitor mode receives frames, nothing is transmitted.
set -euo pipefail

REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
PORT=${GHOSTAP_PORT:-8050}
URL="http://127.0.0.1:$PORT"
HOP=${GHOSTAP_HOP:-1-13,36,40,44,48,149,153,157,161}
PY="$REPO/.venv/bin/python"
cmd=${1:-live}
iface=${2:-wlan0}

die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[+] $*"; }

[[ -x $PY ]] || die "no virtual environment in $REPO/.venv (python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"

up() { curl -s -o /dev/null -m 2 "$URL/api/login/state"; }

open_browser() {
    # wait until the dashboard answers (max ~60 s), then open it in the desktop's default browser
    for _ in $(seq 1 120); do up && break; sleep 0.5; done
    up || { echo "[!] the dashboard did not start; see the messages above" >&2; return; }
    info "opening $URL"
    if [[ -n ${SUDO_USER:-} && $EUID -eq 0 ]]; then        # open it as the desktop user, not root
        sudo -u "$SUDO_USER" DISPLAY="${DISPLAY:-:0}" xdg-open "$URL" >/dev/null 2>&1 &
    else
        xdg-open "$URL" >/dev/null 2>&1 &
    fi
}

running_pids() { pgrep -f "ghostap.web .*--port $PORT" || true; }

case $cmd in
  open)
    up || die "GhostAP is not running on port $PORT (start it with: ghostap)"
    open_browser
    ;;

  stop)
    pids=$(running_pids)
    if [[ -n $pids ]]; then
        [[ $EUID -eq 0 ]] || exec sudo "$0" stop "$iface"
        kill -INT $pids 2>/dev/null || true
        for _ in $(seq 1 20); do running_pids | grep -q . || break; sleep 0.5; done
        info "GhostAP stopped"
    else
        info "GhostAP is not running on port $PORT"
    fi
    # never take the adapter away from another GhostAP capture that is still using it
    if pgrep -f "ghostap.web .*--iface $iface( |$)" >/dev/null; then
        info "another GhostAP capture is still using $iface; leaving it in monitor mode"
    elif command -v iw >/dev/null && [[ $(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}') == monitor ]]; then
        [[ $EUID -eq 0 ]] || exec sudo "$0" stop "$iface"
        "$REPO/tools/kali_monitor.sh" stop "$iface"
    fi
    ;;

  demo|view|live)
    if up; then
        info "GhostAP is already running on port $PORT"
        open_browser
        exit 0
    fi
    cd "$REPO"
    if [[ $cmd == demo ]]; then
        open_browser &
        exec "$PY" -m ghostap.web --pcap data/test_capture.pcap --speed 10 --port "$PORT"
    elif [[ $cmd == view ]]; then
        open_browser &
        exec "$PY" -m ghostap.web --port "$PORT"
    fi
    # live: needs root for monitor mode and capture (asks for your password once)
    [[ $EUID -eq 0 ]] || exec sudo -E "$0" live "$iface"
    if [[ $(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}') != monitor ]]; then
        "$REPO/tools/kali_monitor.sh" start "$iface" || die "could not put $iface into monitor mode"
        restore=1
    else
        restore=0
    fi
    # Ctrl-C stops GhostAP; normal Wi-Fi comes back if this script switched the adapter
    trap '[[ $restore -eq 1 ]] && "$REPO/tools/kali_monitor.sh" stop "$iface"' EXIT
    open_browser &
    info "live capture on $iface (channels $HOP); press Ctrl-C to stop"
    "$PY" -m ghostap.web --iface "$iface" --hop "$HOP" --port "$PORT" || true
    ;;

  -h|--help|help)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    ;;

  *)
    die "unknown command '$cmd' (use: ghostap [live [iface] | demo | view | open | stop])"
    ;;
esac
