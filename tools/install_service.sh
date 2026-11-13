#!/usr/bin/env bash
# Install GhostAP as a systemd service on Kali / Debian (F071). You run this yourself:
#
#   sudo tools/install_service.sh            # install or update
#   sudo tools/install_service.sh --remove   # stop and remove the service (keeps /opt/ghostap/data)
#
# What it does: creates a system user "ghostap", copies this project to /opt/ghostap,
# builds its virtual environment, writes /etc/ghostap/ghostap.env (if missing) and
# installs deploy/ghostap.service. It does not start anything: it prints the commands.
set -euo pipefail
die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[+] $*"; }

[[ $(uname -s) == Linux ]] || die "systemd services need Linux"
[[ $EUID -eq 0 ]] || die "run with sudo: sudo $0 $*"
command -v systemctl >/dev/null || die "systemctl not found (not a systemd system?)"
SRC=$(cd "$(dirname "$0")/.." && pwd)
DEST=/opt/ghostap

if [[ ${1:-} == --remove ]]; then
    systemctl disable --now ghostap.service 2>/dev/null || true
    rm -f /etc/systemd/system/ghostap.service
    systemctl daemon-reload
    info "service removed; data kept in $DEST/data (delete it yourself if you want)"
    exit 0
fi

command -v python3 >/dev/null || die "python3 missing: apt install -y python3 python3-venv"
id ghostap >/dev/null 2>&1 || { useradd --system --home "$DEST" --shell /usr/sbin/nologin ghostap; info "created user ghostap"; }

mkdir -p "$DEST"
# copy the code (not your data, results or virtual environment)
tar -C "$SRC" --exclude=./data --exclude=./results --exclude=./.venv --exclude=./.git -cf - . | tar -C "$DEST" -xf -
mkdir -p "$DEST/data"
[[ -d $DEST/.venv ]] || python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --quiet --upgrade pip
"$DEST/.venv/bin/pip" install --quiet -r "$DEST/requirements.txt"
chown -R root:root "$DEST"
chown -R ghostap:ghostap "$DEST/data"
chmod 750 "$DEST/data"
chmod 755 "$DEST/tools/kali_monitor.sh"

install -d -m 750 /etc/ghostap
if [[ ! -f /etc/ghostap/ghostap.env ]]; then
    install -m 600 "$SRC/deploy/ghostap.env.example" /etc/ghostap/ghostap.env
    info "wrote /etc/ghostap/ghostap.env: set GHOSTAP_IFACE to your monitor-capable adapter"
fi
install -m 644 "$SRC/deploy/ghostap.service" /etc/systemd/system/ghostap.service
systemctl daemon-reload
info "installed. Next (check /etc/ghostap/ghostap.env first):"
echo "      sudo systemctl enable --now ghostap"
echo "      sudo journalctl -u ghostap -f          # logs, including the access link"
echo "      sudo systemctl stop ghostap            # gives the adapter back to NetworkManager"
