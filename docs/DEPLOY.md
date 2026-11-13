# Running GhostAP permanently (F071, F073)

Two ways to keep GhostAP running on a Kali sensor: a **systemd service** (recommended on a
dedicated laptop or Raspberry Pi) or **Docker**. Both are passive: they only receive.

## systemd service

```bash
sudo tools/install_service.sh          # copies the project to /opt/ghostap, makes user "ghostap"
sudo nano /etc/ghostap/ghostap.env     # set GHOSTAP_IFACE to your monitor-capable adapter
sudo systemctl enable --now ghostap
sudo journalctl -u ghostap -f          # logs; with GHOSTAP_HOST=0.0.0.0 the access link is here
```

What the service does and does not get:

| | |
|---|---|
| User | `ghostap`, a system account without a shell or a home directory of its own |
| Capabilities | `CAP_NET_RAW` (receive frames) and `CAP_NET_ADMIN` (channel hopping) only |
| Root | only for the monitor-mode step before start and after stop (`tools/kali_monitor.sh`) |
| Files | read-only everywhere except `/opt/ghostap/data` (`ProtectSystem=strict`) |
| Other hardening | `NoNewPrivileges`, private /tmp and devices, kernel tunables / modules / logs protected, only UNIX, IP, packet and netlink sockets |

Note that `kali_monitor.sh start` stops NetworkManager so it cannot switch the adapter
back. Use a second adapter if the sensor also needs Wi-Fi for itself, or a cable.
`systemctl stop ghostap` gives the adapter back and restarts NetworkManager.

Secrets (the start-up token, SMTP password, ntfy URL) go into `/etc/ghostap/ghostap.env`
(root-only, mode 600), never into `config.yaml`.

Update: pull the new version into your own copy and run `sudo tools/install_service.sh`
again, then `sudo systemctl restart ghostap`. Remove: `sudo tools/install_service.sh --remove`
(your data in `/opt/ghostap/data` stays).

## Docker

Docker was not available on the machine this was written on. The files below are checked
by `tests/test_deploy.py` (structure, users, capabilities) but have **not been built or run**:
please report problems.

```bash
echo "GHOSTAP_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" > .env
docker compose up demo                       # synthetic demo replay: http://127.0.0.1:8050/?token=<token>
```

Live capture needs the host's Wi-Fi interface, so it uses host networking and runs as
root inside the container with only `NET_RAW` and `NET_ADMIN`:

```bash
sudo tools/kali_monitor.sh start wlan1       # on the host, first
GHOSTAP_IFACE=wlan1 docker compose --profile live up live
```

The image runs as user `ghostap` (uid 10001) for the demo, keeps its data in the
`ghostap-data` volume, has a read-only root file system and a health check
(`python -m ghostap.healthcheck`).

## Settings (F075)

Admins can change settings on the **Settings** page. They are validated like
`config.yaml` and saved to `data/settings.yaml` (config.yaml is never rewritten).
Retention, the log level and the metrics endpoint apply at once; everything that changes
how scores are computed applies after a restart, so a running session stays consistent.
