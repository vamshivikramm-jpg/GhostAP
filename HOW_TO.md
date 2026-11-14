# How To — Control GhostAP from the Terminal

Every terminal command for running and managing GhostAP, grouped by task.
Run all commands from the project folder unless noted:

```bash
cd ~/projects/GhostAP
```

> GhostAP only **listens**. Use it only on networks you own or have written permission to monitor.

---

## 1. First-time setup

```bash
python3 -m venv .venv                      # create the virtual environment
source .venv/bin/activate                  # activate it (do this in every new terminal)
pip install -r requirements.txt            # install dependencies
pip install -r requirements-ai.txt         # optional: the opt-in AI features
deactivate                                 # leave the virtual environment
```

Install the one-word `ghostap` shortcut (once):

```bash
sudo ln -sf "$PWD/tools/ghostap.sh" /usr/local/bin/ghostap
```

---

## 2. Quick control with `ghostap` (easiest)

| Command | What it does |
|---|---|
| `ghostap` | Live capture on `wlan0`. Turns on monitor mode and opens the browser. **Ctrl-C** stops it and gives Wi-Fi back |
| `ghostap live wlan1` | Live capture on another adapter |
| `ghostap demo` | Synthetic demo replay (no adapter, no root needed) |
| `ghostap view` | Browse the latest recorded session |
| `ghostap open` | Open the dashboard of a GhostAP that is already running |
| `ghostap stop` | Stop GhostAP and return the adapter to normal Wi-Fi |
| `ghostap stop wlan1` | Same, for another adapter |
| `ghostap help` | Show the built-in help |

Environment variables:

```bash
GHOSTAP_PORT=9000 ghostap demo             # use another port (default 8050)
GHOSTAP_HOP=1,6,11 ghostap                 # channels to hop during live capture
```

Dashboard address: **http://127.0.0.1:8050**

---

## 3. Wi-Fi adapter / monitor mode

```bash
sudo tools/kali_monitor.sh check           # list adapters and whether they support monitor mode
sudo tools/kali_monitor.sh start wlan1     # monitor mode on wlan1 (channel 6)
sudo tools/kali_monitor.sh start wlan1 11  # monitor mode, set to channel 11
sudo tools/kali_monitor.sh stop wlan1      # back to normal Wi-Fi (restarts NetworkManager)
python -m ghostap.hwcaps wlan1             # detailed capability report for an adapter (JSON)
```

Manual way (without the script):

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
iw dev                                     # check the interface type
sudo iw reg set IN                         # set your country if a channel is refused
```

---

## 4. Dashboard (`ghostap.web`): the main app

```bash
# Demo: replay a pcap at 10x speed
python -m ghostap.web --pcap data/test_capture.pcap --speed 10

# Browse the latest session / an existing database
python -m ghostap.web
python -m ghostap.web --db data/ghostap.db

# Live capture (Linux, root, monitor mode)
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11

# Live capture, recorded to a pcap for labelling later
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11 --save-pcap data/lab/run1.pcap

# Reachable from other machines (token sign-in turns on, link printed at start-up)
sudo .venv/bin/python -m ghostap.web --iface wlan1 --hop 1,6,11 --host 0.0.0.0 --https
```

All options:

| Option | Meaning |
|---|---|
| `--pcap FILE` | Replay a pcap (creates a new session) |
| `--iface IFACE` | Live capture on a monitor-mode interface |
| `--name NAME` | Name for the new session |
| `--db FILE` | Use this database instead of a session |
| `--keep` | With `--db`: keep existing data |
| `--config FILE` | Settings file (default `config.yaml`) |
| `--speed N` | Replay speed; `0` = as fast as possible (default 10) |
| `--duration N` | Stop live capture after N seconds |
| `--hop CHANNELS` | Channel hopping: `1,6,11`, `1-13`, `2.4`, `5`, `all` |
| `--dwell SECONDS` | Time on each channel (default 0.25) |
| `--save-pcap FILE` | Record the capture to this file |
| `--no-record` | Do not record a pcap |
| `--monitored FILE` | Use this saved baseline |
| `--no-monitored` | Ignore saved baselines |
| `--host ADDR` | Listen address (default `127.0.0.1`; anything else needs a token) |
| `--port N` | Port (default 8050) |
| `--https` | HTTPS with a self-signed certificate |
| `--tls-cert PEM --tls-key PEM` | HTTPS with your own certificate |

Fixed sign-in token for network access:

```bash
sudo GHOSTAP_TOKEN=some-long-secret .venv/bin/python -m ghostap.web --iface wlan1 --host 0.0.0.0
```

Stop: **Ctrl-C** in the terminal, or `ghostap stop`.

---

## 5. Guided demo

```bash
python tools/demo.py                       # step-by-step demo, ends with the dashboard
python tools/demo.py --no-pause            # run without waiting for Enter
python tools/demo.py --no-dashboard        # skip the dashboard at the end
python tools/demo.py --speed 20 --port 8060
```

---

## 6. Pipeline step by step (offline, any OS)

```bash
python tools/make_test_pcap.py                                  # synthetic capture -> data/test_capture.pcap
python -m ghostap.collector --pcap data/test_capture.pcap        # parse beacons into data/ghostap.db
python -m ghostap.collector --pcap data/test_capture.pcap --reset   # clear the database first
python -m ghostap.indicators --db data/ghostap.db --baseline-minutes 2   # indicator values
python -m ghostap.risk --db data/ghostap.db --config config.yaml         # risk scores + alerts
```

Live collector (no dashboard):

```bash
sudo .venv/bin/python -m ghostap.collector --iface wlan1 --duration 300 --hop 1,6,11 --save-pcap data/run1.pcap
```

Collector options: `--pcap`, `--iface`, `--duration` (default 60), `--hop`, `--dwell`,
`--save-pcap`, `--db` (default `data/ghostap.db`), `--reset`.

---

## 7. Labelling captures and evaluation

```bash
python tools/label_capture.py data/lab1.pcap                          # list APs, find the twin
python tools/label_capture.py data/lab1.pcap --evil <twin-bssid>      # write lab1.labels.json
python tools/label_capture.py data/lab1.pcap --no-twin                # capture with no attack
python tools/label_capture.py data/lab1.pcap --evil <bssid> --attack-start +180 --description "lab run 1"

python tools/make_eval_set.py                                         # synthetic set -> data/eval
python evaluate.py --dataset data/eval --out results                  # metrics, CSVs and charts
python evaluate.py --dataset data/lab_eval                            # metrics on real captures
python evaluate.py --extended                                         # CIs, ROC/PR, learned weights, Kismet
python evaluate.py --pcap X.pcap --labels X.labels.json               # add an extra capture
python evaluate.py --unlabelled ignore --no-charts                    # skip unlabelled APs, no PNGs

python tools/build_scenario.py my_twin --twin-of MVSR_WiFi --channel 11 --open --oui same --rssi -40
python tools/build_scenario.py --spec my_scenarios.json               # scenarios from JSON
python -m ghostap.kismet data/lab/run1.kismet                          # list Kismet's alerts
```

---

## 8. Saved baselines (monitored networks)

```bash
python -m ghostap.monitored save --db data/ghostap.db --ssid MVSR_WiFi   # learn a network
python -m ghostap.monitored save --db data/ghostap.db --ssid A --ssid B --whole
python -m ghostap.monitored show
python -m ghostap.monitored history
python -m ghostap.monitored remove --ssid MVSR_WiFi
python -m ghostap.monitored trust --yes      # accept a hand-edited baseline file after review
```

---

## 9. Sessions

```bash
python -m ghostap.sessions list
python -m ghostap.sessions export <id> session.zip
python -m ghostap.sessions import session.zip
```

---

## 10. Accounts, roles and API keys

Roles: `admin`, `analyst`, `viewer`.

```bash
python -m ghostap.users add alice --role admin     # asks for a password
python -m ghostap.users list
python -m ghostap.users passwd alice
python -m ghostap.users role alice viewer
python -m ghostap.users disable alice
python -m ghostap.users enable alice
python -m ghostap.users reset-2fa alice
python -m ghostap.users signout alice              # end all their sessions

python -m ghostap.apikeys create --name grafana --scope read   # scopes: read, write
python -m ghostap.apikeys list
python -m ghostap.apikeys revoke <id>
```

---

## 11. Vendors and attack-tool signatures

```bash
python -m ghostap.vendors lookup a4:2b:b0:11:22:33 00:c0:ca:de:ad:01
python -m ghostap.vendors import /usr/share/wireshark/manuf

python -m ghostap.signatures list
python -m ghostap.signatures add --db data/ghostap.db --bssid <bssid> --name "WiFi Pineapple" --kind tool
```

---

## 12. Run as a system service (systemd)

```bash
sudo tools/install_service.sh              # install or update (copies to /opt/ghostap)
sudo nano /etc/ghostap/ghostap.env         # set GHOSTAP_IFACE, host, port, extra args
sudo systemctl enable --now ghostap        # start now and at every boot
sudo systemctl status ghostap
sudo systemctl restart ghostap
sudo systemctl stop ghostap                # also gives the adapter back
sudo systemctl disable ghostap             # no longer start at boot
sudo journalctl -u ghostap -f              # live logs (includes the access link)
sudo tools/install_service.sh --remove     # uninstall (keeps /opt/ghostap/data)
```

---

## 13. Docker

Put `GHOSTAP_TOKEN=<long random text>` in a `.env` file next to `docker-compose.yml` first.

```bash
docker compose up demo                                  # demo at http://127.0.0.1:8050
docker compose up -d demo                               # in the background
GHOSTAP_IFACE=wlan1mon docker compose --profile live up live   # live (adapter already in monitor mode)
docker compose logs -f
docker compose down

docker build -t ghostap .
docker run --rm -p 127.0.0.1:8050:8050 -e GHOSTAP_TOKEN=... ghostap
```

---

## 14. Health, logs and processes

```bash
python -m ghostap.healthcheck 8050                      # exit 0 if the dashboard answers
curl -s http://127.0.0.1:8050/api/summary               # quick API check
tail -f data/logs/ghostap.log                           # app log
pgrep -af ghostap.web                                   # is it running?
sudo pkill -INT -f ghostap.web                          # stop every running dashboard
sudo ss -ltnp | grep 8050                               # what is using the port
```

---

## 15. Development and maintenance

```bash
pytest -q                                   # run the test suite
ruff check .                                # lint
pip-audit -r requirements.txt               # check dependencies for known CVEs
python tools/sync_numbers.py                # check report numbers against results/
python tools/sync_numbers.py --write        # update the docs and copy the charts
python tools/screenshot_dashboard.py        # docs/figures/dashboard.png
python tools/screenshot_dashboard.py --theme dark --url http://127.0.0.1:8050
python tools/make_architecture_figure.py    # architecture diagram
python tools/bench_large_site.py --aps 400 --minutes 20   # performance benchmark
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `no virtual environment` | `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` |
| Adapter not in monitor mode | `sudo tools/kali_monitor.sh check`, then `start <iface>` |
| No Wi-Fi after capturing | `sudo tools/kali_monitor.sh stop wlan1` |
| Port 8050 already used | `ghostap stop`, or add `--port 8060` |
| Channel refused | `sudo iw reg set IN` (your country code) |
| Baseline "changed outside GhostAP" | Review `data/monitored.json`, then `python -m ghostap.monitored trust --yes` |

More detail: [README.md](README.md), [docs/KALI_SETUP.md](docs/KALI_SETUP.md),
[docs/DEPLOY.md](docs/DEPLOY.md), [docs/API.md](docs/API.md).
