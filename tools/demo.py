#!/usr/bin/env python3
"""GhostAP guided demo: runs every stage of the pipeline, then opens the dashboard.

    python tools/demo.py                 # pauses for Enter between steps (presenting)
    python tools/demo.py --no-pause      # run straight through
    python tools/demo.py --no-dashboard  # stop after the evaluation
    python tools/demo.py --speed 20      # faster dashboard replay

Uses only synthetic data, so it runs on any laptop (no Wi-Fi adapter needed).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

STEPS = [
    ("1/6  Generate a synthetic capture with an evil twin",
     "300 s of beacons from 4 APs. At t=180 s an open 'MVSR_WiFi' twin appears:\n"
     "      different vendor, channel 11, -38 dBm, and booted 1 ms ago.",
     [PY, "tools/make_test_pcap.py"]),
    ("2/6  Collect: parse beacons into SQLite and build per-AP profiles",
     "Passive only: beacon and probe-response frames, nothing is transmitted.",
     [PY, "-m", "ghostap.collector", "--pcap", "data/test_capture.pcap", "--reset"]),
    ("3/6  Indicators: compare every AP with the 2-minute baseline",
     "Seven indicators, each 0..1 with a reason. Note the legit second\n"
     "      MVSR_WiFi AP (a4:2b:b0:11:22:99) stays at ~0.",
     [PY, "-m", "ghostap.indicators"]),
    ("4/6  Risk engine: weighted score, smoothing, explainable alerts",
     "R = sum(w*x)/sum(w)*100, mean of the last 3 scores. GhostAP raises one alert;\n"
     "      the duplicate-SSID baseline flags all three MVSR_WiFi APs.",
     [PY, "-m", "ghostap.risk"]),
    ("5/6  Evaluation on 10 labelled scenarios (5 attacks, 5 benign)",
     "Precision, recall, F1, false-positive rate and latency vs. the baseline.",
     None),  # two commands, see run_step
    ("6/6  Dashboard: replay the capture and watch the alert appear",
     "Open the browser, wait ~12 s for the baseline, then the twin turns\n"
     "      MEDIUM at t+200 s and HIGH at t+210 s. Click the alert to explain it.",
     None),
]


def banner(title, note):
    print("\n" + "=" * 78)
    print("  " + title)
    print("      " + note)
    print("=" * 78 + "\n", flush=True)


def run(cmd):
    print("$ " + " ".join(["python"] + cmd[1:]), flush=True)
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        print("[!] step failed (exit {}). See the output above.".format(res.returncode))
        sys.exit(res.returncode)


def pause(enabled):
    if enabled:
        try:
            input("\n  [Enter] next step   (Ctrl-C to quit) ")
        except EOFError:
            pass


def main():
    ap = argparse.ArgumentParser(description="GhostAP guided demo")
    ap.add_argument("--no-pause", action="store_true")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--speed", type=float, default=10.0)
    ap.add_argument("--port", type=int, default=8050)
    args = ap.parse_args()
    interactive = not args.no_pause and sys.stdin.isatty()

    try:
        for i, (title, note, cmd) in enumerate(STEPS[:5]):
            banner(title, note)
            if cmd:
                run(cmd)
            else:  # evaluation
                run([PY, "tools/make_eval_set.py"])
                run([PY, "evaluate.py", "--dataset", "data/eval", "--out", "results"])
                print("\n  Charts and tables: results/summary.md, results/*.png")
            pause(interactive)

        if args.no_dashboard:
            print("\n[+] demo finished (dashboard skipped).")
            return 0

        title, note, _ = STEPS[5]
        banner(title, note)
        url = "http://127.0.0.1:{}".format(args.port)
        cmd = [PY, "-m", "ghostap.web", "--pcap", "data/test_capture.pcap",
               "--speed", str(args.speed), "--port", str(args.port)]
        print("$ python -m ghostap.web --pcap data/test_capture.pcap --speed {:g}".format(args.speed))
        server = subprocess.Popen(cmd, cwd=ROOT)
        time.sleep(1.5)
        if server.poll() is not None:
            print("[!] dashboard failed to start (is port {} in use? try --port 8051)".format(args.port))
            return 1
        webbrowser.open(url)
        print("\n  Dashboard: {}   (Ctrl-C to stop)".format(url))
        server.wait()
    except KeyboardInterrupt:
        print("\n[+] demo stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
