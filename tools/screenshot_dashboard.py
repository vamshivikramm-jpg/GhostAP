"""Dashboard screenshot for the report (F091).

Starts a dashboard replaying the SYNTHETIC test capture on a spare port, waits until the
replay has finished, and saves a full-page screenshot with headless Chrome or Chromium.
The browser runs with a temporary profile, so your own browser profile is not touched.

    python tools/screenshot_dashboard.py                        # -> docs/figures/dashboard.png
    python tools/screenshot_dashboard.py --url http://127.0.0.1:8050/ --out shot.png
    python tools/screenshot_dashboard.py --theme dark --width 1600

With --url it photographs a dashboard that is already running (e.g. a live session).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)
NAMES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser", "microsoft-edge")


def find_browser() -> str | None:
    for p in CANDIDATES:
        if os.path.exists(p):
            return p
    for n in NAMES:
        p = shutil.which(n)
        if p:
            return p
    return None


def wait_done(url: str, timeout: float) -> dict:
    """Poll /api/summary until the replay has finished."""
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        try:
            base = url.split("#", 1)[0].rstrip("/")        # a page link like ".../#radar" is fine
            with urllib.request.urlopen(base + "/api/summary", timeout=3) as r:  # noqa: S310 - local URL
                last = json.load(r)
            if last.get("status", {}).get("state") in ("done", "stopped", "error"):
                return last
        except OSError:
            pass
        time.sleep(1)
    raise TimeoutError("the dashboard at {} did not finish within {} s".format(url, timeout))


def shoot(browser: str, url: str, out: str, width: int, height: int, theme: str) -> None:
    with tempfile.TemporaryDirectory() as profile:
        cmd = [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
               "--no-default-browser-check", "--user-data-dir=" + profile,
               "--window-size={},{}".format(width, height), "--virtual-time-budget=15000",
               "--force-device-scale-factor=2", "--screenshot=" + os.path.abspath(out), url]
        # 0 = dark, 1 = light; set either way so the computer's own theme does not leak in
        cmd.insert(1, "--blink-settings=preferredColorScheme={}".format(0 if theme == "dark" else 1))
        if theme == "dark":
            cmd.insert(1, "--force-dark-mode")
        subprocess.run(cmd, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="photograph this running dashboard instead of starting a replay")
    ap.add_argument("--out", default=os.path.join("docs", "figures", "dashboard.png"))
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("--height", type=int, default=2300)
    ap.add_argument("--theme", choices=("light", "dark"), default="light")
    ap.add_argument("--port", type=int, default=8077)
    args = ap.parse_args(argv)
    browser = find_browser()
    if not browser:
        print("[!] no Chrome, Chromium, Brave or Edge found. On Kali: sudo apt install chromium "
              "(you run that yourself), or take the screenshot by hand.", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    proc = None
    tmp = None
    url = args.url
    try:
        if not url:
            # relative path: the dashboard shows it, and an absolute one would put your
            # home folder (user name) into the report figure
            pcap = os.path.join("data", "test_capture.pcap")
            if not os.path.exists(os.path.join(ROOT, pcap)):
                subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_test_pcap.py")], check=True, cwd=ROOT)
            tmp = tempfile.TemporaryDirectory()
            proc = subprocess.Popen([sys.executable, "-m", "ghostap.web", "--pcap", pcap, "--speed", "0",
                                     "--db", os.path.join(tmp.name, "shot.db"), "--port", str(args.port)],
                                    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            url = "http://127.0.0.1:{}/".format(args.port)
        s = wait_done(url, 120)
        target = url
        top = s.get("top_alert")
        if top and "#" not in url:
            from urllib.parse import quote
            target = url + "#ap=" + quote(top["ssid"]) + "|" + quote(top["bssid"])
        shoot(browser, target, args.out, args.width, args.height, args.theme)
    finally:
        if proc is not None:
            proc.terminate()
            proc.wait(10)
        if tmp is not None:
            tmp.cleanup()
    print("[+] saved {} ({}{})".format(args.out, "synthetic test capture" if not args.url else args.url,
                                       ", " + args.theme + " theme"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
