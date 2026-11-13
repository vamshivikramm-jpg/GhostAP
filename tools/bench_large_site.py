"""Large-site benchmark (F038): how fast is the dashboard API with many access points?

Builds a SYNTHETIC session database (author-designed, not a real site): many networks
with several access points each, one beacon per AP per second (real APs send about ten;
fewer keeps the file small while the number of APs and scoring steps stay realistic),
plus a few twins. Then it scores the database and times every endpoint the dashboard
polls or loads.

    python tools/bench_large_site.py                       # 400 APs, 20 minutes
    python tools/bench_large_site.py --aps 1000 --minutes 30 --keep data/large.db
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ghostap.config import load_config  # noqa: E402
from ghostap.pipeline import rescore  # noqa: E402
from ghostap.storage import Store  # noqa: E402
from ghostap.web import create_app  # noqa: E402

T0 = 1_700_000_000.0


def build(db: str, n_aps: int, minutes: float, seed: int = 7) -> dict:
    rnd = random.Random(seed)
    per_net = 5
    nets = max(1, n_aps // per_net)
    aps = []
    for n in range(nets):
        oui = "a4:2b:{:02x}".format(n % 256)
        for k in range(per_net):
            bssid = "{}:{:02x}:{:02x}:{:02x}".format(oui, n // 256, n % 256, k)
            aps.append({"ssid": "Site_{:03d}".format(n), "bssid": bssid,
                        "channel": rnd.choice((1, 6, 11, 36, 44, 149)), "security": "WPA2/PSK",
                        "rssi": rnd.randint(-85, -45), "tsf0": rnd.randint(3_600, 3_000_000) * 1_000_000,
                        "fp": "fp{:03d}".format(n % 7), "start": 0.0})
    twins = []
    for i in range(max(1, nets // 40)):                     # one twin per 40 networks
        victim = aps[i * per_net * 40 % len(aps)]
        twins.append(dict(victim, bssid="00:c0:ca:de:{:02x}:{:02x}".format(i // 256, i % 256), security="OPN",
                          channel=13, rssi=-35, tsf0=0, fp="twin", start=minutes * 60 * 0.5))
    n = 0
    with Store(db) as s:
        for sec in range(int(minutes * 60)):
            for ap in aps + twins:
                if sec < ap["start"]:
                    continue
                ts = T0 + sec + rnd.random() * 0.1
                s.add({"ts": ts, "frame_type": "beacon", "ssid": ap["ssid"], "bssid": ap["bssid"],
                       "oui": ap["bssid"][:8], "channel": ap["channel"], "security": ap["security"],
                       "rssi": ap["rssi"] + rnd.randint(-3, 3), "beacon_interval": 100,
                       "tsf": ap["tsf0"] + int((sec - ap["start"]) * 1e6), "seq": sec % 4096,
                       "fingerprint": ap["fp"], "rsn": None, "freq": None})
                n += 1
        s.commit()
    return {"aps": len(aps) + len(twins), "networks": nets, "twins": len(twins), "frames": n}


def timed(client, url, method="get", repeat=3, **kw):
    best, size = None, 0
    for _ in range(repeat):
        t = time.perf_counter()
        r = getattr(client, method)(url, **kw)
        dt = time.perf_counter() - t
        assert r.status_code == 200, (url, r.status_code)
        size = len(r.data)
        best = dt if best is None else min(best, dt)
    return best, size


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--aps", type=int, default=400)
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--keep", help="write the database here instead of a temporary file")
    ap.add_argument("--json", action="store_true", help="print the timings as JSON")
    args = ap.parse_args(argv)
    tmp = None
    if args.keep:
        db = args.keep
        if os.path.exists(db):
            print("[!] {} exists; choose another path".format(db), file=sys.stderr)
            return 1
    else:
        tmp = tempfile.TemporaryDirectory()
        db = os.path.join(tmp.name, "large.db")
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    t = time.perf_counter()
    info = build(db, args.aps, args.minutes)
    info["build_s"] = round(time.perf_counter() - t, 1)
    t = time.perf_counter()
    res = rescore(db, cfg)
    info["score_s"] = round(time.perf_counter() - t, 1)
    info["alerts"] = res["alerts"]
    c = create_app(db, cfg, admin_db=db + ".admin").test_client()
    with Store(db) as s:
        a = s.alerts("ghostap")
        rows = s.conn.execute("SELECT COUNT(*) FROM risk_timeline").fetchone()[0]
    info["timeline_rows"] = rows
    q = "ssid={}&bssid={}".format(a[0]["ssid"], a[0]["bssid"]) if a else ""
    urls = ["/api/summary", "/api/aps", "/api/networks", "/api/timeline", "/api/events",
            "/api/alerts?detector=ghostap,deauth,flood", "/api/incidents"]
    if q:
        urls += ["/api/ap?" + q, "/api/ap/series?" + q, "/api/ap/related?" + q, "/api/ap/beacon_diff?" + q]
    out = {}
    for u in urls:
        dt, size = timed(c, u)
        out[u.split("?")[0] if "/api/ap" in u else u] = {"ms": round(dt * 1000, 1), "kb": round(size / 1024, 1)}
    t = time.perf_counter()
    r = c.post("/api/whatif", json={})
    def entry(r):
        return {"ms": round((time.perf_counter() - t) * 1000, 1), "kb": round(len(r.data) / 1024, 1)}
    out["/api/whatif first answer"] = entry(r)
    while r.status_code == 202:            # prepared in the background on first use
        time.sleep(0.5)
        r = c.post("/api/whatif", json={})
    out["/api/whatif ready after"] = entry(r)
    dt, size = timed(c, "/api/whatif", method="post", json={"thresholds": {"medium": 20}})
    out["/api/whatif re-score"] = {"ms": round(dt * 1000, 1), "kb": round(size / 1024, 1)}
    if args.json:
        print(json.dumps({"site": info, "endpoints": out}, indent=2))
    else:
        print("SYNTHETIC large site: {aps} APs in {networks} networks ({twins} twins), {frames:,} beacons, "
              "{timeline_rows:,} timeline rows; built in {build_s} s, scored in {score_s} s, "
              "{alerts} alerts".format(**info))
        print("{:<46} {:>9} {:>9}".format("endpoint", "ms", "KB"))
        for k, v in out.items():
            print("{:<46} {:>9} {:>9}".format(k, v["ms"], v["kb"]))
    if tmp:
        tmp.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
