#!/usr/bin/env python3
"""Keep the result numbers quoted in the docs in sync with results/ (F053).

    python tools/sync_numbers.py            # check: list stale numbers, exit 1 if any
    python tools/sync_numbers.py --write    # update them and copy the charts to docs/figures/

Reads results/metrics.csv and results/per_ap.csv (from `python evaluate.py`), then looks
for every place where the docs quote those numbers (README.md, docs/REPORT.md,
docs/DEMO.md, CLAUDE.md). Each place is an explicit pattern below, so nothing else in the
text is touched. docs/REPORT.docx is never changed: regenerate it yourself after
checking `git diff docs/REPORT.docx` (the user may have edited it).

Not covered (check by hand when results change): the per-indicator breakdown of the s01
score in REPORT.md section 7, and the threshold-sweep sentences.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import sys
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIGURES = ("metrics_comparison.png", "latency.png", "risk_timelines.png", "threshold_sweep.png")

N2 = r"(\d\.\d\d)"            # 0.91
NI = r"(\d+)"                 # 16
# (file, regex, [fact for each group]); every regex must match exactly once
PLACES: List[Tuple[str, str, List[str]]] = [
    ("README.md", r"^\| GhostAP \| {0} \| {0} \| {0} \| {0} \| {1} s / {1} s \|$".format(N2, NI),
     ["g_p", "g_r", "g_f1", "g_fpr", "g_lat_mean", "g_lat_max"]),
    ("README.md", r"^\| Baseline \(duplicate SSID\) \| {0} \| {0} \| {0} \| {0} \| {1} s / {1} s \|$".format(N2, NI),
     ["b_p", "b_r", "b_f1", "b_fpr", "b_lat_mean", "b_lat_max"]),
    ("docs/REPORT.md", r"^\| \*\*GhostAP\*\* \| {1} \| {1} \| {1} \| {1} \| \*\*{0}\*\* \| {0} \| \*\*{0}\*\* \| "
     r"\*\*{0}\*\* \| {1} s / {1} s \|$".format(N2, NI),
     ["g_tp", "g_fp", "g_tn", "g_fn", "g_p", "g_r", "g_f1", "g_fpr", "g_lat_mean", "g_lat_max"]),
    ("docs/REPORT.md", r"^\| Baseline \(duplicate SSID\) \| {1} \| {1} \| {1} \| {1} \| {0} \| \*\*{0}\*\* \| {0} \| "
     r"{0} \| {1} s / {1} s \|$".format(N2, NI),
     ["b_tp", "b_fp", "b_tn", "b_fn", "b_p", "b_r", "b_f1", "b_fpr", "b_lat_mean", "b_lat_max"]),
    ("docs/REPORT.md", r"precision {0}, recall {0}, F1 {0} and a false-positive rate of {0}\*\*, with a mean\s+"
     r"detection latency of {1} s\. A baseline that flags every duplicated SSID reached\s+precision {0}, F1 {0} "
     r"and a false-positive rate of {0}".format(N2, NI),
     ["g_p", "g_r", "g_f1", "g_fpr", "g_lat_mean", "b_p", "b_f1", "b_fpr"]),
    ("docs/REPORT.md", r"\| s01 classic open twin \| detected after {0} s \| (\d+\.\d) \|".format(NI),
     ["s01_latency", "s01_peak"]),
    ("docs/REPORT.md", r"the twin's peak score of (\d+\.\d)", ["s01_peak"]),
    ("docs/REPORT.md", r"\| \*\*Total\*\* \| \*\*(\d+\.\d)\*\* \(rounded\) \|", ["s01_peak"]),
    ("docs/REPORT.md", r"its F1 was {0}\s+vs\. {0}, with a false-positive rate of {0} vs\. {0}".format(N2),
     ["g_f1", "b_f1", "g_fpr", "b_fpr"]),
    ("docs/DEMO.md", r"GhostAP: precision (\d\.\d), F1 {0}, (zero|\d+) false alarms?\. Baseline: precision {0}, "
     r"(\d+)% false-alarm rate".format(N2), ["g_p1", "g_f1", "g_fp_words", "b_p", "b_fpr_pct"]),
    ("CLAUDE.md", r"GhostAP P {0} / R {0} / F1 {0} / FPR {0}, latency mean {1} s;\s+baseline P {0} / R {0} / "
     r"F1 {0} / FPR {0}; s01 twin peak (\d+\.\d)\.".format(N2, NI),
     ["g_p", "g_r", "g_f1", "g_fpr", "g_lat_mean", "b_p", "b_r", "b_f1", "b_fpr", "s01_peak"]),
]


def facts(results: str) -> Dict[str, str]:
    with open(os.path.join(results, "metrics.csv")) as f:
        m = {r["detector"]: r for r in csv.DictReader(f)}
    with open(os.path.join(results, "per_ap.csv")) as f:
        s01 = [r for r in csv.DictReader(f) if r["scenario"].startswith("s01") and r["label"] == "evil_twin"]
    out: Dict[str, str] = {}
    for d, k in (("ghostap", "g"), ("baseline", "b")):
        r = m[d]
        for name, col in (("p", "precision"), ("r", "recall"), ("f1", "f1"), ("fpr", "fpr")):
            out["{}_{}".format(k, name)] = "{:.2f}".format(float(r[col]))
        for name in ("tp", "fp", "tn", "fn"):
            out["{}_{}".format(k, name)] = str(int(r[name.upper()]))
        out[k + "_lat_mean"] = "{:.0f}".format(float(r["latency_mean"] or 0))
        out[k + "_lat_max"] = "{:.0f}".format(float(r["latency_max"] or 0))
    out["g_p1"] = "{:.1f}".format(float(m["ghostap"]["precision"]))
    out["g_fp_words"] = "zero" if out["g_fp"] == "0" else out["g_fp"]
    out["b_fpr_pct"] = "{:.0f}".format(100 * float(m["baseline"]["fpr"]))
    if s01:
        out["s01_peak"] = "{:.1f}".format(float(s01[0]["ghostap_peak"]))
        out["s01_latency"] = "{:.0f}".format(float(s01[0]["ghostap_latency"] or 0))
    return out


def scan(root: str, want: Dict[str, str], write: bool) -> Tuple[List[str], List[str]]:
    """(problems, changes)"""
    problems, changes = [], []
    by_file: Dict[str, List[Tuple[str, List[str]]]] = {}
    for f, rx, names in PLACES:
        by_file.setdefault(f, []).append((rx, names))
    for f, items in by_file.items():
        path = os.path.join(root, f)
        if not os.path.exists(path):
            problems.append("{}: file missing".format(f))
            continue
        text = open(path, encoding="utf-8").read()
        new = text
        for rx, names in items:
            ms = list(re.finditer(rx, new, flags=re.M))
            if len(ms) != 1:
                problems.append("{}: pattern found {} times (the wording changed?): {}".format(f, len(ms), rx[:70]))
                continue
            mt = ms[0]
            parts, last = [], mt.start()
            for i, name in enumerate(names, start=1):
                have, need = mt.group(i), want.get(name)
                if need is None:
                    continue
                if have != need:
                    line = new.count("\n", 0, mt.start(i)) + 1
                    changes.append("{}:{}: {} is {} in the text, results say {}".format(f, line, name, have, need))
                parts.append(new[last:mt.start(i)] + need)
                last = mt.end(i)
            new = new[:mt.start()] + "".join(parts) + new[last:]
        if write and new != text:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new)
    return problems, changes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=os.path.join(ROOT, "results"))
    ap.add_argument("--root", default=ROOT, help=argparse.SUPPRESS)
    ap.add_argument("--write", action="store_true", help="update the docs and copy the charts")
    args = ap.parse_args(argv)
    try:
        want = facts(args.results)
    except (OSError, KeyError, ValueError) as e:
        print("[!] cannot read results ({}). Run: python tools/make_eval_set.py && python evaluate.py".format(e),
              file=sys.stderr)
        return 2
    problems, changes = scan(args.root, want, args.write)
    for p in problems:
        print("[!] " + p)
    for c in changes:
        print(("[+] updated " if args.write else "[x] stale: ") + c)
    if args.write:
        for name in FIGURES:
            src = os.path.join(args.results, name)
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(args.root, "docs", "figures", name))
        if changes:
            print("[i] now regenerate docs/REPORT.docx (check `git diff docs/REPORT.docx` first) and the demo banner")
    if not changes and not problems:
        print("[+] every quoted number matches results/ ({} places)".format(len(PLACES)))
    return 1 if problems or (changes and not args.write) else 0


if __name__ == "__main__":
    sys.exit(main())
