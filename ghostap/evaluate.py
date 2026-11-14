"""Phase 6: evaluate GhostAP against the duplicate-SSID baseline on labelled pcaps.

The unit of evaluation is one access point (SSID + BSSID) in one capture.
  * ground truth: the capture's labels file says "legit" or "evil_twin"
  * a detector "flags" an AP if it raises an alert for it at any time
      - GhostAP: smoothed risk reaches the MEDIUM threshold (config.yaml)
      - baseline: the AP's SSID is advertised by more than one BSSID
  * detection latency (true positives only) = first alert time - attack start,
    floored at 0 (an alarm already active when the attack starts counts as 0 s)

Metrics: precision, recall, F1, false-positive rate = FP / (FP + TN), latency.

Labels file for X.pcap: X.labels.json (or X_labels.json) next to it:
    {"aps": {"<bssid>": {"label": "evil_twin", "attack_start": <epoch>}, ...}}
or the Phase-1 form {"attack_start": <epoch>, "aps": {"<bssid>": "evil_twin", ...}}.

Run:
    python tools/make_eval_set.py          # synthetic labelled scenarios -> data/eval/
    python -m ghostap.evaluate --dataset data/eval --out results
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import statistics
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from .collector import collect_pcap
from .config import ConfigError, load_config
from .risk import RiskEngine, analyzer_for, duplicate_ssid_detector
from .storage import Store

DETECTORS = ("ghostap", "baseline")
DETECTOR_NAMES = {"ghostap": "GhostAP", "baseline": "Baseline (duplicate SSID)"}


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #

def load_labels(path: str) -> dict:
    """Normalise both labels formats to {bssid: {"label", "attack_start"}}."""
    with open(path) as f:
        raw = json.load(f)
    default_start = raw.get("attack_start")
    aps = {}
    for bssid, v in raw.get("aps", {}).items():
        if isinstance(v, str):
            v = {"label": v}
        label = v.get("label", "legit")
        aps[bssid.lower()] = {
            "label": label,
            "attack_start": v.get("attack_start", default_start) if label == "evil_twin" else None,
        }
    return {"aps": aps, "description": raw.get("description", ""),
            "synthetic": raw.get("synthetic")}


def find_dataset(directory: str) -> List[Tuple[str, str, str]]:
    """(name, pcap, labels) for every pcap in `directory` that has a labels file."""
    out = []
    for pcap in sorted(glob.glob(os.path.join(directory, "*.pcap")) +
                       glob.glob(os.path.join(directory, "*.pcapng"))):
        stem = os.path.splitext(pcap)[0]
        for cand in (stem + ".labels.json", stem + "_labels.json"):
            if os.path.exists(cand):
                out.append((os.path.basename(stem), pcap, cand))
                break
        else:
            print("[!] skipping {} (no {}.labels.json)".format(pcap, os.path.basename(stem)),
                  file=sys.stderr)
    return out


# --------------------------------------------------------------------------- #
# Running the detectors on one capture
# --------------------------------------------------------------------------- #

def run_capture(name: str, pcap: str, labels_path: str, cfg: dict,
                unlabelled: str = "legit") -> Tuple[List[dict], List[dict]]:
    """Return (one row per AP, GhostAP risk timeline) for one labelled capture."""
    labels = load_labels(labels_path)
    with tempfile.TemporaryDirectory() as tmp:
        with Store(os.path.join(tmp, "eval.db")) as store:
            collect_pcap(pcap, store)
            obs = store.observations()

    an = analyzer_for(cfg, obs)
    engine = RiskEngine(an, cfg)
    engine.record = []                       # indicator values per step, for --extended (F084, F085)
    timeline = engine.run().timeline
    ind_max: Dict[Tuple[str, str], Dict[str, float]] = {}
    for _, key, res in engine.record:
        if res:
            m = ind_max.setdefault(key, {})
            for r in res:
                m[r.name] = max(m.get(r.name, 0.0), float(r.value))
    base_first = {(a["ssid"], a["bssid"]): a["first_ts"] for a in duplicate_ssid_detector(obs)}
    kismet_path = os.path.splitext(pcap)[0] + ".kismet"      # F050: Kismet's log of the same capture
    kismet_first, kismet_timed = None, True
    if os.path.exists(kismet_path):
        from .kismet import first_alerts, replayed
        kismet_first = first_alerts(kismet_path)
        kismet_timed = not replayed(kismet_path)            # replayed log: who, but not when

    series: Dict[Tuple[str, str], List[dict]] = {}
    for r in timeline:
        series.setdefault((r["ssid"], r["bssid"]), []).append(r)
    capture_start = obs[0]["ts"] if obs else None

    rows = []
    for (ssid, bssid) in an.aps():
        lab = labels["aps"].get(bssid)
        if lab is None:
            if unlabelled == "ignore":
                continue
            lab = {"label": "legit", "attack_start": None}
        tl = series.get((ssid, bssid), [])
        rows.append({
            "scenario": name,
            "description": labels["description"],
            "synthetic": bool(labels["synthetic"]),
            "ssid": ssid,
            "bssid": bssid,
            "label": lab["label"],
            "attack_start": lab["attack_start"],
            "capture_start": capture_start,
            "first_seen": an.first_seen(ssid, bssid),
            "ghostap_peak": max((r["score"] for r in tl), default=0.0),
            "ghostap_series": [(r["ts"], r["score"]) for r in tl],
            "baseline_first": base_first.get((ssid, bssid)),
            "indicators": ind_max.get((ssid, bssid), {}),
            "kismet_first": None if kismet_first is None else kismet_first.get(bssid),
            "kismet_available": kismet_first is not None,
            "kismet_timed": kismet_timed,
        })
    for r in timeline:
        r["scenario"] = name
    return rows, timeline


def first_crossing(series, threshold: float) -> Optional[float]:
    for ts, score in series:
        if score >= threshold:
            return ts
    return None


def alert_time(row: dict, detector: str, threshold: float) -> Optional[float]:
    if detector == "ghostap":
        return first_crossing(row["ghostap_series"], threshold)
    if detector == "kismet":
        return row.get("kismet_first")
    return row["baseline_first"]


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def _ratio(a: float, b: float) -> Optional[float]:
    return a / b if b else None


def compute_metrics(rows: List[dict], detector: str, threshold: float) -> dict:
    tp = fp = tn = fn = 0
    latencies = []
    for r in rows:
        t = alert_time(r, detector, threshold)
        positive = r["label"] == "evil_twin"
        if positive and t is not None:
            tp += 1
            if r["attack_start"] is not None and (detector != "kismet" or r.get("kismet_timed", True)):
                latencies.append(max(0.0, t - r["attack_start"]))
        elif positive:
            fn += 1
        elif t is not None:
            fp += 1
        else:
            tn += 1
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else (0.0 if precision is not None and recall is not None else None))
    return {
        "detector": detector, "threshold": threshold if detector == "ghostap" else None,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": _ratio(fp, fp + tn),
        "latency_mean": statistics.fmean(latencies) if latencies else None,
        "latency_median": statistics.median(latencies) if latencies else None,
        "latency_max": max(latencies) if latencies else None,
    }


def threshold_sweep(rows: List[dict], thresholds=None) -> List[dict]:
    thresholds = thresholds or list(range(5, 100, 5))
    return [compute_metrics(rows, "ghostap", float(t)) for t in thresholds]


def per_scenario(rows: List[dict], threshold: float) -> List[dict]:
    out = []
    for name in sorted({r["scenario"] for r in rows}):
        sub = [r for r in rows if r["scenario"] == name]
        entry = {"scenario": name, "description": sub[0]["description"], "aps": len(sub),
                 "evil_twins": sum(r["label"] == "evil_twin" for r in sub)}
        for d in DETECTORS:
            m = compute_metrics(sub, d, threshold)
            entry.update({"{}_{}".format(d, k): m[k] for k in ("TP", "FP", "FN")})
            entry["{}_latency".format(d)] = m["latency_max"]
        out.append(entry)
    return out


# --------------------------------------------------------------------------- #
# Output: tables and charts
# --------------------------------------------------------------------------- #

def _fmt(v, pct=False, digits=2):
    if v is None:
        return "n/a"
    if pct:
        return "{:.0%}".format(v)
    return "{:.{}f}".format(v, digits) if isinstance(v, float) else str(v)


def _write_csv(path: str, rows: List[dict], fields: List[str]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fields})


def metrics_table(metrics: List[dict]) -> str:
    head = "| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Latency mean / max (s) |"
    lines = [head, "|" + "---|" * 10]
    for m in metrics:
        lat = "{} / {}".format(_fmt(m["latency_mean"], digits=1), _fmt(m["latency_max"], digits=1))
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            DETECTOR_NAMES[m["detector"]], m["TP"], m["FP"], m["TN"], m["FN"],
            _fmt(m["precision"]), _fmt(m["recall"]), _fmt(m["f1"]), _fmt(m["fpr"]), lat))
    return "\n".join(lines)


def scenario_table(scen: List[dict]) -> str:
    def cell(e, d):
        parts = []
        if e["evil_twins"]:
            if e[d + "_TP"]:
                lat = e[d + "_latency"]
                parts.append("detected" + ("" if lat is None else " ({:.0f} s)".format(lat)))
            else:
                parts.append("**missed**")
        if e[d + "_FP"]:
            parts.append("{} false alarm{}".format(e[d + "_FP"], "s" if e[d + "_FP"] > 1 else ""))
        return ", ".join(parts) or "no alerts (correct)"

    lines = ["| Scenario | APs | Evil twin | GhostAP | Baseline |", "|---|---|---|---|---|"]
    for e in scen:
        lines.append("| {} | {} | {} | {} | {} |".format(
            e["scenario"], e["aps"], "yes" if e["evil_twins"] else "no",
            cell(e, "ghostap"), cell(e, "baseline")))
    return "\n".join(lines)


# Reference palette (light): categorical slots, chart chrome.
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
S = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
SERIOUS, CRITICAL = "#ec835a", "#d03b3b"


def _style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def make_charts(out: str, metrics: List[dict], sweep: List[dict], scen: List[dict],
                rows: List[dict], cfg: dict) -> List[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "sans-serif", "font.size": 10,
                         "text.color": INK, "axes.labelcolor": INK2,
                         "figure.facecolor": SURFACE, "savefig.facecolor": SURFACE})
    paths = []
    th = cfg["thresholds"]

    # 1) Metric comparison: grouped bars, 2 detectors.
    names = ["Precision", "Recall", "F1", "False-positive rate"]
    keys = ["precision", "recall", "f1", "fpr"]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    _style(ax)
    w = 0.36
    for i, m in enumerate(metrics):
        vals = [m[k] or 0.0 for k in keys]
        xs = [j + (i - 0.5) * (w + 0.02) for j in range(len(keys))]
        ax.bar(xs, vals, width=w, color=S[i], label=DETECTOR_NAMES[m["detector"]], zorder=2)
        for x, v, k in zip(xs, vals, keys):
            ax.text(x, v + 0.02, "n/a" if m[k] is None else "{:.2f}".format(v),
                    ha="center", va="bottom", fontsize=9, color=INK2)
    ax.set_xticks(range(len(keys)), names)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("score (higher is better, except FPR)")
    ax.legend(frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.12))
    fig.tight_layout()
    paths.append(os.path.join(out, "metrics_comparison.png"))
    fig.savefig(paths[-1], dpi=160)
    plt.close(fig)

    # 2) Detection latency per attack scenario.
    attacks = [e for e in scen if e["evil_twins"]]
    if attacks:
        fig, ax = plt.subplots(figsize=(8, 0.6 + 0.62 * len(attacks)))
        _style(ax)
        ax.grid(True, axis="x", color=GRID)
        ax.grid(False, axis="y")
        h = 0.36
        ymax = 0
        for i, d in enumerate(DETECTORS):
            for j, e in enumerate(attacks):
                y = j + (i - 0.5) * (h + 0.04)
                if e[d + "_TP"]:
                    v = e[d + "_latency"] or 0.0
                    ymax = max(ymax, v)
                    ax.barh(y, max(v, 0.4), height=h, color=S[i], zorder=2,
                            label=DETECTOR_NAMES[d] if j == 0 else None)
                    ax.text(max(v, 0.4) + 0.6, y, "{:.0f} s".format(v), va="center", fontsize=9, color=INK2)
                else:
                    ax.text(0.6, y, "missed", va="center", fontsize=9, color=INK, fontweight="bold")
        ax.set_yticks(range(len(attacks)), [e["scenario"] for e in attacks])
        ax.invert_yaxis()
        ax.set_xlim(0, max(ymax * 1.25, 10))
        ax.set_xlabel("seconds from attack start to first alert")
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, labels, frameon=False, loc="lower right")
        fig.tight_layout()
        paths.append(os.path.join(out, "latency.png"))
        fig.savefig(paths[-1], dpi=160)
        plt.close(fig)

    # 3) Threshold sweep for GhostAP.
    fig, ax = plt.subplots(figsize=(8, 4.2))
    _style(ax)
    xs = [m["threshold"] for m in sweep]
    for i, (k, label) in enumerate(zip(keys, names)):
        ys = [m[k] if m[k] is not None else float("nan") for m in sweep]
        ax.plot(xs, ys, color=S[i], linewidth=2, label=label, zorder=3)
    ax.axvline(th["medium"], color=MUTED, linestyle="--", linewidth=1)
    ax.text(th["medium"] + 1, 1.04, "configured threshold ({:g})".format(th["medium"]),
            color=MUTED, fontsize=9)
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.02, 1.1)
    ax.set_xlabel("GhostAP alert threshold (risk score)   -   precision has no value "
                  "once nothing is flagged", fontsize=9)
    ax.set_ylabel("metric value")
    ax.legend(frameon=False, loc="center right", fontsize=9)
    fig.tight_layout()
    paths.append(os.path.join(out, "threshold_sweep.png"))
    fig.savefig(paths[-1], dpi=160)
    plt.close(fig)

    # 4) Risk timelines, one panel per scenario.
    names_s = sorted({r["scenario"] for r in rows})
    attack_names = [n for n in names_s if any(r["scenario"] == n and r["label"] == "evil_twin" for r in rows)]
    benign_names = [n for n in names_s if n not in attack_names]
    groups = [g for g in (attack_names, benign_names) if g]
    cols = max(len(g) for g in groups)
    if cols > 6:                      # many captures: plain grid
        cols = 6
        groups = [names_s[i:i + cols] for i in range(0, len(names_s), cols)]
    nrows = len(groups)
    fig, axes = plt.subplots(nrows, cols, figsize=(3.1 * cols, 2.5 * nrows),
                             sharey=True, squeeze=False)
    placed = []
    for ri, g in enumerate(groups):
        for ci in range(cols):
            if ci < len(g):
                placed.append((axes[ri][ci], g[ci]))
            else:
                axes[ri][ci].set_visible(False)
    for ax, name in placed:
        _style(ax)
        sub = [r for r in rows if r["scenario"] == name]
        t0 = sub[0]["capture_start"]
        for r in sorted(sub, key=lambda r: r["label"] == "evil_twin"):
            if not r["ghostap_series"]:
                continue
            x = [t - t0 for t, _ in r["ghostap_series"]]
            y = [s for _, s in r["ghostap_series"]]
            evil = r["label"] == "evil_twin"
            ax.plot(x, y, color=S[0] if evil else AXIS, linewidth=2 if evil else 1.2,
                    zorder=3 if evil else 2)
            if evil and r["attack_start"] is not None:
                ax.axvline(r["attack_start"] - t0, color=INK2, linestyle=":", linewidth=1)
        ax.axhline(th["medium"], color=SERIOUS, linestyle="--", linewidth=0.9)
        ax.axhline(th["high"], color=CRITICAL, linestyle="--", linewidth=0.9)
        ax.set_title(name, fontsize=9, color=INK, loc="left")
        ax.set_ylim(0, 100)
        ax.set_xlim(120, max(r["capture_start"] for r in sub) - t0 + 300)
    fig.text(0.01, 0.005,
             "Smoothed GhostAP risk after the 2-min baseline. Top row: captures with an evil twin; "
             "bottom row: benign captures. Blue = evil twin, grey = legit APs, dotted = attack start, "
             "dashed = MEDIUM / HIGH thresholds. x: capture time (s).", fontsize=8.5, color=INK2)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    paths.append(os.path.join(out, "risk_timelines.png"))
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)
    return paths


def write_results(out: str, rows, metrics, sweep, scen, cfg, charts=True) -> List[str]:
    os.makedirs(out, exist_ok=True)
    th = cfg["thresholds"]["medium"]
    for r in rows:
        for d in DETECTORS:
            t = alert_time(r, d, th)
            r[d + "_alert"] = t is not None
            r[d + "_latency"] = (max(0.0, t - r["attack_start"])
                                 if t is not None and r["attack_start"] is not None else None)
    _write_csv(os.path.join(out, "per_ap.csv"), rows,
               ["scenario", "ssid", "bssid", "label", "ghostap_peak", "ghostap_alert",
                "ghostap_latency", "baseline_alert", "baseline_latency"])
    _write_csv(os.path.join(out, "metrics.csv"), metrics,
               ["detector", "threshold", "TP", "FP", "TN", "FN", "precision", "recall", "f1",
                "fpr", "latency_mean", "latency_median", "latency_max"])
    _write_csv(os.path.join(out, "threshold_sweep.csv"), sweep,
               ["threshold", "TP", "FP", "TN", "FN", "precision", "recall", "f1", "fpr",
                "latency_mean", "latency_max"])
    _write_csv(os.path.join(out, "per_scenario.csv"), scen,
               ["scenario", "description", "aps", "evil_twins", "ghostap_TP", "ghostap_FP",
                "ghostap_FN", "ghostap_latency", "baseline_TP", "baseline_FP", "baseline_FN",
                "baseline_latency"])
    chart_paths = make_charts(out, metrics, sweep, scen, rows, cfg) if charts else []

    synthetic = any(r["synthetic"] for r in rows)
    md = ["# GhostAP evaluation results", "",
          "{} captures, {} access points ({} evil twins, {} legit). GhostAP alert threshold: "
          "MEDIUM >= {:g}; baseline window {:g} min.".format(
              len(scen), len(rows), sum(r["label"] == "evil_twin" for r in rows),
              sum(r["label"] != "evil_twin" for r in rows), th, cfg["baseline_minutes"]),
          "", "## Overall", "", metrics_table(metrics), "",
          "Unit = one access point (SSID + BSSID) per capture. FPR = FP / (FP + TN). "
          "Latency = first alert minus attack start, for detected evil twins.", "",
          "## Per scenario", "", scenario_table(scen), ""]
    md += ["## Scenario descriptions", ""] + [
        "- **{}**: {}".format(e["scenario"], e["description"]) for e in scen] + [""]
    if charts:
        md += ["## Charts", ""] + ["![{0}]({0})".format(os.path.basename(p)) for p in chart_paths] + [""]
    best = max(sweep, key=lambda m: (m["f1"] or 0, -m["threshold"]))
    md += ["## Threshold sweep", "",
           "Best F1 on this data: {} at threshold {:g} (configured: {:g}). This is tuned on the "
           "same captures it is scored on, so it is optimistic; pick the threshold on one set of "
           "captures and report metrics on another.".format(
               _fmt(best["f1"]), best["threshold"], th), ""]
    md += ["## Caveats", ""]
    if synthetic:
        md += ["- These captures are **synthetic** (`tools/make_eval_set.py`). They exercise the "
               "pipeline end to end and show where each indicator helps, but real lab captures "
               "(Phase 2) are needed before quoting these numbers as results."]
    md += ["- Baseline latency is often 0 s because its alarm on an SSID is already active "
           "(raised by the legitimate APs) when the attack starts.",
           "- GhostAP latency is bounded below by the 10 s scoring step and the 3-step smoothing "
           "(config.yaml).", ""]
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write("\n".join(md))
    return chart_paths


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def evaluate(pairs: List[Tuple[str, str, str]], cfg: dict, unlabelled: str = "legit"):
    rows, timelines = [], []
    for name, pcap, labels in pairs:
        r, tl = run_capture(name, pcap, labels, cfg, unlabelled)
        rows += r
        timelines += tl
    th = cfg["thresholds"]["medium"]
    metrics = [compute_metrics(rows, d, th) for d in DETECTORS]
    return rows, metrics, threshold_sweep(rows), per_scenario(rows, th)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ghostap.evaluate",
                                 description="Evaluate GhostAP vs. the duplicate-SSID baseline.")
    ap.add_argument("--dataset", default="data/eval",
                    help="directory of <name>.pcap + <name>.labels.json (default data/eval)")
    ap.add_argument("--pcap", action="append", default=[], help="extra pcap (pair with --labels)")
    ap.add_argument("--labels", action="append", default=[], help="labels JSON for each --pcap")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default="results")
    ap.add_argument("--unlabelled", choices=("legit", "ignore"), default="legit",
                    help="how to treat APs missing from a labels file (default: legit)")
    ap.add_argument("--no-charts", action="store_true")
    ap.add_argument("--extended", action="store_true",
                    help="also: confidence intervals, tune/test split, ROC and PR curves, learned weights, "
                         "anomaly model, Kismet (see extended.md)")
    ap.add_argument("--test-fraction", type=float, default=0.5, help="share of captures in the test split")
    args = ap.parse_args(argv)

    if len(args.pcap) != len(args.labels):
        ap.error("give one --labels for every --pcap")
    pairs = find_dataset(args.dataset) if os.path.isdir(args.dataset) else []
    pairs += [(os.path.splitext(os.path.basename(p))[0], p, lab) for p, lab in zip(args.pcap, args.labels)]
    if not pairs:
        print("[!] no labelled captures found. Generate the synthetic set with:\n"
              "      python tools/make_eval_set.py\n    or pass --pcap X --labels Y.",
              file=sys.stderr)
        return 1

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("[!] settings problem: {}".format(e), file=sys.stderr)
        return 2
    print("[+] evaluating {} captures ...".format(len(pairs)))
    rows, metrics, sweep, scen = evaluate(pairs, cfg, args.unlabelled)
    charts = write_results(args.out, rows, metrics, sweep, scen, cfg, charts=not args.no_charts)

    print("\n" + metrics_table(metrics) + "\n")
    print(scenario_table(scen) + "\n")
    best = max(sweep, key=lambda m: (m["f1"] or 0, -m["threshold"]))
    print("[+] threshold sweep: best F1 {:.2f} at threshold {:g} (configured: {:g})".format(
        best["f1"] or 0, best["threshold"], cfg["thresholds"]["medium"]))
    print("[+] wrote {}/summary.md, metrics.csv, per_ap.csv, per_scenario.csv, "
          "threshold_sweep.csv".format(args.out))
    for p in charts:
        print("[+] chart: {}".format(p))
    if args.extended:
        from .evaluate_extended import extended
        ext = extended(rows, cfg, args.out, test_fraction=args.test_fraction, charts=not args.no_charts)
        print("[+] extended analysis: {}/extended.md and extended.json".format(args.out))
        for line in ext["headline"]:
            print("    " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
