"""Extended evaluation (python -m ghostap.evaluate --extended), see stats.py.

Writes extended.json, extended.md, ci.csv, roc.csv, pr.csv, splits.csv and (with charts)
roc_pr.png. The default evaluation outputs are not touched.
"""
from __future__ import annotations

import csv
import json
import os
from typing import Dict, List, Optional

import numpy as np

from . import stats
from .evaluate import compute_metrics

METRICS = ("precision", "recall", "f1", "fpr")


def _f(v, d=2):
    return "–" if v is None else "{:.{}f}".format(v, d)


def _ci_txt(lo, hi):
    return "–" if lo is None else "{:.2f}–{:.2f}".format(lo, hi)


def confidence(rows: List[dict], detector: str, threshold: float) -> dict:
    m = compute_metrics(rows, detector, threshold)
    out = {"detector": detector, "TP": m["TP"], "FP": m["FP"], "TN": m["TN"], "FN": m["FN"]}
    w = {"precision": stats.wilson(m["TP"], m["TP"] + m["FP"]), "recall": stats.wilson(m["TP"], m["TP"] + m["FN"]),
         "fpr": stats.wilson(m["FP"], m["FP"] + m["TN"]), "f1": (None, None)}
    for k in METRICS:
        out[k] = m[k]
        out[k + "_wilson"] = w[k]
        out[k + "_bootstrap"] = stats.bootstrap(rows, lambda sub, k=k: compute_metrics(sub, detector, threshold)[k])
    return out


def _flag_static(row: dict, weights: Dict[str, float], threshold: float) -> bool:
    return stats.static_score(row["indicators"], weights) >= threshold


def _static_metrics(rows: List[dict], weights: Dict[str, float], threshold: float) -> dict:
    tp = sum(1 for r in rows if r["label"] == "evil_twin" and _flag_static(r, weights, threshold))
    fn = sum(1 for r in rows if r["label"] == "evil_twin") - tp
    fp = sum(1 for r in rows if r["label"] != "evil_twin" and _flag_static(r, weights, threshold))
    tn = sum(1 for r in rows if r["label"] != "evil_twin") - fp
    p = tp / (tp + fp) if tp + fp else None
    rc = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * rc / (p + rc) if p and rc else (0.0 if p is not None and rc is not None else None)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": p, "recall": rc, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else None}


def extended(rows: List[dict], cfg: dict, out: str, test_fraction: float = 0.5, charts: bool = True) -> dict:
    os.makedirs(out, exist_ok=True)
    th = cfg["thresholds"]["medium"]
    synthetic = any(r.get("synthetic") for r in rows)
    detectors = ["ghostap", "baseline"] + (["kismet"] if any(r.get("kismet_available") for r in rows) else [])
    kismet_rows = [r for r in rows if r.get("kismet_available")]

    # ---- F048 confidence intervals
    ci = [confidence(kismet_rows if d == "kismet" else rows, d, th) for d in detectors]

    # ---- F048 tune / test split (by capture)
    names = sorted({r["scenario"] for r in rows})
    sp = stats.split(names, test_fraction)
    tune = [r for r in rows if sp[r["scenario"]] == "tune"]
    test = [r for r in rows if sp[r["scenario"]] == "test"]
    split_info = {"tune": [n for n in names if sp[n] == "tune"], "test": [n for n in names if sp[n] == "test"],
                  "tune_twins": sum(r["label"] == "evil_twin" for r in tune),
                  "test_twins": sum(r["label"] == "evil_twin" for r in test)}
    usable = bool(tune and test and split_info["tune_twins"] and split_info["test_twins"])
    split_res: dict = {"usable": usable}
    if usable:
        sweep = [(t, compute_metrics(tune, "ghostap", float(t))["f1"] or 0.0) for t in range(5, 100, 5)]
        best_t = max(sweep, key=lambda x: (x[1], -x[0]))[0]
        split_res.update({
            "configured_threshold": th, "threshold_chosen_on_tune": float(best_t),
            "test_configured": compute_metrics(test, "ghostap", th),
            "test_tuned": compute_metrics(test, "ghostap", float(best_t)),
            "test_baseline": compute_metrics(test, "baseline", th),
        })

    # ---- F049 ROC and precision-recall over GhostAP's peak score
    y = [1 if r["label"] == "evil_twin" else 0 for r in rows]
    sc = [r["ghostap_peak"] for r in rows]
    roc_pts, auc = stats.roc(sc, y)
    pr_pts, ap = stats.pr(sc, y)
    base = compute_metrics(rows, "baseline", th)
    curves = {"auc": auc, "average_precision": ap,
              "roc": [{"threshold": None if t == float("inf") else t, "fpr": f, "tpr": tp} for t, f, tp in roc_pts],
              "pr": [{"threshold": t, "recall": r, "precision": p} for t, r, p in pr_pts],
              "baseline_point": {"fpr": base["fpr"], "tpr": base["recall"], "precision": base["precision"]}}

    # ---- F084 learned weights (fitted on tune only, scored on test only)
    feat_names = list(cfg["weights"])
    learned: dict = {"usable": usable}
    if usable:
        x_tune = np.array([[r["indicators"].get(k, 0.0) for k in feat_names] for r in tune])
        y_tune = np.array([1.0 if r["label"] == "evil_twin" else 0.0 for r in tune])
        w = stats.learn_weights(x_tune, y_tune, feat_names, total=sum(cfg["weights"].values()))
        learned.update({"weights": w, "configured": dict(cfg["weights"]),
                        "test_configured_static": _static_metrics(test, cfg["weights"], th),
                        "test_learned_static": _static_metrics(test, w, th)})

    # ---- F085 anomaly model (no labels used to fit)
    anomaly: dict = {"usable": usable}
    if usable:
        x_all = lambda rs: np.array([[r["indicators"].get(k, 0.0) for k in feat_names] for r in rs])  # noqa: E731
        model = stats.Anomaly(x_all(tune))
        s_test = model.score(x_all(test)).tolist()
        y_test = [1 if r["label"] == "evil_twin" else 0 for r in test]
        anomaly.update({"test_auc": stats.auc_of(s_test, y_test),
                        "ghostap_test_auc": stats.auc_of([r["ghostap_peak"] for r in test], y_test)})

    # ---- files
    with open(os.path.join(out, "ci.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["detector", "metric", "value", "wilson_low", "wilson_high", "bootstrap_low", "bootstrap_high"])
        for c in ci:
            for k in METRICS:
                wl, wh = c[k + "_wilson"]
                bl, bh = c[k + "_bootstrap"]
                wr.writerow([c["detector"], k] + [_f(v, 4) if v is not None else "" for v in (c[k], wl, wh, bl, bh)])
    with open(os.path.join(out, "roc.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["threshold", "fpr", "tpr"])
        for p in curves["roc"]:
            wr.writerow(["inf" if p["threshold"] is None else p["threshold"], p["fpr"], p["tpr"]])
    with open(os.path.join(out, "pr.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["threshold", "recall", "precision"])
        for p in curves["pr"]:
            wr.writerow([p["threshold"], p["recall"], p["precision"]])
    with open(os.path.join(out, "splits.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["capture", "split"])
        for n in names:
            wr.writerow([n, sp[n]])
    chart = _chart(out, curves) if charts else None

    headline = ["GhostAP F1 {} (95% bootstrap {}), recall {} (Wilson {}), FPR {} (Wilson {})".format(
        _f(ci[0]["f1"]), _ci_txt(*ci[0]["f1_bootstrap"]), _f(ci[0]["recall"]), _ci_txt(*ci[0]["recall_wilson"]),
        _f(ci[0]["fpr"]), _ci_txt(*ci[0]["fpr_wilson"])),
        "ROC AUC {}, average precision {}".format(_f(auc), _f(ap))]
    result = {"synthetic": synthetic, "threshold": th, "captures": len(names), "aps": len(rows),
              "twins": sum(y), "ci": ci, "split": split_info, "split_results": split_res, "curves": curves,
              "learned_weights": learned, "anomaly": anomaly, "kismet": "kismet" in detectors,
              "chart": os.path.basename(chart) if chart else None, "headline": headline}
    with open(os.path.join(out, "extended.json"), "w") as f:
        json.dump(result, f, indent=2, default=lambda o: None)
    with open(os.path.join(out, "extended.md"), "w") as f:
        f.write(_markdown(result))
    return result


def _chart(out: str, curves: dict) -> Optional[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 4.2))
    a.plot([p["fpr"] for p in curves["roc"]], [p["tpr"] for p in curves["roc"]], color="#2a78d6", lw=2,
           label="GhostAP (AUC {})".format(_f(curves["auc"])), drawstyle="steps-post")
    bp = curves["baseline_point"]
    if bp["fpr"] is not None:
        a.scatter([bp["fpr"]], [bp["tpr"]], color="#d03b3b", zorder=3, label="duplicate-SSID baseline")
    a.plot([0, 1], [0, 1], color="#c3c2b7", ls="--", lw=1)
    a.set(xlabel="false-positive rate", ylabel="true-positive rate (recall)", title="ROC", xlim=(0, 1), ylim=(0, 1.02))
    b.plot([p["recall"] for p in curves["pr"]], [p["precision"] for p in curves["pr"]], color="#2a78d6", lw=2,
           label="GhostAP (AP {})".format(_f(curves["average_precision"])), drawstyle="steps-post")
    if bp["precision"] is not None:
        b.scatter([bp["tpr"]], [bp["precision"]], color="#d03b3b", zorder=3, label="duplicate-SSID baseline")
    b.set(xlabel="recall", ylabel="precision", title="Precision-recall", xlim=(0, 1.02), ylim=(0, 1.02))
    for ax in (a, b):
        ax.legend(loc="lower right", fontsize=9)
        ax.grid(alpha=.3)
    fig.tight_layout()
    path = os.path.join(out, "roc_pr.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _markdown(r: dict) -> str:
    md = ["# GhostAP extended evaluation", ""]
    if r["synthetic"]:
        md += ["> These captures are **synthetic and author-designed**. The numbers show what the method does on "
               "designed cases; they are not field results.", ""]
    md += ["{} captures, {} access points, {} evil twins. Alert threshold MEDIUM >= {:g}.".format(
        r["captures"], r["aps"], r["twins"], r["threshold"]), "", "## Confidence intervals (95%)", "",
        "| Detector | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|"]
    for c in r["ci"]:
        cells = []
        for k in METRICS:
            boot = c[k + "_bootstrap"]
            wil = c[k + "_wilson"]
            cells.append("{} (W {} · B {})".format(_f(c[k]), _ci_txt(*wil), _ci_txt(*boot)))
        md.append("| {} | {} |".format(c["detector"], " | ".join(cells)))
    md += ["", "W = Wilson interval; B = bootstrap over captures (APs in one capture are not independent). "
           "With this few captures the intervals are wide: that is the honest size of the uncertainty.", ""]
    s, sr = r["split"], r["split_results"]
    md += ["## Tune / test split", "", "Tune: {} ({} twins). Test: {} ({} twins).".format(
        ", ".join(s["tune"]) or "–", s["tune_twins"], ", ".join(s["test"]) or "–", s["test_twins"]), ""]
    if sr["usable"]:
        md += ["On the test captures only: configured threshold {:g} gives F1 {}; the threshold that was best on the "
               "tune captures ({:g}) gives F1 {}; the baseline gives F1 {}.".format(
                   sr["configured_threshold"], _f(sr["test_configured"]["f1"]), sr["threshold_chosen_on_tune"],
                   _f(sr["test_tuned"]["f1"]), _f(sr["test_baseline"]["f1"])), ""]
    else:
        md += ["Not enough captures (each split needs at least one evil twin) for a meaningful split.", ""]
    cu = r["curves"]
    md += ["## ROC and precision-recall", "", "ROC AUC {} · average precision {} (GhostAP peak score per access "
           "point). The baseline has no score, so it is one point.".format(_f(cu["auc"]), _f(cu["average_precision"])),
           ""]
    if r["chart"]:
        md += ["![ROC and precision-recall]({})".format(r["chart"]), ""]
    lw = r["learned_weights"]
    md += ["## Learned weights (experiment, not used for alerts)", ""]
    if lw["usable"]:
        md += ["Logistic regression on each access point's highest indicator values, fitted on the tune captures "
               "and scored on the test captures with the same simplified score (no time window or smoothing).", "",
               "| Indicator | Configured | Learned |", "|---|---|---|"]
        md += ["| {} | {:g} | {:g} |".format(k, lw["configured"][k], lw["weights"][k]) for k in lw["configured"]]
        md += ["", "Test F1 with configured weights {} · with learned weights {}.".format(
            _f(lw["test_configured_static"]["f1"]), _f(lw["test_learned_static"]["f1"])), ""]
    else:
        md += ["Not enough data for a tune / test split.", ""]
    an = r["anomaly"]
    md += ["## Anomaly model (experiment, not used for alerts)", ""]
    if an["usable"]:
        md += ["Mahalanobis distance of each access point's indicator values from the bulk of the tune captures' "
               "access points (labels not used). Test AUC {} (GhostAP's peak score: {}).".format(
                   _f(an["test_auc"]), _f(an["ghostap_test_auc"])), ""]
    else:
        md += ["Not enough data.", ""]
    if r["kismet"]:
        md += ["## Kismet", "", "Kismet's own alerts were found next to some captures and are included in the "
               "confidence-interval table as a third detector (only on those captures).", ""]
    return "\n".join(md)
