"""Evaluation statistics (F048, F049, F084, F085).

  wilson / bootstrap   confidence intervals; the bootstrap resamples whole captures,
                       because access points in one capture are not independent
  split                deterministic tune / test split by capture name
  roc / pr             curves over GhostAP's peak score, with AUC and average precision
  learn_weights        logistic regression on per-AP indicator maxima, fitted on the
                       tune split only, scored on the test split only (F084)
  anomaly              unsupervised Mahalanobis score of the same features (F085)

The learned weights and the anomaly score are experiments for the report: GhostAP's
alerts always use the configured weights. Neither may be tuned on the data you report.
"""
from __future__ import annotations

import hashlib
import math
import random
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

Z95 = 1.959963984540054


# --------------------------------------------------------------------------- intervals
def wilson(k: int, n: int, z: float = Z95) -> Tuple[Optional[float], Optional[float]]:
    """Wilson score interval for a proportion k/n (good for small n and 0 or n)."""
    if n == 0:
        return None, None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, centre - half), min(1.0, centre + half)


def bootstrap(rows: List[dict], metric: Callable[[List[dict]], Optional[float]], groups_key: str = "scenario",
              b: int = 2000, seed: int = 7) -> Tuple[Optional[float], Optional[float]]:
    """95% percentile interval, resampling whole captures with replacement."""
    groups: Dict[str, List[dict]] = {}
    for r in rows:
        groups.setdefault(r[groups_key], []).append(r)
    names = sorted(groups)
    if len(names) < 2:
        return None, None
    rnd = random.Random(seed)
    vals = []
    for _ in range(b):
        sample = [r for name in rnd.choices(names, k=len(names)) for r in groups[name]]
        v = metric(sample)
        if v is not None:
            vals.append(v)
    if len(vals) < b * 0.5:
        return None, None
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[min(len(vals) - 1, int(0.975 * len(vals)))]


# --------------------------------------------------------------------------- splits
def split(names: Sequence[str], test_fraction: float = 0.5, salt: str = "ghostap") -> Dict[str, str]:
    """name -> "tune" | "test", stable across runs and machines (hash of the name)."""
    out = {}
    for n in names:
        h = int(hashlib.sha256((salt + ":" + n).encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        out[n] = "test" if h < test_fraction else "tune"
    return out


# --------------------------------------------------------------------------- curves
def roc(scores: Sequence[float], labels: Sequence[int]) -> Tuple[List[Tuple[float, float, float]], Optional[float]]:
    """[(threshold, fpr, tpr)] from high to low threshold, and the area under the curve."""
    pos = sum(labels)
    neg = len(labels) - pos
    if not pos or not neg:
        return [], None
    pts = [(math.inf, 0.0, 0.0)]
    order = sorted(zip(scores, labels), key=lambda x: -x[0])
    tp = fp = 0
    i = 0
    while i < len(order):
        t = order[i][0]
        while i < len(order) and order[i][0] == t:          # ties move together
            tp += order[i][1]
            fp += 1 - order[i][1]
            i += 1
        pts.append((t, fp / neg, tp / pos))
    auc = sum((x2 - x1) * (y1 + y2) / 2 for (_, x1, y1), (_, x2, y2) in zip(pts, pts[1:]))
    return pts, auc


def pr(scores: Sequence[float], labels: Sequence[int]) -> Tuple[List[Tuple[float, float, float]], Optional[float]]:
    """[(threshold, recall, precision)] and average precision (step-wise, no interpolation)."""
    pos = sum(labels)
    if not pos:
        return [], None
    order = sorted(zip(scores, labels), key=lambda x: -x[0])
    pts, ap, tp, fp, prev_r = [], 0.0, 0, 0, 0.0
    i = 0
    while i < len(order):
        t = order[i][0]
        while i < len(order) and order[i][0] == t:
            tp += order[i][1]
            fp += 1 - order[i][1]
            i += 1
        r, p = tp / pos, tp / (tp + fp)
        ap += (r - prev_r) * p
        prev_r = r
        pts.append((t, r, p))
    return pts, ap


# --------------------------------------------------------------------------- learned weights (F084)
def learn_weights(x: np.ndarray, y: np.ndarray, names: Sequence[str], total: float,
                  l2: float = 0.05, steps: int = 4000, lr: float = 0.5) -> Dict[str, float]:
    """Non-negative logistic-regression weights, rescaled to sum to `total` like the
    configured ones. Features are indicator values in [0, 1]."""
    n, d = x.shape
    w = np.full(d, 0.1)
    bias = 0.0
    for _ in range(steps):
        z = x @ w + bias
        p = 1 / (1 + np.exp(-np.clip(z, -30, 30)))
        g = p - y
        w -= lr * (x.T @ g / n + l2 * w)
        bias -= lr * g.mean()
        w = np.maximum(w, 0.0)                    # an indicator may not count *against* a twin
    s = w.sum()
    if s <= 0:
        return {k: 0.0 for k in names}
    return {k: round(float(v) * total / s, 2) for k, v in zip(names, w)}


def static_score(features: Dict[str, float], weights: Dict[str, float]) -> float:
    """Σwx/Σw×100 on one access point's indicator maxima (no time window, no smoothing)."""
    tw = sum(weights.values())
    return 100.0 * sum(weights[k] * features.get(k, 0.0) for k in weights) / tw if tw else 0.0


# --------------------------------------------------------------------------- anomaly model (F085)
class Anomaly:
    """Mahalanobis distance from the bulk of access points (no labels used).
    Covariance is shrunk towards its diagonal so a handful of APs still works."""

    def __init__(self, x: np.ndarray, shrink: float = 0.5):
        self.mu = x.mean(axis=0)
        cov = np.cov(x, rowvar=False) if len(x) > 1 else np.eye(x.shape[1])
        cov = np.atleast_2d(cov)
        cov = (1 - shrink) * cov + shrink * np.diag(np.diag(cov)) + 1e-3 * np.eye(cov.shape[0])
        self.inv = np.linalg.inv(cov)

    def score(self, x: np.ndarray) -> np.ndarray:
        d = x - self.mu
        return np.sqrt(np.einsum("ij,jk,ik->i", d, self.inv, d))


def auc_of(scores: Sequence[float], labels: Sequence[int]) -> Optional[float]:
    return roc(scores, labels)[1]
