#!/usr/bin/env python3
"""Draw docs/figures/architecture.png (system architecture for the report)."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

INK, INK2, MUTED, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#c3c2b7", "#fcfcfb"
ACCENT, ACCENT_BG = "#2a78d6", "#e8f1fc"

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "figures", "architecture.png")

# (key, x, y, title, subtitle, highlighted)
W, H = 2.0, 1.05
BOXES = [
    ("src", 0.0, 2.6, "Monitor-mode NIC\nor pcap file", "beacons + probe responses", False),
    ("col", 2.6, 2.6, "Collector", "collector.py / parser.py\nScapy, passive", False),
    ("db", 5.2, 2.6, "SQLite", "observations\nap_profiles", False),
    ("ind", 7.8, 2.6, "Indicators", "indicators.py\nbaseline + 7 indicators", True),
    ("risk", 7.8, 0.6, "Risk engine", "risk.py · config.yaml\nweights, smoothing, levels", True),
    ("alerts", 5.2, 0.6, "Alerts", "reasons, contributions,\nbenign causes", False),
    ("web", 2.6, 0.6, "Flask API", "web.py · pipeline.py\nreplay / live rescoring", False),
    ("ui", 0.0, 0.6, "Dashboard", "Plotly: alerts, detail,\ntimeline, AP table", False),
    ("eval", 10.4, 0.6, "Evaluation", "evaluate.py\nmetrics + charts", False),
]
ARROWS = [("src", "col"), ("col", "db"), ("db", "ind"), ("ind", "risk"),
          ("risk", "alerts"), ("alerts", "web"), ("web", "ui"), ("risk", "eval")]


def main():
    fig, ax = plt.subplots(figsize=(12.4, 4.4))
    fig.patch.set_facecolor(SURFACE)
    ax.set_xlim(-0.2, 12.6)
    ax.set_ylim(0.2, 4.0)
    ax.axis("off")
    pos = {}
    for key, x, y, title, sub, hi in BOXES:
        ax.add_patch(FancyBboxPatch((x, y), W, H, boxstyle="round,pad=0.02,rounding_size=0.08",
                                    linewidth=1.6 if hi else 1.0,
                                    edgecolor=ACCENT if hi else AXIS,
                                    facecolor=ACCENT_BG if hi else "white"))
        ax.text(x + W / 2, y + H - 0.2, title, ha="center", va="top", fontsize=10.5,
                fontweight="bold", color=INK, linespacing=1.1)
        ax.text(x + W / 2, y + 0.12, sub, ha="center", va="bottom", fontsize=8,
                color=INK2, linespacing=1.15)
        pos[key] = (x, y)

    def anchor(a, b):
        (ax_, ay), (bx, by) = pos[a], pos[b]
        if abs(ay - by) < 1e-6:  # same row
            if bx > ax_:
                return (ax_ + W, ay + H / 2), (bx, by + H / 2)
            return (ax_, ay + H / 2), (bx + W, by + H / 2)
        return (ax_ + W / 2, ay), (bx + W / 2, by + H)

    for a, b in ARROWS:
        p, q = anchor(a, b)
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=13,
                                     color=MUTED, linewidth=1.3, shrinkA=2, shrinkB=2))

    ax.text(0.0, 3.85, "Capture and storage", fontsize=9, color=MUTED)
    ax.text(0.0, 1.85, "Scoring, alerting and presentation", fontsize=9, color=MUTED)
    fig.tight_layout()
    fig.savefig(OUT, dpi=180)
    print("[+] wrote", OUT)


if __name__ == "__main__":
    main()
