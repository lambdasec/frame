#!/usr/bin/env python3
"""Regenerate the figures for the Frame AI-SAST report from assets/figdata.json.

    python writeup/gen_figures.py

Reads writeup/assets/figdata.json (produced from the committed ground truth +
verdict caches) and writes PNGs into writeup/assets/. Deterministic; no network.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DATA = json.loads((ASSETS / "figdata.json").read_text())

# Muted, print-friendly palette.
C_FRAME = "#2f6db3"      # Frame blue
C_FRAME2 = "#7aa8d6"
C_FRAME3 = "#b9d0e8"
C_SEM = "#d98c3f"        # Semgrep amber
C_ENDOR = "#9aa0a6"      # Endor grey
C_SYM = "#3b6ea5"
C_LLM = "#5aa469"        # LLM green
C_FP = "#c9563c"

plt.rcParams.update({
    "font.size": 10, "font.family": "DejaVu Sans",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.6,
    "figure.dpi": 150,
})


def _save(fig, name):
    fig.tight_layout()
    fig.savefig(ASSETS / name, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def fig_scoreboard():
    sb = DATA["scoreboard"]
    scanners = list(sb.keys())
    metrics = ["recall", "precision", "f1"]
    labels = ["Recall", "Precision", "F1"]
    colors = [C_FRAME, C_FRAME2, C_FRAME3]
    x = range(len(scanners))
    w = 0.26
    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    for i, (m, lab, col) in enumerate(zip(metrics, labels, colors)):
        vals = [sb[s][m] for s in scanners]
        bars = ax.bar([xi + (i - 1) * w for xi in x], vals, w, label=lab, color=col,
                      edgecolor="white", linewidth=0.5)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.008, f"{v:.2f}",
                    ha="center", va="bottom", fontsize=7.5)
    # hatch the Endor group to flag "different ground truth"
    endor_idx = scanners.index("Endor (diff GT)")
    for i in range(3):
        ax.patches[i * len(scanners) + endor_idx].set_hatch("///")
    ax.set_xticks(list(x))
    ax.set_xticklabels(scanners, fontsize=9)
    ax.set_ylim(0, 0.85)
    ax.set_ylabel("score")
    ax.set_title("Endor Labs real-world corpus (193 pooled vulnerabilities)")
    ax.legend(loc="upper right", frameon=False, ncol=3, fontsize=8.5)
    ax.text(endor_idx, 0.02, "hatched:\ndifferent GT", ha="center", va="bottom",
            fontsize=6.5, color="#555")
    _save(fig, "fig2_scoreboard.png")


def fig_ablation():
    ab = DATA["ablation"]
    x = range(len(ab["labels"]))
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    ax.plot(list(x), ab["recall"], "-o", color=C_LLM, label="Recall", linewidth=2)
    ax.plot(list(x), ab["precision"], "-s", color=C_FRAME, label="Precision", linewidth=2)
    ax.plot(list(x), ab["f1"], "-^", color=C_ENDOR, label="F1", linewidth=2)
    for xi, r, p, f in zip(x, ab["recall"], ab["precision"], ab["f1"]):
        ax.text(xi, r + 0.02, f"{r:.2f}", ha="center", fontsize=8, color=C_LLM)
        ax.text(xi, p - 0.035, f"{p:.2f}", ha="center", fontsize=8, color=C_FRAME)
        ax.text(xi, f + 0.02, f"{f:.2f}", ha="center", fontsize=8, color="#555")
    ax.set_xticks(list(x))
    ax.set_xticklabels(ab["labels"])
    ax.set_ylim(0.3, 0.8)
    ax.set_ylabel("score")
    ax.set_title("Contribution of each layer (Frame)")
    ax.legend(loc="lower right", frameon=False)
    _save(fig, "fig3_ablation.png")


def fig_triage():
    t = DATA["triage_crosstab"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(8.0, 3.6),
                                 gridspec_kw={"width_ratios": [1, 1.25]})
    # left: precision before/after
    a1.bar(["before", "after"], [t["precision_before"], t["precision_after"]],
           color=[C_ENDOR, C_FRAME], width=0.55, edgecolor="white")
    for i, v in enumerate([t["precision_before"], t["precision_after"]]):
        a1.text(i, v + 0.01, f"{v:.2f}", ha="center", fontsize=9)
    a1.set_ylim(0, 0.7)
    a1.set_ylabel("precision")
    a1.set_title("Detection precision\nwith triage")
    # right: what triage did to TPs and FPs
    cats = ["True positives", "False positives"]
    kept = [t["tp_kept"], t["fp_kept"]]
    dropped = [t["tp_dropped"], t["fp_dropped"]]
    a2.bar(cats, kept, color=C_LLM, label="kept", edgecolor="white")
    a2.bar(cats, dropped, bottom=kept, color=C_FP, label="dropped", edgecolor="white")
    for i, (k, d) in enumerate(zip(kept, dropped)):
        a2.text(i, k / 2, str(k), ha="center", va="center", color="white", fontsize=9)
        a2.text(i, k + d / 2, str(d), ha="center", va="center", color="white", fontsize=9)
    a2.set_title("Triage keeps TPs, drops FPs")
    a2.legend(loc="upper right", frameon=False, fontsize=8.5)
    _save(fig, "fig4_triage.png")


def fig_per_repo():
    pr = DATA["per_repo"]
    repos = list(pr.keys())
    disp = [r.replace("anonymous-", "anon-") for r in repos]
    sym = [pr[r]["symbolic_tp"] for r in repos]
    llm = [pr[r]["llm_detect_tp"] for r in repos]
    gt = [pr[r]["gt"] for r in repos]
    x = range(len(repos))
    fig, ax = plt.subplots(figsize=(7.8, 4.2))
    b1 = ax.bar(list(x), sym, color=C_SYM, label="found by symbolic core", edgecolor="white")
    b2 = ax.bar(list(x), llm, bottom=sym, color=C_LLM,
                label="added by LLM detection", edgecolor="white")
    ax.plot(list(x), gt, "D", color="#333", markersize=5, label="pooled ground truth")
    for xi, s, l, g in zip(x, sym, llm, gt):
        if s:
            ax.text(xi, s / 2, str(s), ha="center", va="center", color="white", fontsize=8)
        if l:
            ax.text(xi, s + l / 2, str(l), ha="center", va="center", color="white", fontsize=8)
        ax.text(xi, g + 1.2, str(g), ha="center", fontsize=7.5, color="#333")
    ax.set_xticks(list(x))
    ax.set_xticklabels(disp, fontsize=9)
    ax.set_ylabel("confirmed vulnerabilities")
    ax.set_title("Per-repository coverage: symbolic core vs LLM detection")
    ax.legend(loc="upper right", frameon=False, fontsize=8.5)
    _save(fig, "fig5_per_repo.png")


def fig_verification():
    v = DATA["verification"]
    vt, vf = v["verified_tp"], v["verified_fp"]
    ut, uf = v["unverified_tp"], v["unverified_fp"]
    vp = vt / (vt + vf) if (vt + vf) else 0
    up = ut / (ut + uf) if (ut + uf) else 0
    fig, ax = plt.subplots(figsize=(5.6, 3.8))
    bars = ax.bar(["sink-verified\ntier", "unverified\ntier"], [vp, up],
                  color=[C_FRAME, C_ENDOR], width=0.55, edgecolor="white")
    ax.text(0, vp + 0.02, f"{vp:.2f}\n({vt}/{vt + vf})", ha="center", fontsize=8.5)
    ax.text(1, up + 0.02, f"{up:.2f}\n({ut}/{ut + uf})", ha="center", fontsize=8.5)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("precision")
    ax.set_title("Sink-verification separates a high-precision tier")
    _save(fig, "fig6_verification.png")


if __name__ == "__main__":
    fig_scoreboard()
    fig_ablation()
    fig_triage()
    fig_per_repo()
    fig_verification()
    print("all figures written to", ASSETS)
