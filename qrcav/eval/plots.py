"""
Figures for the report. Static PNGs (matplotlib), one consistent style:
thin marks, recessive grid, a legend for every multi-series chart plus direct
labels where they fit, colours assigned to suites in a fixed order.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
# fixed categorical order (validated reference palette, light mode)
SUITE_COLOR = {"CLASSIC": "#2a78d6", "L1": "#eb6834", "L3": "#1baf7a", "DECK": "#eda100", "L5": "#e87ba4"}
SUITE_LABEL = {
    "CLASSIC": "Classical ECDH+ECDSA P-256",
    "L1": "L1 ML-KEM-512+ML-DSA-44",
    "L3": "L3 ML-KEM-768+ML-DSA-65",
    "DECK": "Deck ML-KEM-1024+ML-DSA-65",
    "L5": "L5 ML-KEM-1024+ML-DSA-87",
}
ORDER = ["CLASSIC", "L1", "L3", "DECK", "L5"]
MODE_COLOR = {"ags": "#2a78d6", "ags-noshadow": "#1baf7a", "pbft": "#eb6834"}
MODE_LABEL = {"ags": "AGS-PBFT", "ags-noshadow": "AGS-PBFT, no shadow validation", "pbft": "PBFT"}


def _style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False, "font.size": 10,
        "axes.titlesize": 11.5, "axes.titleweight": "bold", "axes.titlecolor": INK,
        "axes.titlelocation": "left", "legend.frameon": False, "lines.linewidth": 2,
        "figure.dpi": 140,
    })


def read_csv(p: Path) -> list[dict]:
    if not p.exists():
        return []
    with p.open() as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            try:
                r[k] = float(v) if v not in ("True", "False") else v == "True"
            except (TypeError, ValueError):
                pass
    return rows


def _save(fig, out: Path, name: str):
    fig.tight_layout()
    fig.savefig(out / name)
    plt.close(fig)


def fig_handshake_time(res: Path, out: Path):
    rows = read_csv(res / "handshake_timing.csv")
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    suites = [s for s in ORDER if any(r["suite"] == s for r in rows)]
    w = 0.38
    for j, be in enumerate(["openssl", "pure"]):
        xs, ys = [], []
        for i, s in enumerate(suites):
            r = next((r for r in rows if r["suite"] == s and str(r["backend"]).startswith(be)), None)
            if r is None and be == "pure" and s == "L1":
                r = next((r for r in rows if r["suite"] == s and "pure" in str(r["backend"])), None)
            if r:
                xs.append(i + (j - 0.5) * w)
                ys.append(r["mean_ms"])
        bars = ax.bar(xs, ys, w * 0.92, color=["#2a78d6", "#eb6834"][j],
                      label={"openssl": "native (OpenSSL)", "pure": "pure Python"}[be])
        for x, y in zip(xs, ys):
            ax.text(x, y * 1.12, f"{y:.1f}" if y < 100 else f"{y:.0f}", ha="center", fontsize=8, color=INK2)
    ax.set_yscale("log")
    ax.set_xticks(range(len(suites)), [s if s != "DECK" else "DECK\n(review 1)" for s in suites])
    ax.set_ylabel("full handshake, ms (log)")
    ax.set_title("Full mutual handshake: compute time, both sides")
    ax.legend(loc="upper left")
    _save(fig, out, "fig1_handshake_compute.png")


def fig_handshake_size(res: Path, out: Path):
    rows = read_csv(res / "sizes.csv")
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    parts = [("client_hello", "ClientHello", "#2a78d6"), ("server_hello", "ServerHello", "#eb6834"),
             ("client_key", "ClientKey+Finished", "#1baf7a"), ("server_finished", "ServerFinished", "#4a3aa7")]
    suites = [s for s in ORDER if any(r["suite"] == s for r in rows)]
    bottoms = [0.0] * len(suites)
    for key, label, col in parts:
        vals = [next(r for r in rows if r["suite"] == s)[key] / 1024 for s in suites]
        ax.bar(range(len(suites)), vals, 0.6, bottom=bottoms, color=col, label=label,
               edgecolor=SURFACE, linewidth=1.5)
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    for i, s in enumerate(suites):
        r = next(r for r in rows if r["suite"] == s)
        ax.text(i, bottoms[i] + 0.4, f"{r['handshake_total'] / 1024:.1f} KB\n{int(r['frames'])} frames",
                ha="center", fontsize=8.5, color=INK)
    ax.set_xticks(range(len(suites)), suites)
    ax.set_ylabel("bytes on the air, KB")
    ax.set_ylim(0, max(bottoms) * 1.25)
    ax.set_title("Handshake size by flight (certificates included)")
    ax.legend(loc="upper left", ncol=2, fontsize=8.5)
    _save(fig, out, "fig2_handshake_size.png")


def fig_beacon_budget(res: Path, out: Path):
    rows = [r for r in read_csv(res / "beacon_budget.csv") if r["backend"] in ("openssl", "pure+openssl")]
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    suites = [s for s in ORDER if any(r["suite"] == s for r in rows)]
    w = 0.38
    for j, mode in enumerate(["AEAD (session)", "signed (broadcast)"]):
        ys = [next(r for r in rows if r["suite"] == s and r["mode"] == mode)["total_p99_ms"] for s in suites]
        xs = [i + (j - 0.5) * w for i in range(len(suites))]
        ax.bar(xs, ys, w * 0.92, color=["#2a78d6", "#eb6834"][j], label=mode + ", p99 crypto + airtime")
        for x, y in zip(xs, ys):
            ax.text(x, y * 1.12, f"{y:.2f}", ha="center", fontsize=8, color=INK2)
    ax.axhline(100, color=INK2, lw=1, ls="--")
    ax.text(len(suites) - 0.5, 115, "100 ms beacon interval", ha="right", fontsize=8.5, color=INK2)
    ax.set_yscale("log")
    ax.set_ylim(0.01, 400)
    ax.set_xticks(range(len(suites)), suites)
    ax.set_ylabel("per-beacon cost, ms (log)")
    ax.set_title("Per-beacon cost against the 100 ms budget (native backend)")
    ax.legend(loc="upper left", bbox_to_anchor=(0, 0.86), fontsize=8.5)
    _save(fig, out, "fig3_beacon_budget.png")


def fig_consensus_scaling(res: Path, out: Path):
    rows = read_csv(res / "consensus_scaling.csv")
    if not rows:
        return
    fig, axs = plt.subplots(1, 3, figsize=(12, 3.7))
    for mode in ("pbft", "ags", "ags-noshadow"):
        rs = sorted([r for r in rows if r["mode"] == mode], key=lambda r: r["nodes"])
        if not rs:
            continue
        x = [r["nodes"] for r in rs]
        for ax, key in zip(axs, ("msgs_per_req", "kbytes_per_req", "latency_p50_ms")):
            ax.plot(x, [r[key] for r in rs], marker="o", ms=5, color=MODE_COLOR[mode], label=MODE_LABEL[mode])
    for a, t, yl in ((axs[0], "Messages per request", "messages"),
                     (axs[1], "Bytes per request", "KB"),
                     (axs[2], "Commit latency, median (1 ms LAN)", "ms")):
        a.set_title(t, fontsize=10.5)
        a.set_xlabel("validator nodes")
        a.set_ylabel(yl)
    axs[2].set_ylim(bottom=0)
    axs[0].legend(loc="upper left", fontsize=8)
    _save(fig, out, "fig4_consensus_scaling.png")


def fig_score_dynamics(res: Path, out: Path):
    p = res / "score_dynamics.json"
    if not p.exists():
        return
    d = json.loads(p.read_text())
    tr = d["trace"]
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    nodes = sorted({r["node"] for r in tr})
    blocks = sorted({r["block"] for r in tr})
    mu = [next(r["mu"] for r in tr if r["block"] == b) for b in blocks]
    sd = [next(r["sigma"] for r in tr if r["block"] == b) for b in blocks]
    ax.fill_between(blocks, [m - s for m, s in zip(mu, sd)], [m + s for m, s in zip(mu, sd)],
                    color="#e4e3df", alpha=0.7, lw=0, label="mu +/- sigma")
    for n in nodes:
        ys = [r["score"] for r in tr if r["node"] == n]
        if n == d["wrong"]:
            ax.plot(blocks, ys, color="#eb6834", label=f"{n} (wrong result)")
        elif n == d["silent"]:
            ax.plot(blocks, ys, color="#4a3aa7", label=f"{n} (silent)")
        else:
            ax.plot(blocks, ys, color="#9a9994", lw=0.9, alpha=0.6)
    ax.plot([], [], color="#9a9994", lw=0.9, label="honest nodes")
    for g in d["regroups"]:
        ax.axvline(g["b_id"], color=INK2, lw=0.8, ls=":")
    ax.set_xlabel("block")
    ax.set_ylabel("AGS score")
    ax.set_title("Score dynamics: +1 agree, -5 disagree, regroup every 10 blocks")
    ax.legend(loc="lower left", fontsize=8.5)
    _save(fig, out, "fig5_score_dynamics.png")


def fig_fault_tolerance(res: Path, out: Path):
    rows = read_csv(res / "fault_tolerance.csv")
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    x = [r["byzantine"] for r in rows]
    ax.bar(x, [r["commit_pct"] for r in rows], 0.6, color=["#2a78d6" if r["within_bound"] else "#eb6834"
                                                         for r in rows])
    f = rows[0]["f"]
    ax.axvline(f + 0.5, color=INK2, lw=1, ls="--")
    ax.text(f + 0.6, 104, f"f = {int(f)} (n = {int(rows[0]['consensus_set'])})", fontsize=8.5, color=INK2)
    for r in rows:
        ax.text(r["byzantine"], r["commit_pct"] + 2, "safe" if r["safety"] else "UNSAFE", ha="center",
                fontsize=8, color=INK2)
    ax.set_ylim(0, 115)
    ax.set_xlabel("colluding Byzantine nodes in the consensus set")
    ax.set_ylabel("requests committed, %")
    ax.set_title("Fault tolerance: liveness lost beyond f, safety kept")
    _save(fig, out, "fig6_fault_tolerance.png")


def _agg(rows, key):
    """(suite, vehicles) -> (mean, min, max) across seeds."""
    groups: dict = {}
    for r in rows:
        if str(r.get("backend")) == "pure":
            continue
        groups.setdefault((str(r["suite"]), int(r["vehicles"])), []).append(float(r[key]))
    return {k: (sum(v) / len(v), min(v), max(v), len(v)) for k, v in groups.items()}


def _ns3_lines(ax, rows, key, ylabel, title, log=False, budget=None):
    agg = _agg(rows, key)
    for s in ORDER:
        pts = sorted((v, m) for (su, v), m in agg.items() if su == s)
        if not pts:
            continue
        x = [p[0] for p in pts]
        mean = [p[1][0] for p in pts]
        lo = [p[1][0] - p[1][1] for p in pts]
        hi = [p[1][2] - p[1][0] for p in pts]
        ax.errorbar(x, mean, yerr=[lo, hi], marker="o", ms=5, color=SUITE_COLOR[s], label=SUITE_LABEL[s],
                    capsize=3, elinewidth=1, lw=2)
    if budget:
        ax.axhline(budget, color=INK2, lw=1, ls="--")
    if log:
        ax.set_yscale("log")
    seeds = max((m[3] for m in agg.values()), default=1)
    ax.set_xlabel(f"vehicles (2.25 km$^2$, 9 RSUs)" + (f"; mean of {seeds} seeds, bars = min-max" if seeds > 1 else ""))
    ax.set_ylabel(ylabel)
    ax.set_title(title)


def fig_ns3(res: Path, out: Path):
    rows = read_csv(res / "ns3_density.csv") + read_csv(res / "ns3_density_seeds.csv")
    if not rows:
        return
    fig, axs = plt.subplots(1, 2, figsize=(10, 3.8))
    _ns3_lines(axs[0], rows, "hs_p50_ms", "ms (log)", "Handshake completion time, median", log=True)
    _ns3_lines(axs[1], rows, "hs_p95_ms", "ms (log)", "Handshake completion time, p95", log=True)
    axs[1].legend(fontsize=7.5, loc="lower right")
    _save(fig, out, "fig7_ns3_handshake_latency.png")
    fig, axs = plt.subplots(1, 2, figsize=(10, 3.8))
    _ns3_lines(axs[0], rows, "handshake_success_pct", "%", "Handshakes completed")
    axs[0].set_ylim(0, 105)
    _ns3_lines(axs[1], rows, "airtime_pct", "% of one channel (sum over cells)", "Aggregate channel airtime")
    axs[0].legend(fontsize=7.5, loc="lower left")
    _save(fig, out, "fig8_ns3_success_airtime.png")
    fig, axs = plt.subplots(1, 2, figsize=(10, 3.8))
    _ns3_lines(axs[0], rows, "beacon_coverage_pct", "%", "Beacon slots with a live session")
    _ns3_lines(axs[1], rows, "alert_p50_ms", "ms", "Critical event -> alert at the reporter, median")
    axs[0].legend(fontsize=7.5, loc="lower left")
    _save(fig, out, "fig9_ns3_coverage_alert.png")


def fig_ns3_ablation(res: Path, out: Path):
    rows = read_csv(res / "ns3_variants.csv")
    deck = [r for r in rows if str(r.get("suite")) == "DECK" and str(r.get("backend")) == "openssl"
            and not r.get("signed_beacons")]
    if not deck:
        return
    def pick(e, b):
        return next((r for r in deck if bool(r.get("edca")) == e and bool(r.get("backoff")) == b), None)
    cases = [("neither", pick(False, False)), ("backoff only", pick(False, True)),
             ("EDCA only", pick(True, False)), ("EDCA + backoff", pick(True, True))]
    cases = [(n, r) for n, r in cases if r]
    if len(cases) < 2:
        return
    fig, axs = plt.subplots(1, 3, figsize=(11, 3.6))
    metrics = [("handshake_success_pct", "Handshakes completed, %"),
               ("beacon_coverage_pct", "Beacon slots with a session, %"),
               ("alert_p50_ms", "Event -> alert, median ms")]
    for ax, (k, t) in zip(axs, metrics):
        vals = [r[k] for _, r in cases]
        ax.bar(range(len(cases)), vals, 0.6, color=["#9a9994"] * (len(cases) - 1) + ["#2a78d6"])
        for i, v in enumerate(vals):
            ax.text(i, v * 1.02 + 0.5, f"{v:.0f}" if v >= 10 else f"{v:.1f}", ha="center", fontsize=8.5, color=INK)
        ax.set_xticks(range(len(cases)), [n for n, _ in cases], fontsize=8, rotation=15)
        ax.set_title(t, fontsize=10)
    v = int(cases[0][1]["vehicles"])
    fig.suptitle(f"DECK suite, {v} vehicles: what EDCA priority and handshake backoff each contribute",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK)
    _save(fig, out, "fig10_ns3_ablation.png")


def make_all(res: Path, out: Path | None = None) -> list[str]:
    _style()
    out = out or res
    out.mkdir(parents=True, exist_ok=True)
    for f in (fig_handshake_time, fig_handshake_size, fig_beacon_budget, fig_consensus_scaling,
              fig_score_dynamics, fig_fault_tolerance, fig_ns3, fig_ns3_ablation):
        f(res, out)
    return sorted(p.name for p in out.glob("fig*.png"))
