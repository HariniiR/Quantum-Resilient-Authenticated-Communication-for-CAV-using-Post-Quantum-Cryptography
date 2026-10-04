#!/usr/bin/env python3
"""
Run the full evaluation.

    ./.venv/bin/python run_evaluation.py

Writes CSV files and figures to results/.
"""

from __future__ import annotations

from cavpqc import PAPER_CITATION
from cavpqc.benchmark import (
    attack_tests,
    benchmark_beacon_path,
    benchmark_classical,
    benchmark_consensus,
    benchmark_fault_tolerance,
    benchmark_primitives,
    benchmark_sizes,
    table,
    write_csv,
)
from cavpqc.network import Link80211p
from cavpqc.simulation import density_sweep


def hr(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main() -> None:
    print("Quantum-resilient secure communication for CAVs")
    print("Base paper:", PAPER_CITATION)
    print("Corrections: D1 signatures, D2/D3 key schedule, D4 escrow, D5 ledger, D6 thresholds")

    hr("1. POST-QUANTUM PRIMITIVES (paper section 7.1)")
    prim = benchmark_primitives()
    print(table(prim, ["level", "operation", "mean_ms", "sd_ms"]))
    write_csv("primitives.csv", prim)

    hr("2. CLASSICAL BASELINE - the schemes V2X uses today")
    clas = benchmark_classical()
    print(table(clas, ["operation", "mean_ms", "sd_ms"]))
    write_csv("classical_baseline.csv", clas)

    hr("3. ARTIFACT SIZES AND 802.11p FRAME COST")
    sizes = benchmark_sizes()
    print(table(sizes, ["level", "kem", "sig", "kem_pk", "sig_len",
                        "handshake_flight_bytes", "frames_1500B", "airtime_ms"]))
    write_csv("sizes.csv", sizes)
    print("\nLink model:", Link80211p().summary())

    hr("4. REAL-TIME BEACON PATH vs THE 100 ms BUDGET")
    print("The handshake runs once per RSU association. Only this path runs every 100 ms.\n")
    beacon = benchmark_beacon_path()
    print(table(beacon, ["mode", "crypto_ms", "sd_ms", "airtime_ms", "total_ms", "fits_100ms"]))
    write_csv("beacon_path.csv", beacon)

    hr("5. AGS-PBFT vs TEXTBOOK PBFT (paper section 7.4)")
    cons = benchmark_consensus()
    print(table(cons, ["nodes", "ags_consensus_set", "ags_msgs_per_req",
                       "plain_msgs_per_req", "msg_reduction_pct",
                       "ags_ms_per_req", "chain_valid"]))
    write_csv("consensus.csv", cons)

    hr("6. BYZANTINE FAULT TOLERANCE (colluding faults forced into the active set)")
    ft = benchmark_fault_tolerance()
    print(table(ft, ["byzantine", "consensus_set", "honest", "f_bound", "quorum_2f1",
                     "safety_ok", "liveness_ok", "commit_rate_pct"]))
    write_csv("fault_tolerance.csv", ft)

    hr("7. SECURITY EVALUATION (paper section 6)")
    atk = attack_tests()
    print(table(atk, ["attack", "rejected", "note"]))
    write_csv("attacks.csv", atk)
    failed = [a["attack"] for a in atk if not a["rejected"]]
    print("\nAll attacks rejected." if not failed else f"\nFAILED: {failed}")

    hr("8. DENSITY SWEEP, 50-300 VEHICLES (paper sections 7.2-7.4)")
    sweep = density_sweep(verbose=True)
    rows = []
    for r in sweep:
        lat = r.latency_summary()
        ov = r.overhead_summary()
        rows.append({
            "vehicles": r.config.vehicles,
            "rsus": r.config.rsus,
            "handshakes": len(r.handshake_ms),
            "out_of_range": r.out_of_range,
            "hs_mean_ms": round(lat.get("mean_ms", 0), 1),
            "hs_p95_ms": round(lat.get("p95_ms", 0), 1),
            "frames": round(ov.get("mean_frames", 0), 1),
            "throughput_kbps": round(r.throughput_bps() / 1000, 1),
            "blocks": r.consensus.get("blocks", 0),
            "msgs_per_req": round(r.consensus.get("messages_per_request", 0), 1),
        })
    print()
    print(table(rows))
    write_csv("density_sweep.csv", rows)

    # -- figures ---------------------------------------------------------
    try:
        make_figures(prim, sizes, beacon, cons, ft, rows)
        print("\nFigures written to results/")
    except Exception as e:  # pragma: no cover
        print(f"\n(figure generation skipped: {e})")

    hr("SUMMARY")
    aead = next(b for b in beacon if b["mode"] == "AEAD only")
    signed = [b for b in beacon if b["mode"].startswith("signed")]
    print(f"Beacon, AEAD only        : {aead['total_ms']:.2f} ms   fits 100 ms: {aead['fits_100ms']}")
    for s in signed:
        print(f"Beacon, {s['mode']:<17}: {s['total_ms']:.2f} ms   fits 100 ms: {s['fits_100ms']}")
    print(f"\nHandshake flight (L3)    : {sizes[1]['handshake_flight_bytes']} B "
          f"= {sizes[1]['frames_1500B']} frames")
    print(f"Classical equivalent     : {sizes[-1]['handshake_flight_bytes']} B "
          f"= {sizes[-1]['frames_1500B']} frame")
    print(f"Consensus message saving : {cons[-1]['msg_reduction_pct']}% at "
          f"{cons[-1]['nodes']} nodes")
    print(f"Attacks rejected         : {sum(a['rejected'] for a in atk)}/{len(atk)}")


def make_figures(prim, sizes, beacon, cons, ft, sweep_rows) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from pathlib import Path
    out = Path("results")
    out.mkdir(exist_ok=True)
    NAVY, CYAN, AMBER = "#0B1437", "#29D3F2", "#FFB000"

    def style(ax, title, xl, yl):
        ax.set_title(title, fontsize=11, weight="bold")
        ax.set_xlabel(xl, fontsize=9)
        ax.set_ylabel(yl, fontsize=9)
        ax.grid(alpha=0.25, linestyle=":")
        ax.tick_params(labelsize=8)

    # Figure 1 - primitive cost by security level
    fig, ax = plt.subplots(figsize=(9, 4.2))
    ops = ["keygen", "encaps", "decaps", "sign", "verify"]
    levels = ["L1", "L3", "L5"]
    width = 0.26
    for i, lv in enumerate(levels):
        vals = []
        for op in ops:
            match = [r for r in prim if r["level"] == lv and r["operation"].endswith(op)]
            vals.append(match[0]["mean_ms"] if match else 0)
        ax.bar([x + i * width for x in range(len(ops))], vals, width,
               label=lv, color=[NAVY, CYAN, AMBER][i])
    ax.set_xticks([x + width for x in range(len(ops))])
    ax.set_xticklabels(ops)
    style(ax, "Post-quantum primitive cost by security level", "operation", "mean time (ms)")
    ax.legend(fontsize=8, title="NIST level")
    fig.tight_layout(); fig.savefig(out / "fig1_primitives.png", dpi=160); plt.close(fig)

    # Figure 2 - the key figure: beacon path against the 100 ms budget
    fig, ax = plt.subplots(figsize=(9, 4.2))
    labels = [b["mode"] for b in beacon]
    crypto = [b["crypto_ms"] for b in beacon]
    air = [b["airtime_ms"] for b in beacon]
    x = range(len(labels))
    ax.bar(x, crypto, 0.55, label="crypto", color=NAVY)
    ax.bar(x, air, 0.55, bottom=crypto, label="802.11p airtime", color=CYAN)
    ax.axhline(100, color="crimson", linestyle="--", linewidth=1.6,
               label="100 ms beacon budget")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, fontsize=8, rotation=12)
    style(ax, "Per-beacon cost against the V2X real-time budget", "", "time (ms)")
    ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "fig2_beacon_budget.png", dpi=160); plt.close(fig)

    # Figure 3 - handshake size and frames
    fig, ax = plt.subplots(figsize=(9, 4.2))
    lv = [s["level"] for s in sizes]
    by = [s["handshake_flight_bytes"] for s in sizes]
    bars = ax.bar(lv, by, 0.55, color=[NAVY, NAVY, NAVY, AMBER])
    for b, s in zip(bars, sizes):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 150,
                f"{s['frames_1500B']} frame(s)", ha="center", fontsize=8)
    ax.axhline(1500, color="crimson", linestyle="--", linewidth=1.2, label="one 1500 B frame")
    style(ax, "Handshake flight size and 802.11p frame count", "suite", "bytes")
    ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "fig3_handshake_size.png", dpi=160); plt.close(fig)

    # Figure 4 - consensus overhead
    fig, ax = plt.subplots(figsize=(9, 4.2))
    n = [c["nodes"] for c in cons]
    ax.plot(n, [c["plain_msgs_per_req"] for c in cons], "o-", color=AMBER, label="PBFT")
    ax.plot(n, [c["ags_msgs_per_req"] for c in cons], "s-", color=CYAN, label="AGS-PBFT")
    style(ax, "Consensus messages per request", "consensus nodes", "messages")
    ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "fig4_consensus.png", dpi=160); plt.close(fig)

    # Figure 5 - Byzantine fault tolerance
    fig, ax = plt.subplots(figsize=(9, 4.2))
    b = [r["byzantine"] for r in ft]
    ax.bar(b, [r["commit_rate_pct"] for r in ft], 0.55,
           color=[CYAN if r["liveness_ok"] else "crimson" for r in ft])
    safe = [r["byzantine"] for r in ft if r["safety_ok"]]
    live = [r["byzantine"] for r in ft if r["liveness_ok"]]
    if safe:
        ax.axvline(max(safe) + 0.5, color=NAVY, linestyle="--", linewidth=1.4,
                   label="safety bound (n >= 3f+1)")
    if live:
        ax.axvline(max(live) + 0.5, color=AMBER, linestyle="-.", linewidth=1.6,
                   label="liveness bound (honest >= 2f+1)")
    style(ax, "Commit rate vs colluding Byzantine nodes in the active consensus set",
          "Byzantine nodes", "requests committed (%)")
    ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "fig5_fault_tolerance.png", dpi=160); plt.close(fig)

    # Figure 6 - density sweep
    fig, ax1 = plt.subplots(figsize=(9, 4.2))
    v = [r["vehicles"] for r in sweep_rows]
    ax1.plot(v, [r["hs_mean_ms"] for r in sweep_rows], "o-", color=NAVY,
             label="handshake mean")
    ax1.plot(v, [r["hs_p95_ms"] for r in sweep_rows], "^--", color="crimson",
             label="handshake p95")
    style(ax1, "Handshake latency and throughput vs vehicle density",
          "vehicles", "latency (ms)")
    ax2 = ax1.twinx()
    ax2.plot(v, [r["throughput_kbps"] for r in sweep_rows], "s-", color=CYAN,
             label="throughput")
    ax2.set_ylabel("throughput (kbps)", fontsize=9)
    ax2.tick_params(labelsize=8)
    h1, l1 = ax1.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, fontsize=8, loc="upper left")
    fig.tight_layout(); fig.savefig(out / "fig6_density.png", dpi=160); plt.close(fig)


if __name__ == "__main__":
    main()
