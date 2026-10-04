"""
Run the evaluation (everything except ns-3) and draw every figure.

    python scripts/run_evaluation.py            # full (~5-10 min, pure-Python backend is the slow part)
    python scripts/run_evaluation.py --quick    # fewer samples, smaller sweeps (~2 min)
    python scripts/run_evaluation.py --plots    # only redraw figures from existing CSVs

Writes CSVs and fig*.png to results/. ns-3 results come from
scripts/run_ns3_sweeps.py (Linux / WSL2) and are plotted here if present.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav.eval import consensus_eval, crypto_bench  # noqa: E402
from qrcav.eval.attacks import run_attacks  # noqa: E402
from qrcav.eval.plots import make_all  # noqa: E402


def write(path: Path, rows: list[dict]) -> None:
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {path.resolve().relative_to(ROOT)} ({len(rows)} rows)", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--plots", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    q = args.quick
    t0 = time.time()

    if not args.plots:
        print("[1/8] primitives", flush=True)
        write(out / "primitives.csv", crypto_bench.primitives(n=60 if q else 200, pure_n=10 if q else 40))
        print("[2/8] sizes", flush=True)
        write(out / "sizes.csv", crypto_bench.sizes())
        print("[3/8] handshakes", flush=True)
        write(out / "handshake_timing.csv", crypto_bench.handshakes(n=30 if q else 100, pure_n=5 if q else 15))
        print("[4/8] beacon budget", flush=True)
        write(out / "beacon_budget.csv", crypto_bench.beacon_budget(n=100 if q else 300))
        print("[5/8] attacks", flush=True)
        rows = run_attacks("DECK")
        write(out / "attacks.csv", rows)
        print(f"      {sum(r['rejected'] for r in rows)}/{len(rows)} rejected", flush=True)
        print("[6/8] consensus scaling + throughput", flush=True)
        write(out / "consensus_scaling.csv",
              consensus_eval.scaling(sizes=(8, 16) if q else (8, 12, 16, 20, 24), requests=8 if q else 20))
        write(out / "consensus_throughput.csv", consensus_eval.throughput(burst=20 if q else 60))
        print("[7/8] fault tolerance, view change", flush=True)
        write(out / "fault_tolerance.csv", consensus_eval.fault_tolerance(requests=6 if q else 15))
        write(out / "view_change.csv", consensus_eval.view_change(timeouts=(0.5,) if q else (0.5, 1.0, 2.0)))
        print("[8/8] score dynamics", flush=True)
        sd = consensus_eval.score_dynamics(requests=30 if q else 60)
        (out / "score_dynamics.json").write_text(json.dumps(sd, indent=1))
    figs = make_all(out)
    print(f"figures: {', '.join(figs)}")
    print(f"done in {time.time() - t0:.0f} s -> {out}")


if __name__ == "__main__":
    main()
