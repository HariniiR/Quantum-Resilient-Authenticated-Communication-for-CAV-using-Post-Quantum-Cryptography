"""
Run the ns-3 experiments and write results/ns3_*.csv plus the raw samples
used by the figures.

    python scripts/run_ns3_sweeps.py              # full: 5 suites x 50-200 vehicles (~20 min on 2 cores)
    python scripts/run_ns3_sweeps.py --quick      # 2 suites x 50,100 vehicles
    python scripts/run_ns3_sweeps.py --vehicles 50 100 200 300

Linux or WSL2 only (needs `pip install ns3`).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav.eval.ns3_sweeps import density_jobs, run_many, write_rows  # noqa: E402
from qrcav.sim.ns3_runner import ns3_available  # noqa: E402
from qrcav.sim.profile import load_or_build  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--vehicles", type=int, nargs="*")
    ap.add_argument("--suites", nargs="*")
    ap.add_argument("--sim-time", type=float, default=30.0)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--seeds", type=int, nargs="*",
                    help="extra seeds for the density sweep only; rows go to ns3_density_seeds.csv")
    args = ap.parse_args()
    if not ns3_available():
        sys.exit("ns-3 Python bindings not found. On Linux / WSL2:  pip install ns3")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    prof_dir = out / "profiles"
    suites = args.suites or (["CLASSIC", "DECK"] if args.quick else ["CLASSIC", "L1", "L3", "DECK", "L5"])
    vehicles = args.vehicles or ([50, 100] if args.quick else [50, 100, 150, 200])

    t0 = time.time()
    print(f"[ns3] building measurement profiles for {suites} ...", flush=True)
    paths = {}
    for s in suites:
        load_or_build(s, "auto", prof_dir)
        paths[s] = str(prof_dir / f"profile_{s}_auto.json")
    if "DECK" in suites:
        load_or_build("DECK", "pure", prof_dir, samples=40, consensus_requests=10)

    if args.seeds:
        jobs = [j for sd in args.seeds for j in density_jobs(paths, vehicles, args.sim_time, seed=sd)]
        print(f"[ns3] {len(jobs)} extra-seed scenarios on {args.workers} workers ...", flush=True)
        rows = run_many(jobs, args.workers)
        for r, (_, kw) in zip(rows, jobs):
            r["seed"] = kw["seed"]
        write_rows(out / "ns3_density_seeds.csv", rows)
        print(f"[ns3] done in {time.time() - t0:.0f} s -> {out}", flush=True)
        return

    jobs = density_jobs(paths, vehicles, args.sim_time)
    mid = vehicles[min(1, len(vehicles) - 1)]
    extra = []
    for s in [x for x in ("CLASSIC", "DECK") if x in paths]:     # broadcast-signed beacons
        extra.append((paths[s], {"n_vehicles": mid, "sim_time": args.sim_time, "signed_beacons": True}))
    if "DECK" in paths:
        extra.append((str(prof_dir / "profile_DECK_pure.json"), {"n_vehicles": mid, "sim_time": args.sim_time}))
        # ablation: what EDCA prioritisation and handshake backoff each contribute
        for edca, backoff in ((False, False), (True, False), (False, True)):
            extra.append((paths["DECK"], {"n_vehicles": mid, "sim_time": args.sim_time,
                                          "edca": edca, "backoff": backoff}))
    print(f"[ns3] {len(jobs) + len(extra)} scenarios on {args.workers} workers ...", flush=True)
    rows = run_many(jobs + extra, args.workers)
    dens = rows[: len(jobs)]
    write_rows(out / "ns3_density.csv", dens)
    write_rows(out / "ns3_variants.csv", rows[len(jobs):] + [r for r in dens if r["vehicles"] == mid])
    raw = {f"{r['profile']}|{r['vehicles']}|{'signed' if r['signed_beacons'] else 'aead'}"
           f"|edca={int(r['edca'])}|backoff={int(r['backoff'])}":
           {"handshake_ms": r["raw_handshake_ms"], "beacon_ms": r["raw_beacon_ms"][:5000],
            "alert_ms": r["raw_alert_ms"]} for r in rows}
    (out / "ns3_raw.json").write_text(json.dumps(raw))
    print(f"[ns3] done in {time.time() - t0:.0f} s -> {out}", flush=True)


if __name__ == "__main__":
    main()
