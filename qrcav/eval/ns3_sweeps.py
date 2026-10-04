"""
ns-3 experiment sweeps. Each scenario runs in its own worker process (ns-3's
global state is not reset cleanly between runs, and two workers use two
cores).

Radio defaults (see docs/05-SYSTEM-DESIGN.md for the reasoning):
  IEEE 802.11p, channel 172 (5.86 GHz), 10 MHz, 6 Mb/s, 23 dBm
  log-distance path loss n = 2.2 + Nakagami fading (m = 3 / 1.5 / 1 at 50 / 150 m)
  preamble detection and CCA at -85 dBm (10 MHz channel)
  1.5 km x 1.5 km Manhattan grid, 250 m blocks, RSU every 500 m (9 RSUs)
"""

from __future__ import annotations

import csv
import json
import multiprocessing as mp
from pathlib import Path

RADIO = {"tx_dbm": 23.0, "pathloss_exp": 2.2, "nakagami": True}


def _worker(args):
    profile_path, kw = args
    from ..sim.ns3_runner import run_scenario
    prof = json.loads(Path(profile_path).read_text())
    r = run_scenario(prof, **{**RADIO, **kw})
    r["profile"] = Path(profile_path).stem
    return r


def run_many(jobs: list[tuple[str, dict]], workers: int = 2) -> list[dict]:
    ctx = mp.get_context("spawn")
    with ctx.Pool(workers, maxtasksperchild=1) as pool:
        return pool.map(_worker, jobs, chunksize=1)


def write_rows(path: Path, rows: list[dict]) -> None:
    rows = [{k: v for k, v in r.items() if not k.startswith("raw_")} for r in rows]
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()})


def density_jobs(profiles: dict[str, str], vehicles=(50, 100, 150, 200), sim_time=30.0, seed=1):
    return [(profiles[s], {"n_vehicles": n, "sim_time": sim_time, "seed": seed})
            for s in profiles for n in vehicles]
