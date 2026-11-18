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


def _progress(i: int, total: int, r: dict) -> None:
    name = r.get("profile", "").replace("profile_", "").replace("_auto", "").replace("_pure", " (pure)")
    tags = []
    cache = int(r.get("cert_cache", 0) or 0)
    if cache:
        tags.append("RSU certs pre-distributed" if cache == 1 else "warm certificate caches")
    if r.get("edca") is not None and not (r.get("edca") and r.get("backoff")):
        tags.append(f"edca={int(bool(r.get('edca')))} backoff={int(bool(r.get('backoff')))}")
    tag = f"  [{'; '.join(tags)}]" if tags else ""
    print(f"[ns3] {i:>2}/{total}  {name:<12} {r.get('vehicles', '?'):>4} vehicles  "
          f"handshake {r.get('hs_mean_ms', 0):>7.1f} ms  success {r.get('handshake_success_pct', 0):>5.1f}%  "
          f"beacon PDR {r.get('beacon_pdr_pct', 0):>5.1f}%  airtime {r.get('airtime_pct', 0):>6.1f}%{tag}",
          flush=True)


def _indexed_worker(item):
    idx, job = item
    return idx, _worker(job)


def run_many(jobs: list[tuple[str, dict]], workers: int = 2) -> list[dict]:
    """Run every scenario in a worker pool and print one line as each one finishes."""
    ctx = mp.get_context("spawn")
    results: list[dict | None] = [None] * len(jobs)
    done = 0
    with ctx.Pool(workers, maxtasksperchild=1) as pool:
        for idx, r in pool.imap_unordered(_indexed_worker, list(enumerate(jobs))):
            results[idx] = r
            done += 1
            _progress(done, len(jobs), r)
    return results


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
