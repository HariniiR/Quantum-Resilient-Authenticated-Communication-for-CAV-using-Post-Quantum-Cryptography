"""
Build the browser replay of the ns-3 simulation (results/viewer.html).

Runs the same scenario (same mobility, same seed) three times with event
tracing on: classical ECDH/ECDSA, the DECK post-quantum suite, and DECK with
certificate caching, then embeds the traces in one self-contained HTML page
you can open in any browser, offline.

    python scripts/make_viewer.py                      # 100 vehicles, 30 s
    python scripts/make_viewer.py --vehicles 150 --sim-time 40

Linux or WSL2 only (needs `pip install ns3`). The measurement profiles in
results/profiles are reused if they exist.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav.eval.ns3_sweeps import RADIO  # noqa: E402
from qrcav.sim.ns3_runner import ns3_available  # noqa: E402
from qrcav.sim.profile import load_or_build  # noqa: E402

SCENARIOS = [
    ("CLASSIC", 0, "Classical", "ECDH-P256 + ECDSA-P256 (today's V2X)"),
    ("DECK", 0, "Post-quantum", "ML-KEM-1024 + ML-DSA-65, certificates sent in full"),
    ("DECK", 1, "PQ + cache", "ML-KEM-1024 + ML-DSA-65, certificates cached"),
]


def _worker(args):
    prof_path, kw = args
    from qrcav.sim.ns3_runner import run_scenario
    prof = json.loads(Path(prof_path).read_text())
    return run_scenario(prof, **{**RADIO, **kw})


def write_page(data: dict, out: Path) -> None:
    """Embed the traces in the template: a fragment for publishing, and a standalone page."""
    fragment = (ROOT / "qrcav" / "eval" / "viewer_template.html").read_text()
    fragment = fragment.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":")))
    out.parent.mkdir(parents=True, exist_ok=True)
    (out.parent / "viewer_fragment.html").write_text(fragment)
    out.write_text('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
                   '<meta name="viewport" content="width=device-width, initial-scale=1">'
                   '<style>body{margin:0}</style></head><body>\n' + fragment + "\n</body></html>\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vehicles", type=int, default=100)
    ap.add_argument("--sim-time", type=float, default=30.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "results" / "viewer.html"))
    ap.add_argument("--from-data", action="store_true",
                    help="rebuild the page from results/viewer_data.json without running ns-3")
    args = ap.parse_args()
    out = Path(args.out)
    data_path = out.parent / "viewer_data.json"
    if args.from_data:
        write_page(json.loads(data_path.read_text()), out)
        return
    if not ns3_available():
        sys.exit("ns-3 Python bindings not found. On Linux / WSL2:  pip install ns3")

    prof_dir = ROOT / "results" / "profiles"
    jobs = []
    for suite, cache, *_ in SCENARIOS:
        prof = load_or_build(suite, "auto", prof_dir)
        jobs.append((str(prof_dir / f"profile_{suite}_auto.json"),
                     {"n_vehicles": args.vehicles, "sim_time": args.sim_time, "seed": args.seed,
                      "cert_cache": cache, "trace": True}))
        jobs[-1][1]["_sizes"] = prof["sizes"]

    import multiprocessing as mp
    t0 = time.time()
    print(f"[viewer] running {len(jobs)} traced scenarios ({args.vehicles} vehicles, {args.sim_time:.0f} s) ...",
          flush=True)
    clean = [(p, {k: v for k, v in kw.items() if not k.startswith("_")}) for p, kw in jobs]
    with mp.get_context("spawn").Pool(2, maxtasksperchild=1) as pool:
        rows = pool.map(_worker, clean, chunksize=1)

    keep = ("handshake_success_pct", "hs_p50_ms", "hs_p95_ms", "beacon_coverage_pct", "alert_p50_ms",
            "airtime_pct", "handshakes_ok", "handshake_attempts")
    scen = []
    for (suite, cache, short, label), (_, kw), r in zip(SCENARIOS, jobs, rows):
        sz = kw["_sizes"]
        hb = (sz["client_hello_cached"] + sz["server_hello_cached"] if cache
              else sz["client_hello"] + sz["server_hello"]) + sz["client_key"] + sz["server_finished"]
        scen.append({"suite": suite, "cache": cache, "short": short, "label": label,
                     "handshake_bytes": hb,
                     "summary": {k: (None if r[k] != r[k] else r[k]) for k in keep},
                     "trace": r["raw_trace"]})
    data = {
        "scenarios": scen,
        "note": ("Each dot is a vehicle. Times are simulated seconds. A handshake is four flights; "
                 "flights larger than one 1,400-byte frame are fragmented, and a lost fragment costs a "
                 "retransmission. The post-quantum handshake is about 20 KB (17 frames) against 1 KB "
                 "(4 frames) classically; certificate caching brings it to about 10 KB (10 frames). "
                 "With caching, a vehicle's first handshake still sends its certificate in full."),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text(json.dumps(data, separators=(",", ":")))
    write_page(data, out)
    for s in scen:
        m = s["summary"]
        print(f"  {s['short']:<13} {s['handshake_bytes']:>6} B  completed {m['handshake_success_pct']:.1f}%  "
              f"p50 {m['hs_p50_ms']:.0f} ms  airtime {m['airtime_pct']:.0f}%")
    print(f"[viewer] wrote {out} ({out.stat().st_size / 1e6:.1f} MB) in {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
