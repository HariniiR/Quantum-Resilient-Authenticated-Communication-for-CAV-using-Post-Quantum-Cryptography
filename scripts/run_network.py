"""
Launch the whole distributed system on one machine and run the scripted
scenario from a config file.

    python scripts/run_network.py                       # config/demo.json, 50 s
    python scripts/run_network.py --duration 30
    python scripts/run_network.py --config config/demo.json --suite CLASSIC

Every entity is a separate OS process talking over TCP on localhost:
TA, cloud, MEC, consensus nodes, RSUs and vehicles. Output from all of them is
interleaved here, colour-coded by role. At the end every process is stopped,
and the run is checked end to end (see qrcav/nodes/report.py).

Works on Windows, Linux and macOS.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav.nodes.base import all_entities, load_config  # noqa: E402
from qrcav.nodes.report import build_report, print_report  # noqa: E402

MODULES = {"CLOUD": "cloud", "MEC": "mec", "NODE": "consensus_node", "RSU": "rsu", "CAV": "cav"}


def pump(proc: subprocess.Popen) -> None:
    for line in iter(proc.stdout.readline, ""):
        sys.stdout.write(line)
    proc.stdout.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config" / "demo.json"))
    ap.add_argument("--duration", type=float, default=50.0)
    ap.add_argument("--suite", help="override suite: DECK, L1, L3, L5, CLASSIC")
    ap.add_argument("--keep", action="store_true", help="do not wipe the run directory first")
    ap.add_argument("--quiet", action="store_true", help="only print the final summary")
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")

    cfg = load_config(args.config)
    if args.suite:
        cfg["suite"] = args.suite
    run_dir = Path(cfg["run_dir"])
    if not run_dir.is_absolute():
        run_dir = ROOT / run_dir
    cfg["run_dir"] = str(run_dir)
    if run_dir.exists() and not args.keep:
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    eff = run_dir / "effective_config.json"
    eff.write_text(json.dumps(cfg, indent=2))

    env = {**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "PYTHONUNBUFFERED": "1"}
    if args.quiet:
        env["QRCAV_QUIET"] = "1"
    procs: list[subprocess.Popen] = []

    def spawn(module: str, ident: str) -> None:
        p = subprocess.Popen(
            [sys.executable, "-m", f"qrcav.nodes.{module}", "--config", str(eff), "--id", ident],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        procs.append(p)
        threading.Thread(target=pump, args=(p,), daemon=True).start()

    print(f"== starting {len(all_entities(cfg)) + 1} processes, suite {cfg['suite']}, "
          f"run dir {run_dir} ==", flush=True)
    spawn("ta", "TA")
    while not (run_dir / "ta_public.bin").exists():
        time.sleep(0.05)
    order = ["CLOUD", "NODE", "MEC", "RSU", "CAV"]
    ents = all_entities(cfg)
    for role in order:
        for eid, e in ents.items():
            if e["role"] == role:
                spawn(MODULES[role], eid)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        print("== stopping ==", flush=True)
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    time.sleep(0.3)
    rep = build_report(str(eff))
    print_report(rep)
    (run_dir / "summary.json").write_text(json.dumps(rep, indent=2, default=str))


if __name__ == "__main__":
    main()
