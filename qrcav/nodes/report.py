"""
Post-run report for the distributed system: reads every process's JSONL log,
every node's ledger and the TA registry, and checks the run end to end.
"""

from __future__ import annotations

import json
import sqlite3
import statistics
from collections import defaultdict
from pathlib import Path

from .. import codec
from ..consensus.agspbft import verify_chain
from ..consensus.messages import Directory
from ..crypto.suites import get_suite
from ..ledger import Ledger
from ..pki import Certificate
from .base import load_config
from .consensus_node import consensus_config


def _logs(run_dir: Path) -> dict[str, list[dict]]:
    out = {}
    for p in sorted((run_dir / "logs").glob("*.jsonl")):
        out[p.stem] = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    return out


def _stats(xs: list[float]) -> str:
    if not xs:
        return "-"
    xs = sorted(xs)
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return f"mean {statistics.fmean(xs):.1f}  median {xs[len(xs) // 2]:.1f}  p95 {p95:.1f}  (n={len(xs)})"


def build_report(config_path: str) -> dict:
    cfg = load_config(config_path)
    run = Path(cfg["run_dir"])
    logs = _logs(run)
    ev = lambda node, kind: [r for r in logs.get(node, []) if r["event"] == kind]  # noqa: E731
    all_ev = lambda kind: [r for recs in logs.values() for r in recs if r["event"] == kind]  # noqa: E731

    rep: dict = {"suite": cfg["suite"]}
    hs = [r for r in all_ev("handshake") if r.get("side") == "initiator"]
    rep["handshakes"] = len(hs)
    rep["handshake_ms"] = [r["ms"] for r in hs]
    rep["handshake_bytes"] = sorted({r["bytes"] for r in hs})
    rep["handshake_rejected"] = len(all_ev("handshake-rejected"))
    rep["beacons_received"] = sum(sum(r["counts"].values()) for r in all_ev("beacon-stats"))
    alerts = all_ev("alert")
    rep["alert_latency_ms"] = [r["latency_ms"] for r in alerts]
    rep["alerts_delivered"] = len(alerts)
    rep["commit_latency_ms"] = [r["latency_ms"] for r in all_ev("committed")]
    rep["recorded_to_vehicle_ms"] = [r["latency_ms"] for r in all_ev("recorded")]
    rep["v2v_ms"] = [r["latency_ms"] for r in all_ev("v2v-recv")]
    rep["cloud_records"] = len(all_ev("stored"))
    rep["regroups"] = [(r["node"], r.get("b_id"), r.get("promoted"), r.get("demoted"))
                       for r in all_ev("regroup")][:1]
    rep["view_changes"] = sorted({r.get("view") for r in all_ev("new-view-accepted")})
    rep["revoked"] = [r["id"] for r in all_ev("revoked")]
    rep["handover"] = [(r["node"], r["old"], r["new"], r["ok"]) for r in all_ev("handover")]

    # ledgers: every node's copy must be a prefix of the longest, and verify from genesis
    suite = get_suite(cfg["suite"], cfg["backend"])
    pub = codec.decode((run / "ta_public.bin").read_bytes()) if (run / "ta_public.bin").exists() else {}
    d = Directory(suite, pub.get("ta_pk"))
    db = run / "ta_registry.db"
    if db.exists():
        con = sqlite3.connect(str(db))
        for (raw,) in con.execute("SELECT cert FROM registry"):
            d.add(Certificate.decode(bytes(raw)))
    ccfg = consensus_config(cfg)
    ledgers = {}
    for n in ccfg.nodes:
        p = run / "ledger" / f"{n}.jsonl"
        ledgers[n] = Ledger(p) if p.exists() else Ledger()
    heights = {n: l.height for n, l in ledgers.items()}
    longest = max(ledgers.values(), key=lambda l: l.height)
    ref = [b.hash for b in longest.blocks]
    consistent = all([b.hash for b in l.blocks] == ref[: l.height] for l in ledgers.values())
    rep["ledger_heights"] = heights
    rep["ledgers_consistent"] = consistent
    rep["ledger_verifies"] = verify_chain(longest, d, ccfg)
    rep["blocks"] = [b.summary() for b in longest.blocks]
    return rep


def print_report(rep: dict) -> None:
    line = "-" * 78
    print("\n" + line)
    print(f" RUN SUMMARY  ({rep['suite']})")
    print(line)
    print(f" handshakes completed     {rep['handshakes']}   rejected {rep['handshake_rejected']}")
    print(f" handshake time (ms)      {_stats(rep['handshake_ms'])}")
    print(f" handshake size (bytes)   {rep['handshake_bytes']}")
    print(f" beacons received at RSUs {rep['beacons_received']}")
    print(f" alerts delivered         {rep['alerts_delivered']}")
    print(f" event -> alert (ms)      {_stats(rep['alert_latency_ms'])}")
    print(f" submit -> commit (ms)    {_stats(rep['commit_latency_ms'])}")
    print(f" event -> on ledger (ms)  {_stats(rep['recorded_to_vehicle_ms'])}")
    print(f" V2V via RSUs (ms)        {_stats(rep['v2v_ms'])}")
    print(f" cloud records            {rep['cloud_records']}")
    print(f" handovers                {rep['handover']}")
    print(f" regroup                  {rep['regroups']}")
    print(f" view changes to          {rep['view_changes']}")
    print(f" revoked                  {rep['revoked']}")
    print(f" ledger heights           {rep['ledger_heights']}")
    print(f" ledgers consistent       {rep['ledgers_consistent']}")
    print(f" ledger verifies          {rep['ledger_verifies']}  (hash links, leader sigs, "
          f"commit certificates, scores, membership)")
    print(line)
    if rep["blocks"]:
        print(f" {'B_ID':>4}  {'Pr_B_Hash':<16}  {'hash':<16}  {'view':>4}  {'leader':<8}  txn")
        for b in rep["blocks"]:
            print(f" {b['B_ID']:>4}  {b['Pr_B_Hash']:<16}  {b['hash']:<16}  {b['view']:>4}  "
                  f"{b['leader']:<8}  {b['txn_id']}")
        print(line)
