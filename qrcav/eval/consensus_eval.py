"""
Consensus-layer experiments, all with real ML-DSA signatures:

  scaling          AGS-PBFT vs textbook PBFT: messages, bytes, latency per request
  throughput       requests committed per second under a burst
  fault_tolerance  colluding Byzantine nodes inside the consensus set: safety and liveness
  score_dynamics   scores and membership per block with faulty nodes present
  view_change      recovery time after the leader crashes
"""

from __future__ import annotations

import statistics

from ..consensus.agspbft import H, f_of, quorum
from ..consensus.sim import ConsensusSim

HONEST_RESULT = H(b"result", b"ACCEPT")


def _p(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else float("nan")


def scaling(sizes=(8, 12, 16, 20, 24), requests: int = 20, suite=None) -> list[dict]:
    rows = []
    variants = (("ags", "ags", {}), ("ags-noshadow", "ags", {"shadow_candidates": False}), ("pbft", "pbft", {}))
    for n in sizes:
        for label, mode, extra in variants:
            sim = ConsensusSim(n_nodes=n, mode=mode, suite=suite, regroup_interval=1000, **extra)
            for i in range(requests):
                sim.submit(0.25 * i, f"tx{i}")
            sim.run(0.25 * requests + 5)
            lat = [c.latency * 1000 for c in sim.done]
            k = max(1, len(sim.done))
            rows.append({
                "nodes": n, "mode": label, "consensus_set": len(sim.cfg.initial_consensus),
                "f": f_of(len(sim.cfg.initial_consensus)),
                "committed": len(sim.done), "msgs_per_req": round(sim.stats.total_msgs / k, 1),
                "kbytes_per_req": round(sim.stats.total_bytes / k / 1024, 1),
                "latency_p50_ms": round(_p(lat, 0.5), 2), "latency_p95_ms": round(_p(lat, 0.95), 2),
                "cpu_s": round(sum(sim.compute_s.values()), 3),
                "consistent": sim.chains_consistent(), "chain_valid": sim.chain_valid(),
                **{f"msgs_{t}": round(v / k, 1) for t, v in sorted(sim.stats.msgs.items())},
            })
    for n in sizes:
        p = next(r for r in rows if r["nodes"] == n and r["mode"] == "pbft")
        for lab in ("ags", "ags-noshadow"):
            a = next(r for r in rows if r["nodes"] == n and r["mode"] == lab)
            a["msg_reduction_pct"] = round(100 * (1 - a["msgs_per_req"] / p["msgs_per_req"]), 1)
            a["byte_reduction_pct"] = round(100 * (1 - a["kbytes_per_req"] / p["kbytes_per_req"]), 1)
            a["latency_change_pct"] = round(100 * (a["latency_p50_ms"] / p["latency_p50_ms"] - 1), 1)
            a["cpu_reduction_pct"] = round(100 * (1 - a["cpu_s"] / p["cpu_s"]), 1)
    return rows


def throughput(n: int = 16, burst: int = 60, suite=None) -> list[dict]:
    rows = []
    for mode in ("ags", "pbft"):
        sim = ConsensusSim(n_nodes=n, mode=mode, suite=suite, regroup_interval=1000,
                           view_change_timeout=30.0)
        for i in range(burst):
            sim.submit(0.0, f"tx{i}")
        sim.run(60)
        if sim.done:
            span = max(c.latency for c in sim.done)
            rows.append({"nodes": n, "mode": mode, "requests": burst, "committed": len(sim.done),
                         "seconds": round(span, 3), "tps": round(len(sim.done) / span, 1),
                         "cpu_s_total": round(sum(sim.compute_s.values()), 3)})
    return rows


def fault_tolerance(n: int = 16, requests: int = 15, suite=None) -> list[dict]:
    """
    Byzantine nodes are placed inside the consensus set and collude on one
    false result. Regrouping is disabled so the set cannot heal itself and the
    PBFT bounds are tested directly.
      safety   = nothing other than the honest result was ever committed
      liveness = every request committed
    """
    rows = []
    probe = ConsensusSim(n_nodes=n, mode="ags", suite=suite)
    cons = probe.cfg.initial_consensus
    size = len(cons)
    for byz in range(0, size - 1):
        sim = ConsensusSim(n_nodes=n, mode="ags", suite=suite, regroup_interval=10_000,
                           view_change_timeout=1.0)
        leader = sim.replicas[cons[0]].leader
        # never make the view-0 leader faulty here; leader faults are tested in view_change()
        faulty = [x for x in cons if x != leader][:byz]
        for x in faulty:
            sim.replicas[x].behaviour = "wrong_result"
        for i in range(requests):
            sim.submit(0.2 * i, f"tx{i}")
        sim.run(0.2 * requests + 8)
        results = [b.result for r in sim.replicas.values() for b in r.ledger.blocks]
        safety = all(x == HONEST_RESULT for x in results)
        rows.append({
            "consensus_set": size, "f": f_of(size), "quorum": quorum(size), "byzantine": byz,
            "honest_in_set": size - byz, "committed": len(sim.done), "requests": requests,
            "commit_pct": round(100 * len(sim.done) / requests, 1),
            "safety": safety, "liveness": len(sim.done) == requests,
            "within_bound": byz <= f_of(size),
        })
    return rows


def score_dynamics(n: int = 16, requests: int = 60, interval: int = 10, suite=None) -> dict:
    sim = ConsensusSim(n_nodes=n, mode="ags", suite=suite, regroup_interval=interval, seed=3)
    cons = sim.cfg.initial_consensus
    leader = sim.replicas[cons[0]].leader
    others = [x for x in cons if x != leader]
    wrong, silent = others[0], others[1]
    sim.replicas[wrong].behaviour = "wrong_result"
    sim.replicas[silent].behaviour = "silent"
    for i in range(requests):
        sim.submit(0.15 * i, f"tx{i}")
    sim.run(0.15 * requests + 10)
    ref = max((r for r in sim.replicas.values() if r.behaviour == "honest"), key=lambda r: r.ledger.height)
    trace = []
    for b in ref.ledger.blocks:
        sc = dict(b.scores)
        vals = list(sc.values())
        mu, sd = statistics.fmean(vals), statistics.pstdev(vals)
        for node, s in sc.items():
            trace.append({"block": b.b_id, "node": node, "score": s, "in_consensus": node in b.consensus,
                          "mu": round(mu, 2), "sigma": round(sd, 2)})
    regroups = [info for (_, k, info) in sim.events("regroup") if _ == ref.id]
    return {"wrong": wrong, "silent": silent, "initial": list(cons), "trace": trace,
            "regroups": regroups, "committed": len(sim.done), "consistent": sim.chains_consistent(),
            "valid": sim.chain_valid()}


def view_change(timeouts=(0.5, 1.0, 2.0), n: int = 8, suite=None) -> list[dict]:
    rows = []
    for mode in ("ags", "pbft"):
        for to in timeouts:
            sim = ConsensusSim(n_nodes=n, mode=mode, suite=suite, view_change_timeout=to,
                               regroup_interval=10_000)
            leader = sim.replicas[sim.cfg.initial_consensus[0]].leader
            for i in range(5):                       # normal operation
                sim.submit(0.1 * i, f"pre{i}")
            crash_at = 1.0
            sim.run(crash_at)
            sim.replicas[leader].behaviour = "crash"
            for i in range(5):
                sim.submit(crash_at + 0.1 * i + 0.01, f"post{i}")
            sim.run(crash_at + 40)
            post = [c for c in sim.done if c.txn_id.startswith("post")]
            lat = [c.latency * 1000 for c in post]
            rows.append({"mode": mode, "vc_timeout_s": to, "crashed_leader": leader,
                         "post_crash_committed": len(post),
                         "recovery_first_commit_ms": round(min(lat), 1) if lat else None,
                         "post_crash_p50_ms": round(_p(lat, 0.5), 1) if lat else None,
                         "new_view": max(r.view for r in sim.replicas.values()),
                         "consistent": sim.chains_consistent()})
    return rows
