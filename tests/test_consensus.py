import pytest

from qrcav.consensus.agspbft import ConsensusConfig, regroup
from qrcav.consensus.sim import ConsensusSim
from qrcav.eval.consensus_eval import HONEST_RESULT


def _run(sim, n, gap=0.1, extra=4.0):
    for i in range(n):
        sim.submit(gap * i, f"tx{i}")
    sim.run(gap * n + extra)


@pytest.mark.parametrize("mode", ["ags", "pbft"])
def test_normal_case_commits(mode):
    sim = ConsensusSim(n_nodes=8, mode=mode)
    _run(sim, 6)
    assert len(sim.done) == 6
    assert set(sim.heights().values()) == {6}
    assert sim.chains_consistent() and sim.chain_valid()


def test_ags_sends_fewer_messages_than_pbft():
    a = ConsensusSim(n_nodes=16, mode="ags", regroup_interval=1000)
    p = ConsensusSim(n_nodes=16, mode="pbft")
    _run(a, 5)
    _run(p, 5)
    assert a.stats.total_msgs < 0.5 * p.stats.total_msgs


def test_block_has_commit_certificate():
    sim = ConsensusSim(n_nodes=8)
    _run(sim, 2)
    r = next(iter(sim.replicas.values()))
    b = r.ledger.blocks[0]
    assert b.result == HONEST_RESULT
    assert len(b.cert) >= 3                  # 2f+1 RESPONSEs (plus shadow responses)


def test_byzantine_within_f_is_safe_and_live():
    sim = ConsensusSim(n_nodes=16, regroup_interval=1000)
    cons = sim.cfg.initial_consensus         # 7 nodes, f = 2
    leader = sim.replicas[cons[0]].leader
    for x in [c for c in cons if c != leader][:2]:
        sim.replicas[x].behaviour = "wrong_result"
    _run(sim, 5)
    assert len(sim.done) == 5
    assert all(b.result == HONEST_RESULT for r in sim.replicas.values() for b in r.ledger.blocks)


def test_byzantine_beyond_f_cannot_commit_a_wrong_result():
    sim = ConsensusSim(n_nodes=16, regroup_interval=1000, view_change_timeout=0.5)
    cons = sim.cfg.initial_consensus
    leader = sim.replicas[cons[0]].leader
    for x in [c for c in cons if c != leader][:3]:          # f + 1 colluders
        sim.replicas[x].behaviour = "wrong_result"
    _run(sim, 3, extra=3)
    # liveness is lost (no 2f+1 honest quorum) but safety holds: nothing wrong is committed
    assert all(b.result == HONEST_RESULT for r in sim.replicas.values() for b in r.ledger.blocks)


def test_regroup_demotes_wrong_result_node():
    sim = ConsensusSim(n_nodes=16, regroup_interval=10, seed=3)
    cons = sim.cfg.initial_consensus
    leader = sim.replicas[cons[0]].leader
    others = [c for c in cons if c != leader]
    sim.replicas[others[0]].behaviour = "wrong_result"
    sim.replicas[others[1]].behaviour = "silent"
    _run(sim, 20, gap=0.15)
    ref = sim.replicas[leader]
    assert others[0] not in ref.consensus                    # -5 per request: demoted
    assert ref.scores[others[0]] < 100 < ref.scores[leader]
    # The silent node scores 0 per request and falls behind honest nodes, but the
    # Byzantine outlier inflates sigma enough that mu - sigma stays below it. This is
    # a property of the paper's mu +/- sigma rule, recorded as a finding.
    assert ref.scores[others[1]] == 100 < ref.scores[leader]
    assert sim.chain_valid()


def test_regroup_demotes_silent_node_without_outlier():
    sim = ConsensusSim(n_nodes=16, regroup_interval=10, seed=3)
    cons = sim.cfg.initial_consensus
    leader = sim.replicas[cons[0]].leader
    silent = [c for c in cons if c != leader][0]
    sim.replicas[silent].behaviour = "silent"
    _run(sim, 12, gap=0.15)
    assert silent not in sim.replicas[leader].consensus


def test_regroup_skipped_when_sigma_zero():
    """D6: every node at 100 -> mu - sigma == mu + sigma; membership must not churn."""
    cfg = ConsensusConfig(nodes=[f"N{i}" for i in range(8)], adaptive_size=False)
    scores = {n: 100 for n in cfg.nodes}
    assert regroup(scores, list(cfg.initial_consensus), cfg, None) == sorted(cfg.initial_consensus)


@pytest.mark.parametrize("mode", ["ags", "pbft"])
def test_view_change_after_leader_crash(mode):
    sim = ConsensusSim(n_nodes=8, mode=mode, view_change_timeout=0.5)
    leader = sim.replicas[sim.cfg.initial_consensus[0]].leader
    sim.replicas[leader].behaviour = "crash"
    _run(sim, 4, extra=10)
    assert len(sim.done) == 4
    live = [r for n, r in sim.replicas.items() if n != leader]
    assert all(r.view >= 1 for r in live if r.is_consensus)
    assert sim.chains_consistent()


def test_view_change_with_prepared_requests():
    """Leader crashes after requests are prepared; the new view must re-issue them, not lose them."""
    sim = ConsensusSim(n_nodes=8, view_change_timeout=0.5)
    leader = sim.replicas[sim.cfg.initial_consensus[0]].leader
    for i in range(3):
        sim.submit(0.01 * i, f"tx{i}")
    sim.run(0.004)                           # mid-flight
    sim.replicas[leader].behaviour = "crash"
    sim.run(20)
    assert len(sim.done) == 3
    assert sim.chains_consistent() and sim.chain_valid()


def test_validation_does_not_depend_on_local_registry_view():
    """
    Regression: nodes used to check "is the reporter registered?" against their own
    copy of the registry, fetched at start-up. Nodes that fetched it before a vehicle
    enrolled rejected its events while others accepted them, so honest nodes
    disagreed and no result reached 2f+1. Now the request carries the reporter's
    TA-signed certificate and every node verifies it, so all honest nodes agree.
    """
    from qrcav.eval.consensus_eval import HONEST_RESULT
    from qrcav.pki import Identity

    sim = ConsensusSim(n_nodes=8)
    cav = Identity.generate("CAV_77", "CAV", sim.suite)
    sim.ta.enrol(cav)                      # registered with the TA, unknown to every node's directory
    assert sim.directory.role("CAV_77") is None
    out = sim.client.submit("txA", "CAV_77", {"kind": "collision", "reporter_cert": cav.cert.encode()}, 0.0)
    sim._emit("MEC_01", out, 0.0)
    rogue = Identity.generate("CAV_88", "CAV", sim.suite)    # self-made certificate, not from the TA
    from qrcav.pki import TrustedAuthority
    TrustedAuthority(sim.suite).enrol(rogue)
    out = sim.client.submit("txB", "CAV_88", {"kind": "collision", "reporter_cert": rogue.cert.encode()}, 0.5)
    sim._emit("MEC_01", out, 0.5)
    sim.run(4)
    assert len(sim.done) == 2
    results = {c.txn_id: c.result for c in sim.done}
    assert results["txA"] == HONEST_RESULT
    assert results["txB"] != HONEST_RESULT           # agreed REJECT, not a stall
    assert sim.chains_consistent()
