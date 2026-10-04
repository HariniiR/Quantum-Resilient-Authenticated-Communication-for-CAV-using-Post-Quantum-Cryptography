"""
Integrated simulation driver.

Runs the complete framework of paper sections 5.1-5.4 end to end:

    preparation -> registration -> V2R handshake -> encrypted beacons
                -> AGS-PBFT consensus -> ledger

and reports the four metrics of paper section 7: end-to-end latency,
throughput, communication overhead and computation cost.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import dataclass, field

from .consensus import AGSPBFT
from .entities import TrustedAuthority, make_cloud, make_mec, make_rsu, make_vehicle
from .handshake import HandshakeError, establish
from .ledger import Transaction
from .network import Link80211p, UrbanGrid


@dataclass
class ScenarioConfig:
    """Defaults taken from paper Table 4."""

    vehicles: int = 50
    rsus: int = 9
    mec_servers: int = 3
    consensus_nodes: int = 16
    byzantine_nodes: int = 0
    sim_time_s: int = 600
    beacons_per_vehicle: int = 10
    consensus_batch: int = 4
    seed: int = 42
    force_byzantine_into_consensus: bool = False


@dataclass
class ScenarioResult:
    config: ScenarioConfig
    handshake_ms: list[float] = field(default_factory=list)
    handshake_bytes: list[int] = field(default_factory=list)
    airtime_ms: list[float] = field(default_factory=list)
    e2e_ms: list[float] = field(default_factory=list)
    beacon_bytes: int = 0
    beacons_sent: int = 0
    handshake_failures: int = 0
    out_of_range: int = 0
    consensus: dict = field(default_factory=dict)
    wall_clock_s: float = 0.0

    # -- paper section 7 metrics -------------------------------------------
    def latency_summary(self) -> dict:
        if not self.e2e_ms:
            return {}
        s = sorted(self.e2e_ms)
        return {
            "mean_ms": statistics.mean(s),
            "median_ms": statistics.median(s),
            "p95_ms": s[int(0.95 * (len(s) - 1))],
            "max_ms": s[-1],
            "within_100ms_pct": 100 * sum(x <= 100 for x in s) / len(s),
        }

    def throughput_bps(self) -> float:
        """p_rv * |p| / T   -- paper section 7.3."""
        total_bits = (self.beacon_bytes + sum(self.handshake_bytes)) * 8
        return total_bits / self.config.sim_time_s

    def overhead_summary(self) -> dict:
        if not self.handshake_bytes:
            return {}
        return {
            "mean_handshake_bytes": statistics.mean(self.handshake_bytes),
            "mean_frames": statistics.mean(
                -(-b // 1500) for b in self.handshake_bytes
            ),
            "total_bytes": sum(self.handshake_bytes) + self.beacon_bytes,
        }


def run_scenario(cfg: ScenarioConfig, verbose: bool = True) -> ScenarioResult:
    """Execute one full scenario at the configured vehicle density."""
    rng = random.Random(cfg.seed)
    grid = UrbanGrid()
    link = Link80211p()
    result = ScenarioResult(config=cfg)
    t_start = time.perf_counter()

    # -- preparation phase (paper section 5.1) -----------------------------
    ta = TrustedAuthority()

    # -- registration phase (paper section 5.2) ----------------------------
    rsu_positions = grid.rsu_positions(cfg.rsus)
    vehicles = [make_vehicle(i) for i in range(cfg.vehicles)]
    rsus = [make_rsu(i, rsu_positions[i]) for i in range(cfg.rsus)]
    mecs = [make_mec(i) for i in range(cfg.mec_servers)]
    validators = [make_rsu(500 + i) for i in range(cfg.consensus_nodes)]
    cloud = make_cloud()

    t0 = time.perf_counter()
    ta.enrol_all(vehicles + rsus + mecs + validators + [cloud])
    enrol_ms = (time.perf_counter() - t0) * 1000

    if verbose:
        print(f"  registration : {len(ta.directory)} entities in {enrol_ms:.0f} ms")

    # -- consensus layer (paper section 5.4) -------------------------------
    ags = AGSPBFT(validators, byzantine_count=cfg.byzantine_nodes, seed=cfg.seed)
    if cfg.force_byzantine_into_consensus:
        # Strict fault-tolerance test: ensure the Byzantine nodes are actually
        # inside the active consensus set, not parked among the candidates.
        from .consensus import NodeSet

        for n in ags.nodes:
            if n.byzantine:
                n.group = NodeSet.CONSENSUS

    # -- authentication and session establishment (paper section 5.3) ------
    sessions: dict[str, object] = {}
    for idx, v in enumerate(vehicles):
        t = rng.uniform(0, cfg.sim_time_s)
        v.position = grid.vehicle_position(idx, t, rng)
        r_idx, dist = grid.nearest_rsu(v.position, rsu_positions)

        if not link.in_range(dist):
            result.out_of_range += 1
            continue

        try:
            s_v, _ = establish(v, rsus[r_idx], ta)
        except HandshakeError:
            result.handshake_failures += 1
            continue

        sessions[v.identity] = s_v
        contenders = max(1, cfg.vehicles // max(1, cfg.rsus))
        air = link.airtime_ms(s_v.handshake_bytes, dist, contenders)

        result.handshake_ms.append(s_v.elapsed_ms)
        result.handshake_bytes.append(s_v.handshake_bytes)
        result.airtime_ms.append(air)
        result.e2e_ms.append(s_v.elapsed_ms + air)

    if verbose:
        print(
            f"  handshakes   : {len(sessions)} established, "
            f"{result.handshake_failures} failed, {result.out_of_range} out of range"
        )

    # -- encrypted beacons + consensus -------------------------------------
    pending: list[Transaction] = []
    for v in vehicles:
        s = sessions.get(v.identity)
        if s is None:
            continue
        for b in range(cfg.beacons_per_vehicle):
            beacon = (
                f'{{"id":"{v.identity}","spd":13.9,'
                f'"x":{v.position[0]:.1f},"y":{v.position[1]:.1f},"seq":{b}}}'
            ).encode()
            ct, tag = s.send.seal(beacon)
            result.beacon_bytes += len(ct) + len(tag) + 12
            result.beacons_sent += 1

            pending.append(
                Transaction(f"{v.identity}-{b}", v.identity, {"spd": 13.9, "seq": b})
            )
            if len(pending) >= cfg.consensus_batch:
                ags.submit(v, pending)
                pending = []

    if pending:
        ags.submit(vehicles[0], pending)

    result.consensus = ags.stats()
    result.wall_clock_s = time.perf_counter() - t_start

    if verbose:
        c = result.consensus
        print(
            f"  consensus    : {c['blocks']} blocks, {c['transactions']} txs, "
            f"chain_valid={c['chain_valid']}"
        )

    return result


def density_sweep(
    densities: tuple[int, ...] = (50, 100, 150, 200, 250, 300),
    verbose: bool = True,
) -> list[ScenarioResult]:
    """
    Paper section 7.2-7.4: vary vehicle count from 50 to 300 and observe the
    effect on latency, throughput and communication overhead.
    """
    out = []
    for n in densities:
        if verbose:
            print(f"\n[{n} vehicles]")
        cfg = ScenarioConfig(
            vehicles=n,
            rsus=max(9, n // 25),
            consensus_nodes=16,
            beacons_per_vehicle=4,
        )
        out.append(run_scenario(cfg, verbose=verbose))
    return out
