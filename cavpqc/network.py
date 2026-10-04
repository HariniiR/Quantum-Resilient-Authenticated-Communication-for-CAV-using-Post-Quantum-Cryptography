"""
IEEE 802.11p link model.

Parameters from paper Table 4:

    Simulation area          5 km x 5 km
    Simulation time          600 s
    Vehicle speed            10 m/s
    Vehicle density          50-300 vehicles
    Data transmission rate   6 Mbps
    Transmission power       20 mW
    Noise floor              -98 dBm
    Wireless protocol        IEEE 802.11p
    Network topology         Urban grid

DEVIATION (toolchain).

The paper validates using OMNeT++ 6.0 with Veins 5.2. That is a C++ and
Eclipse-based toolchain outside the scope of this project, so the link is
modelled analytically from the parameters above: free-space path loss to
establish range, then transmission time from frame count at 6 Mbps, plus
propagation delay and a contention term that grows with the number of
contending neighbours.

This is a simpler model than a full PHY simulation. It captures the two effects
that dominate the post-quantum question -- how many frames a handshake needs,
and how contention scales with vehicle density -- and it is stated as a
limitation rather than presented as equivalent to OMNeT++.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

SPEED_OF_LIGHT = 299_792_458.0  # m/s


@dataclass
class Link80211p:
    """An IEEE 802.11p channel configured from paper Table 4."""

    bitrate_bps: float = 6e6          # 6 Mbps
    tx_power_mw: float = 20.0         # 20 mW
    noise_floor_dbm: float = -98.0    # -98 dBm
    frequency_hz: float = 5.9e9       # 802.11p operates at 5.9 GHz
    mtu_bytes: int = 1500
    required_snr_db: float = 10.0     # margin needed to decode
    slot_time_us: float = 13.0        # 802.11p slot time
    difs_us: float = 58.0             # 802.11p DIFS

    # -- range -------------------------------------------------------------
    def received_power_dbm(self, distance_m: float) -> float:
        """Free-space path loss. Optimistic for an urban grid; stated as such."""
        if distance_m < 1.0:
            distance_m = 1.0
        tx_dbm = 10 * math.log10(self.tx_power_mw)
        fspl_db = (
            20 * math.log10(distance_m)
            + 20 * math.log10(self.frequency_hz)
            - 147.55
        )
        return tx_dbm - fspl_db

    def snr_db(self, distance_m: float) -> float:
        return self.received_power_dbm(distance_m) - self.noise_floor_dbm

    def in_range(self, distance_m: float) -> bool:
        return self.snr_db(distance_m) >= self.required_snr_db

    def max_range_m(self) -> float:
        """Largest distance still decodable, by bisection on SNR."""
        lo, hi = 1.0, 100_000.0
        for _ in range(200):
            mid = (lo + hi) / 2
            if self.snr_db(mid) >= self.required_snr_db:
                lo = mid
            else:
                hi = mid
        return lo

    # -- timing ------------------------------------------------------------
    def frames(self, payload_bytes: int) -> int:
        return max(1, -(-payload_bytes // self.mtu_bytes))

    def transmission_ms(self, payload_bytes: int) -> float:
        """Serialisation time for the payload at the configured bitrate."""
        return (payload_bytes * 8 / self.bitrate_bps) * 1000

    def propagation_ms(self, distance_m: float) -> float:
        return (distance_m / SPEED_OF_LIGHT) * 1000

    def contention_ms(self, contenders: int) -> float:
        """
        CSMA/CA backoff approximation.

        Average backoff grows with the number of stations contending for the
        channel, which is how vehicle density enters the latency figures.
        """
        contenders = max(1, contenders)
        avg_slots = (2 ** min(contenders.bit_length() + 3, 10)) / 2
        return (self.difs_us + avg_slots * self.slot_time_us) / 1000

    def airtime_ms(
        self, payload_bytes: int, distance_m: float = 100.0, contenders: int = 1
    ) -> float:
        """
        Total one-way delivery time, per frame:
            contention + transmission + propagation
        """
        n = self.frames(payload_bytes)
        return (
            n * self.contention_ms(contenders)
            + self.transmission_ms(payload_bytes)
            + self.propagation_ms(distance_m)
        )

    def summary(self) -> dict:
        return {
            "bitrate_mbps": self.bitrate_bps / 1e6,
            "tx_power_mw": self.tx_power_mw,
            "noise_floor_dbm": self.noise_floor_dbm,
            "mtu_bytes": self.mtu_bytes,
            "max_range_m": round(self.max_range_m(), 1),
        }


# ---------------------------------------------------------------------------
# Mobility
# ---------------------------------------------------------------------------

@dataclass
class UrbanGrid:
    """
    5 km x 5 km urban grid (paper Table 4).

    Used when SUMO is not installed. Vehicles travel along grid roads at a
    constant 10 m/s, which matches the paper's configuration.
    """

    size_m: float = 5000.0
    block_m: float = 500.0
    speed_mps: float = 10.0

    def rsu_positions(self, count: int) -> list[tuple[float, float]]:
        """Place RSUs evenly at grid intersections."""
        per_side = max(1, int(math.ceil(math.sqrt(count))))
        step = self.size_m / (per_side + 1)
        out = []
        for i in range(1, per_side + 1):
            for j in range(1, per_side + 1):
                if len(out) < count:
                    out.append((i * step, j * step))
        return out

    def vehicle_position(self, vehicle_index: int, t: float, rng) -> tuple[float, float]:
        """Position at time t, travelling along one axis of the grid."""
        lane = (vehicle_index % int(self.size_m // self.block_m)) * self.block_m
        offset = (vehicle_index * 137.0) % self.size_m
        along = (offset + self.speed_mps * t) % self.size_m
        return (along, lane) if vehicle_index % 2 == 0 else (lane, along)

    @staticmethod
    def distance(a: tuple[float, float], b: tuple[float, float]) -> float:
        return math.hypot(a[0] - b[0], a[1] - b[1])

    def nearest_rsu(
        self, pos: tuple[float, float], rsu_positions: list[tuple[float, float]]
    ) -> tuple[int, float]:
        best_i, best_d = 0, float("inf")
        for i, p in enumerate(rsu_positions):
            d = self.distance(pos, p)
            if d < best_d:
                best_i, best_d = i, d
        return best_i, best_d


def load_sumo_trace(sumocfg_path: str, steps: int = 600):
    """
    Optional SUMO mobility via TraCI.

    Returns a list of {vehicle_id: (x, y)} snapshots, or None if SUMO or traci
    is unavailable, in which case UrbanGrid is used instead.
    """
    try:
        import traci  # type: ignore
    except ImportError:
        return None

    try:
        traci.start(["sumo", "-c", sumocfg_path])
    except Exception:
        return None

    snapshots = []
    try:
        for _ in range(steps):
            traci.simulationStep()
            snapshots.append(
                {vid: traci.vehicle.getPosition(vid) for vid in traci.vehicle.getIDList()}
            )
    finally:
        try:
            traci.close()
        except Exception:
            pass
    return snapshots
