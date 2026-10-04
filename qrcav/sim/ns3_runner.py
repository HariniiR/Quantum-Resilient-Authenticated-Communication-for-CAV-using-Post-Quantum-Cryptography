"""
Run the ns-3 scenario (ns3_scenario.cc) from Python.

Requires the ns-3 Python bindings:   pip install ns3      (Linux / WSL2 only)

The C++ scenario is compiled on first use by cppyy (a few seconds). Mobility is
generated here: vehicles drive a Manhattan grid (blocks of `block_m` metres),
choosing straight / left / right at each intersection, at 8-17 m/s. RSUs sit
at intersections every `rsu_spacing` metres, so the RSU count scales with the
area, not with the number of vehicles.
"""

from __future__ import annotations

import math
import random
import statistics
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_LIB = None


class NS3Unavailable(RuntimeError):
    pass


def ns3_available() -> bool:
    try:
        from ns import ns  # noqa: F401
        return True
    except Exception:
        return False


def _lib():
    global _LIB
    if _LIB is None:
        try:
            from ns import ns
        except Exception as e:  # pragma: no cover
            raise NS3Unavailable(
                "ns-3 Python bindings not found. On Linux or WSL2: pip install ns3"
            ) from e
        ns.cppyy.cppdef((_HERE / "ns3_scenario.cc").read_text())
        _LIB = ns.cppyy.gbl.qrcav
        _LIB._std = ns.cppyy.gbl.std
    return _LIB


# ---------------------------------------------------------------------------
# mobility
# ---------------------------------------------------------------------------

def manhattan_waypoints(n: int, width: float, height: float, block: float, sim_time: float,
                        rng: random.Random) -> list[list[tuple[float, float, float]]]:
    nx, ny = int(width // block), int(height // block)
    dirs = [(1, 0), (0, 1), (-1, 0), (0, -1)]
    out = []
    for _ in range(n):
        ix, iy = rng.randint(0, nx), rng.randint(0, ny)
        d = rng.randrange(4)
        speed = rng.uniform(8.0, 17.0)
        t = 0.0
        # start part-way along a block so vehicles are not all at intersections
        frac = rng.random()
        x, y = ix * block, iy * block
        wps = [(0.0, x, y)]
        while t < sim_time + 5:
            # choose a feasible direction: straight 50 %, left/right 25 % each
            for _attempt in range(8):
                r = rng.random()
                nd = d if r < 0.5 else (d + 1) % 4 if r < 0.75 else (d + 3) % 4
                jx, jy = ix + dirs[nd][0], iy + dirs[nd][1]
                if 0 <= jx <= nx and 0 <= jy <= ny:
                    break
            else:
                nd = (d + 2) % 4
                jx, jy = ix + dirs[nd][0], iy + dirs[nd][1]
            d, ix, iy = nd, jx, jy
            seg = block * (frac if len(wps) == 1 else 1.0)
            seg = max(seg, 1.0)
            t += seg / speed
            x, y = ix * block, iy * block
            wps.append((t, x, y))
        out.append(wps)
    return out


def rsu_grid(width: float, height: float, spacing: float, block: float) -> list[tuple[float, float]]:
    # snap the spacing to whole blocks so RSUs sit at intersections
    step = max(block, round(spacing / block) * block)
    xs = [step / 2 + i * step for i in range(max(1, int(width // step)))]
    ys = [step / 2 + j * step for j in range(max(1, int(height // step)))]
    snap = lambda v: round(v / block) * block  # noqa: E731
    return [(snap(x), snap(y)) for x in xs for y in ys]


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def run_scenario(
    profile: dict,
    n_vehicles: int = 50,
    width: float = 1500.0,
    height: float = 1500.0,
    block: float = 250.0,
    rsu_spacing: float = 500.0,
    sim_time: float = 40.0,
    warmup: float = 5.0,
    beacon_hz: float = 10.0,
    signed_beacons: bool = False,
    event_rate: float = 0.05,
    pbft: bool = False,
    tx_dbm: float = 23.0,
    pathloss_exp: float = 2.2,
    nakagami: bool = True,
    hs_timeout_ms: float = 200.0,
    seed: int = 1,
    edca: bool = True,
    backoff: bool = True,
) -> dict:
    lib = _lib()
    std = lib._std
    lib.reset()
    rng = random.Random(seed)

    params = {
        "sim_time": sim_time, "warmup": warmup, "beacon_hz": beacon_hz,
        "signed": 1.0 if signed_beacons else 0.0, "event_rate": event_rate,
        "pbft": 1.0 if pbft else 0.0, "tx_dbm": tx_dbm, "pathloss_exp": pathloss_exp,
        "nakagami": 1.0 if nakagami else 0.0, "hs_timeout_ms": hs_timeout_ms, "seed": float(seed),
        "hs_retries": 3, "link_timeout": 1.0, "backhaul_ms": 2.0,
        "edca": 1.0 if edca else 0.0, "backoff": 1.0 if backoff else 0.0,
    }
    for k, v in profile["sizes"].items():
        params[f"size_{k}"] = float(v)
    for k, v in params.items():
        lib.set_param(k, float(v))
    for k, v in profile["timing_ms"].items():
        if v:
            lib.set_samples(k, std.vector["double"]([float(x) for x in v]))

    rsus = rsu_grid(width, height, rsu_spacing, block)
    for x, y in rsus:
        lib.add_rsu(float(x), float(y))
    for i, wps in enumerate(manhattan_waypoints(n_vehicles, width, height, block, sim_time, rng)):
        for t, x, y in wps:
            lib.add_waypoint(i, float(t), float(x), float(y))

    lib.run()

    C = {str(k): float(lib.counter(k)) for k in lib.counter_names()}
    get = lambda k: [float(x) for x in lib.get(k)]  # noqa: E731
    hs = get("handshake_ms")
    bl = get("beacon_latency_ms")
    al = get("alert_latency_origin_ms")
    ao = get("alert_latency_others_ms")
    cl = get("commit_latency_ms")
    sess = get("session_s")
    measured = C.get("measured_s", sim_time - warmup)
    slots = C.get("beacon_slots", 0.0)
    res = {
        "suite": profile["suite"], "backend": profile["backend"], "vehicles": n_vehicles,
        "rsus": len(rsus), "area_km2": width * height / 1e6, "signed_beacons": signed_beacons,
        "consensus": "pbft" if pbft else "ags", "edca": edca, "backoff": backoff,
        "handshake_attempts": C.get("handshake_attempts", 0), "handshakes_ok": C.get("handshakes_ok", 0),
        "handshakes_failed": C.get("handshakes_failed", 0),
        "handshake_retx": C.get("handshake_retx", 0),
        "handshake_success_pct": 100 * C.get("handshakes_ok", 0) / max(1, C.get("handshake_attempts", 0)),
        "hs_mean_ms": statistics.fmean(hs) if hs else float("nan"),
        "hs_p50_ms": _pct(hs, 0.5), "hs_p95_ms": _pct(hs, 0.95),
        "beacon_tx": C.get("beacon_tx", 0), "beacon_rx": C.get("beacon_rx", 0),
        "beacon_pdr_pct": 100 * C.get("beacon_rx", 0) / max(1, C.get("beacon_tx", 0)),
        "beacon_coverage_pct": 100 * (1 - C.get("beacon_slots_no_session", 0) / max(1, slots)),
        "beacon_p50_ms": _pct(bl, 0.5), "beacon_p95_ms": _pct(bl, 0.95), "beacon_p99_ms": _pct(bl, 0.99),
        "beacon_within_100ms_pct": 100 * sum(1 for x in bl if x <= 100) / max(1, len(bl)),
        "events_sent": C.get("events_sent", 0), "events_no_session": C.get("events_no_session", 0),
        "alert_origin_pct": 100 * C.get("alert_rx_origin", 0) / max(1, C.get("events_sent", 0)),
        "alert_p50_ms": _pct(al, 0.5), "alert_p95_ms": _pct(al, 0.95),
        "alert_others_p50_ms": _pct(ao, 0.5),
        "commit_p50_ms": _pct(cl, 0.5), "commit_p95_ms": _pct(cl, 0.95),
        "links_lost": C.get("links_lost", 0),
        "mean_session_s": statistics.fmean(sess) if sess else float("nan"),
        "airtime_pct": 100 * C.get("airtime_tx_s", 0) / max(1e-9, measured),
        "tx_mbytes": C.get("tx_bytes", 0) / 1e6,
        "raw_handshake_ms": hs, "raw_beacon_ms": bl[:20000], "raw_alert_ms": al,
    }
    return res
