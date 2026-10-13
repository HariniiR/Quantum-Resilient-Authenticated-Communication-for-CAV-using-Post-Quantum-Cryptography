"""
Cryptographic measurements: primitives, sizes, full handshakes, and the
per-beacon budget, for every suite.
"""

from __future__ import annotations

import math
import statistics
import time

from .. import codec
from ..crypto.records import RECORD_OVERHEAD
from ..crypto.suites import get_suite
from ..handshake import handshake_in_memory
from ..pki import TrustedAuthority, enrol_all

SUITES = ["CLASSIC", "L1", "L3", "DECK", "L5"]
CHUNK = 1400            # application bytes per 802.11p frame (as in the ns-3 scenario)
PHY_RATE = 6e6          # 802.11p default data rate, 10 MHz channel
OVERHEAD_BYTES = 24 + 8 + 20 + 8 + 28   # app hdr + UDP + IPv4 + LLC/SNAP + MAC/FCS
PREAMBLE_US = 40.0      # 802.11p (10 MHz) PLCP preamble + header
SYMBOL_US = 8.0
BITS_PER_SYMBOL = 48    # 6 Mb/s in a 10 MHz channel


def frame_airtime_ms(payload: int) -> float:
    bits = 16 + 8 * (payload + OVERHEAD_BYTES) + 6
    return (PREAMBLE_US + math.ceil(bits / BITS_PER_SYMBOL) * SYMBOL_US) / 1000


def message_airtime_ms(nbytes: int) -> tuple[int, float]:
    frames = max(1, math.ceil(nbytes / CHUNK))
    t = 0.0
    left = nbytes
    for _ in range(frames):
        b = min(CHUNK, left)
        t += frame_airtime_ms(b)
        left -= b
    return frames, t


def bench(fn, n: int = 200, warmup: int = 10) -> dict:
    for _ in range(warmup):
        fn()
    xs = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    xs.sort()
    return {
        "mean_ms": statistics.fmean(xs), "sd_ms": statistics.pstdev(xs),
        "p50_ms": xs[len(xs) // 2], "p95_ms": xs[int(0.95 * (len(xs) - 1))],
        "p99_ms": xs[int(0.99 * (len(xs) - 1))], "n": n,
    }


def primitives(n: int = 200) -> list[dict]:
    rows = []
    for name in SUITES:
        s = get_suite(name)
        m = b"m" * 256
        ek, dk = s.kem.keygen()
        _, ct = s.kem.encaps(ek)
        pk, sk = s.sig.keygen()
        sig = s.sig.sign(sk, m)
        ops = {
            f"{s.kem.name} keygen": s.kem.keygen,
            f"{s.kem.name} encaps": lambda: s.kem.encaps(ek),
            f"{s.kem.name} decaps": lambda: s.kem.decaps(dk, ct),
            f"{s.sig.name} keygen": s.sig.keygen,
            f"{s.sig.name} sign": lambda: s.sig.sign(sk, m),
            f"{s.sig.name} verify": lambda: s.sig.verify(pk, m, sig),
        }
        for op, fn in ops.items():
            r = bench(fn, n, 5)
            rows.append({"suite": name, "operation": op,
                         **{kk: round(v, 4) if isinstance(v, float) else v for kk, v in r.items()}})
    return rows


def _air(flights: dict) -> tuple[int, float]:
    frames, air = 0, 0.0
    for v in flights.values():
        f, a = message_airtime_ms(v)
        frames += f
        air += a
    return frames, air


def sizes() -> list[dict]:
    from ..certcache import CertCache
    rows = []
    for name in SUITES:
        s = get_suite(name)
        ta = TrustedAuthority(s)
        ids = enrol_all(ta, [("CAV_00001", "CAV"), ("RSU_001", "RSU")])
        c, _ = handshake_in_memory(ids["CAV_00001"], ids["RSU_001"])
        fs = c.flight_sizes
        frames, air = _air(fs)
        # certificate caching: second handshake, both certificates as references
        cc, sc = CertCache(), CertCache()
        handshake_in_memory(ids["CAV_00001"], ids["RSU_001"], client_cache=cc, server_cache=sc)
        cw, _ = handshake_in_memory(ids["CAV_00001"], ids["RSU_001"], client_cache=cc, server_cache=sc)
        fc = cw.flight_sizes
        frames_c, air_c = _air(fc)
        rows.append({
            "suite": name, "kem": s.kem.name, "sig_alg": s.sig.name,
            "kem_pk": s.kem.pk_len, "kem_ct": s.kem.ct_len, "sig_pk": s.sig.pk_len,
            "sig": len(s.sig.sign(ids["CAV_00001"].sk, b"x")),
            "cert": len(ids["CAV_00001"].cert.encode()),
            "client_hello": fs["client_hello"], "server_hello": fs["server_hello"],
            "client_key": fs["client_key"], "server_finished": fs["server_finished"],
            "handshake_total": sum(fs.values()), "frames": frames, "airtime_ms": round(air, 3),
            "client_hello_cached": fc["client_hello"], "server_hello_cached": fc["server_hello"],
            "handshake_total_cached": sum(fc.values()), "frames_cached": frames_c,
            "airtime_ms_cached": round(air_c, 3),
            "cache_saving_pct": round(100 * (1 - sum(fc.values()) / sum(fs.values())), 1),
        })
    return rows


def handshakes(n: int = 100) -> list[dict]:
    rows = []
    for name in SUITES:
        s = get_suite(name)
        ta = TrustedAuthority(s)
        ids = enrol_all(ta, [("CAV_00001", "CAV"), ("RSU_001", "RSU")])
        r = bench(lambda: handshake_in_memory(ids["CAV_00001"], ids["RSU_001"]), n, 3)
        c, srv = handshake_in_memory(ids["CAV_00001"], ids["RSU_001"])
        row = {"suite": name, **{kk: round(v, 3) for kk, v in r.items()}}
        for op, v in sorted({**{f"client_{a}": b for a, b in c.crypto_ms.items()},
                             **{f"server_{a}": b for a, b in srv.crypto_ms.items()}}.items()):
            row[op] = round(v, 3)
        rows.append(row)
    return rows


def beacon_budget(n: int = 300) -> list[dict]:
    """
    Per-beacon cost against the 100 ms V2X budget, separated from the one-off
    handshake (which the base paper folds into its latency figure).
      AEAD     inside an established session: seal + open
      signed   broadcast authentication (as IEEE 1609.2 does today): sign + verify,
               beacon carries the signature and a 32-byte certificate digest
    """
    rows = []
    beacon = {"type": "beacon", "src": "CAV_00001", "seq": 1, "ts": 1.0e9, "pos": [1234.5, 678.9],
              "speed": 13.9, "heading": 90.0}
    raw = codec.encode(beacon)
    for name in SUITES:
        s = get_suite(name)
        ta = TrustedAuthority(s)
        ids = enrol_all(ta, [("CAV_00001", "CAV"), ("RSU_001", "RSU")])
        c, srv = handshake_in_memory(ids["CAV_00001"], ids["RSU_001"])
        k = n
        # AEAD path
        recs = []

        def seal_open():
            r = c.seal(beacon)
            srv.open(r)
            recs.append(len(r))
        a = bench(seal_open, k, 5)
        fr, air = message_airtime_ms(recs[-1])
        rows.append({"suite": name, "mode": "AEAD (session)",
                     "bytes": recs[-1], "frames": fr, "crypto_mean_ms": round(a["mean_ms"], 4),
                     "crypto_p99_ms": round(a["p99_ms"], 4), "airtime_ms": round(air, 3),
                     "total_p99_ms": round(a["p99_ms"] + air, 3),
                     "fits_100ms": a["p99_ms"] + air <= 100})
        sk, pk = ids["CAV_00001"].sk, ids["CAV_00001"].pk
        size = len(codec.encode({"b": raw, "sig": s.sig.sign(sk, raw), "cert": bytes(32)}))

        def sign_verify():
            sg = s.sig.sign(sk, raw)
            s.sig.verify(pk, raw, sg)
        g = bench(sign_verify, k, 5)
        fr, air = message_airtime_ms(size)
        rows.append({"suite": name, "mode": "signed (broadcast)",
                     "bytes": size, "frames": fr, "crypto_mean_ms": round(g["mean_ms"], 4),
                     "crypto_p99_ms": round(g["p99_ms"], 4), "airtime_ms": round(air, 3),
                     "total_p99_ms": round(g["p99_ms"] + air, 3),
                     "fits_100ms": g["p99_ms"] + air <= 100})
    return rows
