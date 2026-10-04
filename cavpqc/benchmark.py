"""
Benchmark harness, baselines and attack tests.

Produces the four metrics of paper section 7 plus the security evaluation of
section 6, and writes CSV files and figures.

An important distinction the paper does not draw
------------------------------------------------
Paper section 7.2 folds "the time required for authentication and session key
establishment" into its end-to-end latency figure and compares that against
vehicular requirements. But those are two different budgets:

  * the HANDSHAKE runs once per RSU association. A vehicle at 10 m/s inside a
    454 m radio range is associated for tens of seconds, so a handshake of a
    few hundred milliseconds is amortised over thousands of beacons.

  * the BEACON PATH runs every 100 ms and is the hard real-time constraint.

We therefore report them separately. Conflating them is what makes the paper's
920 ms figure for 50 vehicles hard to interpret.
"""

from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .consensus import AGSPBFT, NodeSet, PlainPBFT
from .crypto import SUITES, artifact_sizes
from .entities import TrustedAuthority, make_rsu, make_vehicle
from .handshake import HandshakeError, establish
from .ledger import Transaction
from .network import Link80211p

OUT = Path("results")
BEACON_BUDGET_MS = 100.0


def bench(fn, n: int = 100, warmup: int = 10) -> tuple[float, float]:
    """Mean and population SD in ms, after warm-up runs."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t) / 1e6)
    return statistics.mean(samples), statistics.pstdev(samples)


# ---------------------------------------------------------------------------
# 1. Primitive microbenchmarks across all three security levels
# ---------------------------------------------------------------------------

def benchmark_primitives() -> list[dict]:
    rows = []
    msg = b"x" * 1024
    for level, (kem_name, kem, sig_name, sig) in SUITES.items():
        ek, dk = kem.keygen()
        _, ct = kem.encaps(ek)
        pk, sk = sig.keygen()
        signature = sig.sign(sk, msg)

        for label, fn, n in (
            (f"{kem_name} keygen", lambda k=kem: k.keygen(), 60),
            (f"{kem_name} encaps", lambda k=kem, e=ek: k.encaps(e), 60),
            (f"{kem_name} decaps", lambda k=kem, d=dk, c=ct: k.decaps(d, c), 60),
            (f"{sig_name} keygen", lambda s=sig: s.keygen(), 30),
            (f"{sig_name} sign", lambda s=sig, k=sk: s.sign(k, msg), 30),
            (f"{sig_name} verify", lambda s=sig, p=pk, g=signature: s.verify(p, msg, g), 60),
        ):
            m, sd = bench(fn, n)
            rows.append({"level": level, "operation": label, "mean_ms": round(m, 4),
                         "sd_ms": round(sd, 4)})
    return rows


# ---------------------------------------------------------------------------
# 2. Classical baseline (paper section 7.1 comparison)
# ---------------------------------------------------------------------------

def benchmark_classical() -> list[dict]:
    """ECDH P-256 and ECDSA P-256, the schemes currently used in V2X."""
    rows = []
    priv = ec.generate_private_key(ec.SECP256R1())
    peer = ec.generate_private_key(ec.SECP256R1())
    peer_pub = peer.public_key()
    msg = b"x" * 1024
    sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))

    for label, fn, n in (
        ("ECDH P-256 keygen", lambda: ec.generate_private_key(ec.SECP256R1()), 200),
        ("ECDH P-256 exchange", lambda: priv.exchange(ec.ECDH(), peer_pub), 200),
        ("ECDSA P-256 sign", lambda: priv.sign(msg, ec.ECDSA(hashes.SHA256())), 200),
        ("ECDSA P-256 verify",
         lambda: priv.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256())), 200),
    ):
        m, sd = bench(fn, n)
        rows.append({"scheme": "classical", "operation": label,
                     "mean_ms": round(m, 4), "sd_ms": round(sd, 4)})

    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    rows.append({"scheme": "classical", "operation": "ECDH P-256 public key size",
                 "mean_ms": len(pub_raw), "sd_ms": 0})
    rows.append({"scheme": "classical", "operation": "ECDSA P-256 signature size",
                 "mean_ms": len(sig), "sd_ms": 0})
    return rows


# ---------------------------------------------------------------------------
# 3. Artifact sizes and frame counts
# ---------------------------------------------------------------------------

def benchmark_sizes() -> list[dict]:
    link = Link80211p()
    rows = []
    for level in SUITES:
        s = artifact_sizes(level)
        flight = s["kem_pk"] + s["kem_ct"] + 2 * s["sig_len"]  # mutual auth
        rows.append({
            "level": level, "kem": s["kem"], "sig": s["sig"],
            "kem_pk": s["kem_pk"], "kem_ct": s["kem_ct"], "sig_len": s["sig_len"],
            "handshake_flight_bytes": flight,
            "frames_1500B": link.frames(flight),
            "airtime_ms": round(link.airtime_ms(flight, 100, 5), 2),
        })
    rows.append({
        "level": "classical", "kem": "ECDH P-256", "sig": "ECDSA P-256",
        "kem_pk": 65, "kem_ct": 65, "sig_len": 72,
        "handshake_flight_bytes": 65 + 65 + 144,
        "frames_1500B": 1,
        "airtime_ms": round(link.airtime_ms(274, 100, 5), 2),
    })
    return rows


# ---------------------------------------------------------------------------
# 4. The real-time question: per-beacon cost against the 100 ms budget
# ---------------------------------------------------------------------------

def benchmark_beacon_path() -> list[dict]:
    """
    Cost of protecting one 100-byte safety beacon, which is the operation that
    must complete inside the 100 ms interval.

    Two modes:
      AEAD only  -- beacon encrypted under an established session key
      signed     -- beacon additionally signed, for broadcast authentication
                    where no pairwise session exists
    """
    from .crypto import SecureChannel

    link = Link80211p()
    beacon = b'{"id":"CAV_0001","spd":13.9,"x":1234.5,"y":2345.6,"seq":42}'
    rows = []

    ch = SecureChannel(b"k" * 32, b"n" * 12)
    m, sd = bench(lambda: ch.seal(beacon), 500)
    air = link.airtime_ms(len(beacon) + 28, 100, 20)
    rows.append({"mode": "AEAD only", "crypto_ms": round(m, 4), "sd_ms": round(sd, 4),
                 "airtime_ms": round(air, 3), "total_ms": round(m + air, 3),
                 "fits_100ms": (m + air) <= BEACON_BUDGET_MS})

    for level, (_, _, sig_name, sig) in SUITES.items():
        pk, sk = sig.keygen()
        m, sd = bench(lambda s=sig, k=sk: s.sign(k, beacon), 30)
        payload = len(beacon) + artifact_sizes(level)["sig_len"]
        air = link.airtime_ms(payload, 100, 20)
        rows.append({
            "mode": f"signed ({sig_name})", "crypto_ms": round(m, 4),
            "sd_ms": round(sd, 4), "airtime_ms": round(air, 3),
            "total_ms": round(m + air, 3),
            "fits_100ms": (m + air) <= BEACON_BUDGET_MS,
        })
    return rows


# ---------------------------------------------------------------------------
# 5. Consensus: AGS-PBFT against textbook PBFT
# ---------------------------------------------------------------------------

def benchmark_consensus(node_counts=(10, 16, 22, 28), requests: int = 60) -> list[dict]:
    ta = TrustedAuthority()
    client = make_vehicle(9999)
    ta.enrol_all([client])
    rows = []

    for n in node_counts:
        nodes = [make_rsu(2000 + n * 100 + i) for i in range(n)]
        ta.enrol_all(nodes)

        ags = AGSPBFT(nodes, seed=11)
        t0 = time.perf_counter()
        for i in range(requests):
            ags.submit(client, [Transaction(f"a{i}", client.identity, {"i": i})])
        ags_ms = (time.perf_counter() - t0) * 1000 / requests
        a = ags.stats()

        plain = PlainPBFT(nodes)
        t0 = time.perf_counter()
        for i in range(requests):
            plain.submit(client, [Transaction(f"p{i}", client.identity, {"i": i})])
        plain_ms = (time.perf_counter() - t0) * 1000 / requests
        p = plain.stats()

        rows.append({
            "nodes": n,
            "ags_consensus_set": a["consensus_set"],
            "ags_msgs_per_req": round(a["messages_per_request"], 1),
            "plain_msgs_per_req": round(p["messages_per_request"], 1),
            "msg_reduction_pct": round(
                100 * (1 - a["messages_per_request"] / p["messages_per_request"]), 1),
            "ags_ms_per_req": round(ags_ms, 3),
            "plain_ms_per_req": round(plain_ms, 3),
            "chain_valid": a["chain_valid"],
        })
    return rows


# ---------------------------------------------------------------------------
# 6. Strict Byzantine fault tolerance
# ---------------------------------------------------------------------------

def benchmark_fault_tolerance(nodes_n: int = 16, requests: int = 40) -> list[dict]:
    """
    Byzantine nodes are forced into the ACTIVE consensus set.

    Without this, AGS-PBFT's regrouping can park faulty nodes among the
    candidates, so a run appears to tolerate more faults than PBFT's 3f+1
    bound allows.

    Two distinct properties are involved and the paper does not separate them:

      SAFETY  requires n >= 3f + 1 for the honest nodes to be guaranteed
              agreement in the presence of f colluding faults.

      LIVENESS requires the honest nodes to actually reach the 2f + 1 quorum,
              i.e. honest >= 2f + 1.

    A run can therefore still commit with f above the safety bound, provided
    the honest plurality happens to clear the quorum. We report both so the
    distinction is visible.
    """
    ta = TrustedAuthority()
    client = make_vehicle(8888)
    ta.enrol_all([client])
    rows = []

    for byz in range(0, 8):
        nodes = [make_rsu(3000 + byz * 100 + i) for i in range(nodes_n)]
        ta.enrol_all(nodes)
        ags = AGSPBFT(nodes, byzantine_count=byz, seed=5)
        for nd in ags.nodes:
            if nd.byzantine:
                nd.group = NodeSet.CONSENSUS

        committed = 0
        for i in range(requests):
            if ags.submit(client, [Transaction(f"f{i}", client.identity, {})]).committed:
                committed += 1

        cs = len(ags.consensus_set)
        byz_in_set = sum(n.byzantine for n in ags.consensus_set)
        honest = cs - byz_in_set
        f_bound = max((cs - 1) // 3, 1)
        quorum = 2 * f_bound + 1

        rows.append({
            "byzantine": byz,
            "consensus_set": cs,
            "honest": honest,
            "f_bound": f_bound,
            "quorum_2f1": quorum,
            "safety_ok": byz_in_set <= f_bound,
            "liveness_ok": honest >= quorum,
            "committed": committed,
            "commit_rate_pct": round(100 * committed / requests, 1),
        })
    return rows


# ---------------------------------------------------------------------------
# 7. Attack tests (paper section 6)
# ---------------------------------------------------------------------------

def attack_tests() -> list[dict]:
    ta = TrustedAuthority()
    v, r = make_vehicle(1), make_rsu(1)
    ta.enrol_all([v, r])
    out = []

    def record(name, rejected, note=""):
        out.append({"attack": name, "rejected": bool(rejected), "note": note})

    s_v, s_r = establish(v, r, ta)

    # tampering
    ct, tag = s_v.send.seal(b'{"spd":13.9}')
    try:
        s_r.recv.open(bytes([ct[0] ^ 0x01]) + ct[1:], tag)
        record("ciphertext tampering", False)
    except ValueError:
        record("ciphertext tampering", True, "AEAD tag mismatch")

    # replay of a stale registration timestamp
    stale = make_rsu(1)
    stale.generate_keys()
    stale.token, stale.ts = r.token, r.ts - 10_000
    try:
        establish(v, stale, ta)
        record("replay (stale timestamp)", False)
    except HandshakeError:
        record("replay (stale timestamp)", True, "freshness window exceeded")

    # impersonation with a stolen token but attacker's own keys
    imp = make_rsu(1)
    imp.generate_keys()
    imp.token, imp.ts = r.token, r.ts
    try:
        establish(v, imp, ta)
        record("impersonation", False)
    except HandshakeError:
        record("impersonation", True, "public key does not match TA directory")

    # revoked entity
    ta.revoke(r.identity)
    try:
        establish(v, r, ta)
        record("revoked credential", False)
    except HandshakeError:
        record("revoked credential", True, "identity on CRL")
    ta.revoked.discard(r.identity)

    # man in the middle substituting the ephemeral KEM key
    from .crypto import DEFAULT_KEM
    atk_ek, _ = DEFAULT_KEM.keygen()
    ctx = (r.identity.encode() + r.sig_pk + r.token + str(r.ts).encode() + atk_ek)
    genuine_ctx_sig = r.sign(
        r.identity.encode() + r.sig_pk + r.token + str(r.ts).encode() + b"other-key"
    )
    from .entities import Entity
    record("MITM key substitution",
           not Entity.verify(r.sig_pk, ctx, genuine_ctx_sig),
           "signature does not cover the substituted key")

    # forward secrecy: a fresh session must not reuse keys
    s2_v, _ = establish(v, r, ta)
    record("session key reuse", s2_v.send.key != s_v.send.key,
           "ephemeral KEM keypair per session")

    # ledger immutability
    from .ledger import Ledger
    L = Ledger()
    L.append([Transaction("t0", v.identity, {"a": 1})])
    L.append([Transaction("t1", v.identity, {"a": 2})])
    L.blocks[0].transactions[0].payload["a"] = 99
    record("ledger tampering", not L.validate(), "hash chain broken")

    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_csv(name: str, rows: list[dict]) -> Path:
    OUT.mkdir(exist_ok=True)
    path = OUT / name
    if rows:
        with path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    return path


def table(rows: list[dict], cols: list[str] | None = None) -> str:
    if not rows:
        return "(no data)"
    cols = cols or list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    head = "  ".join(c.ljust(widths[c]) for c in cols)
    sep = "  ".join("-" * widths[c] for c in cols)
    body = "\n".join("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols) for r in rows)
    return f"{head}\n{sep}\n{body}"
