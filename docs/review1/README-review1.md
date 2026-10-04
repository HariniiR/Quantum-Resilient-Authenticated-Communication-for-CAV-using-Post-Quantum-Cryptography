# Quantum-Resilient Authenticated Communication for CAVs

Implementation of the framework proposed in:

> A. M. Aslam, A. Bhardwaj, R. Chaudhary, "Quantum-resilient blockchain-enabled
> secure communication framework for connected autonomous vehicles using
> post-quantum cryptography", **Vehicular Communications 52 (2025) 100880**,
> Elsevier. DOI: `10.1016/j.vehcom.2025.100880`

using NIST-standardised post-quantum primitives — ML-KEM (FIPS 203) and ML-DSA
(FIPS 204) — with six defects in the published algorithm listings corrected and
documented.

## Setup

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Optional, for real road-network mobility: install [Eclipse SUMO](https://eclipse.dev/sumo/)
and `pip install traci`. The code falls back to a synthetic urban grid if SUMO is
absent.

## Run

```bash
./.venv/bin/python demo.py                     # the core idea, 15 lines
./.venv/bin/python handshake.py                # standalone handshake + attack tests
./.venv/bin/python why_composition_matters.py  # why library calls are not the work
./.venv/bin/python run_evaluation.py           # full evaluation -> results/
```

`run_evaluation.py` writes 8 CSV files and 6 figures to `results/`.

## Layout

```
cavpqc/
  __init__.py     deviations D1-D6 from the published paper, documented
  crypto.py       ML-KEM, ML-DSA, SHAKE-256 KDF, AES-256-GCM channels
  entities.py     Trusted Authority, vehicles, RSUs, MEC, cloud; registration
  ledger.py       Block = (B_ID, Pr_B_Hash, T_Block), hash-linked
  handshake.py    corrected Algorithm 1; V2R and V2V-via-RSU
  consensus.py    AGS-PBFT (Algorithm 2) + textbook PBFT baseline
  network.py      IEEE 802.11p model from paper Table 4; mobility
  simulation.py   end-to-end driver; density sweep
  benchmark.py    metrics, classical baseline, attack tests
run_evaluation.py runs all eight evaluation sections
docs/             00 start here · 01 background · 02 abstract · 03 full document
results/          generated CSVs and figures
```

## Corrections to the published paper

| # | Location | Issue | Resolution |
|---|---|---|---|
| D1 | Algorithm 2, Table 3 | Consensus messages signed "using KYBER-PQC"; ML-KEM has no signing operation | ML-DSA-65 (FIPS 204) |
| D2 | Algorithm 1, lines 25, 28 | `k_i` defined in terms of `k_i`; decapsulator requires a value it cannot hold | Standard `encaps()`/`decaps()` |
| D3 | Algorithm 1, line 32 | `K = H(k_i ‖ k'_j)` where a correct KEM guarantees they are equal | Transcript-bound HKDF–SHAKE256 |
| D4 | §5.2.2 vs Table 2 | TA generates entity private keys, contradicting the paper's "No key escrow" claim | Entity generates; TA certifies public key only |
| D5 | Table 4 | Hyperledger Fabric 2.2 cannot host PBFT-family consensus (it orders via Raft) | Ledger implemented directly |
| D6 | §5.4 | `T_low = μ−σ`, `T_high = μ+σ` undefined on first use, since σ = 0 when all scores are 100 | Rank-order fallback until scores spread |

## Headline results

Measured on commodity hardware; see `docs/03-FULL-PROJECT-DOCUMENT.md` for full
tables and interpretation.

- **Per-beacon cost fits the 100 ms V2X budget at every security level**:
  1.87 ms with AEAD only, 35–64 ms with a fresh ML-DSA signature per beacon.
  This becomes visible only when the one-time handshake cost is separated from
  the per-beacon cost, which the base paper conflates.
- **Bandwidth is the binding constraint, not compute**: 8,890 B / 6 frames per
  handshake at NIST level 3, against 274 B / 1 frame for classical ECDH+ECDSA.
- **Signing dominates and varies widely**: ML-DSA-65 at 41 ± 23 ms, because of
  rejection sampling. Verification is 8.6 ± 0.07 ms.
- **AGS-PBFT reduces consensus messages by ~76%**, stable from 10 to 28 nodes —
  though part of the saving comes from omitting PBFT's commit phase.
- **7 of 7 attacks rejected**: tampering, replay, impersonation, revocation,
  MITM key substitution, session-key reuse, ledger tampering.

## Limitations

`kyber-py` and `dilithium-py` are documented by their authors as educational and
are **not constant-time**; they are validated against NIST ACVP known-answer
vectors but do not resist timing side-channel attacks. This is a functional and
performance study, not a deployable system. The 802.11p link is modelled
analytically rather than simulated at PHY level. Absolute timings are not
comparable to compiled C implementations. Full list in
`docs/03-FULL-PROJECT-DOCUMENT.md` §10.
