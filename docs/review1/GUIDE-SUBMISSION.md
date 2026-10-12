# Final Year Project — Guide Submission Document

**Programme:** B.Tech, Information Technology
**Department:** ___________________________
**Institution:** ___________________________
**Team Members:** ___________________________
**Guide:** ___________________________
**Date:** ___________________________

---

## Project Title

**Quantum-Resilient Authenticated Communication for Connected and Autonomous Vehicles
using ML-KEM, ML-DSA and Adaptive Grouping Score PBFT Consensus**

---

## One-Line Summary

We implement a quantum-safe security framework for connected vehicles and measure
whether the NIST post-quantum standards fit the 100 millisecond vehicular
safety-message deadline.

---

## Problem Being Solved

Vehicles send safety-critical messages — braking alerts, hazard warnings, intersection
entries — over open wireless channels. These are protected today by ECDSA signatures
and ECDH key exchange.

Shor's algorithm, running on a large quantum computer, breaks both in polynomial time.
An attacker can also record encrypted traffic today and decrypt it later once such a
machine exists — relevant for vehicle location histories that remain sensitive years
from now.

In August 2024 NIST standardised the replacements:

| Old scheme | What it does | New standard | NIST ID |
|---|---|---|---|
| ECDH | Key agreement | ML-KEM (Kyber) | FIPS 203 |
| ECDSA | Signatures | ML-DSA (Dilithium) | FIPS 204 |

The replacements are secure. The engineering question is whether they are fast and
small enough. An ECDH public key is 32 bytes; an ML-KEM-1024 public key is 1,568 bytes.
An IEEE 802.11p safety beacon must be produced every 100 ms over a 6 Mbps link.

**Does it fit? That is our project.**

---

## Base Paper

> A. M. Aslam, A. Bhardwaj, R. Chaudhary,
> *"Quantum-resilient blockchain-enabled secure communication framework for
> connected autonomous vehicles using post-quantum cryptography"*,
> **Vehicular Communications, Vol. 52, Article 100880, 2025**, Elsevier.
> DOI: `10.1016/j.vehcom.2025.100880`
> Affiliation: Bennett University, Greater Noida, India.

### What the paper proposes

The paper designs a four-layer framework for connected vehicles:

1. **User layer** — vehicles with onboard units, secured by Kyber (ML-KEM) session keys
2. **MEC layer** — roadside units and edge computing servers
3. **Consensus layer** — a novel voting protocol called AGS-PBFT
4. **Cloud layer** — non-critical data archival

The original contribution is the **AGS-PBFT consensus mechanism**: nodes are scored
on their voting behaviour (+1 for agreeing with the majority, −5 for disagreeing).
Every 50 requests, nodes are promoted or demoted between an active consensus set and
a passive candidate set based on whether their score is above or below μ±σ thresholds.
This reduces the number of participating nodes dynamically, lowering communication
overhead compared to standard PBFT.

### Identified defects in the base paper

On close reading, four defects were found that prevent the paper from being implemented
as published. These are documented here and at the point of correction in the code.

| # | Location | Defect |
|---|---|---|
| 1 | Algorithm 2, Table 3 (Sign_c, Sign_l, Sign_r) | Consensus messages are signed "using KYBER-PQC". ML-KEM is a key encapsulation mechanism with no signing operation. |
| 2 | Algorithm 1, lines 25 and 28 | The shared secret k_i is defined in terms of k_i (circular). Line 28 requires the decapsulating party to use a value it cannot possess. |
| 3 | Algorithm 1, line 32 | K ← H(k_i ‖ k'_j), but a correct KEM guarantees these are equal, so the key is derived by hashing a value against itself. |
| 4 | Section 5.2.2 vs Table 2 | The TA generates entity private keys (key escrow), contradicting the paper's own "No key escrow ✓" claim in Table 2. |

Each defect is resolved in the implementation and documented at the point of correction.
The supporting reference for the corrected handshake construction is:

> A. Olushola, S. P. Meenakshi,
> *"Design and implementation of an authenticated post-quantum session protocol
> using ML-KEM, ML-DSA, and AES-256-GCM"*,
> **Frontiers in Physics, Vol. 13, Article 1723966, 2026**.
> DOI: `10.3389/fphy.2025.1723966` — open access, CC BY 4.0.

---

## What We Are Building

The base paper's complete framework, implemented correctly in Python.

| Component | Source | Our approach |
|---|---|---|
| Four-layer architecture | Paper §4 | Implemented as specified |
| Entity model (TA, CAVs, RSUs, MEC, cloud) | Paper §4 | Implemented; TA generates no private keys (fixes defect 4) |
| Registration, tokens S = H(ID‖pk‖MK‖TS) | Paper §5.2 | Implemented as specified |
| Key establishment | Paper §5.3 | Defects 2 and 3 corrected; uses standard ML-KEM interface |
| Entity authentication | Missing in paper | Added: ML-DSA-65, fixes defect 1 |
| Handshake composition | Olushola & Meenakshi (2026) | Transcript-bound HKDF, AES-256-GCM records |
| AGS-PBFT consensus | Paper Algorithm 2 | Implemented as specified; defect 6 (zero-σ tie-break) documented |
| Hash-linked ledger | Paper §5.4 | Implemented as specified |
| Mobility | Paper Table 4 | Urban grid model; SUMO + TraCI when installed |
| Evaluation | Paper §7 | Own measurements; ECDH/ECDSA and plain PBFT baselines |

---

## Tools and Environment

All tools are free and open source. No commercial licence, GPU or special hardware is
required. Measured peak memory is under 10 MB.

| Purpose | Tool | Licence |
|---|---|---|
| Language | Python 3.9+ | PSF |
| Key establishment (FIPS 203) | kyber-py — ML-KEM | MIT / Apache-2.0 |
| Signatures (FIPS 204) | dilithium-py — ML-DSA | MIT / Apache-2.0 |
| Record encryption | pycryptodome — AES-256-GCM | BSD |
| Classical baseline | cryptography — ECDH, ECDSA | Apache-2.0 |
| Traffic simulation | Eclipse SUMO + TraCI | EPL-2.0 |
| Network event model | SimPy | MIT |
| Analysis and graphs | pandas, NumPy, Matplotlib | BSD |

**Substitutions from the paper's toolchain, with justification:**

- OMNeT++ 6.0 + Veins 5.2 → Python analytic 802.11p model. The C++ Eclipse toolchain
  is outside project scope; the network delay model is derived analytically from the
  paper's own Table 4 parameters.
- Hyperledger Fabric 2.2 → direct Python ledger. Fabric 2.2 uses Raft ordering and
  cannot host PBFT-family consensus.
- PQClean (C library) → kyber-py and dilithium-py. Pure Python, validated against
  NIST ACVP known-answer test vectors, no build toolchain required.
- MIRACL → cryptography package. MIRACL carries a commercial licence tier.

---

## Current Status — Already Built and Running

**Seven Python modules are complete.** The core cryptographic, consensus, ledger,
network model and simulation components are implemented and tested.

```
~/fyp-cav-pqc/
├── cavpqc/
│   ├── crypto.py      — ML-KEM, ML-DSA, SHAKE-256, AES-256-GCM, HKDF
│   ├── entities.py    — Trusted Authority, vehicles, RSUs, MEC, cloud
│   ├── handshake.py   — corrected Algorithm 1, V2R and V2V
│   ├── consensus.py   — AGS-PBFT and plain PBFT baseline
│   ├── ledger.py      — hash-linked ledger
│   ├── network.py     — IEEE 802.11p model and urban grid mobility
│   └── simulation.py  — integrated scenario runner
├── demo.py            — 15-line proof-of-concept
└── handshake.py       — standalone demo with attack tests
```

**Preliminary measurements**, obtained on commodity hardware, 200 iterations each:

| Operation | Mean (ms) | SD (ms) |
|---|---|---|
| ML-KEM-1024 encapsulation | 5.03 | 0.14 |
| ML-KEM-1024 decapsulation | 6.56 | 0.14 |
| ML-DSA-65 signing | 47.18 | 31.92 |
| ML-DSA-65 verification | 8.73 | 0.26 |
| AES-256-GCM encrypt 1 KB | 0.04 | 0.01 |

Complete V2R handshake: **48 ms**, **15,325 bytes** (mutual authentication),
**11 frames** at 802.11p 1500-byte limit.

Consensus: 120 blocks committed with 3 Byzantine nodes, chain valid, **76% fewer
messages per request** than standard PBFT with 16 nodes.

**Tampered ciphertexts and impersonation with replayed tokens are both rejected.**

---

## Key Findings So Far

**1. Signing is the bottleneck, not key exchange.**
ML-KEM-1024 encapsulation takes 5 ms; ML-DSA-65 signing takes 47 ms on average with a
32 ms standard deviation. This is a property of rejection sampling in ML-DSA, not
measurement error. The handshake at 48 ms meets the 100 ms budget on average, but the
tail may not.

**2. The 100 ms budget is tight, not comfortable.**
This motivates our specific research question: which parameter sets keep the worst-case
within budget? Lower sets (ML-KEM-768 + ML-DSA-65 or ML-DSA-44) will be evaluated.

**3. Mutual authentication raises the wire size.**
The paper describes one-sided authentication but never specifies direction clearly. Full
mutual authentication requires two ML-DSA signatures, raising the handshake payload to
15,325 bytes across 11 frames versus 4–5 frames for one-sided auth. Both variants will
be measured and the tradeoff reported.

**4. The published handshake size in the reference paper is an undercount.**
The secondary reference (Olushola & Meenakshi) reports 4.86 KB; our measurement of the
same construction yields 6,494 bytes because the ephemeral ML-KEM public key is counted
correctly. Their tables also list the ML-DSA-65 signature as 3,293 bytes; FIPS 204 and
our measurement both give 3,309 bytes.

---

## Remaining Work — Weeks 9–12

| Weeks | Work |
|---|---|
| 9 | SUMO road network from OpenStreetMap; TraCI mobility integration |
| 10 | Full benchmark suite: primitive sweeps across all security levels, classical baseline, density sweep |
| 11 | Attack harness (replay, tamper, impersonation, downgrade), graphs, AGS-PBFT vs PBFT comparison |
| 12 | Report, demonstration, viva preparation |

---

## Expected Deliverables

1. Working documented implementation of the framework, all four defects resolved
2. Measured performance of ML-KEM and ML-DSA across all parameter sets with a correct
   classical ECDH/ECDSA baseline
3. Answer to the primary research question: which parameter sets fit the 100 ms V2X
   deadline, and by what margin
4. AGS-PBFT vs standard PBFT comparison: message count, latency, fault tolerance at
   50–300 vehicles
5. Demonstrated resistance to replay, tampering, impersonation and downgrade attacks
6. Live demonstration: running vehicles, handshakes, consensus, and rejected attacks

---

## Scope Statement

**In scope:** simulation-based implementation; functional protocol correctness;
comparative performance measurement under vehicular mobility; attack-resistance
demonstration.

**Out of scope:** deployment on vehicle hardware; constant-time or side-channel-hardened
implementations; formal protocol verification using ProVerif or Scyther; reproduction of
the base paper's specific latency and throughput figures, which cannot be reconciled with
its own reported computation cost (920 ms end-to-end versus 10.31 ms computation).

**Stated limitation:** the pure-Python cryptographic libraries used (kyber-py,
dilithium-py) are documented by their authors as educational and not constant-time. This
is appropriate for a functional and performance study. The base paper's Section 6.7 makes
timing-attack resistance claims; our implementation does not satisfy those claims and
this is stated explicitly in our report.

---

## References

1. A. M. Aslam, A. Bhardwaj, R. Chaudhary, *Vehicular Communications*, 52, 100880, 2025. *(Base paper)*
2. A. Olushola, S. P. Meenakshi, *Frontiers in Physics*, 13, 1723966, 2026. *(Handshake reference)*
3. NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
4. NIST, *FIPS 204: Module-Lattice-Based Digital Signature Standard*, 2024.
5. P. W. Shor, *SIAM J. Comput.*, 26, 1484–1509, 1997. *(Shor's algorithm)*
6. J. Bos et al., "CRYSTALS-Kyber," *IEEE EuroS&P*, 353–367, 2018.
7. L. Ducas et al., "CRYSTALS-Dilithium," *EUROCRYPT*, 238–268, 2018.
8. M. Castro, B. Liskov, "Practical Byzantine fault tolerance," *OSDI*, 1999.
9. M. Mosca, *IEEE Security & Privacy*, 16, 38–41, 2018. *(Harvest-now-decrypt-later)*
10. NIST, *SP 800-38D: GCM and GMAC*, 2007.
