# Final Year Project — Abstract and Scope

**Programme:** B.Tech, Information Technology
**Department:** _______________________
**Institution:** _______________________
**Team:** _______________________
**Guide:** _______________________
**Review:** Abstract / Zeroth Review
**Date:** _______________________

---

## Title

**Quantum-Resilient Authenticated Communication for Connected and Autonomous
Vehicles using ML-KEM, ML-DSA and Adaptive Grouping Score PBFT Consensus**

---

## Abstract

Connected and Autonomous Vehicles (CAVs) exchange safety-critical messages over
open wireless channels, secured today by the Elliptic Curve Digital Signature
Algorithm and Elliptic Curve Diffie–Hellman. Both are broken in polynomial time by
Shor's algorithm on a sufficiently large quantum computer, and traffic recorded
today can be decrypted retrospectively once such a machine exists. In August 2024
NIST standardised the replacements: ML-KEM (FIPS 203) for key establishment and
ML-DSA (FIPS 204) for authentication. These are computationally practical but
substantially larger than the schemes they replace, which conflicts with the small
packets and 100 ms beacon interval of IEEE 802.11p vehicular communication.

This project implements the quantum-resilient CAV framework proposed by Aslam,
Bhardwaj and Chaudhary (Vehicular Communications 52, 2025, 100880) and evaluates it
under realistic vehicular mobility. Detailed reading of the base paper identified
four defects that prevent implementation as published: consensus messages are signed
using a key encapsulation mechanism, which possesses no signing operation; the
key-exchange pseudocode defines the shared secret in terms of itself; the session
key is derived by hashing a value against itself; and the registration phase has the
Trusted Authority generate entity private keys, contradicting the paper's own claim
of no key escrow.

We resolve each defect, introducing ML-DSA-65 for the absent signature primitive and
composing key establishment with a transcript-bound HKDF–SHA3-256 schedule following
Olushola and Meenakshi (Frontiers in Physics 13:1723966, 2026). The base paper's
Adaptive Grouping Score PBFT consensus layer, in which nodes are scored on consensus
behaviour and periodically reassigned between active and candidate sets against
μ±σ thresholds, is implemented as specified. The system is evaluated over
SUMO-generated urban mobility for 50 to 300 vehicles, measuring handshake latency,
on-wire size, consensus rounds and throughput against ECDH/ECDSA and standard PBFT
baselines.

Preliminary measurements on commodity hardware give ML-KEM-1024 encapsulation at
5.03 ms and decapsulation at 6.56 ms, while ML-DSA-65 signing costs 47.18 ms with a
32 ms standard deviation arising from rejection sampling. A complete
vehicle-to-RSU handshake completes in 48.23 ms and transmits 6,494 bytes across five
802.11p frames. Signature generation, not key establishment, is therefore the
binding constraint on post-quantum V2X authentication.

*(Approximately 340 words. Trim the final paragraph for a 250-word limit.)*

---

## Keywords

Post-quantum cryptography; ML-KEM; ML-DSA; connected and autonomous vehicles; V2X
security; Practical Byzantine Fault Tolerance; blockchain; harvest-now-decrypt-later

---

## Base Paper

> A. M. Aslam, A. Bhardwaj, R. Chaudhary, "Quantum-resilient blockchain-enabled
> secure communication framework for connected autonomous vehicles using
> post-quantum cryptography," *Vehicular Communications*, vol. 52, art. 100880,
> 2025. DOI: 10.1016/j.vehcom.2025.100880. Publisher: Elsevier.
> Authors' affiliation: School of Computer Science Engineering & Technology,
> Bennett University, Greater Noida, India.

**Supporting reference used to correct the base paper's key establishment:**

> A. Olushola, S. P. Meenakshi, "Design and implementation of an authenticated
> post-quantum session protocol using ML-KEM (Kyber), ML-DSA (Dilithium), and
> AES-256-GCM," *Frontiers in Physics*, vol. 13, art. 1723966, 2026.
> DOI: 10.3389/fphy.2025.1723966. Publisher: Frontiers Media SA. Open access,
> CC BY 4.0. Authors' affiliation: School of Computer Science and Engineering,
> VIT Vellore, India.

---

## Problem Statement

The cryptographic primitives currently securing V2X communication are known to be
vulnerable to quantum cryptanalysis. Standardised post-quantum replacements exist
but carry public keys, ciphertexts and signatures one to two orders of magnitude
larger than the elliptic-curve schemes they replace. Whether these replacements
satisfy the latency and bandwidth constraints of vehicular safety messaging has not
been established under realistic mobility. The base paper proposes such a framework
but cannot be implemented as published.

--- 

## Objectives

1. Implement registration and enrolment for vehicles, roadside units, edge servers
   and cloud servers, with entity-generated keypairs and Trusted Authority
   certification, correcting the key-escrow contradiction in the base paper.
2. Implement authenticated key establishment using ML-KEM-1024 with ML-DSA-65
   endpoint authentication, a transcript-bound HKDF–SHA3-256 key schedule, and
   AES-256-GCM record protection with per-direction non-repeating nonces. 
3. Implement the Adaptive Grouping Score PBFT consensus mechanism: score
   initialisation at 100, +1 for agreement and −5 for disagreement, μ±σ
   promotion and demotion every 50 requests, and maintenance of `CN ≥ 3f+1`.
4. Implement a hash-linked ledger recording validated traffic transactions as
   `Block = (B_ID, Pr_B_Hash, T_Block)`.
5. Evaluate over SUMO-generated urban mobility for 50–300 vehicles with an
   IEEE 802.11p link model, measuring end-to-end latency, on-wire handshake size,
   consensus rounds, throughput and handshake success rate during RSU transit.
6. Compare against ECDH/ECDSA and standard PBFT baselines, and demonstrate
   resistance to replay, tampering, impersonation and downgrade attacks.
7. Determine whether ML-KEM-768 with ML-DSA-44 brings the worst-case handshake
   within the 100 ms safety-beacon budget where the level-5 parameter sets do not.

---

## Identified Defects in the Base Paper

| # | Location | Defect | Resolution |
|---|---|---|---|
| 1 | Algorithm 2; `Sign_c`, `Sign_l`, `Sign_r` in Table 3 | Consensus messages signed "using KYBER-PQC". ML-KEM is a key encapsulation mechanism and defines no signing operation. | Introduce ML-DSA-65 (FIPS 204) |
| 2 | Algorithm 1, lines 25 and 28 | `k_i` is defined in terms of `k_i`; line 28 requires the decapsulating party to use a value it cannot possess. | Standard `encaps()` / `decaps()` |
| 3 | Algorithm 1, line 32 | `K ← H(k_i ‖ k'_j)` where a correct KEM guarantees the two are identical. | Transcript-bound HKDF–SHA3-256 |
| 4 | Section 5.2.2 against Table 2 | The Trusted Authority generates entity private keys, which constitutes escrow and contradicts the "No key escrow" claim; the entity then generates a second keypair, leaving the token bound to the wrong key. | Entity generates keypair; TA certifies public key only |

Supporting observations: Table 4 pairs Hyperledger Fabric 2.2 with AGS-PBFT, but
Fabric 2.2 orders transactions via Raft and cannot host PBFT-family consensus.
Table 2 attributes "Post Quantum Cryptography (NTRU)" to the proposed scheme, which
uses Kyber (Module-LWE), a different hardness assumption.

---

## Methodology and Tools

| Layer | Tool | Licence |
|---|---|---|
| Implementation language | Python 3.9+ | PSF |
| Key establishment | `kyber-py` (ML-KEM-1024, FIPS 203) | MIT / Apache-2.0 |
| Authentication | `dilithium-py` (ML-DSA-65, FIPS 204) | MIT / Apache-2.0 |
| Record protection | `pycryptodome` (AES-256-GCM) | BSD / public domain |
| Hashing and KDF | Python `hashlib` (SHAKE-256, SHA3) | PSF |
| Classical baseline | `cryptography` (ECDH, ECDSA) | Apache-2.0 / BSD |
| Traffic mobility | Eclipse SUMO + `traci` | EPL-2.0 |
| Network model | SimPy discrete-event simulation | MIT |
| Road network | OpenStreetMap extract | ODbL |
| Analysis and figures | pandas, NumPy, Matplotlib | BSD |

All tools are free and open source. No commercial licence, hardware accelerator or
GPU is required; measured peak memory use is under 10 MB.

### Deliberate substitutions

| Base paper uses | We use | Justification |
|---|---|---|
| OMNeT++ 6.0 + Veins 5.2 | SimPy discrete-event model | 802.11p delay is modelled analytically from the base paper's own Table 4 parameters (6 Mbps, 20 mW, −98 dBm noise floor), avoiding a C++ and Eclipse toolchain outside project scope. |
| Hyperledger Fabric 2.2 | Python hash-linked ledger | Fabric 2.2 orders transactions via Raft and cannot host AGS-PBFT; a direct implementation is required to execute the proposed consensus. |
| PQClean (C) | `kyber-py`, `dilithium-py` | Pure Python, validated against NIST ACVP known-answer test vectors, no build toolchain required. |
| MIRACL | `cryptography` | MIRACL is dual-licensed with a commercial tier; an open equivalent is used for the classical baseline. |

### Validation

Library correctness is established against the NIST ACVP known-answer test vectors
distributed with `kyber-py` and `dilithium-py`. Protocol correctness is established
by negative testing: tampered ciphertexts, replayed handshake transcripts,
downgraded algorithm identifiers and impersonated identities must each produce a
uniform abort with no application data released.

---

## Preliminary Results

Measured on commodity hardware, 200 iterations per operation with warm-up:

| Operation | Mean (ms) | SD (ms) |
|---|---|---|
| ML-KEM-1024 key generation | 3.965 | 0.113 |
| ML-KEM-1024 encapsulation | 5.025 | 0.135 |
| ML-KEM-1024 decapsulation | 6.562 | 0.138 |
| ML-DSA-65 key generation | 7.745 | 0.120 |
| ML-DSA-65 signing | 47.179 | 31.923 |
| ML-DSA-65 verification | 8.726 | 0.255 |
| AES-256-GCM encryption, 1 KB | 0.040 | 0.015 |

Complete vehicle-to-RSU handshake: **48.23 ms**, **6,494 bytes**, **5 frames** at a
1500-byte limit. Tampered ciphertexts and impersonation attempts using a replayed
registration token were both rejected.

Three observations follow. First, signature generation dominates the handshake and
exhibits high variance, a consequence of ML-DSA's rejection sampling rather than of
measurement error. Second, the 100 ms beacon budget is met on average but the
signing tail may exceed it, which motivates Objective 7. Third, the supporting
reference reports an on-wire handshake size of 4.86 KB, counting the KEM ciphertext
and signature but omitting the ephemeral ML-KEM public key that its own protocol
step 3 requires be transmitted; the corrected figure is 6,494 bytes, an undercount of
approximately 32%. That reference also lists the ML-DSA-65 signature as 3,293 bytes
in three tables, whereas FIPS 204 and our measurement both give 3,309 bytes.

---

## Expected Outcomes

1. A working, documented, open implementation of the base paper's framework with all
   four defects resolved.
2. Independently measured performance for ML-KEM and ML-DSA across parameter sets,
   with a correctly constructed classical baseline.
3. A determination of whether standardised post-quantum authentication fits the
   IEEE 802.11p 100 ms safety-beacon budget, and under which parameter sets.
4. Comparative evaluation of AGS-PBFT against standard PBFT for message count,
   latency and fault tolerance at 50–300 vehicles.
5. Demonstrated resistance to replay, tampering, impersonation and downgrade.
6. A documented defect analysis of the base paper, with each finding located to a
   specific algorithm line or table.

---

## Scope Boundaries

**In scope:** simulation-based implementation; functional protocol correctness;
comparative performance measurement; attack-resistance demonstration under the
stated adversary model.

**Out of scope:** deployment on vehicle hardware or real onboard units;
constant-time or side-channel-hardened cryptographic implementations; formal
protocol verification using tools such as ProVerif or Scyther; reproduction of the
base paper's published latency and throughput figures, which are not reconcilable
with its own reported computation cost.

**Stated limitation:** the pure-Python cryptographic libraries used are documented
by their authors as educational and not constant-time. They are appropriate for a
functional and performance study but do not provide the side-channel resistance that
the base paper's Section 6.7 claims. All timing figures are reported for our own
hardware and are not comparable in absolute terms to figures obtained from compiled
C implementations.

---

## Timeline

| Weeks | Milestone |
|---|---|
| 1–2 | Fundamentals; locate and document all four defects in the base paper |
| 3 | Environment; validate libraries against ACVP test vectors |
| 4–5 | Registration, enrolment, tokens, CRL, timestamp freshness |
| 6 | Handshake: ML-KEM + ML-DSA + HKDF + AES-256-GCM |
| 7–8 | AGS-PBFT consensus and hash-linked ledger |
| 9 | SUMO road network and TraCI mobility integration |
| 10 | IEEE 802.11p link model; full system integration |
| 11 | Baselines, attack harness, experiments, figures |
| 12 | Report, demonstration, viva preparation |

---

## References

1. P. W. Shor, "Polynomial-time algorithms for prime factorization and discrete
   logarithms on a quantum computer," *SIAM J. Comput.*, vol. 26, pp. 1484–1509, 1997.
2. L. K. Grover, "A fast quantum mechanical algorithm for database search," *Proc.
   28th ACM STOC*, pp. 212–219, 1996.
3. NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
4. NIST, *FIPS 204: Module-Lattice-Based Digital Signature Standard*, 2024.
5. J. Bos et al., "CRYSTALS-Kyber: a CCA-secure module-lattice-based KEM," *IEEE
   EuroS&P*, pp. 353–367, 2018.
6. L. Ducas et al., "CRYSTALS-Dilithium: digital signatures from module lattices,"
   *EUROCRYPT*, pp. 238–268, 2018.
7. A. M. Aslam, A. Bhardwaj, R. Chaudhary, "Quantum-resilient blockchain-enabled
   secure communication framework for connected autonomous vehicles using
   post-quantum cryptography," *Vehicular Communications*, vol. 52, art. 100880, 2025.
8. A. Olushola, S. P. Meenakshi, "Design and implementation of an authenticated
   post-quantum session protocol using ML-KEM, ML-DSA, and AES-256-GCM,"
   *Frontiers in Physics*, vol. 13, art. 1723966, 2026.
9. M. Castro, B. Liskov, "Practical Byzantine fault tolerance," *OSDI*, 1999.
10. C. Peikert, "A decade of lattice cryptography," *Found. Trends Theor. Comput.
    Sci.*, vol. 10, pp. 283–424, 2016.
11. A. Langlois, D. Stehlé, "Worst-case to average-case reductions for module
    lattices," *Des. Codes Cryptogr.*, vol. 75, no. 3, pp. 565–599, 2015.
12. M. Mosca, "Cybersecurity in an era with quantum computers: will we be ready?"
    *IEEE Security & Privacy*, vol. 16, pp. 38–41, 2018.
13. NIST, *SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM and
    GMAC*, 2007.
14. E. Rescorla, *The Transport Layer Security (TLS) Protocol Version 1.3*, RFC 8446,
    2018.
15. P. A. Lopez et al., "Microscopic traffic simulation using SUMO," *IEEE ITSC*,
    pp. 2575–2582, 2018.
