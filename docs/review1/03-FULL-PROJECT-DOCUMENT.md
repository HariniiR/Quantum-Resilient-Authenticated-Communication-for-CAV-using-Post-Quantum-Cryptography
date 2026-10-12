# Quantum-Resilient Authenticated Communication for Connected and Autonomous Vehicles

**Full project document — the deck in prose, with every result explained**

Base paper: A. M. Aslam, A. Bhardwaj, R. Chaudhary, *"Quantum-resilient
blockchain-enabled secure communication framework for connected autonomous
vehicles using post-quantum cryptography"*, Vehicular Communications 52 (2025)
100880, Elsevier. DOI `10.1016/j.vehcom.2025.100880`

Implementation: `~/fyp-cav-pqc/` — 2,270 lines of Python, nine modules, runs on
any laptop.

---

## 1. The project in one paragraph

Cars send each other safety messages — braking, hazards, intersection entry —
over an open radio link. Those messages are protected today by two pieces of
mathematics, ECDSA and ECDH, both of which a quantum computer breaks. In August
2024 NIST published the official replacements, ML-KEM and ML-DSA. They work, but
they are roughly fifty times larger, and a car has to produce a safety message
every 100 milliseconds over a slow radio. **We implemented the base paper's
vehicular security framework using the standardised replacements and measured
whether they still fit.** They do — but only once you notice that the paper
measures the wrong thing.

---

## 2. The problem, in plain terms

All public-key cryptography rests on a sum that is easy one way and impossible
in reverse. Multiplying two large primes takes a microsecond; recovering them
from the product takes longer than the universe has existed. You publish the easy
direction as your public key and keep the hard direction private.

Three families of hard problem underpin everything deployed today:

- **RSA** — factoring large integers
- **Diffie–Hellman** — the discrete logarithm problem
- **ECC / ECDSA / ECDH** — the same discrete logarithm, on an elliptic curve

In 1994 Peter Shor published a quantum algorithm that solves factoring *and*
discrete logarithms efficiently. One algorithm, all three families.

Grover's algorithm is milder — it halves the effective strength of symmetric
ciphers and hashes, so AES-256 drops to about 128 bits, which is still ample.

> **AES and SHA-3 survive. Public-key cryptography does not.**

### Why it matters before quantum computers exist

An adversary records encrypted traffic today, stores it, and decrypts it in
fifteen years when the hardware arrives. This is called **harvest now, decrypt
later**. For a vehicle's location history, 2041 is not far enough away to be
comfortable.

### Post-quantum is not quantum

Two things that sound identical and are not:

| | What it is | Needs quantum hardware? |
|---|---|---|
| **Post-quantum cryptography** | New mathematics, ordinary software, ordinary chips | No |
| **Quantum cryptography (QKD)** | Security from physics — photons, no-cloning | Yes |

No car has a quantum channel to a roadside unit. This project is entirely the
first kind. That is the point of it.

---

## 3. The new mathematics

The replacements are built on **lattices**. Picture an endless grid of points in
256-dimensional space. Given a random location, which grid point is nearest? In
two dimensions you can point at it. In 256 dimensions, with a deliberately
awkward basis, nobody knows how — classically or quantumly.

The working form is **Learning With Errors**. Publish

```
b = A·s + e          A public matrix, s the secret, e small random noise
```

Without `e` this is school linear algebra and `s` falls out immediately. The
noise is what makes it hard. ML-KEM uses a variant called Module-LWE, which
balances key size against speed.

Two standards came out of this:

| Standard | Name | Replaces | Purpose |
|---|---|---|---|
| **FIPS 203** | ML-KEM (was Kyber) | ECDH | agree a shared secret |
| **FIPS 204** | ML-DSA (was Dilithium) | ECDSA | prove identity |

### A KEM is not Diffie–Hellman

This distinction matters more than any other in the project, because the base
paper gets it wrong.

- **Diffie–Hellman**: both sides contribute a secret and mix them.
- **KEM**: *one* side invents a random secret and seals it in a box using the
  other side's public key. Only the matching private key opens it.

The whole interface is three functions:

```python
ek, dk  = keygen()          # encapsulation (public) and decapsulation (private) keys
key, ct = encaps(ek)        # invent a secret, seal it into ciphertext ct
key     = decaps(dk, ct)    # open it, recover the same secret
```

**A KEM has no signing operation.** There is no `sign()`. Remember that for
section 5.

---

## 4. What the base paper proposes

Two things joined together.

### Quantum-safe communication

A four-layer architecture — vehicles at the user layer, RSUs and edge servers at
the MEC layer, validators at the consensus layer, and a cloud archive. Every
entity registers with a Trusted Authority and receives a token

```
S_i = H(ID_i ‖ pk_i ‖ MK ‖ TS_i)
```

where `MK` is the authority's master key and `TS` a timestamp, which is the
defence against replay. Vehicles then establish session keys with RSUs, and with
each other by relaying through RSUs.

### AGS-PBFT — the paper's genuine contribution

Traffic records go into a tamper-proof ledger agreed by voting. Textbook PBFT
makes every node vote on every transaction, which is expensive. The paper's
**Adaptive Grouping Score** variant:

- every node starts at score **100**
- nodes split into an active **consensus set** and a passive **candidate set**
- vote with the majority: **+1**. Vote against it: **−5**
- every **50** requests, compute mean μ and standard deviation σ over all
  scores. Below **μ−σ** you are demoted; above **μ+σ** you are promoted
- the consensus set grows under load and shrinks when quiet
- the set always satisfies **CN ≥ 3f+1**

This is the part we implemented most faithfully, because it is the part with no
existing implementation anywhere.

---

## 5. What we found in the base paper

Six issues. Each is documented in `cavpqc/__init__.py` and at the point of
implementation, so every deviation is traceable.

### D1 — It signs with something that cannot sign

*Algorithm 2, and `Sign_c` / `Sign_l` / `Sign_r` in Table 3.*

Consensus nodes are instructed to sign and verify "using KYBER-PQC." Per section
3, ML-KEM is a key encapsulation mechanism with no signing operation. The entire
consensus protocol cannot authenticate a single message as written.

**Fix:** ML-DSA-65 (FIPS 204). The paper mentions Dilithium only in its future
work section, apparently unaware it was required in the present work.

### D2 — The key exchange is circular

*Algorithm 1, lines 25 and 28.*

```
25:  Encapsulate: (c, k_i) ← (NTT⁻¹(Âᵀ·r + e), H(k_i ‖ H(c)))
28:  k'_j ← H(k_i ‖ H(c))
```

Line 25 defines `k_i` using `k_i`. Line 28 then requires the *decapsulating*
party to use `k_i` — a value it does not have, since obtaining it is the entire
purpose of the step.

**Fix:** the standard `encaps()` / `decaps()` interface.

### D3 — The session key hashes a value against itself

*Algorithm 1, line 32.* `K ← H(k_i ‖ k'_j)`. A correct KEM guarantees
`k_i == k'_j` — that is what makes it work — so this concatenates a value with
itself and adds nothing.

**Fix:** derive traffic keys with an extract-then-expand schedule bound to a hash
of the entire handshake transcript. This also buys downgrade resistance, which
the original had no mechanism for.

### D4 — It contradicts its own security claim

*Section 5.2.2 against Table 2.*

Table 2 credits the scheme with "No key escrow ✓". Section 5.2.2 has the Trusted
Authority generate each entity's private key — which *is* escrow — and then has
the entity generate a *second* keypair, leaving the registration token computed
over a public key that is then discarded.

**Fix:** each entity generates its own keypair; the authority certifies the public
key only. Our `TrustedAuthority.enrol()` refuses to enrol an entity that has not
generated its own keys, so the property is enforced by the code rather than
merely claimed.

### D5 — The blockchain framework cannot host the consensus protocol

*Table 4* lists Hyperledger Fabric 2.2 alongside AGS-PBFT. Fabric 2.2 orders
transactions using **Raft** and offers no way to substitute a PBFT-family
protocol.

**Fix:** implement the ledger directly so AGS-PBFT can actually drive it.

### D6 — The regrouping thresholds are undefined on first use

*Section 5.4.* Thresholds are `T_low = μ − σ` and `T_high = μ + σ`. But every
node starts at 100, so on the first reassignment σ = 0 and μ = 100, making
`T_low == T_high == 100`. Every node is then simultaneously at-or-below the
demotion threshold and at-or-above the promotion threshold.

**Fix:** require a strict spread (σ > 0) before applying thresholds, otherwise
fall back to rank order — which is what the paper's prose actually describes
("move the lowest-scoring nodes … move the highest-scoring nodes").

### Two further observations

- Table 2 credits the scheme with "Post Quantum Cryptography (**NTRU**) ✓". They
  use Kyber, which is Module-LWE — a different hardness assumption.
- The paper omits PBFT's **commit** phase, running Pre-Prepare → Prepare →
  Response → Reply. We implement it as specified and record the omission, since
  it is the likely source of the reduced round count reported in section 7.4.

### How to say this out loud

Not *"the paper is wrong."* Say: *"two of the algorithm listings were incomplete,
so we reconstructed them from FIPS 203 and FIPS 204 and documented every
deviation."* Same content, and it does not put your guide on the defensive.

---

## 6. What we built

| Module | Lines | What it does |
|---|---|---|
| `cavpqc/crypto.py` | 184 | ML-KEM and ML-DSA across all three security levels, SHAKE-256 hashing, transcript-bound key derivation, AES-256-GCM channels with `base_iv ⊕ counter` nonces and a hard rekey limit |
| `cavpqc/entities.py` | 219 | Trusted Authority, vehicles, RSUs, MEC and cloud servers. Registration, tokens, revocation list, timestamp freshness. Escrow refusal enforced. |
| `cavpqc/ledger.py` | 148 | `Block = (B_ID, Pr_B_Hash, T_Block)` chained with SHAKE-256, plus a Merkle root so a vehicle can verify one transaction without downloading a whole block |
| `cavpqc/handshake.py` | 203 | Corrected Algorithm 1. Mutual authentication, V2R and V2V-via-RSU relay, uniform abort with zeroization |
| `cavpqc/consensus.py` | 408 | AGS-PBFT: four phases, leader `p = v mod CN`, scoring, μ±σ regrouping, quorum maintenance, colluding Byzantine nodes. Plus textbook PBFT as the baseline |
| `cavpqc/network.py` | 207 | IEEE 802.11p from Table 4 — free-space path loss, 6 Mbps serialisation, CSMA/CA contention, frame segmentation. Urban grid mobility with optional SUMO |
| `cavpqc/simulation.py` | 213 | End-to-end driver: preparation → registration → handshake → encrypted beacons → consensus → ledger. Density sweep |
| `cavpqc/benchmark.py` | 373 | All metrics, classical baseline, attack tests, CSV output |
| `run_evaluation.py` | 231 | Runs all eight sections, writes 8 CSVs and 6 figures |

Run it:

```bash
cd ~/fyp-cav-pqc
./.venv/bin/python run_evaluation.py     # full evaluation
./.venv/bin/python demo.py               # the core idea in 15 lines
./.venv/bin/python why_composition_matters.py   # why libraries aren't the work
```

---

## 7. Results

All measured on our own hardware. Mean and population standard deviation, with
warm-up runs discarded — a detail that matters, as section 9 explains.

### 7.1 Post-quantum primitives

| Level | Operation | Mean (ms) | SD (ms) |
|---|---|---|---|
| L1 | ML-KEM-512 keygen | 1.52 | 0.04 |
| L1 | ML-KEM-512 encaps | 2.20 | 0.03 |
| L1 | ML-KEM-512 decaps | 3.12 | 0.06 |
| L1 | ML-DSA-44 keygen | 4.68 | 0.08 |
| L1 | **ML-DSA-44 sign** | **22.88** | **13.98** |
| L1 | ML-DSA-44 verify | 5.53 | 0.08 |
| L3 | ML-KEM-768 keygen | 2.58 | 0.05 |
| L3 | ML-KEM-768 encaps | 3.45 | 0.05 |
| L3 | ML-KEM-768 decaps | 4.65 | 0.08 |
| L3 | ML-DSA-65 keygen | 7.63 | 0.09 |
| L3 | **ML-DSA-65 sign** | **41.19** | **22.56** |
| L3 | ML-DSA-65 verify | 8.56 | 0.07 |
| L5 | ML-KEM-1024 keygen | 3.88 | 0.05 |
| L5 | ML-KEM-1024 encaps | 4.91 | 0.08 |
| L5 | ML-KEM-1024 decaps | 6.42 | 0.08 |
| L5 | ML-DSA-87 keygen | 11.74 | 0.09 |
| L5 | **ML-DSA-87 sign** | **60.68** | **40.17** |
| L5 | ML-DSA-87 verify | 13.27 | 0.13 |

**What this means.** Signing dominates everything, and it is wildly variable —
the standard deviation is more than half the mean. That is not sloppy
measurement. ML-DSA uses **rejection sampling**: it generates a candidate
signature, checks whether it falls inside required bounds, and retries if not.
The number of retries varies per signature. Verification, which is
deterministic, has almost no spread at all. Contrast ML-DSA-65 signing at
41.19 ± 22.56 ms with verification at 8.56 ± 0.07 ms.

### 7.2 The classical baseline — what V2X uses today

| Operation | Mean (ms) |
|---|---|
| ECDH P-256 keygen | 0.021 |
| ECDH P-256 exchange | 0.053 |
| ECDSA P-256 sign | 0.032 |
| ECDSA P-256 verify | 0.086 |
| ECDH P-256 public key | 65 bytes |
| ECDSA P-256 signature | 70 bytes |

**What this means.** Classical elliptic curve operations are three orders of
magnitude faster. Post-quantum security is not free — it costs roughly 1000× in
compute and 50× in size. The honest question is not whether it is cheaper, but
whether it is cheap *enough*.

### 7.3 Sizes and 802.11p frame cost

| Suite | KEM pk | Signature | Handshake flight | Frames | Airtime |
|---|---|---|---|---|---|
| L1 (512 / 44) | 800 B | 2,420 B | 6,408 B | 5 | 10.91 ms |
| L3 (768 / 65) | 1,184 B | 3,309 B | 8,890 B | 6 | 14.70 ms |
| L5 (1024 / 87) | 1,568 B | 4,627 B | 12,390 B | 9 | 20.79 ms |
| **classical** | 65 B | 72 B | **274 B** | **1** | **0.84 ms** |

Link model, from paper Table 4: 6 Mbps, 20 mW transmit, −98 dBm noise floor,
1500 B MTU. Computed maximum range **454 m**.

**What this means.** This is the real cost of post-quantum V2X, and it is
bandwidth, not compute. A classical handshake is one frame. L3 needs six. At L5
it is nine. On a shared 6 Mbps channel with many vehicles contending, frame count
is what hurts.

### 7.4 The 100 ms question

Here is the distinction the base paper does not draw, and it is the most
important thing in this document.

Paper section 7.2 folds "the time required for authentication and session key
establishment" into its end-to-end latency and compares that against vehicular
requirements. But those are **two different budgets**:

- The **handshake** runs once per RSU association. A vehicle at 10 m/s inside a
  454 m radio range is associated for tens of seconds, so a handshake of a few
  hundred milliseconds is amortised over thousands of beacons.
- The **beacon path** runs every 100 ms. This is the hard real-time constraint.

Measuring the beacon path alone:

| Mode | Crypto | Airtime | Total | Fits 100 ms? |
|---|---|---|---|---|
| AEAD only | 0.03 ms | 1.84 ms | **1.87 ms** | **yes** |
| signed, ML-DSA-44 | 28.53 ms | 6.75 ms | **35.28 ms** | **yes** |
| signed, ML-DSA-65 | 47.13 ms | 9.66 ms | **56.79 ms** | **yes** |
| signed, ML-DSA-87 | 50.46 ms | 13.14 ms | **63.59 ms** | **yes** |

**What this means.** Post-quantum V2X authentication fits, at every NIST security
level, even in pure Python. Once a session exists, protecting a beacon costs
1.87 ms against a 100 ms budget — a 50× margin. Broadcast authentication with a
fresh signature per beacon is more expensive but still fits, using 57% of budget
at level 3.

This is the project's headline result, and it only becomes visible once the
one-time and per-beacon costs are separated.

### 7.5 AGS-PBFT against textbook PBFT

| Nodes | Active set | AGS-PBFT msgs/req | PBFT msgs/req | Reduction |
|---|---|---|---|---|
| 10 | 5 | 42 | 182 | **76.9%** |
| 16 | 8 | 114 | 482 | **76.3%** |
| 22 | 11 | 222 | 926 | **76.0%** |
| 28 | 14 | 366 | 1,514 | **75.8%** |

Chain valid in every configuration.

**What this means.** The paper's central claim holds. Roughly three quarters of
consensus traffic disappears, and the saving is stable as the network grows.
Two effects contribute: only the active consensus set votes, and the commit phase
is absent. The second is a design choice with a safety cost, which is why we
record the omission rather than presenting the saving as free.

### 7.6 Byzantine fault tolerance

Faulty nodes forced into the *active* consensus set, colluding on a single false
value.

| Byzantine | Set | Honest | f bound | Quorum 2f+1 | Safety | Liveness | Committed |
|---|---|---|---|---|---|---|---|
| 0 | 8 | 8 | 2 | 5 | ok | ok | 100% |
| 1 | 8 | 7 | 2 | 5 | ok | ok | 100% |
| 2 | 8 | 6 | 2 | 5 | ok | ok | 100% |
| 3 | 11 | 8 | 3 | 7 | ok | ok | 100% |
| 4 | 11 | 7 | 3 | 7 | **violated** | ok | 100% |
| 5 | 12 | 7 | 3 | 7 | **violated** | ok | 100% |
| 6 | 12 | 6 | 3 | 7 | violated | **violated** | 92.5% |
| 7 | 12 | 5 | 3 | 7 | violated | violated | **0%** |

**What this means.** Two properties are involved and they are not the same thing:

- **Safety** needs `n ≥ 3f+1` for agreement to be *guaranteed* against `f`
  colluding faults.
- **Liveness** needs the honest nodes to actually reach the `2f+1` quorum.

Commits continue past the safety bound at 4 and 5 faults because the honest
plurality happens to clear the quorum anyway. Guarantee lost, function retained.
Commit rate collapses exactly when liveness fails. The base paper does not
separate these.

### 7.7 Security evaluation

| Attack | Rejected | Mechanism |
|---|---|---|
| Ciphertext tampering | yes | AEAD tag mismatch |
| Replay, stale timestamp | yes | freshness window exceeded |
| Impersonation with stolen token | yes | public key absent from TA directory |
| Revoked credential | yes | identity on CRL |
| MITM ephemeral key substitution | yes | signature does not cover substituted key |
| Session key reuse | yes | ephemeral KEM keypair per session |
| Ledger tampering | yes | hash chain broken |

**7 of 7 rejected.**

### 7.8 Density sweep, 50–300 vehicles

Handshake latency stays flat at roughly 130–175 ms mean across all densities,
with 11 frames per handshake and throughput rising from 2.1 to 14.4 kbps. Blocks
committed scale with successful handshakes and the chain remains valid
throughout. Messages per consensus request stay constant at 114, since the
consensus set size is independent of vehicle count.

---

## 8. The four findings

**1. Post-quantum V2X authentication fits the 100 ms budget** — at every NIST
security level, on commodity hardware, in pure Python. AEAD-protected beacons use
under 2% of budget; per-beacon signing uses 35–64%.

**2. Bandwidth is the binding constraint, not compute.** Six 802.11p frames per
handshake at level 3 against one for classical. That is what will limit
deployment.

**3. Signing dominates and it is unpredictable.** 41 ± 23 ms at level 3, because
ML-DSA uses rejection sampling. Verification is 8.6 ± 0.07 ms. Any latency budget
must be built around the signing tail, not the mean.

**4. AGS-PBFT's claimed saving is real** — about 76% fewer messages, stable from
10 to 28 nodes — but part of it comes from omitting PBFT's commit phase, which
costs safety guarantees the paper does not discuss.

---

## 9. Two bugs our own verification caught

Worth including in your report. Finding mistakes in your own work is what makes
the results credible.

**An 868 ms measurement that was really 0.04 ms.** The first handshake run showed
AES-GCM taking 868 ms to encrypt 55 bytes. That was pycryptodome loading its AES
backend on first call. With warm-up runs the true cost is 0.03 ms — a factor of
29,000. This is exactly the failure mode that produces the kind of implausible
figures we found in the literature, such as an X25519 baseline reported as
2.81 ± 23.44 ms, where the standard deviation is eight times the mean.

**Byzantine nodes that weren't colluding.** Initially each faulty node emitted a
*different* wrong digest. They therefore split their own vote, the honest
plurality won, and consensus appeared to survive well past the 3f+1 bound —
making the protocol look more robust than PBFT theory permits. Fixed so all
faulty nodes collude on one false value, which is the adversary model the bound
is actually stated against.

A third issue turned out not to be a bug at all: commits continuing past the
safety bound looked wrong, but PBFT commits whenever honest nodes reach quorum.
Our pass/fail criterion was wrong, not the implementation. Separating safety from
liveness resolved it.

---

## 10. Known limitations — state these before you are asked

**The cryptographic libraries are not constant-time.** `kyber-py` and
`dilithium-py` are documented by their authors as educational. They are correct
— we validate against the NIST ACVP known-answer vectors — but they do not
resist timing side-channel attacks. The base paper's section 6.7 makes timing
attack claims that our implementation does **not** satisfy. This is a functional
and performance study, not a deployable system.

**RSU density is too low in the current sweep.** At 454 m range, nine RSUs over a
5 km × 5 km grid leaves about 80% of vehicles unable to reach one. Full coverage
needs roughly 120 RSUs. The sweep should scale RSU count with area rather than
vehicle count. Fix before quoting handshake success rates.

**The network model is analytic, not a PHY simulation.** We model free-space path
loss, serialisation at 6 Mbps, and CSMA/CA contention. The base paper used
OMNeT++ with Veins. Ours captures frame count and contention scaling — the two
effects that dominate the post-quantum question — but it is not equivalent, and
free-space path loss is optimistic for an urban grid.

**V2V through RSUs is not end-to-end confidential.** In the paper's relay design
the RSUs learn the vehicle-to-vehicle key. Confidential against outsiders, not
against infrastructure. The paper does not state this; we record it as a finding.

**Absolute timings are not comparable to compiled implementations.** Pure Python
is roughly 50–100× slower than PQClean in C. Our numbers are valid for our
platform and the comparative ratios hold, but they should not be set against
figures from C implementations.

---

## 11. What remains

| Weeks | Work |
|---|---|
| 9 | SUMO road network for a real city, TraCI integration (hook already present in `network.py`) |
| 10 | Scale RSU density properly; handshake success rate across RSU transit |
| 11 | Rerun the full sweep; finalise all figures |
| 12 | Report, demonstration, viva |

---

## 12. How to present this

### Opening sentence

> "Vehicle safety messages are secured today with ECDSA and ECDH, which Shor's
> algorithm breaks. We implemented our base paper's framework using the NIST
> post-quantum replacements and measured whether they meet the 100 millisecond
> safety-message deadline. They do — but only once the one-time handshake cost is
> separated from the per-beacon cost, which the paper conflates."

### Questions you will get

**"What's novel? You implemented an existing paper."**
The paper cannot be executed as printed — two algorithm listings are incomplete
and the consensus layer signs with a primitive that has no signing operation. We
reconstructed both, supplied the missing primitive, and measured the result under
vehicular conditions the original never tested. We also separate the handshake
budget from the beacon budget, which changes the conclusion.

**"Do you understand the cryptography or just call libraries?"**
Explain Module-LWE as finding a hidden lattice point once noise is added, and why
a KEM differs from Diffie–Hellman. Then say plainly that you use audited library
implementations because hand-written lattice arithmetic is a documented source of
vulnerabilities. That answer is stronger than pretending otherwise. Then run
`why_composition_matters.py`, which shows the same six library calls producing a
secure system in one arrangement and an attacker-readable one in another.

**"Is it secure enough to deploy?"**
No — say so first. Section 10 lists exactly why.

**"Where's the quantum computing?"**
There is none, and that is the point. Post-quantum cryptography is designed for
the hardware we already have. Mention that you evaluated and rejected two
QKD-based papers for requiring hardware no vehicle has.

**"Why not Hyperledger Fabric, as the paper says?"**
Fabric 2.2 orders via Raft and cannot host PBFT-family consensus. Implementing
the ledger directly is the only way to actually run AGS-PBFT.

**"Your laptops are weak."**
A car's onboard unit is far closer to a modest laptop than to a desktop i7. Modest
hardware makes these numbers *more* relevant to deployment, not less. We report
our platform, as the papers do.

### The thing that lands hardest

Open a terminal and run `run_evaluation.py`. Eight sections of real
measurements, 7 of 7 attacks rejected, six figures. A panel that sees working
code stops interrogating scope and starts discussing results.

---

## 13. References

1. P. W. Shor, "Polynomial-time algorithms for prime factorization and discrete
   logarithms on a quantum computer," *SIAM J. Comput.* 26:1484–1509, 1997.
2. L. K. Grover, "A fast quantum mechanical algorithm for database search,"
   *Proc. 28th ACM STOC*, 212–219, 1996.
3. NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism*, 2024.
4. NIST, *FIPS 204: Module-Lattice-Based Digital Signature Algorithm*, 2024.
5. J. Bos et al., "CRYSTALS-Kyber: a CCA-secure module-lattice-based KEM,"
   *IEEE EuroS&P*, 353–367, 2018.
6. L. Ducas et al., "CRYSTALS-Dilithium: digital signatures from module
   lattices," *EUROCRYPT*, 238–268, 2018.
7. A. M. Aslam, A. Bhardwaj, R. Chaudhary, *Vehicular Communications* 52,
   art. 100880, 2025. **(base paper)**
8. A. Olushola, S. P. Meenakshi, *Frontiers in Physics* 13, art. 1723966, 2026.
   (handshake composition reference)
9. M. Castro, B. Liskov, "Practical Byzantine fault tolerance," *OSDI*, 1999.
10. C. Peikert, "A decade of lattice cryptography," *Found. Trends Theor.
    Comput. Sci.* 10:283–424, 2016.
11. A. Langlois, D. Stehlé, "Worst-case to average-case reductions for module
    lattices," *Des. Codes Cryptogr.* 75(3):565–599, 2015.
12. M. Mosca, "Cybersecurity in an era with quantum computers: will we be
    ready?" *IEEE Security & Privacy* 16:38–41, 2018.
13. NIST, *SP 800-38D: GCM and GMAC*, 2007.
14. E. Rescorla, *TLS Protocol Version 1.3*, RFC 8446, 2018.
15. P. A. Lopez et al., "Microscopic traffic simulation using SUMO," *IEEE
    ITSC*, 2575–2582, 2018.

---

## Appendix — Glossary

| Term | Meaning |
|---|---|
| CAV | Connected and Autonomous Vehicle |
| V2V / V2I / V2X | Vehicle-to-Vehicle / -Infrastructure / -Everything |
| RSU | Roadside Unit — the radio on a pole |
| OBU | Onboard Unit — radio and computer in the car |
| MEC | Multi-access Edge Computing — a server near the road |
| TA | Trusted Authority — issues and certifies identities |
| PQC | Post-Quantum Cryptography — classical software, quantum-resistant maths |
| QKD | Quantum Key Distribution — needs quantum hardware. Not this project. |
| KEM | Key Encapsulation Mechanism — seals a secret into a ciphertext |
| ML-KEM | The standardised KEM, FIPS 203. Formerly Kyber. |
| ML-DSA | The standardised signature scheme, FIPS 204. Formerly Dilithium. |
| LWE / MLWE | Learning With Errors — the lattice problem underneath both |
| AEAD | Authenticated Encryption with Associated Data — encrypts and detects tampering |
| HKDF | Turns one shared secret into several independent keys |
| Nonce | A number used once. Reuse with the same key breaks GCM entirely. |
| Transcript binding | Hashing every handshake message into the key, so nothing can be swapped |
| Forward secrecy | Stealing today's long-term key does not decrypt yesterday's traffic |
| Rejection sampling | Retry-until-valid. Why ML-DSA signing time varies. |
| HNDL | Harvest Now, Decrypt Later |
| PBFT | Byzantine-tolerant voting; needs `n ≥ 3f+1` |
| AGS-PBFT | The base paper's variant, with node scores and periodic regrouping |
| Safety / Liveness | Agreement is *guaranteed* / agreement is *reached* |
| SUMO | Eclipse Simulation of Urban MObility — the traffic simulator |
| TraCI | Traffic Control Interface — Python API for SUMO |
| IEEE 802.11p | The Wi-Fi variant used for vehicular radio |
| Shor's algorithm | Breaks RSA, ECDH, ECDSA |
| Grover's algorithm | Halves symmetric strength. AES-256 survives. |
