# Quantum-Resilient Authenticated Communication for Connected Autonomous Vehicles

Final Year Project, Department of Information Technology, College of Engineering Guindy.
Harini R, Ananyalakshmi VK, Adhithya K, Ratish SA. Guide: Dr. Vijayalakshmi M.

A complete, working implementation of a post-quantum V2X security framework:
ML-KEM key establishment, ML-DSA authentication, AES-256-GCM records, a Trusted
Authority PKI, criticality-based routing, and an AGS-PBFT consensus layer with
view change over a hash-linked ledger. It runs three ways:

1. **As a distributed system:** 19 separate processes over TCP (TA, cloud, MEC,
   8 consensus nodes, 3 RSUs, 5 vehicles), with fault injection.
2. **In ns-3:** IEEE 802.11p with mobility for 50–200 vehicles, carrying the
   protocol's real message sizes and measured processing times.
3. **As an evaluation suite:** benchmarks, 19 attacks, consensus experiments,
   figures, and 48 tests.

Base paper: A. M. Aslam, A. Bhardwaj, R. Chaudhary, *Quantum-resilient
blockchain-enabled secure communication framework for connected autonomous
vehicles using post-quantum cryptography*, Vehicular Communications 52 (2025)
100880. Handshake composition follows Olushola and Meenakshi, Frontiers in
Physics 13 (2025) 1723966.

---

## Quick start (Windows, Linux, macOS)

```powershell
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

python scripts\demo_protocol.py   # the protocol step by step (1 s)
python scripts\run_network.py     # the whole distributed system (50 s)
python -m pytest                  # 48 tests (~2 min)
python scripts\run_evaluation.py  # benchmarks + figures into results\ (~3 min)
```

ns-3 runs in WSL2 / Linux: `pip install -r requirements-ns3.txt`, then
`python scripts/run_ns3_sweeps.py`. Full instructions and the Review 2 demo
script are in [`docs/06-RUNNING-AND-DEMO.md`](docs/06-RUNNING-AND-DEMO.md).

---

## Layout

```
qrcav/                         the system (v2)
  crypto/suites.py             ML-KEM / ML-DSA suites; OpenSSL and pure-Python backends; ECDH/ECDSA baseline
  crypto/kdf.py                SHAKE-256, HKDF-SHA3-256, DERIVE_SESSION_KEYS (deck slide 14)
  crypto/records.py            AES-256-GCM <ctr, ciphertext, tag> records, replay window (slide 17)
  pki.py                       Trusted Authority, certificates, signed CRL, registry DB (slides 12-13)
  handshake.py                 four-flight mutually authenticated handshake (slides 15-16), sans-IO
  ledger.py                    hash-linked blocks with commit certificates
  consensus/agspbft.py         AGS-PBFT: request ... reply, scoring, regrouping, view change (slides 22-29)
  consensus/client.py          the MEC's consensus client
  consensus/sim.py             in-process discrete-event harness with real signatures
  net/secure.py                secure channels over TCP
  nodes/                       one process per entity: ta, cloud, mec, consensus_node, rsu, cav
  sim/                         ns-3 802.11p scenario (C++ via cppyy) + measurement profiles
  eval/                        benchmarks, attacks, consensus experiments, ns-3 sweeps, plots
scripts/                       demo_protocol, run_network, run_evaluation, run_ns3_sweeps
config/demo.json               the Review 2 scenario (faults, revocation, handover, V2V)
tests/                         pytest suite, including a real multi-process run
docs/                          00-04 background (Review 1); 05 design; 06 running + demo; 07 results
results/                       CSVs and figures (results/review1/ holds the Review 1 outputs)

cavpqc/, demo.py, handshake.py, run_evaluation.py, why_composition_matters.py
                               the Review 1 prototype, kept unchanged for reference
```

---

## What changed since Review 1

| Area | Review 1 | Now |
|---|---|---|
| Crypto backend | pure Python only (not constant-time, ~45 ms per ML-DSA-65 signature) | native OpenSSL (constant-time, ~1 ms per signature) by default; pure Python kept for comparison |
| Registration | HMAC-style token checked online by the TA | ML-DSA certificates (role, serial, validity) checked offline; proof of possession; signed CRL |
| Handshake | server-only signature; keys compared in memory | ClientHello, then mutual signatures and encrypted Finished messages in both directions |
| Records | sequential nonce | `<ctr, ct, tag>`, data counter from 1, 64-record replay window |
| Topology | function calls in one process | 19 processes over TCP; MEC criticality routing; V2V via RSUs; cloud path |
| Consensus | no view change; textbook PBFT baseline only counted messages | full view change; certified blocks; a PBFT baseline that runs with real signatures |
| Simulation | analytic 802.11p model, SUMO planned | ns-3 802.11p, mobility, handover, EDCA, fragmentation |
| Tests | none | 48, including a multi-process run |

## Corrections to the Review 1 design

Details in [`docs/05-SYSTEM-DESIGN.md`](docs/05-SYSTEM-DESIGN.md) §4.

- **F1:** The transcript is never initialised. Fixed with a ClientHello carrying
  a fresh nonce and timestamp.
- **F2:** Only the server signs, so a copied vehicle certificate is enough to
  impersonate that vehicle. Fixed with a client signature.
- **F3:** Finished uses counter 0 and the data counter's start is unspecified,
  which risks AES-GCM nonce reuse. Data now starts at 1.
- **F4:** Slide 15's ML-KEM key generation is shown incorrectly (`e` is not
  part of the decapsulation key).
- **F5:** The certificate binds no role or validity period.
- **F6:** There is no downgrade protection.
- **F7:** Abort reasons are not made uniform.
- **Naming:** the KDF is named three different ways on the slides; the code
  uses HKDF-SHA3-256 throughout.

The base paper's own defects D1–D5 (signing with a KEM, a circular shared
secret, hashing a value against itself, key escrow, Fabric not supporting PBFT)
are documented in `docs/03-FULL-PROJECT-DOCUMENT.md`. New design decisions
where the paper is undefined are numbered D6–D9 in `docs/05`.

---

## Headline results

Measured on a 2-core cloud VM; your laptop will differ in absolute numbers,
not in shape. Full tables and figures are in
[`docs/07-RESULTS.md`](docs/07-RESULTS.md).

| | Classical (ECDH + ECDSA P-256) | Post-quantum (ML-KEM-1024 + ML-DSA-65) |
|---|---|---|
| Handshake size (certificates included) | 1,042 B, 4 frames | 20,779 B, 17 frames |
| Handshake compute, both sides, native | 1.1 ms | 3.9 ms |
| Handshake compute, both sides, pure Python | n/a | 142 ms |
| Per-beacon cost in a session (p99, crypto + airtime) | 0.39 ms | 0.39 ms |
| Per-beacon cost, signed broadcast (p99) | 0.64 ms | 8.8 ms native, 163 ms pure Python |
| ns-3, 50 vehicles: handshakes completed / median time | 100 % / 6 ms | 99 % / 106 ms |
| ns-3, 100 vehicles | 100 % / 9 ms | 77 % / 379 ms |
| ns-3, 200 vehicles | 100 % / 13 ms | 29 % / 790 ms |

ns-3 figures are the mean of 3 seeds, over 1.5 km × 1.5 km with 9 RSUs.

1. **Compute is no longer the problem; bytes are.** With a native
   implementation, a post-quantum handshake costs about 4 ms of CPU. It costs
   20 KB on a 6 Mb/s shared channel, and in a dense cell that is what fails.
2. **Session beacons cost nothing extra.** Inside an established session a
   beacon is an AES-GCM record (135 B) whatever the suite: 0.4 ms against a
   100 ms budget. Per-beacon ML-DSA signatures fit the deadline natively
   (8.8 ms p99) but not in pure Python (163 ms), and they are 3 frames each.
3. **Dense traffic breaks post-quantum handshakes first, ordered by size.** At
   about 44 vehicles/km² (100 vehicles) handshake success is L1 96 %, L3 78 %,
   DECK 77 %, L5 50 %; at 200 vehicles every PQ suite is at 21-37 %. The
   classical handshake stays at 100 % throughout.
4. **Two MAC/protocol mitigations rescue the moderate case.** At 100
   vehicles, EDCA priority for safety traffic plus exponential handshake
   backoff take DECK handshake success from 11 % to 88 % and the median alert
   time from 392 ms to 7.6 ms (single-seed ablation).
5. **Consensus never sits on the safety path.** Alerts reach vehicles in about
   5 ms; the ledger commit follows in 15–45 ms.
6. **AGS-PBFT sends 73-86 % fewer messages than PBFT and uses 16-35 % less
   CPU, but is not faster.** Its leader-centred certificate step adds an extra
   hop: +36-48 % commit latency on a LAN. The byte saving is only 8-30 %
   because certified blocks carry ML-DSA signatures. Without shadow
   validation the byte saving is 41-64 %.
7. **Safety held in every Byzantine run; liveness is lost above f.** Wrong-result
   nodes are demoted by the μ−σ rule. A silent node can escape demotion when an
   outlier inflates σ, a weakness of the paper's rule.
8. **All 19 attacks were rejected.**

---

## Known limitations

- **One machine.** The distributed system runs on localhost; radio effects come
  only from ns-3.
- **ns-3 does not run the cryptography.** It replays measured size and timing
  distributions.
- **No WAVE module.** ns-3 3.44's pip wheel has none, so 802.11p runs in ad-hoc
  MAC mode.
- **V2V is not end-to-end confidential.** It is relayed through RSUs, as in the
  deck's design.
- **Certificates are sent in full on every handshake.** Caching would roughly
  halve the post-quantum handshake (future work).
- **No formal verification.**
