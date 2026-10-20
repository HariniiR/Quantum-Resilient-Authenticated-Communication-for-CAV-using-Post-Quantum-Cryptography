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
3. **As an evaluation suite:** benchmarks, 21 attacks, consensus experiments,
   figures, and 55 tests.

It adds **certificate caching** (32-byte certificate references instead of
5.3 KB ML-DSA certificates), which halves the post-quantum handshake, and a
**browser replay** of the ns-3 simulation (`results/viewer.html`). The final
report is in `report/` and the Review 2 deck in `slides/`.

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
python scripts\demo_parts.py pki  # one component on its own (see --help)
python scripts\run_network.py     # the whole distributed system (50 s)
python -m pytest                  # 55 tests (~1 min)
python scripts\run_evaluation.py  # benchmarks + figures into results\ (~4 min)
```

ns-3 runs in WSL2 / Linux: `pip install -r requirements-ns3.txt`, then
`python scripts/run_ns3_sweeps.py` and `python scripts/make_viewer.py`.
Open `results/viewer.html` in any browser to watch the simulation. For a guided tour of every module, open `results/explorer.html` (rebuild it with `python scripts/make_explorer.py`). Full instructions and the Review 2 demo
script are in [`docs/06-RUNNING-AND-DEMO.md`](docs/06-RUNNING-AND-DEMO.md).

---

## Layout

```
qrcav/                         the system (v2)
  crypto/suites.py             ML-KEM / ML-DSA suites (OpenSSL; kyber-py for ML-KEM-512 only); ECDH/ECDSA baseline
  crypto/kdf.py                SHAKE-256, HKDF-SHA3-256, DERIVE_SESSION_KEYS (deck slide 14)
  crypto/records.py            AES-256-GCM <ctr, ciphertext, tag> records, replay window (slide 17)
  pki.py                       Trusted Authority, certificates, signed CRL, registry DB (slides 12-13)
  handshake.py                 four-flight mutually authenticated handshake (slides 15-16), sans-IO
  certcache.py                 certificate caching: 32-byte references, bounded LRU, HelloRetry fallback
  ledger.py                    hash-linked blocks with commit certificates
  consensus/agspbft.py         AGS-PBFT: request ... reply, scoring, regrouping, view change (slides 22-29)
  consensus/client.py          the MEC's consensus client
  consensus/sim.py             in-process discrete-event harness with real signatures
  net/secure.py                secure channels over TCP
  nodes/                       one process per entity: ta, cloud, mec, consensus_node, rsu, cav
  sim/                         ns-3 802.11p scenario (C++ via cppyy) + measurement profiles
  eval/                        benchmarks, attacks, consensus experiments, ns-3 sweeps, plots, replay viewer
scripts/                       demo_protocol, demo_parts, run_network, run_evaluation, run_ns3_sweeps, make_viewer, make_explorer, make_tables
config/demo.json               the Review 2 scenario (faults, revocation, handover, V2V)
tests/                         pytest suite, including a real multi-process run
docs/                          00 start here; 05 design; 06 running + demo; 07 results; review1/ archived
report/                        final report (LaTeX); numbers and tables generated from results/
slides/                        Review 2 deck (Beamer)
results/                       CSVs, figures, viewer.html, explorer.html (results/review1/ holds the Review 1 outputs)

cavpqc/, demo.py, handshake.py, run_evaluation.py, why_composition_matters.py
                               the Review 1 prototype, kept unchanged for reference
```

---

## What changed since Review 1

| Area | Review 1 | Now |
|---|---|---|
| Cryptography library | pure Python (not constant-time) | native OpenSSL (constant-time, ~1 ms per ML-DSA-65 signature) |
| Registration | HMAC-style token checked online by the TA | ML-DSA certificates (role, serial, validity) checked offline; proof of possession; signed CRL |
| Handshake | server-only signature; keys compared in memory | ClientHello, then mutual signatures and encrypted Finished messages in both directions |
| Records | sequential nonce | `<ctr, ct, tag>`, data counter from 1, 64-record replay window |
| Topology | function calls in one process | 19 processes over TCP; MEC criticality routing; V2V via RSUs; cloud path |
| Consensus | no view change; textbook PBFT baseline only counted messages | full view change; certified blocks; a PBFT baseline that runs with real signatures |
| Simulation | analytic 802.11p model, SUMO planned | ns-3 802.11p, mobility, handover, EDCA, fragmentation |
| Handshake size | 6,494 B counted (certificates left out) | 20,779 B full; 10,173 B with certificate caching |
| Tests | none | 55, including a multi-process run |

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
are documented in `docs/05-SYSTEM-DESIGN.md` and the report (chapter 4). New design decisions
where the paper is undefined are numbered D6–D9 in `docs/05`.

---

## Headline results

Measured on a 2-core cloud VM; your laptop will differ in absolute numbers,
not in shape. Full tables and figures are in
[`docs/07-RESULTS.md`](docs/07-RESULTS.md).

| | Classical (ECDH + ECDSA P-256) | Post-quantum (ML-KEM-1024 + ML-DSA-65) | PQ + certificate caching |
|---|---|---|---|
| Handshake size | 1,043 B, 4 frames | 20,779 B, 17 frames | 10,173 B, 10 frames |
| Handshake compute, both sides | 1.2 ms | 4.8 ms | same |
| Per-beacon cost in a session (p99) | 0.40 ms | 0.41 ms | 0.41 ms |
| ns-3, 50 vehicles: completed / median | 100 % / 7 ms | 100 % / 90 ms | 100 % / 54 ms |
| ns-3, 100 vehicles | 100 % / 8 ms | 74 % / 285 ms | 98 % / 73 ms |
| ns-3, 200 vehicles | 100 % / 12 ms | 27 % / 795 ms | 57 % / 417 ms |

ns-3 figures are the mean of 3 seeds over 1.5 km × 1.5 km with 9 RSUs.

1. **Compute is not the problem; bytes are.** A post-quantum handshake
   costs about 5 ms of CPU, but
   20.8 KB on a shared 6 Mb/s channel, and in a dense cell that is what fails.
2. **Session beacons cost nothing extra.** Inside a session a beacon is a
   135-byte AES-GCM record whatever the suite. Per-beacon ML-DSA signatures
   fit (9.5 ms p99) but are 3 frames each and collapse coverage in
   ns-3.
3. **Dense traffic breaks post-quantum handshakes, roughly in order of size.**
   At 100 vehicles: L1 97 %, DECK 74 %, L3 70 %, L5 56 %; classical 100 %.
   (L3 and DECK differ by under 1 KB and are within seed-to-seed noise.)
4. **Certificate caching recovers most of it.** At 100 vehicles DECK goes from
   74 % to 98 % completed and from 285 ms to 73 ms median; at 200 vehicles
   from 27 % to 57 %. Exponential backoff after failed handshakes is what
   prevents congestion collapse (7–11 % without it).
5. **Consensus never sits on the safety path.** Alerts reach vehicles in about
   5 ms; the ledger follows in about 50 ms.
6. **AGS-PBFT sends 73–86 % fewer messages than PBFT and uses 18–25 % less
   CPU at light load, but is not faster** (+41–58 % commit latency): its
   leader-centred certificate step adds a hop. Bytes fall only 8–30 %,
   because certified blocks carry ML-DSA signatures, and under a 60-request
   burst it used 65 % more CPU than PBFT.
7. **Liveness is lost above f Byzantine nodes; no false result was committed**
   (with an honest leader). A silent
   node can escape demotion when an outlier inflates σ, a weakness of the
   paper's μ ± σ rule.
8. **All 21 attacks were rejected.**

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
- **Certificate caching relies on infrastructure we model** (an edge
  directory); a vehicle's first handshake still sends its certificate.
- **Certificates and references are linkable**; no pseudonyms.
- **No formal verification.**
