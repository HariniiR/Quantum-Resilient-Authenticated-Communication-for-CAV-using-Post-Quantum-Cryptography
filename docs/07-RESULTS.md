# Results

All numbers come from `results/*.csv`. Regenerate with
`python scripts/run_evaluation.py` (everything except ns-3) and
`python scripts/run_ns3_sweeps.py` plus `--seeds 2 3` (ns-3, WSL2).

The measurement machine was a 2-core cloud VM. Absolute timings on your
laptops will differ; the shape of every result should not. Timing
benchmarks were run with the CPU otherwise idle.

---

## 1. Cryptographic cost

### Primitives (native OpenSSL backend, mean ms)

| Suite | KEM keygen | encaps | decaps | sign | verify |
|---|---|---|---|---|---|
| Classical (ECDH/ECDSA P-256) | 0.02 | 0.11 | 0.11 | 0.03 | 0.14 |
| ML-KEM-1024 / ML-DSA-65 (DECK) | 0.19 | 0.06 | 0.04 | 0.99 (p99 3.7) | 0.19 |
| same, pure Python | 3.9 | 4.8 | 6.5 | 44.7 (p99 134) | 8.6 |

Full table: `results/primitives.csv` (all five suites, both backends).

**What it means.**
- **Signing is the only expensive post-quantum operation, and its variance is
  intrinsic.** ML-DSA rejection sampling gives a long tail: p99 is about 4×
  the mean in both backends.
- **The implementation matters about 45× more than the algorithm.** The same
  ML-DSA-65 takes 1 ms natively and 45 ms in pure Python. Review 1's
  conclusion that signing does not fit 100 ms was a property of the pure-Python
  library, not of ML-DSA.

### Handshake (Figure 1, Figure 2)

| Suite | Bytes on the air | Frames (1,400 B) | Airtime at 6 Mb/s | Compute, native | Compute, pure |
|---|---|---|---|---|---|
| CLASSIC | 1,042 | 4 | 2.0 ms | 1.1 ms | n/a |
| L1 | 14,373 | 13 | 21.3 ms | 9.0 ms* | 83 ms |
| L3 | 19,913 | 17 | 29.4 ms | 3.1 ms | 136 ms |
| DECK | 20,779 | 17 | 30.5 ms | 3.9 ms | 142 ms |
| L5 | 27,329 | 22 | 40.1 ms | 4.7 ms | 175 ms |

\* L1's KEM is always pure Python (OpenSSL has no ML-KEM-512).

**What it means.**
- **A post-quantum handshake is 14–26× the bytes of a classical one, and the
  certificates are most of it.** An ML-DSA-65 certificate is 5,355 B, and
  each side sends one. Certificate caching would roughly halve the
  handshake; that is the obvious next optimisation.
- **The Review 1 figure was an undercount.** 6,494 B left the certificates
  out, and so did the supporting paper's 4.86 KB.

### Per-beacon budget (Figure 3)

p99 crypto plus airtime, against the 100 ms beacon interval:

| Suite | AEAD inside a session | ML-DSA-signed broadcast, native | signed, pure Python |
|---|---|---|---|
| CLASSIC | 0.39 ms (135 B) | 0.64 ms (233 B) | n/a |
| DECK | 0.39 ms (135 B) | 8.8 ms (3,472 B, 3 frames) | **163 ms: does not fit** |
| L5 | 0.41 ms | 10.7 ms (4,790 B, 4 frames) | **148 ms: does not fit** |

**What it means.** The base paper folds the one-off handshake into its
per-message latency. Separated, the per-beacon cost of the session design is
identical for classical and post-quantum: a 135-byte AES-GCM record. Signing
every beacon (as IEEE 1609.2 does today) fits natively but costs 3 frames per
beacon, and that matters in ns-3 (§3).

---

## 2. Distributed system (`python scripts/run_network.py`)

One run of `config/demo.json` (19 processes over TCP on one machine):

| Measure | Result |
|---|---|
| Secure sessions established | 48, each 20,775–20,779 B |
| Critical event → alert at vehicles | median ≈ 5 ms |
| Event submitted → block committed | median ≈ 40–45 ms |
| V2V via two RSUs | ≈ 1.2 ms |
| Byzantine NODE_03 (wrong results) | demoted at block 8; NODE_05 promoted |
| Leader NODE_01 crashes at 34 s | view change to view 1; later events commit |
| CAV_05 revoked at 40 s | session dropped; reconnection rejected |
| 8 ledger copies | consistent; verify from genesis (signatures, certificates, scores, membership) |

Identical in 3 of 3 repeated runs.

**What it means.** The MEC sends the alert *before* it submits to consensus,
so the safety path (about 5 ms) never waits for the ledger (about 45 ms).

---

## 3. ns-3: 802.11p with mobility (Figures 7–10)

Setup: 1.5 km × 1.5 km Manhattan grid, 9 RSUs, 23 dBm, Nakagami fading,
10 Hz broadcast beacons, EDCA and backoff on. Mean of 3 seeds; error bars
show min–max.

### Handshakes completed (%)

| Vehicles (per km²) | CLASSIC | L1 | L3 | DECK | L5 |
|---|---|---|---|---|---|
| 50 (22) | 100 | 100 | 98 | 99 | 96 |
| 100 (44) | 100 | 96 | 78 | 77 | 50 |
| 150 (67) | 100 | 57 | 37 | 42 | 31 |
| 200 (89) | 100 | 37 | 26 | 29 | 21 |

### Median handshake completion (ms)

| Vehicles | CLASSIC | L1 | L3 | DECK | L5 |
|---|---|---|---|---|---|
| 50 | 6 | 70 | 93 | 106 | 165 |
| 100 | 9 | 120 | 201 | 379 | 509 |
| 200 | 13 | 732 | 828 | 790 | 828 |

### Other measures at 100 vehicles

| Measure | CLASSIC | DECK |
|---|---|---|
| Beacon slots covered by a session | 99.9 % | 81.7 % |
| Aggregate airtime (sum over 9 cells) | 42 % | 184 % |
| Event → alert at the reporter, median | 5.4 ms | 9.3 ms |
| Ledger commit after the event, median | 11.5 ms | 22 ms |

### What it means

1. **Post-quantum V2X fails on bandwidth, not compute.** Every PQ suite
   degrades with density, in order of handshake size, while classical stays
   at 100 %. Handshake airtime pushes the channel into saturation: aggregate
   airtime is 184 % for DECK against 42 % classical at 100 vehicles.
2. **The suite ordering is the size ordering.** L1 (14 KB) > L3 ≈ DECK
   (20 KB) > L5 (27 KB). At 100 vehicles, DECK's level-5 KEM costs nothing
   over L3; L5's larger signature costs a lot.
3. **Signed beacons are unaffordable in a post-quantum world** (variant run,
   DECK, 100 vehicles). 3-frame broadcast beacons push session coverage down
   to 44 % and beacon delivery to 4 %. Session-based AEAD beacons (135 B) are
   the only post-quantum beacon design that scales here.
4. **Implementation still matters in the network** (variant run, DECK, 100
   vehicles). The pure-Python profile completes 60 % of handshakes against
   about 77–88 % native, and its ledger commit takes 2.7 s.

### Mitigations: ablation (Figure 10, DECK, 100 vehicles, seed 1)

| | Handshakes completed | Beacon coverage | Event → alert, median |
|---|---|---|---|
| Neither | 11 % | 50 % | 392 ms |
| EDCA only | 11 % | 53 % | 328 ms |
| Backoff only | 64 % | 74 % | 7.8 ms |
| **EDCA + backoff** | **88 %** | **89 %** | **7.6 ms** |

- **Exponential backoff stops the congestion collapse.** Without it, failed
  handshakes retry immediately.
- **EDCA alone cannot help a saturated channel, but on top of backoff it adds
  another 24 points.** Safety traffic stops queueing behind handshake
  fragments.

These are protocol-design recommendations that come directly out of the
simulation.

---

## 4. Consensus (Figures 4–6)

### AGS-PBFT vs PBFT (real ML-DSA signatures, 1 ms LAN, light load)

| Nodes | Msgs/req AGS / PBFT | Fewer messages | Fewer bytes | Fewer bytes, no shadow | Latency change | Less CPU |
|---|---|---|---|---|---|---|
| 8 | 35 / 128 | 73 % | 9 % | 41 % | +37 % | 16 % |
| 16 | 89 / 512 | 83 % | 25 % | 57 % | +48 % | 22 % |
| 24 | 161 / 1,152 | 86 % | 30 % | 63 % | +36 % | 35 % |

Throughput, 16 nodes, 60-request burst: AGS-PBFT 59 req/s, PBFT 89 req/s.

**What it means.**
- **The paper's message saving is real and grows with network size.** The
  consensus set is 3f+1, not N, so messages grow as O(|CN|²) instead of O(N²).
- **Bytes fall much less than messages.** Every block carries its commit
  certificate (2f+1 ML-DSA signatures of 3,309 B each), and with D7 shadow
  validation the certificate also carries the candidates' responses. Dropping
  shadow validation recovers most of the byte saving but leaves candidates
  unable to earn promotion.
- **It is not faster.** AGS-PBFT replaces PBFT's parallel all-to-all commit
  with responses to the leader, a certified block, and verification at every
  node. That is one more sequential hop through a single node. Under a burst
  the leader is the bottleneck.

### Fault tolerance (consensus set 7, f = 2, colluding wrong results, regrouping off)

| Byzantine nodes | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| Requests committed | 100 % | 100 % | 100 % | 0 % | 0 % | 0 % |
| Safety (only the honest result ever committed) | yes | yes | yes | yes | yes | yes |

**What it means.** This is exactly PBFT's bound. Up to f faulty nodes, nothing
changes. Above f, the honest nodes can no longer form a 2f+1 quorum, so
progress stops; but the colluders cannot form one either, so nothing false is
ever committed.

### Score dynamics (16 nodes, regroup every 10 blocks, Figure 5)

- **The wrong-result node is demoted at the first regroup** (block 10): its
  score falls 5 per block.
- **The silent node is never demoted.** Its score stays at 100 while honest
  nodes climb, but the wrong-result outlier inflates σ so much that `μ − σ`
  stays below 100.
- **Without an outlier, a silent node is demoted**
  (`tests/test_consensus.py::test_regroup_demotes_silent_node_without_outlier`).

This is a weakness of the paper's μ ± σ rule. A robust statistic (median and
MAD) would not be distorted by one extreme node. Recommended as an improvement.

### View change (8 nodes, leader crashes after 5 commits)

| View-change timeout | Time to first commit after the crash (AGS / PBFT) |
|---|---|
| 0.5 s | 1.20 s / 1.16 s |
| 1.0 s | 2.19 s / 2.17 s |
| 2.0 s | 4.71 s / 4.67 s |

Recovery is dominated by the timeout (client retransmission, then
backup timeout); the protocol work after it is about 100–200 ms.

---

## 5. Security (`results/attacks.csv`)

**19 of 19 attacks rejected**, each run against the real implementation:

- **Records:** tampering, replay, nonce reuse with Finished.
- **Handshake:** ClientHello replay, stale timestamp, client and RSU
  impersonation with a copied certificate, a certificate from a rogue TA,
  a revoked credential, a vehicle posing as an RSU, a man-in-the-middle
  swapping the ML-KEM key or the KEM ciphertext, downgrade to classical, a
  tampered Finished, and retention of the ephemeral key (forward secrecy).
- **Consensus:** a vote from a non-member, a spoofed vote, a tampered block,
  and a rewritten ledger history.

Client impersonation with a copied certificate would **succeed against the
Review 1 slide design**, which has no client signature (F2).

---

## 6. Answers to the questions a panel will ask

**"Does post-quantum fit the 100 ms budget?"**
Per message, yes, at every security level, provided beacons travel inside a
session (0.4 ms) or an ML-DSA signature is computed natively (≈ 9 ms). The
real limit is channel capacity during handshakes in dense traffic.

**"Why ML-KEM-1024 with ML-DSA-65?"**
That is the deck's choice and the supporting paper's. Its overall strength is
category 3, set by the signature. L3 (ML-KEM-768) gives the same security
with 866 fewer bytes, and in ns-3 it performs the same.

**"Does AGS-PBFT beat PBFT?"**
On messages (−73 to −86 %) and CPU (−16 to −35 %), yes. On latency and burst
throughput, no, in our measurements. The paper reports only the message
count.

**"Is your simulation realistic?"**
The sizes and processing times are measured from the real code, and ns-3
models 802.11p PHY/MAC with fading and mobility. The radio parameters and the
five simulator defaults we had to correct are listed in `docs/05` §8.
Single machine, three seeds.
