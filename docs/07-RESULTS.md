# Results

All numbers come from `results/*.csv`. Regenerate with
`python scripts/run_evaluation.py` (everything except ns-3) and
`python scripts/run_ns3_sweeps.py` plus `--seeds 2 3` (ns-3, WSL2).
`python scripts/make_tables.py` turns the CSVs into the tables and numbers
used by the report and the slides, so those always match the data.

The measurement machine was a 2-core cloud VM. Absolute timings on your
laptops will differ; the comparisons between suites should not. Timing
benchmarks were run with the CPU otherwise idle.

---

## 1. Cryptographic cost

### Primitives (mean ms; sign also p99)

| Suite | KEM keygen | encaps | decaps | sign | sign p99 | verify |
|---|---|---|---|---|---|---|
| Classical (ECDH/ECDSA P-256) | 0.024 | 0.12 | 0.091 | 0.031 | 0.072 | 0.12 |
| DECK (ML-KEM-1024 / ML-DSA-65), native | 0.23 | 0.067 | 0.052 | 1.28 | 4.38 | 0.23 |
| DECK, pure Python | 6.87 | 6.82 | 7.60 | 74.0 | 258 | 14.7 |

Full table: `results/primitives.csv` (all five suites, both backends).

**What it means.**
- **Signing is the only expensive post-quantum operation, and its variance is
  intrinsic.** ML-DSA's rejection sampling gives a long tail: p99 is 2–4× the
  mean depending on suite and backend. Verification is deterministic.
- **The implementation matters far more than the algorithm.** The same
  ML-DSA-65 signs in 1.3 ms natively and 74 ms in pure Python (about 58×).
  Review 1's conclusion that signing might not fit 100 ms was a property of
  the pure-Python library, not of ML-DSA.

### Handshake (Figures 1, 2)

| Suite | Bytes | Frames | Airtime at 6 Mb/s | Bytes, cached certs | Frames | Compute, native | Compute, pure |
|---|---|---|---|---|---|---|---|
| Classical | 1,043 | 4 | 2.05 ms | 691 | 4 | 1.2 ms | n/a |
| L1 | 14,373 | 13 | 21.3 ms | 6,825 | 8 | 11.6 ms* | 106 ms |
| L3 | 19,913 | 17 | 29.4 ms | 9,307 | 10 | 4.8 ms | 178 ms |
| DECK | 20,779 | 17 | 30.5 ms | 10,173 | 10 | 4.8 ms | 209 ms |
| L5 | 27,329 | 22 | 40.1 ms | 12,807 | 12 | 5.7 ms | 219 ms |

\* L1's KEM is always pure Python: the `cryptography` library exposes no
ML-KEM-512.

**What it means.**
- **A post-quantum handshake is 14–26× the bytes of a classical one.** An
  ML-DSA-65 certificate is 5,355 B and each side sends one.
- **Certificate caching removes 51–53 %** of every post-quantum handshake
  (DECK: 20,779 → 10,173 B, 17 → 10 frames). See `docs/05` §4 for the design
  and its security argument.
- **Computation is not the problem.** About 5 ms for a complete DECK
  handshake natively; 0.2 s in pure Python.
- **The Review 1 figure was an undercount.** 6,494 B left the certificates
  out.

### Per-beacon budget (Figure 3)

p99 crypto plus airtime, against the 100 ms beacon interval:

| Suite | AEAD inside a session | ML-DSA-signed broadcast, native | signed, pure Python |
|---|---|---|---|
| Classical | 0.40 ms (135 B) | 0.88 ms (234 B) | n/a |
| DECK | 0.41 ms (135 B) | 9.5 ms (3,472 B, 3 frames) | **236 ms: misses** |
| L5 | 0.47 ms (135 B) | 12.6 ms (4,790 B, 4 frames) | **184 ms: misses** |

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
| Secure sessions established | 48 (10,173–20,779 B each, depending on cached certificates); 6 rejected |
| Critical event → alert at vehicles | median 5.4 ms |
| Event → on the ledger (vehicle notified) | median 62 ms |
| V2V via two RSUs | ≈ 1 ms |
| Byzantine NODE_03 (wrong results) | demoted at block 8; NODE_05 promoted |
| Leader NODE_01 crashes at 34 s | view change to view 1; later events commit |
| CAV_03 handover RSU_02 → RSU_03 | 10,173 B: both certificates by reference; RSU_03 fetched CAV_03's from the directory |
| CAV_05 revoked at 40 s | session dropped; reconnection rejected, although its certificate was cached |
| 8 ledger copies | consistent (the crashed leader's copy is a prefix of the others); verify from genesis |

**What it means.** The MEC sends the alert *before* it submits to consensus,
so the safety path (about 5 ms) never waits for the ledger (about 60 ms).

---

## 3. ns-3: 802.11p with mobility (Figures 7–11)

Setup: 1.5 km × 1.5 km Manhattan grid, 9 RSUs, 23 dBm, Nakagami fading,
10 Hz broadcast beacons, EDCA and backoff on. Mean of 3 seeds; error bars
show min–max. "DECK + cache" = RSU certificates pre-distributed, vehicle
certificates resolved from the MEC directory after the first session.

### Handshakes completed (%)

| Vehicles (per km²) | Classical | L1 | L3 | DECK | L5 | DECK + cache |
|---|---|---|---|---|---|---|
| 50 (22) | 100 | 100 | 99 | 100 | 99 | 100 |
| 100 (44) | 100 | 97 | 70 | 74 | 56 | **98** |
| 150 (67) | 100 | 54 | 40 | 38 | 32 | **80** |
| 200 (89) | 100 | 39 | 27 | 27 | 22 | **57** |

### Median handshake completion (ms)

| Vehicles | Classical | L1 | L3 | DECK | L5 | DECK + cache |
|---|---|---|---|---|---|---|
| 50 | 7 | 73 | 88 | 90 | 139 | 54 |
| 100 | 8 | 109 | 288 | 285 | 482 | 73 |
| 150 | 10 | 575 | 651 | 636 | 750 | 197 |
| 200 | 12 | 763 | 760 | 795 | 844 | 417 |

### Other measures at 100 vehicles

| Measure | Classical | DECK | DECK + cache |
|---|---|---|---|
| Beacon slots covered by a session | 99.9 % | 83.3 % | 97.4 % |
| Aggregate airtime (sum over 9 cells) | 41 % | 160 % | 68 % |
| Handshake time, p95 | 33 ms | 1,094 ms | 359 ms |
| Event → alert at the reporter, median | 5.4 ms | 7.6 ms | 5.6 ms |
| Ledger commit after the event, median | 11.6 ms | 24.6 ms | 24.0 ms |

Alerts at 200 vehicles: 5.7 ms classical, 218 ms DECK, 33 ms DECK + cache.

### What it means

1. **Post-quantum V2X fails on bandwidth, not compute.** Every PQ suite
   degrades with density while classical stays at 100 % (99.9 % at 200 vehicles). Handshake airtime
   pushes the channel into saturation (160 % aggregate airtime for DECK at
   100 vehicles against 41 % classical), losses trigger retransmissions, and
   the retransmissions add load.
2. **Roughly in order of size.** L1 (14 KB) holds up longest, L5 (27 KB)
   fails first. L3 and DECK differ by under 1 KB and are within seed-to-seed
   variation of each other: DECK's category-5 KEM buys nothing over L3,
   because the category-3 signature sets the suite's strength.
3. **Certificate caching recovers most of it up to 100 vehicles** (74 → 98 %
   completed, 285 → 73 ms median, airtime 160 → 68 %) and doubles completion
   at 200 vehicles (27 → 57 %). It does not close the gap: a cached DECK
   handshake is still about 10× a classical one (KEM key, ciphertext, two
   signatures).
4. **A saturated channel delays alerts too.** Up to 100 vehicles the median
   alert stays below 20 ms for every suite (5.4 ms classical to 16.5 ms L5);
   at 200 vehicles DECK alerts take 218 ms (33 ms with caching).

### Variants (seed 1, 100 vehicles; `results/ns3_variants.csv`, Figure 10)

| Scenario | Completed | Median handshake | Beacon coverage | Event → alert |
|---|---|---|---|---|
| DECK, EDCA + backoff (baseline) | 75 % | 283 ms | 82 % | 7.2 ms |
| DECK, neither | 7 % | 921 ms | 40 % | 433 ms |
| DECK, EDCA only | 11 % | 926 ms | 44 % | 382 ms |
| DECK, backoff only | 77 % | 291 ms | 85 % | 8.9 ms |
| DECK + cache (directory) | 100 % | 68 ms | 98 % | 5.5 ms |
| DECK + cache (all warm) | 97 % | 66 ms | 99 % | 6.0 ms |
| L3 + cache (directory) | 100 % | 76 ms | 97 % | 5.9 ms |
| DECK, signed beacons | 23 % | 704 ms | 46 % | 233 ms |
| Classical, signed beacons | 100 % | 9 ms | 100 % | 5.4 ms |
| DECK, pure-Python timings | 69 % | 593 ms | 74 % | 8.6 ms |

- **Exponential backoff is what prevents congestion collapse.** Without it,
  failed handshakes retry immediately: 7–11 % complete and alerts queue for
  380–430 ms behind handshake fragments.
- **EDCA adds little once backoff is on, at this density.** Both settings are
  within single-seed noise. EDCA remains a sensible safeguard, but the earlier
  claim that it adds 24 points does not hold with the current model.
- **Signed beacons do not scale with post-quantum signatures**: 3-frame
  beacons leave 46 % of beacon slots covered. Session-based AEAD beacons are
  the design that scales.
- **Warm caches from the start (all warm) are no better than the directory
  model**: by the time measurement starts (after 5 s) almost every vehicle has
  had its first, full-certificate handshake.
- **Implementation still matters in the network**: pure-Python processing
  times double the median handshake (593 vs 283 ms).

---

## 4. Consensus (Figures 4–6)

### AGS-PBFT vs PBFT (real ML-DSA signatures, 1 ms links, 20 requests)

| Nodes | Msgs/req AGS / PBFT | Fewer messages | Fewer bytes | Fewer bytes, no shadow | Latency change | Less CPU |
|---|---|---|---|---|---|---|
| 8 | 35 / 128 | 73 % | 8 % | 41 % | +49 % | 18 % |
| 16 | 89 / 512 | 83 % | 25 % | 57 % | +41 % | 18 % |
| 24 | 161 / 1,152 | 86 % | 30 % | 63 % | +58 % | 24 % |

Throughput, 16 nodes, 60-request burst: AGS-PBFT 47 req/s, PBFT 69 req/s,
and AGS-PBFT used 65 % **more** CPU in that run (23.3 s vs 14.1 s). The
light-load CPU saving reverses under a burst; we have not isolated why.

**What it means.**
- **The paper's message saving is real**: 73 % at 8 nodes, 81–86 % at 12–24.
  The consensus set is 3f+1, not N, so messages grow as O(|CN|²) instead of
  O(N²).
- **Bytes fall much less than messages.** Every block carries its commit
  certificate (2f+1 ML-DSA signatures of 3,309 B each), and with D7 shadow
  validation the candidates' responses too. Dropping shadow validation
  recovers most of the byte saving but leaves candidates unable to earn
  promotion.
- **It is not faster.** AGS-PBFT replaces PBFT's parallel all-to-all commit
  with responses to the leader, a certified block, and verification at every
  node: one more sequential hop through a single node. Under a burst the
  leader is the bottleneck.

### Fault tolerance (consensus set 7, f = 2, colluding wrong results, regrouping off)

| Byzantine nodes | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| Requests committed | 100 % | 100 % | 100 % | 0 % | 0 % | 0 % |
| Safety (only the honest result ever committed) | yes | yes | yes | yes | yes | yes |

PBFT's liveness bound: up to f faults nothing changes; above f the honest
nodes can no longer form a 2f+1 quorum, so progress stops. Nothing false was
committed in any run, but the leader is kept honest here and never certifies
a result different from its own. With 5 colluders (a quorum of 5 by
themselves) a Byzantine leader beyond f could commit a false result, as PBFT
theory predicts.

### Score dynamics (16 nodes, regroup every 10 blocks, Figure 5)

- **The wrong-result node is demoted at the first regroup** (block 10).
- **The silent node is never demoted.** Its score stays at 100 while honest
  nodes climb, but the wrong-result outlier inflates σ so much that `μ − σ`
  stays below 100.
- **Without an outlier, a silent node is demoted**
  (`tests/test_consensus.py::test_regroup_demotes_silent_node_without_outlier`).

A weakness of the paper's μ ± σ rule; median and MAD would not be distorted by
one extreme node. Recommended as an improvement.

### View change (8 nodes, leader crashes after 5 commits)

| View-change timeout | First commit after the crash (AGS / PBFT) |
|---|---|
| 0.5 s | 1.21 s / 1.19 s |
| 1.0 s | 2.22 s / 2.17 s |
| 2.0 s | 4.72 s / 4.68 s |

Recovery takes about 2.2–2.4× the timeout: the client's retransmission
timeout and the backups' view-change timeout run one after the other.

---

## 5. Security (`results/attacks.csv`)

**21 of 21 attacks rejected**, each run against the real implementation:

- **Records:** tampering, replay, nonce reuse with Finished.
- **Handshake:** ClientHello replay, stale timestamp, client and RSU
  impersonation with a copied certificate, a certificate from a rogue TA, a
  revoked credential, a vehicle posing as an RSU, a man-in-the-middle
  swapping the ML-KEM key or the KEM ciphertext, downgrade to classical, a
  tampered Finished, and retention of the ephemeral key (forward secrecy).
- **Certificate cache:** claiming another vehicle's cached certificate by
  reference; a revoked certificate still in the cache.
- **Consensus:** a vote from a non-member, a spoofed vote, a tampered block,
  and a rewritten ledger history.

Client impersonation with a copied certificate would **succeed against the
Review 1 slide design**, which has no client signature (F2).

---

## 6. Answers to the questions a panel will ask

**"Does post-quantum fit the 100 ms budget?"**
Per message, yes, at every security level, provided beacons travel inside a
session (0.4 ms) or an ML-DSA signature is computed natively (≈ 10 ms). The
real limit is channel capacity during handshakes in dense traffic.

**"Why ML-KEM-1024 with ML-DSA-65?"**
That is the deck's choice and the supporting paper's. Its overall strength is
category 3, set by the signature. L3 (ML-KEM-768) gives the same security with
866 fewer bytes, and in ns-3 it performs the same.

**"What did you add beyond the paper?"**
Certificate caching: 32-byte references instead of 5.3 KB certificates, with
every check still applied. It halves the handshake and, at 100 vehicles,
raises handshake completion from 74 % to 98 %.

**"Does AGS-PBFT beat PBFT?"**
On messages (−73 to −86 %), yes, and on CPU at light load (−18 to −25 %).
On latency, burst throughput and CPU under a burst, no, in our measurements. The paper reports only the message
count.

**"Is your simulation realistic?"**
The sizes and processing times are measured from the real code, and ns-3
models 802.11p PHY/MAC with fading and mobility. The radio parameters and the
five simulator defaults we had to correct are listed in `docs/05` §8.
Single machine, three seeds.
