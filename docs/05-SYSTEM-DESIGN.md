# System Design: `qrcav`

This document describes the implementation in `qrcav/`. It is a complete,
working version of the architecture presented at Review 1 (deck slides 11–31),
with the gaps in that design closed. Every section points to the code.

---

## 1. What runs where

```
                          ┌───────────────────────── consensus layer ─────────────────────────┐
                          │  NODE_01 … NODE_08   AGS-PBFT replicas, full mesh of secure links │
 CAV ──802.11p──► RSU ──► │  ▲ REQUEST                       COMMIT (certified block) ▼       │
  ▲   (secure      │      └──┼───────────────────────────────────────────────────────────────┘
  │    session)    ▼         │
  └── ALERT ◄──── RSU ◄── MEC ── non-critical ──► CLOUD (SQLite archive)
                  ▲          (routes by criticality)
                  └── V2V relay between neighbouring RSUs
 TA: registration (certificates), signed CRL, registry DB
```

Every arrow except TA registration is a mutually authenticated ML-KEM + ML-DSA
session carrying AES-256-GCM records. Each box is its own OS process in the
distributed system (`scripts/run_network.py`).

| Deck slide | Component | Code |
|---|---|---|
| 12 Preparation | TA keypair, public parameters | `qrcav/pki.py` `TrustedAuthority`, `qrcav/nodes/ta.py` |
| 13 Registration | entity keygen, certificate, registry DB | `pki.py` `Identity`, `TrustedAuthority.register` |
| 14 DERIVE_SESSION_KEYS | HKDF-SHA3-256 over transcript | `qrcav/crypto/kdf.py` `derive_session_keys` |
| 15–16 Handshake | four flights, Finished messages | `qrcav/handshake.py` |
| 17 Communication | `<ctr, ciphertext, tag>` records | `qrcav/crypto/records.py` |
| 18 MEC → consensus | signed REQUEST over a secure link | `qrcav/consensus/client.py`, `nodes/mec.py` |
| 19 CAV ↔ CAV | relayed through RSUs | `nodes/rsu.py` `_route_v2v` |
| 20 RSU ↔ MEC | secure link | `nodes/rsu.py`, `nodes/mec.py` |
| 21 Criticality routing | critical → consensus, routine → cloud | `nodes/mec.py` `_on_event` |
| 22–25 AGS-PBFT | request, pre-prepare, prepare, response, reply, scores | `qrcav/consensus/agspbft.py` |
| 26–27, 29 View change | trigger, new-view, new leader | `agspbft.py` `_start_view_change`, `_send_new_view`, `_on_new_view` |
| 30 After consensus | REPLY to MEC, ledger | `agspbft.py` `_finalize`, `qrcav/ledger.py` |
| 31 Non-critical path | MEC → cloud | `nodes/mec.py`, `nodes/cloud.py` |

---

## 2. Cryptography (`qrcav/crypto/`)

### Suites

| Suite | KEM | Signature | Why it exists |
|---|---|---|---|
| `DECK` (default) | ML-KEM-1024 | ML-DSA-65 | the parameter choice on the Review 1 slides |
| `L1` | ML-KEM-512 | ML-DSA-44 | NIST category 1/2 |
| `L3` | ML-KEM-768 | ML-DSA-65 | NIST category 3, matched levels |
| `L5` | ML-KEM-1024 | ML-DSA-87 | NIST category 5, matched levels |
| `CLASSIC` | ECDH P-256 (as a KEM) | ECDSA P-256 | what V2X uses today: the baseline |

`DECK` pairs a category-5 KEM with a category-3 signature, so its overall
strength is category 3. That pairing is legitimate (it is what the Olushola and
Meenakshi paper uses), but `L3` gives the same security with a smaller KEM. Say
this if asked.

ECDH is wrapped as a KEM (ephemeral-static DH, the DHKEM construction of RFC
9180). The classical baseline therefore runs through **exactly the same protocol
code** as the post-quantum suites, so the comparison is like-for-like.

### Two backends

| Backend | Library | Notes |
|---|---|---|
| `openssl` (default) | `cryptography` ≥ 47 (bundles OpenSSL ≥ 3.5) | native, constant-time; ML-DSA-65 signs in about 1 ms |
| `pure` | `kyber-py`, `dilithium-py` | pure Python, what Review 1 used, *not* constant-time; about 50 ms per signature |

The two are byte-compatible: `tests/test_crypto.py::test_backends_interoperate`
encapsulates with one and decapsulates with the other, and signs with one and
verifies with the other. OpenSSL does not ship ML-KEM-512, so `L1` always uses
the pure KEM.

Moving to the native backend removes the Review 1 limitation that the
cryptography was not constant-time. The pure backend stays for comparison:
it shows how strongly implementation quality, not the algorithm, decides
whether PQC fits the latency budget.

### Hash and KDF

- **H** = SHAKE-256 over length-prefixed parts (so `H(ab, c) ≠ H(a, bc)`).
- **KDF** = HKDF (RFC 5869) with HMAC-SHA3-256, called HKDF-SHA3-256. One name
  is used everywhere. The deck uses "HKDF-SHA-256" in one place and
  "HKDF-SHA3-256" in two others.
- `derive_session_keys(ss, T)` is slide 14 line for line: `T_hash = H(T)`, the
  extract step with a zero salt, then four expand calls labelled `key_c2s`,
  `iv_c2s`, `key_s2c`, `iv_s2c`.

### Record layer (slide 17)

```
record = ctr (8 bytes, big-endian) || AES-256-GCM(k_dir, nonce, plaintext, aad = dir || ctr) || tag (16)
nonce  = v_dir XOR (0^32 || be64(ctr))
```

- **Counter 0 is reserved for Finished; data starts at 1.** The deck encrypts
  Finished with `v ⊕ be96(0)` and never says where the data counter starts.
  Starting it at 0 would reuse a (key, nonce) pair. That is catastrophic for
  GCM: it leaks the authentication key and lets an attacker forge records.
- **64-record sliding replay window** (IPsec style). Out-of-order delivery is
  accepted once; replays and records too old to judge are rejected. The window
  is checked *before* decryption, so a replay flood costs a lookup, not an AES
  operation (the deck checks after decrypting).
- **Rekey limit:** a session is refused after 2³² records.

---

## 3. PKI (`qrcav/pki.py`)

**Preparation.** The TA generates `(pk_TA, sk_TA)` and publishes `{suite, KEM
parameters, H, KDF, AEAD, pk_TA}`. In the distributed system it writes them to
`run/ta_public.bin`. That file stands in for the root key installed in every
OBU and RSU at manufacture.

**Registration.**
1. The entity generates its own ML-DSA keypair. The TA never sees a private
   key, which fixes the base paper's key escrow (D4).
2. Entity → TA: `{id, role, pk, alg, pop}`, where `pop` is a signature over the
   request with the new key (proof of possession). Without it, an attacker
   could have the TA certify someone else's public key under the attacker's name.
3. The TA checks the roster (the identities vetted out of band: vehicle
   manufacturer records, the RSU deployment list), the algorithm, the key
   length and the PoP, then signs the certificate:
   `Cert = Sign(sk_TA, {id, role, pk, alg, serial, not_before, not_after})`.
4. The TA stores `(id, role, pk, cert, serial)` in the SQLite registry DB.
5. The entity verifies the certificate with `pk_TA` before storing it.

The certificate binds **role**: a registered vehicle cannot present its
certificate as an RSU. The deck's `cert_payload = ID || pk_DSA` has no role.
The deck's master key `MK` is not needed once registration uses certificates,
so the TA does not create one.

**Revocation** is a signed CRL (`{version, issued_at, revoked serials}`). Nodes
poll the TA, accept only a newer, validly signed CRL, and close any open session
whose peer is now revoked.

An ML-DSA-65 certificate is **5,353 bytes** (a 1,952-byte public key plus a
3,309-byte TA signature). This dominates handshake size; see section 8.

---

## 4. Handshake (`qrcav/handshake.py`)

```
1. C → S  ClientHello     {v, suite, Cert_C, nonce_C (32 B), ts}
2. S → C  ServerHello     {Cert_S, pk_kem, nonce_S, sig_S}
          (pk_kem, sk_kem) ← KEM.keygen()                       ephemeral, one per session
          sig_S = Sign(sk_S, "sh" || H(CH, SH_body))
3. C → S  ClientKey       {c, sig_C, Finished_C}
          check Cert_S (TA signature, CRL, role, expiry, expected id), check sig_S
          (ss, c) ← KEM.encaps(pk_kem)
          sig_C = Sign(sk_C, "ck" || H(CH || SH || CK_body))
          keys  ← DERIVE_SESSION_KEYS(ss, CH || SH || CK_body || sig_C)
          Finished_C = AES-GCM(k_c2s, v_c2s ⊕ 0, H("client_finished", T_hash))
4. S → C  ServerFinished  {Finished_S}
          check sig_C, ss ← KEM.decaps(sk_kem, c), erase sk_kem, derive keys,
          check Finished_C, send Finished_S under k_s2c with counter 0
```

### What changed from the deck, and why

| # | Deck (slides 15–16) | Implementation | Reason |
|---|---|---|---|
| F1 | Server signs `T ‖ pk_kem` with `T` never initialised | ClientHello opens `T` with a fresh client nonce, timestamp, suite and certificate | Without client freshness, a recorded server flight can be replayed to the client |
| F2 | Only the server signs | Client signs the transcript too (`sig_C`) | Otherwise anyone holding a *copy* of a vehicle's certificate can open a session as that vehicle: nothing proves possession of the private key |
| F3 | Finished uses counter 0 and the data counter's start is unspecified | Data starts at 1 | Avoids GCM nonce reuse (section 2) |
| F4 | Slide 15 step 1 shows `sk_kem ← (s, e, pk_kem)` | `KEM.keygen()` | FIPS 203's decapsulation key is `(s, ek, H(ek), z)`; `e` is not kept. Do not show KEM internals on slides |
| F5 | Certificate is `Sign(sk_TA, ID ‖ pk_DSA)` | Role, serial and validity bound too | Role confusion, expiry, revocation by serial |
| F6 | No explicit downgrade protection | Suite carried in ClientHello, must match exactly, and covered by both signatures | Downgrade to `CLASSIC` is rejected |
| F7 | Abort reasons unspecified | One `HandshakeError` with no detail | A probing attacker cannot tell which check failed |

The state machines are **sans-IO**: they take bytes and return bytes. The same
code runs over TCP (`qrcav/net/secure.py`), in memory (tests and benchmarks),
and supplies exact message sizes to ns-3.

### Servers accept only expected roles

| Server | Accepts clients with role |
|---|---|
| RSU | CAV, RSU |
| MEC | RSU |
| Consensus node | NODE, MEC |
| Cloud | MEC |

---

## 5. Consensus (`qrcav/consensus/`)

`agspbft.py` is a sans-IO `Replica`. `client.py` is the MEC side. `sim.py`
runs real replicas in a discrete-event loop with real signatures, adding the
measured processing time to simulated time.

### Normal case

```
MEC ──REQUEST(Sign_c)──► leader ──PRE-PREPARE(Sign_l)──► consensus set  (+ candidates, D7)
consensus set ──PREPARE(Sign_r)──► consensus set (all-to-all)
on 2f+1 matching PREPAREs: node executes, sends RESPONSE{result} (Sign_r) ──► leader
candidates send SHADOW-RESPONSE{result} ──► leader (scored, not counted for quorum)
on 2f+1 matching RESPONSEs: leader builds Block{B_ID, Pr_B_Hash, T_Block, view, seq,
     request, result, cert = the signed RESPONSEs, scores, consensus set}, signs it,
     sends COMMIT{block} to every node and REPLY{block} to the MEC
every node re-verifies the block (hash link, leader signature, commit certificate,
     recomputed scores, recomputed membership) before appending it
```

Leader = `R[v mod |R|]`, with `R` the sorted consensus set (slide 22).

The **"individual result"** that is scored is each node's own validation of the
transaction: required fields present, reporting entity registered, transaction
id not already committed. Honest nodes agree; a Byzantine node reports a
different value.

"Reporting entity registered" is checked from the request itself. The RSU
attaches the vehicle's TA-signed certificate, which it holds from the
handshake, and every node verifies it against pk_TA (without the CRL, so all
nodes reach the same answer). Execution must be deterministic. An earlier
version looked the vehicle up in each node's local copy of the registry, and
honest nodes disagreed whenever one had fetched it before the vehicle enrolled
(see section 11).

### Score update and regrouping (slide 25)

- `+1` if a node's result matches the committed result, `−5` if it differs.
- Every `regroup_interval` blocks (50 in the paper; 8–10 in the demos so it is
  visible): compute μ and σ over all scores; demote consensus nodes below
  `μ − σ`; promote candidates above `μ + σ`; resize to `3f + 1`.
- Scores and membership are written into each block and every node
  re-derives them, so all nodes agree on who is in the consensus set.

### Design decisions where the paper is undefined

| # | Problem | Decision |
|---|---|---|
| D6 | All nodes start at 100, so at the first regroup σ = 0 and `μ − σ = μ + σ`: every node is both above and below threshold | Skip regrouping while σ = 0 |
| D7 | Candidates never take part, so they never gain score and can never be promoted | Candidates validate as shadows: they receive PRE-PREPARE and send a signed SHADOW-RESPONSE, which is scored but not counted for quorum. Absent nodes score 0 rather than −5, since otherwise a Byzantine leader could punish honest nodes by leaving their responses out of the block |
| D8 | "Group size adjusted based on network activity" | Request rate *r* over the interval, from request timestamps so every node computes the same value: `r ≤ 2/s → f = f_max`, `r ≥ 20/s → f = f_min = 1`, linear in between; size = 3f + 1 |
| D9 | Slide 24 counts 2f+1 PREPAREs, but the leader sends none, so 2f+1 is unreachable with f faulty backups | The leader also sends a PREPARE for its own proposal |

### View change (slides 26–27)

- **Trigger:** a consensus node that has seen a request (pre-prepare or
  forwarded request) but not its commit within the timeout multicasts
  `VIEW-CHANGE{v+1, h, head, P}`. `P` holds its prepared certificates (the
  pre-prepare plus 2f+1 matching prepares) above its ledger height `h`. The
  timeout doubles on each failed view.
- **Joining:** f+1 VIEW-CHANGEs for a higher view make a node join it.
- **New view:** the new leader, on 2f+1 VIEW-CHANGEs, computes the re-issue set
  `O`: for every sequence number above the highest checkpoint, the prepared
  request from the highest view, or a no-op for a gap. It sends
  `NEW-VIEW{v+1, V, O}`.
- **Replicas** verify the 2f+1 VIEW-CHANGE signatures, *recompute* `O` and
  compare. On a match they enter the view and resume at PREPARE.
- **Messages for a future view** are buffered and replayed on entering it,
  because PRE-PREPAREs can overtake the NEW-VIEW.
- **Clients** that time out broadcast the request to every consensus node,
  which is how backups notice a silent leader.

### PBFT baseline

`mode="pbft"` reuses the same replica with every node in the consensus set,
the textbook all-to-all COMMIT phase in place of RESPONSE-to-leader, a reply
from every replica (the client waits for f+1), and no scoring. It runs with the
same signatures, so the comparison isolates the protocol difference.

---

## 6. Ledger (`qrcav/ledger.py`)

`Block = (B_ID, Pr_B_Hash, T_Block)` from the deck, plus view, sequence number,
the signed request, the agreed result, the commit certificate, the score table,
the consensus membership, the leader id and the leader's signature. Each
node's ledger is persisted as JSON lines (`run/ledger/NODE_xx.jsonl`).

`verify_chain()` replays a ledger from genesis using only the TA's public key:
hash links, leader signatures, commit certificates, recomputed scores and
recomputed membership.

---

## 7. Distributed system (`qrcav/nodes/`, `qrcav/net/`)

- Each entity is a process started with `python -m qrcav.nodes.<kind> --config
  <file> --id <ID>`. `scripts/run_network.py` starts all of them from one
  config, interleaves their output colour-coded by role, stops them, and runs
  the end-to-end check in `qrcav/nodes/report.py`.
- **Transport:** TCP with 4-byte length framing. The four handshake flights
  travel as frames; after that, every frame is one AES-GCM record.
- **Registration and CRL** use plain TCP. That is safe because the certificate
  and the CRL are TA-signed and verified on receipt.
- **Consensus mesh:** the lower id initiates each pair, giving exactly one
  channel per pair. With 8 nodes that is 28 node-to-node handshakes plus 8 from
  the MEC; with N nodes it is N(N−1)/2.
- **Logs:** every process writes structured JSON lines to `run/logs/<ID>.jsonl`,
  which the report reads.

**Critical path vs ledger.** The MEC *first* sends the alert to the RSUs, *then*
submits the event to consensus. Safety warnings must never wait for a PBFT
round. The ledger records what happened; it does not gate the response.
Measured over TCP on one machine: event → alert at vehicles ≈ 5 ms median;
event → committed block ≈ 45 ms.

**Fault injection** from the config: `"behaviour": "wrong_result" | "silent"`,
or `"crash_at": <seconds>` on a consensus node; `"revoke": [{"at", "id"}]` on
the TA; and scripted vehicle actions (`event`, `v2v`, `handover`, `reconnect`).

---

## 8. ns-3 simulation (`qrcav/sim/`)

ns-3 3.44 through its Python bindings (`pip install ns3`, Linux and WSL2 only).
The scenario is C++ (`ns3_scenario.cc`) compiled at run time by cppyy, driven
from `ns3_runner.py`.

**Method.** ns-3 simulates the radio, MAC, backhaul and mobility. It does not
run the Python cryptography; that would mix wall-clock with simulated time.
Instead, `profile.py` runs the real protocol code and records:

- **sizes:** the exact bytes of every handshake flight, AEAD beacon, signed
  beacon, event and alert
- **timing samples:** an empirical distribution (not a mean and SD) of
  processing time at every handshake stage and per beacon, plus consensus
  commit latency measured with real signatures

The simulation draws from those samples whenever a node "processes" a message.
Each node has a single-server CPU queue.

**Scenario**

| Parameter | Value | Basis |
|---|---|---|
| Radio | IEEE 802.11p, channel 172, 10 MHz, 6 Mb/s | standard safety channel |
| Tx power | 23 dBm (20 dBm in the sensitivity runs) | typical DSRC deployment |
| Path loss | log-distance, n = 2.2, 47.86 dB at 1 m | light urban |
| Fading | Nakagami m = 3 / 1.5 / 1 at < 50 / < 150 / ≥ 150 m | Torrent-Moreno et al. 2004 |
| Detection / CCA | −85 dBm | 802.11p 10 MHz (ns-3's default −82 dBm is the 20 MHz value) |
| Area | 1.5 km × 1.5 km Manhattan grid, 250 m blocks | |
| RSUs | at intersections every 500 m: 9 RSUs | RSU count scales with area, not vehicles |
| Mobility | 8–17 m/s; straight 50 % / left 25 % / right 25 % at intersections | |
| Backhaul | 1 Gb/s, 2 ms point-to-point to the MEC | |
| Beacons | 10 Hz, link-layer broadcast (no ACK, no retries, like BSM/CAM) | |
| Fragmentation | 1,400-byte application chunks; reassembly at the receiver | |
| Handshake retransmission | 200 ms timeout, 3 retries; a NACK asks for missing ServerHello chunks only | |
| Association | handshake starts once an RSU's announcements arrive at ≥ 6 of 10 per second; handover when another RSU is heard ≥ 4 announcements/s better | |
| MAC priority (EDCA) | announces, beacons, events and alerts as AC_VO; handshake flights as AC_BE | 802.11p EDCA access categories |
| Handshake backoff | after a failed handshake wait U(0.5, 1) x 2^k s (k = failures, capped at 4) | standard exponential backoff |
| Warm-up | first 5 s excluded (the initial association storm) | |

**Simulator traps found and fixed.** Each would have distorted the results by
an order of magnitude, so they belong in the report's methodology:

1. **ARP.** ns-3's ARP cache queues only 3 packets per unresolved address, so 5
   of the 8 ServerHello fragments were silently dropped on every first
   contact. 802.11p safety messaging (WSMP) has no ARP, so neighbour caches
   are pre-populated.
2. **Preamble detection.** ns-3 defaults to −82 dBm (20 MHz Wi-Fi). The 10 MHz
   802.11p value is −85 dBm. The wrong value cut coverage from 99 % to about
   80 %.
3. **Unicast beacons.** These incur up to 7 MAC retries each when the link
   degrades. Real beacons are broadcasts.
4. **Whole-flight retransmission.** Resending all 8 ServerHello fragments
   because one was lost caused a retransmission storm. Replaced with
   NACK-based selective retransmission.
5. **First-contact association.** Starting a 15-frame handshake on the first
   announcement heard, usually at the coverage edge, gave 5 % handshake
   success. Replaced with link-quality gating.

**Two protocol-level mitigations, kept because they change the answer.** Both
are evaluated by ablation (`results/ns3_variants.csv`, Figure 10):

- **EDCA prioritisation.** Without it, alerts queue behind ServerHello
  fragments in the RSU's MAC queue (head-of-line blocking): about 400 ms
  instead of about 5 ms.
- **Exponential handshake backoff.** Without it, failed handshakes are retried
  immediately and feed a congestion collapse.

---

## 9. Evaluation (`qrcav/eval/`, `scripts/`)

| Script | Produces |
|---|---|
| `scripts/run_evaluation.py` | primitives, sizes, handshake timing, beacon budget, 19 attacks, consensus scaling, throughput, fault tolerance, view change, score dynamics; all figures |
| `scripts/run_ns3_sweeps.py` | density sweep for 5 suites × 50–200 vehicles, signed vs AEAD beacons, pure vs native backend |
| `scripts/run_network.py` | the distributed system run, with the end-to-end report |
| `scripts/demo_protocol.py` | step-by-step protocol walkthrough for the viva |
| `pytest` | 48 tests (unit tests plus a real multi-process run) |

---

## 10. Known limitations

- **One machine.** The distributed system runs on localhost, so its timings
  include TCP over loopback, not radio. Radio effects come from ns-3.
- **ns-3 models the network, not the code.** It uses measured processing-time
  distributions rather than executing the cryptography.
- **No 802.11p WAVE stack.** ns-3 3.44's pip wheel ships 802.11p PHY/MAC but no
  WAVE/OCB module, so ad-hoc MAC is used. Ad-hoc mode has no association
  either, so the behaviour is close; documented as an approximation.
- **V2V through RSUs is not end-to-end.** RSUs see the plaintext, as in the
  deck's design.
- **Certificates are sent in full in every handshake.** Certificate caching
  (as in TLS's cached-info extension) would cut the post-quantum handshake by
  about half. Listed as future work.
- **No formal verification** (ProVerif / Tamarin).


---

## 11. Bugs found by our own verification

Worth including in the report: they show the results were checked, not assumed.

1. **Non-deterministic validation stalled consensus (about 1 run in 14).**
   Consensus nodes checked "is the reporter registered?" against the registry
   copy they fetched at start-up. A node that started before a vehicle enrolled
   rejected its events while the others accepted them. With one Byzantine node
   in a set of four, all three honest nodes must agree, so no result reached
   2f+1. Safety held (nothing wrong was committed) but liveness was lost.
   Found by tracing every message in a failing run, where the leader saw three
   *different* results from four nodes. Fixed by carrying the reporter's
   certificate in the request (section 5). Verified with 0 failures in 25
   repeated runs and a regression test
   (`test_validation_does_not_depend_on_local_registry_view`).
   Lesson: in BFT, every honest node's execution must be a pure function of the
   request and the ledger.
2. **Sequence-number reuse after a view change.** The new leader re-issued
   prepared requests at sequence numbers h+1 ... and then proposed new
   requests from h+1 again, so replicas saw two pre-prepares for one (view,
   sequence) and flagged equivocation. Fixed by continuing after the highest
   re-issued number.
3. **PRE-PREPAREs overtaking NEW-VIEW.** A large NEW-VIEW message can arrive
   after the pre-prepares that follow it; replicas dropped them as wrong-view.
   Fixed by buffering future-view messages and replaying them on view entry.
4. **Five ns-3 configuration traps** (section 8): ARP queue, preamble
   threshold, unicast beacons, whole-flight retransmission, first-contact
   association.
5. **Measurement contention.** Timing benchmarks run while ns-3 used both
   cores inflated consensus latency. All reported timings were re-measured
   with the CPU otherwise idle.
