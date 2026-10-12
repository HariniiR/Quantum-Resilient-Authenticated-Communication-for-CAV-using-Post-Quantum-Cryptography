# Code Walkthrough and Development Roadmap

How the implementation works, what is not built yet, and exactly what to do next.
Written so you can come back in three weeks and still find your way around.

Line numbers refer to the state of the code at the time of writing; use the
function names if they have drifted.

---

## Part 1 — Navigating the code

### The dependency order

Read the modules in this order. Each depends only on the ones above it.

```
crypto.py      ← no internal dependencies
   ↓
entities.py    ← uses crypto
ledger.py      ← uses crypto
   ↓
handshake.py   ← uses crypto, entities
consensus.py   ← uses crypto, entities, ledger
network.py     ← no internal dependencies
   ↓
simulation.py  ← uses everything above
benchmark.py   ← uses everything above
   ↓
run_evaluation.py  ← calls benchmark + simulation, writes results/
```

### Standalone scripts, for teaching rather than for the system

| File | Purpose |
|---|---|
| `demo.py` | The core idea in 15 lines. Start here when explaining the project to anyone. |
| `handshake.py` (root) | An earlier self-contained version, kept because it prints a readable trace. Superseded by `cavpqc/handshake.py`. |
| `why_composition_matters.py` | Demonstrates that identical library calls yield a secure or an attacker-readable system depending on composition. Run this when someone says "you just called functions." |

The root-level `handshake.py` is **not** imported by the package. If you edit the
protocol, edit `cavpqc/handshake.py`.

---

## Part 2 — Module by module

### `cavpqc/crypto.py` — the primitive layer

Everything cryptographic funnels through here, so swapping algorithms touches
one file.

**Key objects**

| Name | Line | What it does |
|---|---|---|
| `SUITES` | 34 | Maps `"L1"/"L3"/"L5"` to (KEM name, KEM module, sig name, sig module). This is how the evaluation sweeps security levels. |
| `DEFAULT_KEM`, `DEFAULT_SIG` | 44–45 | What the system uses by default. **Change these two lines to switch the whole system's security level.** |
| `H(*parts, length)` | 54 | SHAKE-256 over *length-prefixed* parts. |
| `derive_traffic_secret(...)` | 79 | Deviation D3. Extract-then-expand bound to the transcript hash. |
| `registration_token(...)` | 100 | `S_i = H(ID ‖ pk ‖ MK ‖ TS)` from paper §5.2. |
| `SecureChannel` | 114 | One direction of AES-256-GCM. `seal()` / `open()`. |
| `channel_pair(...)` | 151 | Derives both directions from one shared secret. |
| `artifact_sizes(suite)` | 169 | Measures real key/signature sizes by generating them. |

**Two design decisions worth understanding**

*Length-prefixing in `H`.* Without it, `H(b"ab", b"c")` and `H(b"a", b"bc")` would
produce the same digest. That is exploitable when hashing attacker-influenced
fields such as identities. Every part is prefixed with its 4-byte length first.

*Nonce construction in `SecureChannel._nonce()` (line 128).* The nonce is
`base_iv XOR counter`, the counter is monotonic, and exhaustion raises
`NonceExhausted` rather than wrapping. AES-GCM fails **catastrophically** on
nonce reuse — an attacker recovers the authentication key — so wrapping silently
would be worse than crashing.

### `cavpqc/entities.py` — identities and registration

| Name | Line | What it does |
|---|---|---|
| `Role` | 36 | Enum: VEHICLE, RSU, MEC, CLOUD — paper §4's four layers. |
| `Entity` | 54 | Any network participant. Holds identity, keypair, token, position. |
| `Entity.generate_keys()` | 72 | Deviation D4 — the *entity* generates, not the TA. |
| `make_vehicle/rsu/mec/cloud` | 98–110 | Factory helpers. |
| `TrustedAuthority` | 118 | Publishes parameters, enrols entities, holds the CRL. |
| `TrustedAuthority.enrol()` | 140 | **Raises `RegistrationError` if the entity has no keypair.** This is how D4 is enforced in code rather than merely claimed. |
| `verify_registration()` | 169 | Four checks: CRL, public key matches directory, token recomputes, timestamp fresh. |

**The important detail.** `TrustedAuthority` has `master_key`, `directory`,
`tokens` and `revoked` — and deliberately no field for entity private keys. If a
future change makes the TA hold one, deviation D4 is undone and the paper's "No
key escrow" property is lost again.

### `cavpqc/ledger.py` — the chain

| Name | Line | What it does |
|---|---|---|
| `Transaction` | 30 | Frozen dataclass. `digest()` canonicalises via sorted-key JSON so hashing is deterministic. |
| `Block` | 59 | `(b_id, prev_hash, transactions)` per paper §5.4. |
| `Block.merkle_root()` | 69 | **Not in the paper.** Lets a vehicle verify one transaction without downloading a whole block, which matters on a 6 Mbps link. |
| `Block.hash()` | 84 | The cryptographic link to the previous block. |
| `Ledger.validate()` | 131 | Recomputes every link. Any tampered block breaks the chain from that point on. |

`validate()` is what the ledger-tampering attack test exercises.

### `cavpqc/handshake.py` — corrected Algorithm 1

The most security-sensitive file. Read the whole thing before changing anything.

| Name | Line | What it does |
|---|---|---|
| `HandshakeError` | 36 | Uniform abort. Carries **no reason**, deliberately — a probing adversary must not learn whether the token, signature or key confirmation failed. |
| `Session` | 47 | Established channels plus the metrics we measure. |
| `establish()` | 66 | The seven-step handshake. |
| `establish_v2v()` | 167 | Three-hop relay per paper §5.3.3. |

**The order of operations in `establish()` is security-critical.** Specifically:

1. Ephemeral KEM keypair generated (forward secrecy)
2. Responder signs `identity ‖ pk ‖ token ‖ ts ‖ ephemeral_key`
3. **Token verified against the TA, then signature verified — before any key
   material is used**
4. Encapsulate
5. Initiator signs too (mutual authentication)
6. Decapsulate
7. Derive over the transcript, then confirm keys match

If you move step 3 after step 4, you have rebuilt Version A of
`why_composition_matters.py` and a man-in-the-middle succeeds. The signature must
cover the ephemeral key, and it must be checked before that key is used.

`del kem_dk, shared_i, shared_r` near the end is not decoration — forward secrecy
is only real if ephemeral secrets are dropped.

### `cavpqc/consensus.py` — AGS-PBFT

The largest module (414 lines) and the paper's actual contribution.

| Name | Line | What it does |
|---|---|---|
| `NodeSet` | 52 | CONSENSUS (active) or CANDIDATE (passive). |
| `ConsensusNode` | 58 | Wraps an `Entity` with score, group, byzantine flag, local ledger. |
| `ConsensusNode.vote()` | 90 | Honest nodes echo the digest; Byzantine nodes **collude on one false value**. |
| `AGSPBFT` | 107 | The engine. |
| `_initial_split()` | 133 | Half candidates, per paper §5.4. |
| `_enforce_quorum()` | 145 | Maintains `CN ≥ 3f+1`. |
| `leader` | 178 | `p = v mod CN`. |
| `submit()` | 185 | One full round: Request → Pre-Prepare → Prepare → Response → Reply. |
| `_update_scores()` | 268 | +1 agree, −5 disagree. |
| `_reassign()` | 280 | Deviation D6 — μ±σ thresholds with a rank-order fallback. |
| `PlainPBFT` | 365 | Textbook baseline for the message-count comparison. |

**Why Byzantine nodes must collude.** In `vote()` the faulty nodes all return
`H(b"byzantine-collusion", digest)` — the *same* wrong value. An earlier version
gave each node a different wrong value, and the consequence was subtle: the
faulty nodes split their own vote, the honest plurality won, and consensus
appeared to survive well past the 3f+1 bound. That made the protocol look more
robust than PBFT theory permits. The 3f+1 bound is stated against *colluding*
adversaries, so the model has to collude.

**Why `_reassign()` has a fallback.** Paper §5.4 gives `T_low = μ−σ` and
`T_high = μ+σ`. Every node starts at 100, so on the first reassignment σ = 0 and
μ = 100, making both thresholds equal to 100 — every node is simultaneously
demotable and promotable. We require σ > 0 before applying thresholds and
otherwise use rank order, which is what the paper's prose describes.

**Message counting in `submit()` is exact**, because the whole point of §7.4 is
comparing communication overhead. If you change the phase structure, update the
counts or the comparison becomes meaningless.

### `cavpqc/network.py` — 802.11p and mobility

| Name | Line | What it does |
|---|---|---|
| `Link80211p` | 40 | Configured from paper Table 4: 6 Mbps, 20 mW, −98 dBm, 1500 B MTU. |
| `received_power_dbm()` | 53 | Free-space path loss. **Optimistic for an urban grid** — stated as a limitation. |
| `max_range_m()` | 71 | Bisection on SNR. Computes **454 m** with the paper's parameters. |
| `airtime_ms()` | 104 | `contention + transmission + propagation`. This is how vehicle density enters the latency figures. |
| `UrbanGrid` | 133 | 5 km × 5 km synthetic grid used when SUMO is absent. |
| `load_sumo_trace()` | 178 | **The SUMO hook. Returns `None` if SUMO or traci is unavailable.** This is where week 9's work plugs in. |

### `cavpqc/simulation.py` — the driver

| Name | Line | What it does |
|---|---|---|
| `ScenarioConfig` | 28 | All knobs. Defaults from paper Table 4. |
| `ScenarioResult` | 44 | Collected measurements plus the paper's §7 metric calculations. |
| `run_scenario()` | 87 | One full run: preparation → registration → handshake → beacons → consensus. |
| `density_sweep()` | 194 | Sweeps 50–300 vehicles per paper §7.2–7.4. |

`run_scenario()` follows the paper's phase order and is commented with the
section numbers, so it doubles as a map of the paper.

### `cavpqc/benchmark.py` — measurement

| Name | Line | Produces |
|---|---|---|
| `bench(fn, n, warmup)` | 44 | Mean and SD in ms. **The `warmup` parameter is not optional in practice** — see the gotcha below. |
| `benchmark_primitives()` | 60 | All three levels, six operations each |
| `benchmark_classical()` | 87 | ECDH and ECDSA P-256 baseline |
| `benchmark_sizes()` | 121 | Artifact sizes and 802.11p frame counts |
| `benchmark_beacon_path()` | 148 | **The 100 ms question.** The key result. |
| `benchmark_consensus()` | 189 | AGS-PBFT vs PlainPBFT |
| `benchmark_fault_tolerance()` | 231 | Safety vs liveness under colluding faults |
| `attack_tests()` | 293 | Seven attacks |

---

## Part 3 — How a request flows through the system

Tracing one vehicle from power-on to a committed ledger entry:

```
1. vehicle.generate_keys()                    entities.py:72
   → ML-DSA-65 keypair, private key never leaves the vehicle

2. ta.enrol(vehicle)                          entities.py:140
   → refuses if no keypair (D4)
   → issues S = H(ID ‖ pk ‖ MK ‖ TS)

3. grid.nearest_rsu(pos, rsu_positions)       network.py:167
   → which RSU, and how far

4. link.in_range(dist)                        network.py:68
   → SNR ≥ 10 dB? beyond 454 m the vehicle simply cannot associate

5. establish(vehicle, rsu, ta)                handshake.py:66
   → 7 steps; raises HandshakeError on any failure
   → returns Session with send/recv channels

6. session.send.seal(beacon)                  crypto.py:134
   → AES-256-GCM, nonce = base_iv XOR counter

7. ags.submit(vehicle, [Transaction(...)])    consensus.py:185
   → Request → Pre-Prepare → Prepare → Response → Reply
   → scores updated; every 50 requests, groups reassigned

8. ledger.append(transactions)                ledger.py:115
   → Block(b_id, prev_hash, txs), chained by SHAKE-256
```

Steps 3, 4 and 7 are where the interesting measurements come from.

---

## Part 4 — What is NOT built

Be honest about these in your report. They are the difference between "we
implemented the paper" and "we implemented the paper's protocol logic."

### Not built at all

| Missing | Why it matters | Effort |
|---|---|---|
| **Real SUMO mobility** | Currently a synthetic grid. Vehicles move on straight lines at constant speed; no junctions, no traffic lights, no queueing. The hook exists at `network.py:178` but is never called. | 1 week |
| **PBFT view change** | When consensus fails we increment `self.view` (`consensus.py:253`) and pick a new leader, but there is no view-change *protocol* — no NEW-VIEW message, no state transfer. A real primary failure would not recover correctly. | 3–4 days |
| **Commit phase** | Omitted because the paper omits it. Costs PBFT's safety argument across view changes. Implementing it would let you quantify what the paper's message saving actually costs. | 2 days |
| **Certificate chains** | Entities hold a token, not an X.509 certificate. No hierarchy, no intermediate authorities, no expiry. | 3 days |
| **Cloud layer** | `make_cloud()` exists and enrols, but nothing is ever archived to it. Paper §4's fourth layer is a stub. | 1 day |
| **MEC processing** | Same — MEC servers register but perform no aggregation or edge computation. | 2 days |
| **Packet loss and retransmission** | `airtime_ms()` assumes every frame arrives. At 6 frames per handshake on a contended channel, loss matters. | 2 days |
| **Handshake success rate across RSU transit** | The interesting mobility question: a vehicle entering and leaving range. Needs real mobility first. | 2 days |

### Built but simplified

| Simplification | Consequence |
|---|---|
| Free-space path loss | Optimistic. Real urban 802.11p range is well under 454 m due to buildings. |
| Contention model | An approximation in `contention_ms()` (`network.py:93`), not real CSMA/CA with collisions and exponential backoff. |
| Consensus runs in-process | No real network between validators, so consensus latency measures computation only, not wire time. |
| No persistence | Ledger lives in memory. Restart loses everything. |
| Single Trusted Authority | No distribution, no failover. |

### Deliberately out of scope

Constant-time cryptography, side-channel hardening, formal verification
(ProVerif/Scyther), deployment on vehicle hardware. Say so plainly rather than
being asked.

---

## Part 5 — What to do next, in priority order

### Priority 1 — Fix RSU density (half a day)

**The problem.** With 9 RSUs over 5 km × 5 km and 454 m range, about 80% of
vehicles cannot reach an RSU. The current density sweep therefore measures very
few handshakes.

**Where.** `simulation.py:194`, `density_sweep()`. It currently sets
`rsus=max(9, n // 25)` — scaling with *vehicle count*, which is wrong. RSU count
should scale with *area and range*.

**What to do.** Full coverage of 5 km² at 454 m radius needs roughly
`(5000 / (454 × 1.4))² ≈ 61` RSUs; about 120 for overlap. Either raise the count,
or make coverage an explicit variable and report handshake success rate against
it. The second is more interesting — it becomes a result rather than a fix.

### Priority 2 — Real SUMO mobility (1 week, this is week 9)

**Where.** `network.py:178`, `load_sumo_trace()` already returns snapshots or
`None`. Nothing calls it yet.

**Steps.**
1. Install SUMO, export your city from OpenStreetMap
2. Generate trips with `randomTrips.py`
3. Call `load_sumo_trace()` from `run_scenario()` and use the snapshots instead
   of `UrbanGrid.vehicle_position()`
4. Keep the fallback — the project must still run without SUMO

**Why it matters.** Real junctions mean vehicles bunch at lights, which spikes
contention exactly when message volume peaks. The synthetic grid cannot show
that.

### Priority 3 — Handshake success rate across RSU transit (2 days)

The genuinely novel V2X question, and it needs Priority 2 first.

A vehicle at 10 m/s crossing a 454 m radius is in range for about 90 seconds.
The handshake takes ~130 ms. So association is not the problem — but at a
junction with 50 vehicles contending, does the 6-frame flight still complete
before the vehicle leaves range? Measure completion rate against vehicle density
and RSU spacing.

### Priority 4 — Packet loss (2 days)

Add a loss probability to `airtime_ms()` derived from SNR, and retransmission
with backoff. With 6 frames per handshake, a 5% per-frame loss rate gives a
~26% chance at least one frame is lost. That changes the conclusions and is worth
knowing.

### Priority 5 — Quantify the missing commit phase (2 days)

Implement the commit phase in `AGSPBFT.submit()` behind a flag, then compare
message counts with and without it. You could then state precisely how much of
the paper's 76% saving comes from adaptive grouping versus from dropping commit.
That would be a genuine contribution beyond the paper.

### Priority 6 — Persistence and a live demo (2 days)

Write the ledger to disk, and build the three-terminal demo described in the full
project document: SUMO GUI, scrolling system log, attack script rejecting things.
For a viva this is worth more than another table.

---

## Part 6 — Common tasks

### Change the security level everywhere

`crypto.py:44–45`:

```python
DEFAULT_KEM_NAME, DEFAULT_KEM = "ML-KEM-768", ML_KEM_768
DEFAULT_SIG_NAME, DEFAULT_SIG = "ML-DSA-44", ML_DSA_44
```

Everything downstream follows, since all crypto goes through this module.

### Add a metric

1. Add a field to `ScenarioResult` (`simulation.py:44`)
2. Populate it in `run_scenario()` (`simulation.py:87`)
3. Add a summary method next to `latency_summary()`
4. Add the column in `run_evaluation.py` section 8

### Add an attack test

Append to `attack_tests()` (`benchmark.py:293`) using the local `record()` helper.
The test must show the attack is **rejected**; a test that passes trivially proves
nothing.

### Add a figure

Add a block to `make_figures()` in `run_evaluation.py`. Follow the existing
pattern — `style()` helper, `NAVY`/`CYAN`/`AMBER` palette, `dpi=160`.

---

## Part 7 — Gotchas that will cost you a day

**Always warm up before timing.** The first `AES.new()` call takes ~868 ms while
pycryptodome loads its backend; the true cost is 0.03 ms. A factor of 29,000. Use
`bench()` from `benchmark.py`, which discards warm-up runs. This is the same
error that produces implausible published figures such as an X25519 baseline of
2.81 ± 23.44 ms, where the SD is eight times the mean.

**ML-DSA signing time varies by design.** 41 ± 23 ms at level 3 is not noise —
rejection sampling retries until the signature meets its bounds. Report medians
and p95 as well as means, and never size a latency budget from the mean alone.

**Safety and liveness are different properties.** Consensus can commit past the
`n ≥ 3f+1` safety bound if honest nodes happen to reach the `2f+1` quorum.
Guarantee lost, function retained. If you write a test asserting "commits fail
beyond f faults," it will fail — and the test is wrong, not the code. See
`benchmark_fault_tolerance()`.

**Byzantine nodes must collude.** If each faulty node emits a different wrong
value they split their own vote and the protocol looks stronger than it is.

**Don't reorder the handshake.** Token and signature verification must precede
any use of key material. `why_composition_matters.py` shows what breaks.

**Edit `cavpqc/handshake.py`, not the root `handshake.py`.** The root file is a
standalone teaching script and is not imported.

**`freshness_window` defaults to 300 s.** Tests that fabricate timestamps must
stay inside it or they will fail for the wrong reason.

---

## Part 8 — Quick reference

```bash
cd ~/fyp-cav-pqc

./.venv/bin/python demo.py                     # 15-line core idea
./.venv/bin/python why_composition_matters.py  # composition vs library calls
./.venv/bin/python run_evaluation.py           # full evaluation → results/

# one scenario
./.venv/bin/python -c "
from cavpqc.simulation import ScenarioConfig, run_scenario
r = run_scenario(ScenarioConfig(vehicles=100, rsus=60))
print(r.latency_summary())"

# just the key result
./.venv/bin/python -c "
from cavpqc.benchmark import benchmark_beacon_path, table
print(table(benchmark_beacon_path()))"
```

| Want to change | File | Line |
|---|---|---|
| Security level | `crypto.py` | 44–45 |
| Nonce or rekey policy | `crypto.py` | 114–148 |
| Registration or CRL rules | `entities.py` | 140, 169 |
| Handshake steps | `handshake.py` | 66 |
| Consensus phases | `consensus.py` | 185 |
| Scoring values | `consensus.py` | 128–130 |
| Regrouping rule | `consensus.py` | 280 |
| Radio parameters | `network.py` | 40–52 |
| RSU placement | `network.py` | 145 |
| SUMO integration | `network.py` | 178 |
| Scenario defaults | `simulation.py` | 28 |
| Density sweep | `simulation.py` | 194 |
| Attack tests | `benchmark.py` | 293 |
| Figures | `run_evaluation.py` | `make_figures()` |
