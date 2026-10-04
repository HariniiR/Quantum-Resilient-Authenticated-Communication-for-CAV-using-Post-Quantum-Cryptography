# Understanding Our Project — Start Here

Read this before you read either research paper. It assumes you know nothing about
cryptography, quantum computing, or vehicular networks. By the end you will be able
to explain the project to your guide without notes.

---

## 1. The problem, with no jargon

Self-driving and connected cars constantly send messages to each other and to
roadside equipment: *"I am braking hard," "there is ice at this junction," "I am
entering the intersection."* These messages must be

- **secret** — nobody should read your location history, and
- **genuine** — nobody should be able to fake a message from another car.

Both properties come from cryptography. The specific cryptography used in cars
today is called **ECDSA** (for genuineness) and **ECDH** (for secrecy).

In 1994 a mathematician named Peter Shor found a method that breaks both of these
completely — but it only runs on a *quantum computer*. Large enough quantum
computers do not exist yet. They are expected to.

So there are two dangers:

1. **Later:** when quantum computers arrive, faked messages become possible. A car
   could be told to brake when it should not.
2. **Now:** an attacker can record encrypted traffic today, store it, and decrypt it
   in fifteen years. Your location history is still your location history in 2041.
   The industry calls this **harvest now, decrypt later**.

In August 2024 the US standards body NIST published the official replacements:

| Old (breakable) | New (quantum-safe) | Standard |
|---|---|---|
| ECDH — agreeing a secret key | **ML-KEM** (was called Kyber) | FIPS 203 |
| ECDSA — signing messages | **ML-DSA** (was called Dilithium) | FIPS 204 |

The replacements work. The catch is **size**. An ECDH public key is 32 bytes.
ML-KEM-1024's is 1,568 bytes — about fifty times bigger. And car safety messages
must be sent every 100 milliseconds over a slow, short-range radio link.

**So our project is not "is it secure?" — that is settled. Our project is
"does it fit?"**

That is the single sentence to say when someone asks what your project is about.

---

## 2. The five ideas you must actually understand

You do **not** need quantum physics. You do not need lattice mathematics. You need
these five, and nothing more.

### Idea 1 — One-way problems

All public-key cryptography relies on a sum that is easy forwards and impossible
backwards. Multiply two large prime numbers: instant. Take the answer and find the
original primes: longer than the universe has existed.

You publish the easy direction (your **public key**) and keep the hard direction
(your **private key**).

### Idea 2 — Shor's algorithm breaks the old one-way problems

RSA, ECDH, and ECDSA all rest on two problems: factoring, and the discrete
logarithm. Shor's algorithm solves both. One algorithm, three dead systems.

Grover's algorithm is the milder cousin — it halves the strength of AES and hash
functions. AES-256 drops to about 128 bits of strength, which is still plenty.

> **AES and SHA-3 survive. Public-key cryptography does not.** That is the whole
> threat, in one line.

### Idea 3 — Lattices are the new one-way problem

Imagine an endless grid of dots in 256-dimensional space. Given a random point,
which grid dot is nearest? In 2D you can point at it. In 256D nobody knows how —
not with a normal computer, not with a quantum one.

The working form: publish `b = A·s + e`, where `A` is a public matrix, `s` is your
secret, and `e` is small random noise. Without the noise this is school algebra.
The noise is what makes it hard.

That is all ML-KEM and ML-DSA are built on. You will never write this code — the
library does it. You only need to be able to say this paragraph out loud.

### Idea 4 — A KEM is not Diffie–Hellman

This one matters, because both our papers get it confused.

- **Diffie–Hellman:** both sides contribute a secret and mix them together.
- **KEM (Key Encapsulation Mechanism):** *one* side generates a random secret and
  seals it inside a box using the other side's public key. Only the private key
  opens the box.

Three functions, and that is the entire interface:

```python
ek, dk  = keygen()      # ek = encapsulation (public) key, dk = decapsulation (private) key
key, ct = encaps(ek)    # invent a secret, seal it into ciphertext ct
key     = decaps(dk, ct)  # open the box, recover the same secret
```

**A KEM cannot sign anything.** There is no `sign()` function. This is the single
most important sentence in our project, and section 5 explains why.

### Idea 5 — Post-quantum is not the same as quantum

Two completely different things that sound identical:

- **Post-quantum cryptography (PQC)** — ordinary software on ordinary laptops. New
  mathematics that quantum computers cannot crack. **This is us.**
- **Quantum cryptography (QKD)** — uses real photons and real quantum hardware.
  Secure because of physics. Needs a fibre-optic quantum channel.

No car has a quantum channel. Any paper promising QKD in a vehicle is describing a
laboratory, not a road. If a panel member asks "where is the quantum computing in
your project?", the answer is: *"There is none, and that is the point — post-quantum
cryptography is designed to run on the hardware we already have."*

---

## 3. Our base paper

> Anjum Mohd Aslam, Aditya Bhardwaj, Rajat Chaudhary,
> *"Quantum-resilient blockchain-enabled secure communication framework for
> connected autonomous vehicles using post-quantum cryptography"*,
> **Vehicular Communications 52 (2025) 100880**, Elsevier.
> DOI: `10.1016/j.vehcom.2025.100880`

It proposes two things joined together.

**Part one — quantum-safe communication.** Vehicles, roadside units (RSUs), edge
servers and a cloud server all register with a Trusted Authority, then use Kyber
(ML-KEM) to establish session keys for vehicle-to-vehicle and
vehicle-to-infrastructure links.

**Part two — AGS-PBFT.** A tamper-proof shared record of traffic events, agreed by
voting. Ordinary PBFT makes *every* node vote on *every* transaction, which is slow.
Their **Adaptive Grouping Score** variant improves it:

- every node starts with a score of 100
- nodes split into an active **consensus set** and a passive **candidate set**
- vote with the majority: **+1**. Vote against it: **−5**
- every 50 requests, recalculate the mean (μ) and standard deviation (σ) of all
  scores. Anyone below **μ−σ** is demoted; anyone above **μ+σ** is promoted
- the active group grows when the network is busy and shrinks when it is quiet

That scoring mechanism is the genuinely original idea in the paper, and it is the
part we will implement most faithfully.

---

## 4. What is wrong with our base paper

This is where your project gets its contribution. **Verify every one of these
yourself in the PDF before your review.** If you cannot find it on the page, do not
claim it.

### Gap 1 — It signs with something that cannot sign

*Where:* Algorithm 2, and the `Sign_c` / `Sign_l` / `Sign_r` entries in Table 3.

Consensus nodes are instructed to sign and verify messages "using KYBER-PQC."
Kyber is a KEM. Per Idea 4, a KEM has no signing operation. The entire consensus
protocol therefore cannot run as written.

**Our fix:** ML-DSA-65 (FIPS 204). The paper mentions Dilithium only in its future
work section, apparently unaware it was required in the present work.

### Gap 2 — The key exchange is circular

*Where:* Algorithm 1, lines 25 and 28.

Line 25 reads `(c, k_i) ← (NTT⁻¹(Âᵀ·r + e), H(k_i ‖ H(c)))`. It defines `k_i` using
`k_i`. Line 28 then has the *receiving* party compute `k'_j ← H(k_i ‖ H(c))` using
`k_i` — a value it does not have, since obtaining it is the entire purpose of the step.

**Our fix:** the library's standard `encaps()` / `decaps()`.

### Gap 3 — The session key hashes a value against itself

*Where:* Algorithm 1, line 32.

`K ← H(k_i ‖ k'_j)`. But a correct KEM guarantees `k_i == k'_j` — that is what makes
it work. So this concatenates a value with itself.

**Our fix:** bind the key to the full handshake transcript using HKDF–SHA3-256,
which is also what gives protection against downgrade attacks.

### Gap 4 — It contradicts its own security claim

*Where:* Section 5.2.2 against Table 2.

Table 2 credits the scheme with "No key escrow ✓". But Section 5.2.2 has the Trusted
Authority generate each entity's private key — which *is* escrow — and then has the
entity generate a *second* keypair of its own, leaving the registration token
computed over the wrong key.

**Our fix:** each entity generates its own keypair; the TA certifies the public key
only.

### Two supporting observations

- Table 4 lists Hyperledger Fabric 2.2 alongside AGS-PBFT, but Fabric 2.2 orders
  transactions using **Raft**, not PBFT. It cannot host their consensus mechanism.
- Table 2 credits their own approach with "Post Quantum Cryptography (**NTRU**) ✓".
  They use Kyber, which is Module-LWE — a different hard problem entirely.

---

## 5. What we are building

Paper 1's complete system, implemented correctly.

| Component | From | Status |
|---|---|---|
| Four-layer architecture (vehicle / MEC-RSU / consensus / cloud) | Paper 1 §4 | as specified |
| Registration, tokens `S = H(ID‖pk‖MK‖TS)` | Paper 1 §5.2 | **Gap 4 fixed** |
| Key establishment | Paper 1 §5.3 | **Gaps 2, 3 fixed** |
| Entity authentication | — | **Gap 1 fixed — added** |
| Handshake composition | Olushola & Meenakshi (2026) | reference for the fix |
| AGS-PBFT consensus | Paper 1 Algorithm 2 | as specified |
| Hash-linked ledger | Paper 1 §5.4 | as specified |
| Mobility, 50–300 vehicles | Paper 1 Table 4 | SUMO + TraCI |
| Metrics and baselines | Paper 1 §7 | our own measurements |

The correction reference is:

> Akinlemi Olushola, S. P. Meenakshi, *"Design and implementation of an
> authenticated post-quantum session protocol using ML-KEM (Kyber), ML-DSA
> (Dilithium), and AES-256-GCM"*, **Frontiers in Physics 13:1723966 (2026)**.
> DOI: `10.3389/fphy.2025.1723966` (open access)

That paper contains one handshake and a benchmark table — no vehicles, no
blockchain, no consensus. It is a **citation**, not a second base paper. If you call
it a base paper the panel will ask why you have two.

### Tools — every one free and open source

```bash
pip install kyber-py dilithium-py pycryptodome simpy traci pandas matplotlib
```

Plus Eclipse SUMO for traffic simulation, and OpenStreetMap for the road network.

We deliberately do **not** use OMNeT++, Veins, Hyperledger Fabric, Docker, or
MIRACL. Reasons in the abstract document.

---

## 6. What we have already proved

Measured on our own hardware, 200 iterations per operation with warm-up runs:

```
operation                            mean ms    sd ms
-----------------------------------------------------
ML-KEM-1024 keygen                     3.965    0.113
ML-KEM-1024 encaps                     5.025    0.135
ML-KEM-1024 decaps                     6.562    0.138
ML-DSA-65 keygen                       7.745    0.120
ML-DSA-65 sign                        47.179   31.923
ML-DSA-65 verify                       8.726    0.255
AES-256-GCM encrypt 1KB                0.040    0.015
```

Full vehicle-to-RSU handshake: **48.23 ms**, **6,494 bytes**, **5 frames** at the
1500-byte limit. Tampered ciphertexts rejected. Impersonation with a replayed token
rejected.

Three findings from this, which are yours to present:

**A. Signing is the bottleneck, and it is erratic.** 47 ms average with a 32 ms
standard deviation. That is not sloppy measurement — ML-DSA uses *rejection
sampling*, retrying until the signature satisfies its size bounds, so the time
genuinely varies per signature. Verification, being deterministic, is 8.7 ms with
almost no spread.

**B. The 100 ms budget is tight, not comfortable.** Our handshake fits at 48 ms, but
the signing variance means the slowest cases may not. This is the real research
question.

**C. The published on-wire size is undercounted.** The Frontiers paper's Section 6.1
gives 4.86 KB — the 1,568-byte KEM ciphertext plus a 3,293-byte signature. But
Step 3 of their own protocol requires the ephemeral ML-KEM public key to be sent
too: another 1,568 bytes. We measure 6,494 bytes, five frames rather than four.
A 32% undercount of the quantity that matters most for V2X.

Also: their tables give the ML-DSA-65 signature as 3,293 bytes. We measured
**3,309 bytes**, which is what FIPS 204 specifies. Their own Section 3.9 says 3,309.
The tables are wrong.

---

## 7. What each of you needs to learn, and when

**Weeks 1–2 — everyone.** Sections 1 and 2 of this document until you can say them
without reading. Then read paper 1 and locate all four gaps in the PDF yourself.

Then split up:

| Person | Owns | Reads |
|---|---|---|
| 1 | Cryptography: registration, handshake, ML-KEM, ML-DSA, HKDF, AES-GCM | FIPS 203, FIPS 204 (skim), Frontiers §3 |
| 2 | Consensus: AGS-PBFT, scoring, regrouping, ledger | Paper 1 §5.4 + Algorithm 2; PBFT basics |
| 3 | Simulation: SUMO, TraCI, 802.11p model, graphs, evaluation | Paper 1 §7 + Table 4; SUMO TraCI tutorial |

Everyone must be able to explain the whole system. Only your own part in detail.

**Free reading, in this order:**

1. NIST FIPS 203 — ML-KEM (read the intro and the parameter tables, skip the proofs)
2. NIST FIPS 204 — ML-DSA (same)
3. Frontiers paper §3 — the handshake, 6 pages, open access
4. SUMO TraCI tutorial — official docs
5. Any PBFT explainer covering pre-prepare / prepare / commit and why `n ≥ 3f+1`

---

## 8. Convincing your guide and the panel

### Your opening sentence

> "Vehicle-to-vehicle safety messages are secured today with ECDSA and ECDH, which
> Shor's algorithm breaks. We implement the NIST-standardised replacements —
> ML-KEM and ML-DSA — for the CAV framework in our base paper, and measure whether
> they fit the 100 millisecond safety-beacon budget. We also found four errors in
> the base paper that prevent it from being implemented as published."

### Five slides, no more

1. **The problem** — one table: RSA, ECDH, ECDSA broken by Shor; AES and SHA-3
   survive. Harvest-now-decrypt-later means it matters today.
2. **The base paper** — its architecture and its AGS-PBFT scoring idea.
3. **The four gaps** — Algorithm 1 line 25 on screen. This slide does more work
   than the other four combined.
4. **What we build** — the component table from section 5, and the tool list.
5. **What we already measured** — the benchmark table from section 6, and the three
   findings.

### Questions you will be asked

**"What is novel? You are only implementing an existing paper."**
The paper cannot be implemented as printed — it signs with a key encapsulation
mechanism that has no signing operation, and its key-exchange pseudocode is
circular. We supply the missing primitive and measure the result under vehicular
mobility, which the original never did.

**"Do you understand the cryptography or just calling libraries?"**
Explain Module-LWE as finding a hidden lattice point after noise is added, and
explain why a KEM differs from Diffie–Hellman. Then say plainly that you use
audited library implementations because hand-written lattice arithmetic is how real
systems get broken. That answer is stronger than pretending otherwise.

**"Is your implementation secure enough to deploy?"**
No, and say so first. The pure-Python libraries are explicitly educational and not
constant-time, so they do not resist timing side-channel attacks. Ours is a
functional and performance study. Volunteering this earns more credit than being
caught on it.

**"Where is the quantum computing?"**
There is none — see Idea 5. Post-quantum cryptography is designed for the hardware
we already have. Mention that you evaluated and rejected two QKD-based papers for
exactly this reason.

**"Why not use Hyperledger Fabric like the paper says?"**
Fabric 2.2 orders transactions with Raft, not PBFT, so it cannot host AGS-PBFT.
Implementing the consensus directly is the only way to actually run it.

**"Your laptops are weak. Does that invalidate the results?"**
The opposite. A car's onboard unit is far closer to a modest laptop than to the
desktop i7-12700K used in the reference paper. Modest hardware makes our numbers
*more* relevant to deployment. We report our specifications, which is exactly what
the papers do.

**"Three months is not much time."**
Show the twelve-week plan — and show the working code. We already have the
handshake running with measured timings.

### The thing that will land hardest

Walk in with a terminal open. Run the handshake. Let them watch ML-KEM-1024
encapsulate and ML-DSA-65 verify with real numbers from your own machine. A panel
that sees working code stops interrogating scope and starts discussing results.

---

## 9. Glossary

| Term | Meaning |
|---|---|
| **CAV** | Connected and Autonomous Vehicle |
| **V2V / V2I / V2X** | Vehicle-to-Vehicle / -Infrastructure / -Everything |
| **RSU** | Roadside Unit — the radio box on a pole |
| **OBU** | Onboard Unit — the radio and computer inside the car |
| **MEC** | Multi-access Edge Computing — a small server near the road |
| **TA** | Trusted Authority — issues and certifies identities |
| **PQC** | Post-Quantum Cryptography — classical software, quantum-resistant maths |
| **QKD** | Quantum Key Distribution — needs real quantum hardware. Not us. |
| **KEM** | Key Encapsulation Mechanism — seals a secret into a ciphertext |
| **ML-KEM** | The standardised KEM, FIPS 203. Was called Kyber. |
| **ML-DSA** | The standardised signature scheme, FIPS 204. Was called Dilithium. |
| **LWE / MLWE** | Learning With Errors — the lattice problem underneath both |
| **AEAD** | Authenticated Encryption with Associated Data — encrypts *and* detects tampering |
| **AES-256-GCM** | The AEAD we use for the actual message data |
| **HKDF** | A function that turns one shared secret into several separate keys |
| **Nonce** | A number used once. Reusing one with the same key breaks GCM completely. |
| **Transcript binding** | Hashing every handshake message into the key, so nothing can be swapped |
| **Forward secrecy** | Stealing today's long-term key does not decrypt yesterday's traffic |
| **HNDL** | Harvest Now, Decrypt Later |
| **PBFT** | Practical Byzantine Fault Tolerance — voting that tolerates `f` liars among `3f+1` nodes |
| **AGS-PBFT** | Paper 1's version, with node scores and periodic regrouping |
| **SUMO** | Eclipse Simulation of Urban MObility — the traffic simulator |
| **TraCI** | Traffic Control Interface — the Python API for driving SUMO |
| **IEEE 802.11p** | The Wi-Fi variant used for vehicle radio links |
| **Shor's algorithm** | Quantum method that breaks RSA, ECDH and ECDSA |
| **Grover's algorithm** | Quantum method that halves symmetric strength. AES-256 survives. |
