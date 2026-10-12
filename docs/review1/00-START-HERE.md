# Start Here

One page. Read this and nothing else for now.

---

## What the project is

Cars send each other safety messages. Those messages are protected by maths that a
quantum computer can break. Someone has already invented the replacement maths and
made it an official standard. The replacement works, but it is about fifty times
bigger, and cars have a slow radio and only 100 milliseconds to send each message.

**Our project: swap the old maths for the new maths in a car network, and measure
whether it still fits in time.**

That is the whole thing. If someone asks what your project is, say that.

---

## What the code looks like

Open `demo.py`. It is fifteen lines and it is the heart of the project:

```python
rsu_public, rsu_private = ML_DSA_65.keygen()      # RSU's permanent ID
temp_lock, temp_key     = ML_KEM_1024.keygen()    # a lock for this chat only
proof                   = ML_DSA_65.sign(rsu_private, temp_lock)
assert ML_DSA_65.verify(rsu_public, temp_lock, proof)   # is this really the RSU?
car_secret, box         = ML_KEM_1024.encaps(temp_lock) # car locks a secret in a box
rsu_secret              = ML_KEM_1024.decaps(temp_key, box)  # RSU opens it
assert car_secret == rsu_secret                   # both have the same secret
```

Run it:

```bash
cd ~/fyp-cav-pqc && ./.venv/bin/python demo.py
```

Six library calls. You never write cryptography. You call functions that mathematicians
already wrote and NIST already approved.

---

## The only six words you need this week

| Word | What it means |
|---|---|
| **ML-KEM** | The function that agrees a shared secret. Old name: Kyber. |
| **ML-DSA** | The function that signs, to prove identity. Old name: Dilithium. |
| **AES** | Encrypts the actual message once you have the shared secret. |
| **RSU** | Roadside unit — the radio box on a pole. |
| **CAV** | Connected and autonomous vehicle. A car. |
| **Shor's algorithm** | The quantum method that breaks the old maths. Why we are doing this. |

That is enough vocabulary to build the project. Everything else you learn as you go.

---

## What we build, in order

Each row is a Python file. Each one is small.

| # | File | What it does | When |
|---|---|---|---|
| 1 | `demo.py` | the core idea | **done** |
| 2 | `handshake.py` | same thing, but with registration and message encryption | **done** |
| 3 | `entities.py` | classes for cars, RSUs, servers | week 4 |
| 4 | `consensus.py` | the voting system from our paper (the hard one) | weeks 6–8 |
| 5 | `ledger.py` | a chain of blocks holding traffic records | week 8 |
| 6 | `mobility.py` | move cars around a real map using SUMO | week 9 |
| 7 | `benchmark.py` | measure everything, draw graphs | week 11 |

Two of seven already run.

---

## What you already have that a panel will respect

Real numbers, measured on our own machine:

```
ML-KEM-1024 encapsulation      5.03 ms
ML-KEM-1024 decapsulation      6.56 ms
ML-DSA-65   signing           47.18 ms   (± 32 ms - varies a lot)
ML-DSA-65   verification       8.73 ms
Full car-to-RSU handshake     48.23 ms   (budget is 100 ms)
Bytes sent                     6,494 B   (5 radio frames)
```

And one sentence that is your entire research finding:

> **Signing is the slow part, not key exchange — and it is unpredictable, so the
> worst case may not fit in 100 milliseconds.**

That is a genuine result. You got it on day one.

---

## What to say to the panel

Four sentences. Memorise these, not the theory.

1. "Cars use ECDSA and ECDH today. Shor's algorithm breaks both."
2. "NIST standardised the replacements in 2024: ML-KEM and ML-DSA."
3. "We implement them in the CAV framework from our base paper, and we found four
   errors in that paper that stop it working as published — the biggest one is that
   it tries to sign messages with a function that has no signing operation."
4. "Our early measurements show signing, not key exchange, is the bottleneck."

Then open a terminal and run `demo.py` in front of them.

---

## What to do next, in order

1. Run `demo.py`. Read it. Change a byte in `box` and watch it break.
2. Run `handshake.py`. Same idea plus registration, encryption, and attack tests.
3. Open our base paper's PDF. Find **Algorithm 1 on page 8**. Read **line 25**. See
   that it defines `k_i` using `k_i`. That is error number one, and you found it.
4. Only then read `01-UNDERSTANDING-THE-PROJECT.md` — it is a reference for when you
   write the report, not an introduction. Around week 3.

---

## If you feel lost

You are not behind. You are three days into a subject people spend years on, and you
already have working code and real measurements. Nobody on your panel expects you to
derive lattice mathematics. They expect you to build something, measure it honestly,
and know what your own code does.

You are already doing that.
