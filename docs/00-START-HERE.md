# Start Here

The project in one sentence: we built the base paper's V2X security framework
with the NIST post-quantum standards (ML-KEM, ML-DSA), fixed what stops it
working, and measured whether it still fits a vehicle's radio and time budget.

## What to read, in order

| Document | What it is for |
|---|---|
| [`05-SYSTEM-DESIGN.md`](05-SYSTEM-DESIGN.md) | how every part works and why, with the defects we fixed (D1–D9, F1–F7) and certificate caching |
| [`06-RUNNING-AND-DEMO.md`](06-RUNNING-AND-DEMO.md) | installing, every command, and the Review 2 demo script |
| [`07-RESULTS.md`](07-RESULTS.md) | every result with what it means, and answers to likely panel questions |
| [`../report/main.pdf`](../report/) | the full project report (LaTeX source in `report/`) |
| [`../slides/review2.pdf`](../slides/) | the Review 2 deck (Beamer source in `slides/`) |
| `../results/viewer.html` | the ns-3 replay: open it in any browser |

`review1/` holds the Review 1 documents. They describe the first prototype
(`cavpqc/`, pure-Python crypto, an analytic radio model, SUMO planned) and are
kept for reference only; where they disagree with the files above, the files
above are current.

## The five findings

1. **Per message, post-quantum V2X fits** the 100 ms beacon budget at every
   security level once the cryptography is native: a beacon inside a session
   is the same 135-byte AES-GCM record for every suite.
2. **Bandwidth is the binding constraint, not CPU.** A post-quantum handshake
   is about 20× the bytes of a classical one, and in dense traffic the shared
   802.11p channel saturates.
3. **Certificate caching halves the handshake**; EDCA priority and
   exponential backoff keep the channel usable.
4. **DECK (ML-KEM-1024 + ML-DSA-65) is category 3**, set by its signature; L3
   gives the same security with a smaller KEM.
5. **AGS-PBFT sends far fewer messages than PBFT but is not faster**, and the
   safety path never waits for it.

## Code map

```
qrcav/crypto/      suites (ML-KEM/ML-DSA, two backends, classical baseline), KDF, records
qrcav/pki.py       Trusted Authority, certificates, CRL
qrcav/handshake.py the four-flight handshake (sans-IO)
qrcav/certcache.py certificate caching
qrcav/consensus/   AGS-PBFT and PBFT
qrcav/ledger.py    certified, hash-linked blocks
qrcav/nodes/       one process per entity
qrcav/sim/         ns-3 scenario and measurement profiles
qrcav/eval/        benchmarks, attacks, consensus experiments, plots, viewer
scripts/           the commands you run
tests/             57 tests
```
