# Running the System and the Review 2 Demo

## 1. Setup on Windows (everything except ns-3)

Use PowerShell or the VS Code terminal, from the project folder:

```powershell
cd "C:\Users\harin\Desktop\FYP 2026\fyp-cav-pqc"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Python 3.10 or newer. `cryptography` 49 bundles OpenSSL with native ML-KEM and
ML-DSA, so nothing else needs installing. Check it with:

```powershell
python -c "from qrcav.crypto import get_suite; print(get_suite('DECK').label)"
# ML-KEM-1024 + ML-DSA-65
```

If it fails with "this project needs native ML-KEM / ML-DSA", run
`pip install -U "cryptography>=47"`.

## 2. Setup for ns-3 (WSL2, once)

The ns-3 Python bindings exist only for Linux. On Windows, use WSL2:

```powershell
wsl --install -d Ubuntu          # admin PowerShell, then reboot
```

Then in the Ubuntu terminal:

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip build-essential
cd "/mnt/c/Users/harin/Desktop/FYP 2026/fyp-cav-pqc"
python3 -m venv ~/qrcav-venv && source ~/qrcav-venv/bin/activate
pip install -r requirements.txt -r requirements-ns3.txt
python scripts/run_ns3_sweeps.py --quick       # ~3 min; checks the setup
```

`build-essential` is needed because the scenario's C++ is compiled at run time
(first run takes about 10 s longer).

## 3. Commands

| What | Command | Time |
|---|---|---|
| Protocol walkthrough (viva) | `python scripts/demo_protocol.py` | 1 s |
| One component on its own | `python scripts/demo_parts.py suites` (or `codec`, `kdf`, `records`, `pki`, `handshake`, `certcache`, `secure`, `attacks`, `all`) | 1 s each |
| Two processes, two terminals | `python scripts/two_terminals.py setup`, then `... rsu` in one terminal and `... cav` in another | live |
| Distributed system, 19 processes | `python scripts/run_network.py` | 50 s |
| Same, classical crypto for comparison | `python scripts/run_network.py --suite CLASSIC` | 50 s |
| Same, certificate caching off | set `"cert_cache": false` in `config/demo.json` | 50 s |
| Tests | `python -m pytest` (or `-m "not slow"` to skip the network test) | ~2 min |
| Evaluation + figures | `python scripts/run_evaluation.py` (`--quick` for ~2 min) | ~4 min |
| ns-3 sweeps (WSL2) | `python scripts/run_ns3_sweeps.py`, then `--seeds 2 3` | ~40 + ~70 min on 2 cores |
| Replay viewer (WSL2) | `python scripts/make_viewer.py` → open `results/viewer.html` | ~10 min |
| Redraw figures only | `python scripts/run_evaluation.py --plots` | 5 s |
| Report and slide numbers | `python scripts/make_tables.py` | 1 s |
| Report PDF | `cd report && latexmk -pdf main.tex` | 30 s |
| Slides PDF | `cd slides && latexmk -pdf review2.tex` | 20 s |

Run timing benchmarks (`run_evaluation.py`, and the profile step at the start
of `run_ns3_sweeps.py`) with nothing else running. Two ns-3 workers on the
same cores inflate every timing.

Output goes to `run/` (the distributed run: logs, ledgers, registry DB, cloud
DB, `summary.json`) and `results/` (CSVs, `fig*.png`).

---

## 4. Review 2 demo script (about 10 minutes)

### Part A: the protocol (2 min)

```powershell
python scripts/demo_protocol.py
```

Walk down the output. What to point at:

- **Registration:** "The vehicle generates its own key; the TA only signs it.
  The base paper had the TA generate private keys, which contradicts its own
  no-escrow claim."
- **Handshake:** the four flights and their sizes. "ServerHello is 10 KB
  because it carries a 5.3 KB ML-DSA certificate and a 1.5 KB ML-KEM key.
  This whole handshake is 20.8 KB against 1 KB classical. That size, not
  compute time, is the problem we study."
- **Certificate caching:** the second handshake in the walkthrough. "Both
  certificates now travel as 32-byte hashes, so the handshake is 10.2 KB.
  They are still checked in full, including against the CRL."
- **Communication:** `ctr=1`. "Data starts at counter 1, because Finished
  used 0. If both used 0 we would reuse a GCM nonce, which breaks GCM
  completely. The Review 1 design left this unspecified."
- **Attacks:** all rejected.

### Part B: the distributed system (5 min)

```powershell
python scripts/run_network.py
```

19 processes start (TA, cloud, MEC, 8 consensus nodes, 3 RSUs, 5 vehicles).
What happens, by time:

| t (s) | Event | What to say |
|---|---|---|
| 0–3 | every entity registers; vehicles pre-load the 3 RSU certificates; about 48 handshakes | "Every link in the architecture slide is now a real ML-KEM + ML-DSA session." Point at `cached cert: server` on the vehicle lines: the RSU sent a 32-byte reference instead of its 5.3 KB certificate (15.5 KB instead of 20.8 KB). |
| 7 | CAV_01 reports `collision_ahead` (critical) | "MEC alerts every vehicle within ~5 ms, then records it on the ledger. Consensus is not on the safety path." |
| 8 | CAV_02 reports a pothole (routine) | goes to the cloud, not the ledger |
| 10 | CAV_01 → CAV_04 V2V | relayed RSU_01 → RSU_02, re-encrypted per hop |
| 12 | CAV_03 handover RSU_02 → RSU_03 | a fresh handshake with the new RSU. Both certificates are references now (10.2 KB): RSU_03 fetched CAV_03's certificate from the directory over the wired side |
| 16–25 | CAV_04 reports 10 traffic-jam events | blocks 3–12 |
| ~21 | **REGROUP at block 8** | "NODE_03 has been returning a wrong result. Its score fell by 5 per block; it is now below μ−σ and has been demoted. NODE_05, a candidate, has been promoted." |
| 34 | **NODE_01 (the leader) crashes** | |
| 36 | CAV_05 event → backups time out → **VIEW-CHANGE → NEW-VIEW** | "NODE_02 takes over as leader; the event still commits." |
| 40 | **TA revokes CAV_05** | RSU_03 drops its session |
| 43 | CAV_05 tries to reconnect → **rejected** | "Revocation works within a CRL refresh, even though RSU_03 still has CAV_05's certificate in its cache: cached certificates are re-checked against the CRL every time." |
| 50 | stop → **summary** | ledger heights, *ledgers consistent: True*, *ledger verifies: True*, the block table |

### Part C: the simulation, visually (2 min)

Open `results/viewer.html` in a browser (no internet needed apart from fonts).
Press Play on **Classical**: almost every dot turns green within a second.
Switch to **Post-quantum** at the same moment: many dots stay amber (a
handshake in flight) or flash red (failed), and the airtime strip below is far
taller. Switch to **PQ + cache**: more green, lower airtime. "Same cars, same
roads, same radio; only the cryptography changes."

### Part D: results (3 min)

Use the Review 2 slides (`slides/review2.pdf`), results section. The talking
points are in `docs/07-RESULTS.md`.

---

## 5. Changing the scenario

Everything is in `config/demo.json`:

- **More vehicles:** add entries to `"cavs"`.
- **A Byzantine node:** `"behaviour": "wrong_result"` or `"silent"` on a node.
- **A crash:** `"crash_at": 30` on a node.
- **Faster regrouping:** `"regroup_interval"` (the paper uses 50).
- **Plain PBFT instead of AGS-PBFT:** `"consensus": {"mode": "pbft", ...}`.
- **Another suite:** `"suite": "L3"` (or pass `--suite` on the command line).

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` | a previous run is still alive: close it, or change the ports in the config |
| "this project needs native ML-KEM / ML-DSA" | `pip install -U "cryptography>=47"` |
| `ns-3 Python bindings not found` | run in WSL2 with `pip install -r requirements-ns3.txt` |
| ns-3 run fails compiling | `sudo apt install build-essential` in WSL2 |
| Colours show as `[92m` | use Windows Terminal or the VS Code terminal |
