"""
Build the project explorer (results/explorer.html): one self-contained page
that walks a viewer through every module of qrcav, with animations driven by
data produced by the real code, not by hand-written examples.

    python scripts/make_explorer.py                 # uses run/logs if present, else runs the network
    python scripts/make_explorer.py --network       # re-run the distributed system first (about 60 s)
    python scripts/make_explorer.py --suite L3      # a different suite for the walkthrough

What the page shows, and where each part's data comes from:

  Overview          architecture, the problem, headline numbers      results/*.csv
  1 Crypto suites   five suites, key / ciphertext / signature sizes  results/sizes.csv, primitives.csv
  2 PKI             TA set-up, registration with proof of possession, certificate fields
                    -> a real TrustedAuthority and Identity, run here
  3 Handshake       the four flights field by field, full and cached -> a real ClientHandshake / ServerHandshake
  4 Record layer    a real AES-256-GCM record; the browser re-opens it with WebCrypto,
                    and the replay window can be driven by hand
  5 Attacks         21 attacks and the check that stops each one       results/attacks.csv,
                    plus 8 attacks re-run live here
  6 Consensus       an AGS-PBFT run with a Byzantine node, message by message, scores and
                    regrouping, then a leader crash and view change  -> qrcav.consensus.sim, run here
  7 Ledger          the hash-linked chain from that run
  8 Whole system    replay of a real multi-process run (scripts/run_network.py): 19 processes,
                    registration, handshakes, events, alerts, consensus, cloud, handover, V2V,
                    leader crash, view change, revocation               run/logs/*.jsonl
  9 ns-3            the radio simulation replay and density sweep    results/viewer_data.json, ns3_*.csv
 10 Results         the evaluation in charts                          results/*.csv

Runs on Windows, Linux and macOS. ns-3 is not needed: the ns-3 trace is read
from results/viewer_data.json (built by scripts/make_viewer.py).
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav import codec  # noqa: E402
from qrcav.certcache import CertCache, cert_ref  # noqa: E402
from qrcav.crypto import get_suite  # noqa: E402
from qrcav.crypto.records import RecordError  # noqa: E402
from qrcav.handshake import ClientHandshake, HandshakeError, ServerHandshake  # noqa: E402
from qrcav.pki import Identity, TrustedAuthority  # noqa: E402

FRAME = 1400  # application chunk size used by ns-3 and the frame counts in the report


def hx(b: bytes, n: int = 24) -> str:
    return b[:n].hex()


def frames(n: int) -> int:
    return -(-n // FRAME)


def read_csv(name: str) -> list[dict]:
    p = ROOT / "results" / name
    if not p.exists():
        return []
    with p.open(newline="") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        d = {}
        for k, v in r.items():
            if v is None or v == "":
                d[k] = None
                continue
            if v in ("True", "False"):
                d[k] = v == "True"
                continue
            try:
                d[k] = float(v) if any(c in v for c in ".eE") else int(v)
            except ValueError:
                d[k] = v
        out.append(d)
    return out


def describe(obj, depth: int = 0):
    """Field-by-field view of a decoded message: name, type, size in bytes, preview."""
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            enc = len(codec.encode(v))
            if isinstance(v, bytes):
                out.append({"k": k, "bytes": len(v), "hex": hx(v, 16)})
            elif isinstance(v, dict) and depth < 1:
                out.append({"k": k, "bytes": enc, "sub": describe(v, depth + 1)})
            else:
                s = json.dumps(v, default=str)
                out.append({"k": k, "bytes": enc, "val": s[:60]})
        return out
    return []


# ---------------------------------------------------------------------------
# 2. PKI
# ---------------------------------------------------------------------------

def collect_pki(suite) -> tuple[dict, TrustedAuthority, Identity, Identity]:
    t = time.perf_counter()
    ta = TrustedAuthority(suite)
    t_ta = (time.perf_counter() - t) * 1000
    params = ta.public_parameters()
    t = time.perf_counter()
    cav = Identity.generate("CAV_001", "CAV", suite)
    t_keygen = (time.perf_counter() - t) * 1000
    rsu = Identity.generate("RSU_001", "RSU", suite)
    req = cav.registration_request()
    t = time.perf_counter()
    cert = ta.register(req)
    t_reg = (time.perf_counter() - t) * 1000
    cav.accept_certificate(cert, ta.anchor())
    ta.enrol(rsu)
    cd = cert.to_dict()
    req_d = codec.decode(req)
    return {
        "suite": suite.name, "label": suite.label,
        "params": {k: (v.hex()[:48] if isinstance(v, bytes) else v) for k, v in params.items()},
        "ta_pk_bytes": len(ta.pk), "ta_pk_hex": hx(ta.pk, 32), "ta_keygen_ms": round(t_ta, 2),
        "entity_pk_bytes": len(cav.cert.pk), "entity_keygen_ms": round(t_keygen, 2),
        "request_bytes": len(req), "request_fields": describe(req_d),
        "register_ms": round(t_reg, 2),
        "cert_bytes": len(cert.encode()),
        "cert_fields": [
            {"k": "id", "val": cd["id"]}, {"k": "role", "val": cd["role"]},
            {"k": "alg", "val": cd["alg"]}, {"k": "serial", "val": cd["serial"]},
            {"k": "nb", "val": cd["nb"]}, {"k": "na", "val": cd["na"]},
            {"k": "pk", "bytes": len(cd["pk"]), "hex": hx(cd["pk"], 16)},
            {"k": "sig", "bytes": len(cd["sig"]), "hex": hx(cd["sig"], 16)},
        ],
        "registry": [list(r) for r in ta.registry()],
    }, ta, cav, rsu


# ---------------------------------------------------------------------------
# 3. Handshake and 4. record layer
# ---------------------------------------------------------------------------

def _flight(name, raw, who):
    d = codec.decode(raw)
    return {"name": name, "from": who, "bytes": len(raw), "frames": frames(len(raw)),
            "fields": describe(d)}


def collect_handshake(suite, cav, rsu) -> tuple[dict, object, object]:
    # warm-up so first-call costs do not show up in the timings
    for _ in range(2):
        c = ClientHandshake(cav, expected_role="RSU")
        s = ServerHandshake(rsu, allowed_roles=("CAV",))
        fs, _ = s.on_client_key(c.on_server_hello(s.on_client_hello(c.client_hello())))
        c.on_server_finished(fs)

    c = ClientHandshake(cav, expected_role="RSU")
    s = ServerHandshake(rsu, allowed_roles=("CAV",))
    ch = c.client_hello()
    sh = s.on_client_hello(ch)
    ck = c.on_server_hello(sh)
    fs, s_sess = s.on_client_key(ck)
    c_sess = c.on_server_finished(fs)
    full = {
        "flights": [_flight("ClientHello", ch, "C"), _flight("ServerHello", sh, "S"),
                    _flight("ClientKey", ck, "C"), _flight("ServerFinished", fs, "S")],
        "client_ms": {k: round(v, 3) for k, v in c_sess.crypto_ms.items()},
        "server_ms": {k: round(v, 3) for k, v in s_sess.crypto_ms.items()},
        "t_hash": hx(c_sess.t_hash, 32),
        "k_c2s": hx(c_sess.sender.key, 32), "k_s2c": hx(c_sess.receiver.key, 32),
        "same_keys": c_sess.sender.key == s_sess.receiver.key and c_sess.receiver.key == s_sess.sender.key,
    }
    full["total"] = sum(f["bytes"] for f in full["flights"])

    cc, sc = CertCache(), CertCache()
    cc.put(rsu.cert.encode(), rsu.id)
    sc.put(cav.cert.encode(), cav.id)
    cc.mine_known = True
    c2 = ClientHandshake(cav, expected_role="RSU", expected_id=rsu.id, cache=cc)
    s2 = ServerHandshake(rsu, allowed_roles=("CAV",), cache=sc)
    ch2 = c2.client_hello()
    sh2 = s2.on_client_hello(ch2)
    ck2 = c2.on_server_hello(sh2)
    fs2, _ = s2.on_client_key(ck2)
    c2.on_server_finished(fs2)
    cached = {"flights": [_flight("ClientHello", ch2, "C"), _flight("ServerHello", sh2, "S"),
                          _flight("ClientKey", ck2, "C"), _flight("ServerFinished", fs2, "S")],
              "cref": hx(cert_ref(cav.cert.encode()), 32)}
    cached["total"] = sum(f["bytes"] for f in cached["flights"])
    return {"full": full, "cached": cached}, c_sess, s_sess


def collect_record(c_sess, s_sess) -> dict:
    """A real record, plus the key material the browser needs to re-open it with WebCrypto.
    These are throw-away demo keys from a session that exists only inside this script."""
    msg = {"type": "beacon", "src": "CAV_001", "seq": 1, "pos": [80.27, 13.08], "speed": 13.9}
    pt = codec.encode(msg)
    rec = c_sess.sender.seal(pt)
    back = s_sess.open(rec)
    return {
        "plaintext": msg, "plaintext_hex": pt.hex(), "plaintext_bytes": len(pt),
        "record_hex": rec.hex(), "record_bytes": len(rec),
        "key_hex": c_sess.sender.key.hex(), "iv_hex": c_sess.sender._iv.hex(), "label": "c2s",
        "opened_by_python": back == msg,
        "next_ctr": c_sess.sender.next_ctr,
    }


# ---------------------------------------------------------------------------
# 5. Attacks re-run live (the full list of 21 comes from results/attacks.csv)
# ---------------------------------------------------------------------------

def collect_live_attacks(suite, ta, cav, rsu, c_sess, s_sess) -> list[dict]:
    out = []

    def run(name, check, fn):
        try:
            fn()
            out.append({"attack": name, "rejected": False, "check": check})
        except (HandshakeError, RecordError):
            out.append({"attack": name, "rejected": True, "check": check})

    rec = c_sess.seal({"type": "beacon", "seq": 2})
    s_sess.open(rec)
    run("replay a recorded beacon", "counter already in the 64-record window",
        lambda: s_sess.open(rec))
    bad = bytearray(c_sess.seal({"type": "beacon", "seq": 3}))
    bad[12] ^= 1
    run("flip one bit of a record", "AES-GCM tag does not verify", lambda: s_sess.open(bytes(bad)))

    def stolen():
        m = Identity.generate("CAV_001", "CAV", suite)
        m.cert, m.anchor = cav.cert, cav.anchor
        c2, s2 = ClientHandshake(m), ServerHandshake(rsu)
        s2.on_client_key(c2.on_server_hello(s2.on_client_hello(c2.client_hello())))
    run("present a copied vehicle certificate without its private key",
        "client signature sig_C does not verify with the certificate's key", stolen)

    def mitm():
        c2, s2 = ClientHandshake(cav), ServerHandshake(rsu)
        d = codec.decode(s2.on_client_hello(c2.client_hello()))
        d["pk_kem"] = suite.kem.keygen()[0]
        c2.on_server_hello(codec.encode(d))
    run("man in the middle swaps the ephemeral ML-KEM key",
        "server signature sig_S covers pk_kem", mitm)

    def downgrade():
        c2, s2 = ClientHandshake(cav), ServerHandshake(rsu)
        d = codec.decode(c2.client_hello())
        d["suite"] = "CLASSIC"
        s2.on_client_hello(codec.encode(d))
    run("downgrade the suite to classical crypto", "suite must match exactly and is signed", downgrade)

    def ch_replay():
        c2, s2 = ClientHandshake(cav), ServerHandshake(rsu)
        ch = c2.client_hello()
        s2.on_client_hello(ch)
        ServerHandshake(rsu, replay_cache=s2.replay_cache).on_client_hello(ch)
    run("replay a recorded ClientHello", "client nonce already in the replay cache", ch_replay)

    def rogue():
        rogue_ta = TrustedAuthority(suite)
        m = Identity.generate("CAV_666", "CAV", suite)
        m.accept_certificate(rogue_ta.register(m.registration_request()), rogue_ta.anchor())
        m.anchor = cav.anchor
        c2, s2 = ClientHandshake(m), ServerHandshake(rsu)
        s2.on_client_hello(c2.client_hello())
    run("certificate issued by a rogue TA", "certificate signature fails under pk_TA", rogue)

    def revoked():
        ta.revoke("CAV_001")
        rsu.anchor.update_crl(ta.crl)
        c2 = ClientHandshake(cav)
        ServerHandshake(rsu).on_client_hello(c2.client_hello())
    run("revoked vehicle reconnects", "certificate serial is on the signed CRL", revoked)
    return out


# ---------------------------------------------------------------------------
# 6 / 7. Consensus and ledger, from the real replicas in the discrete-event harness
# ---------------------------------------------------------------------------

def _traced(sim):
    """Wrap ConsensusSim._emit so every message is recorded with send and arrival times."""
    log = []
    orig = sim._emit

    def emit(src, out, t):
        for dest, raw in out:
            if src in sim.partitioned or dest in sim.partitioned:
                continue
            typ = codec.decode_dict(raw, "t")["t"]
            arrival = t + sim.latency + len(raw) * 8 / sim.bw
            log.append([round(t * 1000, 3), round(arrival * 1000, 3), src, dest, typ, len(raw)])
        orig(src, out, t)
    sim._emit = emit
    return log


def _block_view(b) -> dict:
    req = codec.decode(b.request)
    body = req.get("body", {}) if isinstance(req, dict) else {}
    from qrcav.crypto.kdf import H
    verdict = "ACCEPT" if b.result == H(b"result", b"ACCEPT") else (
        "NOOP" if b.result == H(b"result", b"NOOP") else "REJECT")
    return {"b_id": b.b_id, "hash": b.hash.hex()[:16], "prev": b.prev_hash.hex()[:16],
            "t": b.t_block, "view": b.view, "seq": b.seq, "leader": b.leader,
            "txn": body.get("txn_id"), "entity": body.get("entity_id"),
            "result": verdict, "cert_n": len(b.cert), "cert_bytes": sum(len(c) for c in b.cert),
            "scores": dict(b.scores), "consensus": list(b.consensus),
            "sig_bytes": len(b.leader_sig), "bytes": len(b.encode())}


def collect_consensus(suite) -> dict:
    from qrcav.consensus.sim import ConsensusSim

    # Run 1: normal case with a Byzantine node, regrouping every 4 blocks
    sim = ConsensusSim(n_nodes=8, mode="ags", suite=suite, behaviours={"NODE_03": "wrong_result"},
                       initial_consensus=["NODE_01", "NODE_02", "NODE_03", "NODE_04"],
                       regroup_interval=4, seed=1, latency_ms=1.0)
    log = _traced(sim)
    reqs = []
    for i in range(10):
        at = 0.05 + i * 0.25
        sim.submit(at, f"EVT-{i + 1:02d}", "MEC_01", {"event": "hazard", "seq": i + 1})
        reqs.append({"txn": f"EVT-{i + 1:02d}", "at_ms": round(at * 1000, 1)})
    sim.run(3.5)
    best = max(sim.replicas.values(), key=lambda r: r.ledger.height)
    blocks = [_block_view(b) for b in best.ledger.blocks]
    done = {c.txn_id: c for c in sim.done} if sim.done and hasattr(sim.done[0], "txn_id") else {}
    for r in reqs:
        c = done.get(r["txn"])
        if c is not None:
            r["latency_ms"] = round(getattr(c, "latency", 0) * 1000, 2) if hasattr(c, "latency") else None
    events = [[n, k, {kk: (list(v) if isinstance(v, (tuple, set)) else v) for kk, v in info.items()}]
              for n, k, info in sim.events() if k in ("regroup", "commit", "equivocation", "reject-block")]
    normal = {
        "nodes": sorted(sim.replicas), "initial_consensus": ["NODE_01", "NODE_02", "NODE_03", "NODE_04"],
        "byzantine": ["NODE_03"], "regroup_interval": 4,
        "msgs": log, "requests": reqs, "blocks": blocks,
        "events": [e for e in events if e[1] == "regroup" and e[0] == best.id],
        "consistent": sim.chains_consistent(), "chain_valid": sim.chain_valid(),
        "msg_bytes": dict(sim.stats.bytes), "msg_counts": dict(sim.stats.msgs),
    }

    # Run 2: the leader crashes; view change elects the next node
    sim = ConsensusSim(n_nodes=8, mode="ags", suite=suite,
                       initial_consensus=["NODE_01", "NODE_02", "NODE_04", "NODE_05"],
                       regroup_interval=1000, view_change_timeout=0.5, seed=2, latency_ms=1.0)
    log = _traced(sim)
    leader = sim.replicas["NODE_01"].leader
    sim.submit(0.05, "EVT-A", "MEC_01")
    sim.run(0.4)
    crash_ms = 400.0
    sim.replicas[leader].behaviour = "crash"
    sim.partitioned.add(leader)
    sim.submit(0.45, "EVT-B", "MEC_01")
    sim.submit(0.60, "EVT-C", "MEC_01")
    sim.run(4.0)
    best = max((r for n, r in sim.replicas.items() if n != leader), key=lambda r: r.ledger.height)
    vc_events = [[n, k, {kk: (list(v) if isinstance(v, (tuple, set)) else v) for kk, v in info.items()}]
                 for n, k, info in sim.events() if k in ("view-change-sent", "new-view", "new-view-accepted")]
    viewchange = {
        "nodes": sorted(sim.replicas), "initial_consensus": ["NODE_01", "NODE_02", "NODE_04", "NODE_05"],
        "crashed": leader, "crash_ms": crash_ms, "timeout_ms": 500,
        "msgs": log, "blocks": [_block_view(b) for b in best.ledger.blocks],
        "events": vc_events, "consistent": sim.chains_consistent(),
        "new_leader": best.leader, "view": best.view,
    }
    return {"normal": normal, "viewchange": viewchange}


# ---------------------------------------------------------------------------
# 8. The distributed system run
# ---------------------------------------------------------------------------

def collect_network(run_network: bool, suite_name: str | None) -> dict | None:
    run_dir = ROOT / "run"
    logs = run_dir / "logs"
    if run_network or not logs.exists() or not any(logs.glob("*.jsonl")):
        print("[explorer] running the distributed system (scripts/run_network.py, about 60 s) ...", flush=True)
        cmd = [sys.executable, str(ROOT / "scripts" / "run_network.py"), "--quiet"]
        if suite_name:
            cmd += ["--suite", suite_name]
        subprocess.run(cmd, cwd=ROOT, check=False)
    if not logs.exists():
        return None
    rows = []
    for f in sorted(logs.glob("*.jsonl")):
        for line in f.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    if not rows:
        return None
    rows.sort(key=lambda r: r["t"])
    t0 = rows[0]["t"]
    keep_keys = {"t", "node", "event", "peer", "side", "bytes", "ms", "id", "role", "serial",
                 "event_id", "latency_ms", "own", "b_id", "B_ID", "hash", "Pr_B_Hash", "view", "leader",
                 "txn_id", "entity_id", "promoted", "demoted", "consensus", "new_view", "to", "msg_id",
                 "old", "new", "ok", "criticality", "rsu", "version", "counts", "median_ms", "mec_delay_ms",
                 "cert_cache", "flights", "src", "dest", "retries", "suite", "reissued"}
    ev = []
    for r in rows:
        d = {k: v for k, v in r.items() if k in keep_keys}
        d["t"] = round(r["t"] - t0, 4)
        if "ms" in d:
            d["ms"] = round(d["ms"], 2)
        if "latency_ms" in d:
            d["latency_ms"] = round(d["latency_ms"], 2)
        ev.append(d)
    cfg_path = run_dir / "effective_config.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else json.loads(
        (ROOT / "config" / "demo.json").read_text())
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
    return {"events": ev, "config": cfg, "summary": summary}


# ---------------------------------------------------------------------------

def collect_results() -> dict:
    out = {}
    for name in ("sizes", "primitives", "handshake_timing", "beacon_budget", "attacks",
                 "consensus_scaling", "consensus_throughput", "fault_tolerance", "view_change",
                 "ns3_density", "ns3_variants"):
        out[name] = read_csv(name + ".csv")
    sd = ROOT / "results" / "score_dynamics.json"
    if sd.exists():
        out["score_dynamics"] = json.loads(sd.read_text())
    return out


def collect_ns3() -> dict | None:
    p = ROOT / "results" / "viewer_data.json"
    return json.loads(p.read_text()) if p.exists() else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="DECK", help="suite for the walkthrough pages")
    ap.add_argument("--network", action="store_true", help="re-run the distributed system first")
    ap.add_argument("--out", default=str(ROOT / "results" / "explorer.html"))
    ap.add_argument("--fragment", action="store_true", help="write the page body only (for embedding)")
    ap.add_argument("--data-only", action="store_true", help="write results/explorer_data.json only")
    args = ap.parse_args()
    t0 = time.time()
    suite = get_suite(args.suite)
    print(f"[explorer] suite {suite.name}: PKI, handshake, record layer, attacks ...", flush=True)
    pki, ta, cav, rsu = collect_pki(suite)
    hs, c_sess, s_sess = collect_handshake(suite, cav, rsu)
    record = collect_record(c_sess, s_sess)
    live = collect_live_attacks(suite, ta, cav, rsu, c_sess, s_sess)
    print("[explorer] consensus runs (real replicas, real signatures) ...", flush=True)
    cons = collect_consensus(suite)
    net = collect_network(args.network, None)
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "suite": suite.name, "suite_label": suite.label,
        "pki": pki, "handshake": hs, "record": record, "live_attacks": live,
        "consensus": cons, "network": net, "results": collect_results(), "ns3": collect_ns3(),
    }
    blob = json.dumps(data, separators=(",", ":"), default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    (out.parent / "explorer_data.json").write_text(blob)
    if args.data_only:
        print(f"[explorer] wrote {out.parent / 'explorer_data.json'}")
        return
    page = (ROOT / "qrcav" / "eval" / "explorer_template.html").read_text(encoding="utf-8")
    page = page.replace("/*__DATA__*/null", blob.replace("</", "<\\/"))
    if args.fragment:
        out.write_text(page, encoding="utf-8")
    else:
        out.write_text('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
                       '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
                       '<style>body{margin:0}</style></head><body>\n' + page + "\n</body></html>\n",
                       encoding="utf-8")
    print(f"[explorer] wrote {out} ({out.stat().st_size / 1e6:.1f} MB) in {time.time() - t0:.0f} s")
    print(f"[explorer] open it in any browser: {out}")


if __name__ == "__main__":
    main()
