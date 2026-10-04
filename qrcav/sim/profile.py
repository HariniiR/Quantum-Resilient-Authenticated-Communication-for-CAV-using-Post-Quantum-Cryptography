"""
Measurement profiles that feed the ns-3 simulation.

ns-3 simulates the radio, the backhaul and mobility. It does not run Python
cryptography inside its event loop (that would be far too slow, and would
mix wall-clock with simulated time). Instead, the real protocol code is run
here and two things are recorded:

  sizes    the exact byte length of every message the protocol puts on the
           air: the four handshake flights, beacon records (AEAD-only and
           signed), event, alert, and consensus messages
  timings  empirical samples (not just mean and SD) of the processing time at
           each handshake stage and per beacon, so the simulation reproduces
           the real distribution, including ML-DSA's rejection-sampling tail

The simulation draws from these samples whenever a node "processes" a message.
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from .. import codec
from ..consensus.sim import ConsensusSim
from ..crypto.records import RECORD_OVERHEAD
from ..crypto.suites import get_suite
from ..handshake import ClientHandshake, ServerHandshake
from ..pki import TrustedAuthority, enrol_all


def _t(fn, *a):
    t0 = time.perf_counter()
    r = fn(*a)
    return r, (time.perf_counter() - t0) * 1000


def build_profile(suite_name: str, backend: str = "auto", samples: int = 150,
                  consensus_requests: int = 30, seed: int = 1) -> dict:
    suite = get_suite(suite_name, backend)
    ta = TrustedAuthority(suite)
    ids = enrol_all(ta, [("CAV_00001", "CAV"), ("RSU_001", "RSU")])
    cav, rsu = ids["CAV_00001"], ids["RSU_001"]

    stages = {k: [] for k in ("client_ch", "server_ch", "client_sh", "server_ck", "client_fs")}
    sizes = {}
    beacon_seal, beacon_open, sbeacon_sign, sbeacon_verify = [], [], [], []
    for i in range(samples + 5):
        c = ClientHandshake(cav, expected_role="RSU")
        s = ServerHandshake(rsu, allowed_roles=("CAV",))
        ch, t1 = _t(c.client_hello)
        sh, t2 = _t(s.on_client_hello, ch)
        ck, t3 = _t(c.on_server_hello, sh)
        (fs, s_sess), t4 = _t(s.on_client_key, ck)
        c_sess, t5 = _t(c.on_server_finished, fs)
        if i < 5:
            continue  # warm-up: first calls load backends and fill caches
        for k, v in zip(stages, (t1, t2, t3, t4, t5)):
            stages[k].append(v)
        sizes = {"client_hello": len(ch), "server_hello": len(sh), "client_key": len(ck),
                 "server_finished": len(fs)}
        beacon = {"type": "beacon", "src": cav.id, "seq": i, "ts": time.time(),
                  "pos": [1234.5, 678.9], "speed": 13.9, "heading": 90.0}
        rec, tb = _t(c_sess.seal, beacon)
        _, to = _t(s_sess.open, rec)
        beacon_seal.append(tb)
        beacon_open.append(to)
        # signed beacon (broadcast authentication without a session, as in IEEE 1609.2):
        # payload + ML-DSA signature + 32-byte certificate digest
        raw = codec.encode(beacon)
        sig, ts_ = _t(cav.sign, raw)
        ok, tv = _t(suite.sig.verify, cav.pk, raw, sig)
        sbeacon_sign.append(ts_)
        sbeacon_verify.append(tv)
        sizes["beacon_aead"] = len(rec)
        sizes["beacon_signed"] = len(codec.encode({"b": raw, "sig": sig, "cert": bytes(32)}))
    event = {"type": "event", "event_id": "CAV_00001-E1", "src": cav.id, "kind": "collision_ahead",
             "criticality": 1, "ts": time.time(), "pos": [1234.5, 678.9], "data": {}}
    sizes["event"] = len(codec.encode(event)) + RECORD_OVERHEAD
    alert = {**event, "type": "alert", "rsu": "RSU_001", "t_mec": time.time()}
    sizes["alert"] = len(codec.encode(alert)) + RECORD_OVERHEAD
    sizes["announce"] = 64
    sizes["cert"] = len(cav.cert.encode())

    # consensus commit latency at the MEC, measured with real signatures
    commit = {}
    if consensus_requests:
        for mode in ("ags", "pbft"):
            sim = ConsensusSim(n_nodes=8, mode=mode, suite=suite, seed=seed)
            for i in range(consensus_requests):
                sim.submit(0.2 * i, f"tx{i}")
            sim.run(0.2 * consensus_requests + 5)
            commit[mode] = [c.latency * 1000 for c in sim.done]

    prof = {
        "suite": suite.name, "label": suite.label, "backend": suite.backend,
        "sizes": sizes,
        "timing_ms": {
            **stages,
            "beacon_seal": beacon_seal, "beacon_open": beacon_open,
            "beacon_sign": sbeacon_sign, "beacon_verify": sbeacon_verify,
            "commit_ags": commit.get("ags", []), "commit_pbft": commit.get("pbft", []),
        },
    }
    prof["summary"] = {k: (round(statistics.fmean(v), 4), round(statistics.pstdev(v), 4))
                       for k, v in prof["timing_ms"].items() if v}
    return prof


def load_or_build(suite_name: str, backend: str, cache_dir: Path, **kw) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = cache_dir / f"profile_{suite_name}_{backend}.json"
    if p.exists():
        return json.loads(p.read_text())
    prof = build_profile(suite_name, backend, **kw)
    p.write_text(json.dumps(prof))
    return prof
