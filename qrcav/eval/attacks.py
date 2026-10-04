"""
Attack harness. Every attack is run against the real implementation and the
outcome is observed, not asserted from the design. An attack counts as
rejected only if the protocol aborts (or drops the message) and no
application data is accepted.
"""

from __future__ import annotations

import time

from .. import codec
from ..consensus.agspbft import Replica
from ..consensus.messages import PREPARE, seal
from ..consensus.sim import ConsensusSim
from ..crypto.records import FINISHED_CTR, RecordError
from ..crypto.suites import get_suite
from ..handshake import ClientHandshake, HandshakeError, ReplayCache, ServerHandshake, handshake_in_memory
from ..ledger import Block
from ..pki import Certificate, Identity, TrustedAuthority, enrol_all


def _flip(b: bytes, i: int = -20) -> bytes:
    x = bytearray(b)
    x[i] ^= 0x01
    return bytes(x)


def _edit(raw: bytes, **changes) -> bytes:
    d = codec.decode(raw)
    d.update(changes)
    return codec.encode(d)


def run_attacks(suite_name: str = "DECK") -> list[dict]:
    suite = get_suite(suite_name)
    ta = TrustedAuthority(suite)
    ids = enrol_all(ta, [("CAV_01", "CAV"), ("CAV_02", "CAV"), ("RSU_01", "RSU")])
    cav, cav2, rsu = ids["CAV_01"], ids["CAV_02"], ids["RSU_01"]
    rows: list[dict] = []

    def record(name: str, fn, mechanism: str) -> None:
        try:
            rejected = bool(fn())
        except (HandshakeError, RecordError):
            rejected = True
        rows.append({"attack": name, "rejected": rejected, "mechanism": mechanism})

    # ---- record layer ---------------------------------------------------
    c, s = handshake_in_memory(cav, rsu)

    def tamper():
        rec = c.seal({"type": "beacon", "speed": 13.9})
        s.open(_flip(rec))
        return False
    record("record tampering (1 bit flipped)", tamper, "AES-256-GCM tag check fails")

    def replay_record():
        rec = c.seal({"type": "event", "kind": "collision_ahead"})
        s.open(rec)
        s.open(rec)
        return False
    record("record replay", replay_record, "counter already seen in the 64-record window")

    def nonce_reuse():
        rec = c.seal({"x": 1})
        ctr = int.from_bytes(rec[:8], "big")
        return ctr != FINISHED_CTR  # data never shares counter 0 with Finished
    record("GCM nonce reuse with Finished", nonce_reuse, "data counters start at 1; 0 is Finished only")

    # ---- handshake --------------------------------------------------------
    def replay_hello():
        cache = ReplayCache()
        ch = ClientHandshake(cav, expected_role="RSU").client_hello()
        ServerHandshake(rsu, replay_cache=cache).on_client_hello(ch)
        ServerHandshake(rsu, replay_cache=cache).on_client_hello(ch)
        return False
    record("ClientHello replay", replay_hello, "nonce already in the server's replay cache")

    def stale():
        ch = ClientHandshake(cav, now=time.time() - 300).client_hello()
        ServerHandshake(rsu).on_client_hello(ch)
        return False
    record("stale ClientHello (timestamp -300 s)", stale, "outside the 30 s freshness window")

    def impersonate_client():
        # attacker holds a copy of CAV_01's certificate but not its private key
        mallory = Identity.generate("CAV_01", "CAV", suite)
        mallory.cert, mallory.anchor = cav.cert, cav.anchor
        handshake_in_memory(mallory, rsu)
        return False
    record("client impersonation with stolen certificate", impersonate_client,
           "client signature over the transcript fails (deck design had no client signature)")

    def impersonate_server():
        mallory = Identity.generate("RSU_01", "RSU", suite)
        mallory.cert, mallory.anchor = rsu.cert, rsu.anchor
        handshake_in_memory(cav, mallory)
        return False
    record("RSU impersonation with stolen certificate", impersonate_server,
           "server signature over transcript + pk_kem fails")

    def forged_cert():
        rogue = TrustedAuthority(suite)
        m = Identity.generate("CAV_99", "CAV", suite)
        rogue.enrol(m)
        m.anchor = cav.anchor   # present it to a network that trusts the real TA
        handshake_in_memory(m, rsu)
        return False
    record("certificate from a rogue TA", forged_cert, "certificate signature does not verify under pk_TA")

    def revoked():
        ta2 = TrustedAuthority(suite)
        i2 = enrol_all(ta2, [("CAV_R", "CAV"), ("RSU_R", "RSU")])
        ta2.revoke("CAV_R")
        i2["RSU_R"].anchor.update_crl(ta2.crl)
        handshake_in_memory(i2["CAV_R"], i2["RSU_R"])
        return False
    record("revoked credential", revoked, "certificate serial on the signed CRL")

    def role_confusion():
        handshake_in_memory(cav, cav2, expected_role="RSU")
        return False
    record("vehicle posing as an RSU", role_confusion, "role is bound into the certificate")

    def mitm_kem():
        cl = ClientHandshake(cav, expected_role="RSU")
        sv = ServerHandshake(rsu)
        sh = sv.on_client_hello(cl.client_hello())
        attacker_ek, _ = suite.kem.keygen()
        cl.on_server_hello(_edit(sh, pk_kem=attacker_ek))
        return False
    record("MITM substitutes the ephemeral ML-KEM key", mitm_kem,
           "server signature covers pk_kem")

    def mitm_ct():
        cl = ClientHandshake(cav, expected_role="RSU")
        sv = ServerHandshake(rsu)
        sh = sv.on_client_hello(cl.client_hello())
        ck = cl.on_server_hello(sh)
        _, ct2 = suite.kem.encaps(codec.decode(sh)["pk_kem"])
        sv.on_client_key(_edit(ck, ct=ct2))
        return False
    record("MITM substitutes the KEM ciphertext", mitm_ct, "client signature covers c")

    def downgrade():
        ch = ClientHandshake(cav).client_hello()
        ServerHandshake(rsu).on_client_hello(_edit(ch, suite="CLASSIC"))
        return False
    record("downgrade to classical suite", downgrade, "suite must match and is inside both signatures")

    def finished_tamper():
        cl = ClientHandshake(cav, expected_role="RSU")
        sv = ServerHandshake(rsu)
        sh = sv.on_client_hello(cl.client_hello())
        ck = cl.on_server_hello(sh)
        d = codec.decode(ck)
        sv.on_client_key(_edit(ck, fin=_flip(d["fin"])))
        return False
    record("tampered Finished", finished_tamper, "key confirmation under transcript-bound keys fails")

    def forward_secrecy():
        cl = ClientHandshake(cav, expected_role="RSU")
        sv = ServerHandshake(rsu)
        sh = sv.on_client_hello(cl.client_hello())
        fs, _ = sv.on_client_key(cl.on_server_hello(sh))
        return sv._sk_kem is None   # ephemeral decapsulation key erased after use
    record("forward secrecy: ephemeral key retained", forward_secrecy,
           "ephemeral ML-KEM key per session, erased after decapsulation")

    # ---- consensus and ledger ------------------------------------------------
    sim = ConsensusSim(n_nodes=8, mode="ags", suite=suite)
    for i in range(3):
        sim.submit(0.1 * i, f"tx{i}")
    sim.run(3)
    honest = next(r for r in sim.replicas.values() if r.behaviour == "honest")
    outsider = Identity.generate("NODE_99", "NODE", suite)

    def forged_vote():
        raw = seal(outsider, PREPARE, {"v": 0, "n": 4, "d": b"x" * 32})
        return honest.dir.open(raw) is None
    record("consensus vote from a non-member", forged_vote, "sender has no certificate in the directory")

    def spoofed_vote():
        member = sim.cfg.nodes[0]
        raw = seal(outsider, PREPARE, {"v": 0, "n": 4, "d": b"x" * 32})
        raw = _edit(raw, **{"from": member})
        return honest.dir.open(raw) is None
    record("consensus vote spoofing another member", spoofed_vote, "ML-DSA signature does not verify")

    def block_tamper():
        b = honest.ledger.blocks[-1]
        probe = Replica.__new__(Replica)
        probe.__dict__.update(honest.__dict__)
        from ..ledger import Ledger
        probe.ledger = Ledger()
        for blk in honest.ledger.blocks[:-1]:
            probe.ledger.append(blk)
        bad = Block(**{**b.__dict__, "result": b"\x00" * 32})
        return not probe.verify_block(bad)
    record("tampered block (result changed)", block_tamper, "leader signature and commit certificate")

    def chain_tamper():
        from ..ledger import Ledger
        led = Ledger()
        for blk in honest.ledger.blocks:
            led.blocks.append(blk)
        led.blocks[0] = Block(**{**led.blocks[0].__dict__, "t_block": 0})
        return not led.validate()
    record("ledger history rewrite", chain_tamper, "Pr_B_Hash link broken")

    return rows
