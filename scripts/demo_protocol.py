"""
Step-by-step walkthrough of the protocol for a viva or review, in one process.

    python scripts/demo_protocol.py               # ML-KEM-1024 + ML-DSA-65 (the deck's suite)
    python scripts/demo_protocol.py --suite L3
    python scripts/demo_protocol.py --backend pure

Prints every phase of the deck (preparation, registration, handshake,
communication) with real sizes, timings and key material, then shows a few
attacks being rejected.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav import codec  # noqa: E402
from qrcav.crypto import get_suite  # noqa: E402
from qrcav.crypto.records import RecordError  # noqa: E402
from qrcav.handshake import ClientHandshake, HandshakeError, ServerHandshake  # noqa: E402
from qrcav.pki import Identity, TrustedAuthority  # noqa: E402

B = "\033[1m"
D = "\033[2m"
G = "\033[92m"
R = "\033[91m"
X = "\033[0m"


def hx(b: bytes, n: int = 16) -> str:
    return b[:n].hex() + ("..." if len(b) > n else "")


def step(title: str) -> None:
    print(f"\n{B}{title}{X}")


def timed(fn, *a):
    t = time.perf_counter()
    r = fn(*a)
    return r, (time.perf_counter() - t) * 1000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="DECK")
    ap.add_argument("--backend", default="auto")
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")
    suite = get_suite(args.suite, args.backend)
    # warm up the backend so first-call loading does not pollute the timings
    pk, sk = suite.sig.keygen(); suite.sig.sign(sk, b"w"); ek, dk = suite.kem.keygen(); suite.kem.encaps(ek)

    print(f"{B}Quantum-resilient authenticated communication for CAVs{X}")
    print(f"suite {suite.name}: {suite.label}   backend: {suite.backend}")

    step("PREPARATION PHASE  (Trusted Authority)")
    ta, t = timed(TrustedAuthority, suite)
    p = ta.public_parameters()
    print(f"  (TA_sig_pk, TA_sig_sk) <- {suite.sig.name}.keygen()      {t:.2f} ms")
    print(f"  publish: H={p['H']}, KDF={p['KDF']}, AEAD={p['AEAD']}, ML-KEM params {p['kem_params']}")
    print(f"  pk_TA = {hx(ta.pk)}  ({len(ta.pk)} B)")

    step("REGISTRATION PHASE")
    cav, t1 = timed(Identity.generate, "CAV_001", "CAV", suite)
    rsu, t2 = timed(Identity.generate, "RSU_001", "RSU", suite)
    print(f"  CAV_001 generates its own keypair ({t1:.2f} ms); RSU_001 likewise ({t2:.2f} ms)")
    req = cav.registration_request()
    print(f"  CAV_001 -> TA: (ID, role, pk_DSA, proof-of-possession)   {len(req)} B")
    cert, t = timed(ta.register, req)
    print(f"  TA: Cert = Sign(sk_TA, ID || role || pk_DSA || serial || validity)   {t:.2f} ms")
    cav.accept_certificate(cert, ta.anchor())
    ta.enrol(rsu)
    print(f"  CAV_001 verifies Cert with pk_TA and stores it. Certificate: {len(cert.encode())} B, serial {cert.serial}")
    print(f"  {D}The TA never sees a private key (fixes the base paper's key escrow, D4){X}")
    print(f"  registry: {ta.registry()}")

    step("HANDSHAKE PHASE  (CAV_001 = client, RSU_001 = server)")
    c = ClientHandshake(cav, expected_role="RSU")
    s = ServerHandshake(rsu, allowed_roles=("CAV",))
    ch = c.client_hello()
    print(f"  1. CAV -> RSU  ClientHello {{suite, Cert_C, nonce_C, ts}}            {len(ch):>6} B")
    sh, t = timed(s.on_client_hello, ch)
    shd = codec.decode(sh)
    print(f"  2. RSU: verify Cert_C, ephemeral (pk_kem, sk_kem) <- {suite.kem.name}.keygen(),")
    print(f"          sig_S = Sign(sk_RSU, H(CH || Cert_S || pk_kem || nonce_S))     {t:.2f} ms")
    print(f"     RSU -> CAV  ServerHello {{Cert_S, pk_kem, nonce_S, sig_S}}          {len(sh):>6} B")
    print(f"          pk_kem = {hx(shd['pk_kem'])} ({len(shd['pk_kem'])} B)")
    ck, t = timed(c.on_server_hello, sh)
    ckd = codec.decode(ck)
    print(f"  3. CAV: verify Cert_S + sig_S, (ss, c) <- encaps(pk_kem), sig_C over transcript,")
    print(f"          keys <- DERIVE_SESSION_KEYS(ss, T), Finished_C under k_c2s     {t:.2f} ms")
    print(f"     CAV -> RSU  ClientKey {{c, sig_C, Finished_C}}                      {len(ck):>6} B")
    print(f"          c = {hx(ckd['ct'])} ({len(ckd['ct'])} B)")
    (fs, s_sess), t = timed(s.on_client_key, ck)
    print(f"  4. RSU: verify sig_C, ss <- decaps(sk_kem, c), erase sk_kem, derive keys,")
    print(f"          check Finished_C, send Finished_S                              {t:.2f} ms")
    print(f"     RSU -> CAV  ServerFinished {{Finished_S}}                            {len(fs):>6} B")
    c_sess, t = timed(c.on_server_finished, fs)
    print(f"  5. CAV: check Finished_S                                               {t:.2f} ms")
    total = sum(c_sess.flight_sizes.values())
    print(f"  {G}mutually authenticated session established{X}: {total} B in 4 flights "
          f"({-(-total // 1400)} frames of 1400 B)")
    print(f"  transcript hash {hx(c_sess.t_hash)}")
    print(f"  k_c2s {hx(c_sess.sender.key)}   k_s2c {hx(c_sess.receiver.key)}")
    print(f"  client crypto ms {{{', '.join(f'{k}: {v:.2f}' for k, v in c_sess.crypto_ms.items())}}}")
    print(f"  server crypto ms {{{', '.join(f'{k}: {v:.2f}' for k, v in s_sess.crypto_ms.items())}}}")

    step("COMMUNICATION PHASE  (AES-256-GCM records, slide 17)")
    msg = {"type": "beacon", "src": "CAV_001", "seq": 1, "pos": [80.27, 13.08], "speed": 13.9}
    rec, t = timed(c_sess.seal, msg)
    print(f"  plaintext  {msg}")
    print(f"  record     ctr={int.from_bytes(rec[:8], 'big')} (data starts at 1; 0 is Finished) "
          f"ciphertext+tag {len(rec) - 8} B   seal {t * 1000:.1f} us")
    back, t = timed(s_sess.open, rec)
    print(f"  RSU opens  {back}   {t * 1000:.1f} us")
    reply = s_sess.seal({"type": "ack", "seq": 1})
    print(f"  RSU -> CAV ack: {c_sess.open(reply)}")

    step("ATTACKS")
    def show(name, fn):
        try:
            fn()
            print(f"  {R}ACCEPTED{X}  {name}")
        except (HandshakeError, RecordError):
            print(f"  {G}rejected{X}  {name}")
    show("replayed record", lambda: s_sess.open(rec))
    bad = bytearray(c_sess.seal(msg)); bad[12] ^= 1
    show("tampered record", lambda: s_sess.open(bytes(bad)))
    def stolen_cert():
        m = Identity.generate("CAV_001", "CAV", suite)
        m.cert, m.anchor = cav.cert, cav.anchor
        c2 = ClientHandshake(m)
        s2 = ServerHandshake(rsu)
        s2.on_client_key(c2.on_server_hello(s2.on_client_hello(c2.client_hello())))
    show("impersonation with a copied certificate (no private key)", stolen_cert)
    def mitm():
        c2 = ClientHandshake(cav)
        s2 = ServerHandshake(rsu)
        sh2 = codec.decode(s2.on_client_hello(c2.client_hello()))
        sh2["pk_kem"] = suite.kem.keygen()[0]
        c2.on_server_hello(codec.encode(sh2))
    show("man-in-the-middle swaps the ephemeral ML-KEM key", mitm)
    def revoked():
        ta.revoke("CAV_001")
        rsu.anchor.update_crl(ta.crl)
        c2 = ClientHandshake(cav)
        ServerHandshake(rsu).on_client_hello(c2.client_hello())
    show("revoked vehicle reconnects", revoked)
    print()


if __name__ == "__main__":
    main()
