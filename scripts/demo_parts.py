"""
Run one part of Phases 2-3 on its own, so each component can be shown separately.

    python scripts/demo_parts.py suites       # ML-KEM and ML-DSA on their own
    python scripts/demo_parts.py codec        # canonical encoding
    python scripts/demo_parts.py kdf          # hash, HKDF, session-key derivation
    python scripts/demo_parts.py records      # AES-256-GCM records, replay window
    python scripts/demo_parts.py pki          # TA, registration, certificate, CRL
    python scripts/demo_parts.py handshake    # the four flights, step by step
    python scripts/demo_parts.py certcache    # handshake with cached certificates
    python scripts/demo_parts.py secure       # the handshake over a real TCP socket
    python scripts/demo_parts.py attacks      # the attack harness
    python scripts/demo_parts.py all          # every part in order

Add --suite L1 / L3 / L5 / CLASSIC to change the suite (default DECK).
Every part builds only what it needs, so each can be run without the others.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav import codec  # noqa: E402
from qrcav.crypto import get_suite  # noqa: E402

B, D, G, R, X = "\033[1m", "\033[2m", "\033[92m", "\033[91m", "\033[0m"


def hx(b: bytes, n: int = 16) -> str:
    return b[:n].hex() + ("..." if len(b) > n else "")


def title(t: str) -> None:
    print(f"\n{B}=== {t} ==={X}")


def ok(cond: bool, what: str) -> None:
    print(f"  {G + 'OK      ' if cond else R + 'FAILED  '}{X}{what}")


def ms(fn, *a):
    t = time.perf_counter()
    r = fn(*a)
    return r, (time.perf_counter() - t) * 1000


def expect_error(what: str, fn, *errors) -> None:
    try:
        fn()
        print(f"  {R}ACCEPTED{X}  {what}")
    except errors:
        print(f"  {G}rejected{X}  {what}")


def _registered(suite, *specs):
    """A TA plus registered identities, for the parts that need certificates."""
    from qrcav.pki import TrustedAuthority, enrol_all
    ta = TrustedAuthority(suite)
    return ta, enrol_all(ta, list(specs))


# --------------------------------------------------------------------------- parts

def part_suites(suite) -> None:
    title(f"crypto/suites.py  -  suite {suite.name}: {suite.label}")
    kem, sig = suite.kem, suite.sig
    print(f"  post-quantum: {suite.is_post_quantum}")

    print(f"\n  {B}KEM {kem.name}{X}  (key exchange)")
    (ek, dk), t = ms(kem.keygen)
    print(f"  receiver: (pk, sk) <- keygen()          pk {len(ek)} B   {t:.2f} ms")
    (ss1, ct), t = ms(kem.encaps, ek)
    print(f"  sender:   (ss, c) <- encaps(pk)         c {len(ct)} B, ss {len(ss1)} B   {t:.2f} ms")
    print(f"  {D}the sender has no key pair: it only uses the receiver's public key{X}")
    ss2, t = ms(kem.decaps, dk, ct)
    print(f"  receiver: ss <- decaps(sk, c)                                  {t:.2f} ms")
    ok(ss1 == ss2, f"both sides hold the same 32-byte secret {hx(ss1, 8)}")
    bad = bytearray(ct); bad[0] ^= 1
    try:
        ss3 = kem.decaps(dk, bytes(bad))
        ok(ss3 != ss1, "tampered ciphertext gives a different secret, with no error (implicit rejection)")
    except ValueError:
        print(f"  {D}tampered ciphertext raises an error here: classical ECDH has no implicit rejection{X}")

    print(f"\n  {B}Signature {sig.name}{X}  (authentication)")
    (pk, sk), t = ms(sig.keygen)
    print(f"  (pk, sk) <- keygen()                    pk {len(pk)} B   {t:.2f} ms")
    msg = b"beacon: CAV_001 at (80.27, 13.08), 13.9 m/s"
    s, t = ms(sig.sign, sk, msg)
    print(f"  sig <- sign(sk, msg)                    sig {len(s)} B   {t:.2f} ms")
    v, t = ms(sig.verify, pk, msg, s)
    print(f"  verify(pk, msg, sig)                                           {t:.2f} ms")
    ok(v, "the receiver has msg and sig, and the signature verifies")
    ok(not sig.verify(pk, msg + b"!", s), "a changed message does not verify")
    ok(not sig.verify(sig.keygen()[0], msg, s), "another key does not verify")


def part_codec(suite) -> None:
    title("codec.py  -  canonical encoding")
    a = codec.encode({"b": 2, "a": b"\x01\x02", "n": [1, "x", None, True]})
    b = codec.encode({"n": [1, "x", None, True], "a": b"\x01\x02", "b": 2})
    print(f"  encode(dict) -> {len(a)} B: {a.hex()}")
    ok(a == b, "same dict in a different key order gives identical bytes (keys are sorted)")
    ok(codec.decode(a) == {"a": b"\x01\x02", "b": 2, "n": [1, "x", None, True]}, "decode gives back the same object")
    print(f"  {D}why: we sign and hash encoded bytes, so one object must have exactly one encoding{X}")
    expect_error("trailing bytes after a valid object", lambda: codec.decode(a + b"\x00"), codec.CodecError)
    expect_error("truncated input", lambda: codec.decode(a[:-3]), codec.CodecError)
    expect_error("missing required field", lambda: codec.decode_dict(a, "a", "missing"), codec.CodecError)
    deep = []
    for _ in range(40):
        deep = [deep]
    expect_error("nesting deeper than 32", lambda: codec.encode(deep), codec.CodecError)


def part_kdf(suite) -> None:
    from qrcav.crypto.kdf import H, derive_session_keys, hkdf_expand, hkdf_extract
    title("crypto/kdf.py  -  hash and key derivation")
    print(f"  H(\"label\", data) = SHAKE-256 over length-prefixed parts, 32 B")
    ok(H(b"ab", b"c") != H(b"a", b"bc"), "H(\"ab\",\"c\") != H(\"a\",\"bc\")  (length prefixes stop part-shifting)")
    ok(H(b"cert", b"x") != H(b"transcript", b"x"), "different labels give different hashes (domain separation)")
    ss = os.urandom(32)
    prk = hkdf_extract(bytes(32), ss)
    print(f"  PRK = HKDF-Extract(0, ss)        = {hx(prk)}")
    print(f"  k   = HKDF-Expand(PRK, info, 32) = {hx(hkdf_expand(prk, b'key_c2s', 32))}")
    k1 = derive_session_keys(ss, b"transcript of flights 1-3")
    print(f"  derive_session_keys(ss, T):")
    print(f"    k_c2s {hx(k1.k_c2s)}  v_c2s {k1.v_c2s.hex()}")
    print(f"    k_s2c {hx(k1.k_s2c)}  v_s2c {k1.v_s2c.hex()}")
    ok(k1 == derive_session_keys(ss, b"transcript of flights 1-3"), "same ss and transcript -> same keys on both sides")
    ok(k1.k_c2s != k1.k_s2c, "each direction gets its own key")
    k2 = derive_session_keys(ss, b"transcript of flights 1-3 (changed)")
    ok(k1.k_c2s != k2.k_c2s, "one changed handshake byte -> different keys (keys bound to the transcript)")


def part_records(suite) -> None:
    from qrcav.crypto.records import RecordError, RecordReceiver, RecordSender, make_nonce
    title("crypto/records.py  -  AES-256-GCM records")
    key, iv = os.urandom(32), os.urandom(12)
    tx, rx = RecordSender(key, iv), RecordReceiver(key, iv)
    print(f"  nonce = base_iv XOR (0^32 || counter):  ctr 1 -> {make_nonce(iv, 1).hex()}")
    print(f"                                          ctr 2 -> {make_nonce(iv, 2).hex()}")
    recs = [tx.seal(f"beacon {i}".encode()) for i in range(1, 4)]
    r = recs[0]
    print(f"  record = ctr(8) || ciphertext || tag(16): {len(r)} B for a {len('beacon 1')} B message")
    print(f"           ctr {int.from_bytes(r[:8], 'big')} (data starts at 1; 0 is reserved for Finished)")
    for rec in recs:
        c, pt = rx.open(rec)
        ok(True, f"opened ctr {c}: {pt.decode()}")
    expect_error("replay of record 2", lambda: rx.open(recs[1]), RecordError)
    bad = bytearray(tx.seal(b"brake!")); bad[10] ^= 1
    expect_error("one bit flipped in the ciphertext", lambda: rx.open(bytes(bad)), RecordError)
    later = [tx.seal(b"x") for _ in range(3)]
    rx.open(later[2]); c, _ = rx.open(later[0])
    ok(True, f"out-of-order record ctr {c} still accepted (64-record window)")
    other = RecordReceiver(os.urandom(32), iv)
    expect_error("record opened with the wrong key", lambda: other.open(tx.seal(b"x")), RecordError)
    print(f"  receiver rejected {rx.rejected} records; replay is checked before decryption")


def part_pki(suite) -> None:
    from qrcav.pki import Identity, TrustedAuthority
    title(f"pki.py  -  Trusted Authority and certificates ({suite.sig.name})")
    ta, t = ms(TrustedAuthority, suite)
    print(f"  TA key pair generated ({t:.2f} ms); TA public key {len(ta.pk)} B is the trust anchor")
    cav = Identity.generate("CAV_001", "CAV", suite)
    print(f"  CAV_001 generates its OWN key pair; the TA never sees the private key")
    req = cav.registration_request()
    print(f"  registration request (id, role, pk, proof of possession): {len(req)} B")
    cert, t = ms(ta.register, req)
    cav.accept_certificate(cert, ta.anchor())
    print(f"  TA signs the certificate ({t:.2f} ms): {len(cert.encode())} B")
    print(f"    id {cert.id}  role {cert.role}  serial {cert.serial}  alg {cert.alg}")
    anchor = ta.anchor()
    ok(anchor.verify_cert(cert), "anyone holding the TA public key can verify it (signature, validity, CRL, alg)")
    ok(not anchor.verify_cert(cert, expected_role="RSU"), "the same certificate is refused where an RSU is expected")
    from qrcav.pki import RegistrationError
    mallory = Identity.generate("CAV_002", "CAV", suite)
    forged = codec.decode(mallory.registration_request())
    forged["pk"] = cav.cert.pk          # claim CAV_001's key without its private key
    expect_error("registering someone else's public key (proof of possession fails)",
                 lambda: ta.register(codec.encode(forged)), RegistrationError)
    bad = codec.decode(cert.encode()); bad["role"] = "RSU"
    from qrcav.pki import Certificate
    expect_error("certificate with role changed CAV -> RSU",
                 lambda: _must(anchor.verify_cert(Certificate.from_dict(bad))), ValueError)
    crl = ta.revoke("CAV_001")
    anchor.update_crl(crl)
    print(f"  TA revokes CAV_001: signed CRL version {crl.version}, revoked serials {list(crl.revoked_serials)}")
    expect_error("certificate after revocation", lambda: _must(anchor.verify_cert(cert)), ValueError)
    print(f"  registry: {ta.registry()}")


def _must(x):
    if not x:
        raise ValueError("rejected")
    return x


def part_handshake(suite) -> None:
    from qrcav.handshake import ClientHandshake, ServerHandshake
    title(f"handshake.py  -  the four flights ({suite.label})")
    ta, ids = _registered(suite, ("CAV_001", "CAV"), ("RSU_001", "RSU"))
    cav, rsu = ids["CAV_001"], ids["RSU_001"]
    c = ClientHandshake(cav, expected_role="RSU")
    s = ServerHandshake(rsu, allowed_roles=("CAV",))
    print(f"  {D}sans-IO: these objects only turn bytes into bytes; no sockets here{X}")
    ch = c.client_hello()
    print(f"  1 CAV->RSU ClientHello  {sorted(codec.decode(ch))}  {len(ch)} B   state {c.state}")
    sh, t = ms(s.on_client_hello, ch)
    print(f"  2 RSU->CAV ServerHello  {sorted(codec.decode(sh))}  {len(sh)} B   {t:.2f} ms")
    ck, t = ms(c.on_server_hello, sh)
    print(f"  3 CAV->RSU ClientKey    {sorted(codec.decode(ck))}  {len(ck)} B   {t:.2f} ms")
    (fs, ss), t = ms(s.on_client_key, ck)
    print(f"  4 RSU->CAV Finished     {sorted(codec.decode(fs))}  {len(fs)} B   {t:.2f} ms")
    cs = c.on_server_finished(fs)
    ok(cs.t_hash == ss.t_hash, f"both sides agree on the transcript hash {hx(cs.t_hash, 8)}")
    ok(cs.sender.key == ss.receiver.key, "client's sending key = server's receiving key")
    print(f"  peers: client sees {cs.peer_id}, server sees {ss.peer_id}")
    print(f"  total {sum(cs.flight_sizes.values())} B: {cs.flight_sizes}")
    rec = cs.seal({"type": "beacon", "seq": 1})
    print(f"  first record over the session: {len(rec)} B -> {ss.open(rec)}")


def part_certcache(suite) -> None:
    from qrcav.certcache import CertCache, cert_ref
    from qrcav.handshake import handshake_in_memory
    title("certcache.py  -  certificate caching")
    ta, ids = _registered(suite, ("CAV_001", "CAV"), ("RSU_001", "RSU"))
    cav, rsu = ids["CAV_001"], ids["RSU_001"]
    full, _ = handshake_in_memory(cav, rsu)
    nfull = sum(full.flight_sizes.values())
    print(f"  without caching: {nfull} B   {full.flight_sizes}")
    cc, sc = CertCache(), CertCache()
    cc.put(rsu.cert.encode(), rsu.id)       # RSU certificates are pre-distributed to vehicles
    sc.put(cav.cert.encode(), cav.id)       # the vehicle's certificate is in the edge directory
    cc.mine_known = True
    print(f"  cref = H(\"qrcav-cert\", cert) = {hx(cert_ref(cav.cert.encode()))}  (32 B instead of {len(cav.cert.encode())} B)")
    cached, _ = handshake_in_memory(cav, rsu, client_cache=cc, server_cache=sc)
    n = sum(cached.flight_sizes.values())
    print(f"  with caching:    {n} B   {cached.flight_sizes}")
    ok(n < nfull, f"{100 * (1 - n / nfull):.0f} % smaller; certificates are still fully verified each time")
    print(f"  cache use: {cached.cert_cache}")
    cc2 = CertCache(); cc2.put(rsu.cert.encode(), rsu.id); cc2.mine_known = True
    retry, _ = handshake_in_memory(cav, rsu, client_cache=cc2, server_cache=CertCache())
    ok(True, f"server did not know the vehicle -> HelloRetry, full certificate sent: {sum(retry.flight_sizes.values())} B")


def part_secure(suite) -> None:
    from qrcav.handshake import HandshakeError
    from qrcav.net.secure import secure_connect, start_secure_server
    title("net/secure.py  -  the handshake over TCP on localhost")
    ta, ids = _registered(suite, ("CAV_001", "CAV"), ("RSU_001", "RSU"))
    cav, rsu = ids["CAV_001"], ids["RSU_001"]

    async def run():
        got = asyncio.get_running_loop().create_future()

        async def on_channel(chan):
            msg = await chan.recv()
            await chan.send({"type": "ack", "for": msg["seq"]})
            got.set_result(msg)

        server = await start_secure_server("127.0.0.1", 0, rsu, ("CAV",), on_channel)
        port = server.sockets[0].getsockname()[1]
        print(f"  RSU_001 listening on 127.0.0.1:{port} (4-byte length-prefixed frames)")
        t = time.perf_counter()
        chan = await secure_connect("127.0.0.1", port, cav, expected_role="RSU")
        print(f"  CAV_001 connected; handshake {(time.perf_counter() - t) * 1000:.1f} ms; peer {chan.peer_id} ({chan.peer_role})")
        await chan.send({"type": "beacon", "seq": 7, "speed": 13.9})
        print(f"  RSU received {await got}")
        print(f"  CAV received {await chan.recv()}")
        chan.close()
        try:
            await secure_connect("127.0.0.1", port, cav, expected_role="TA")
            print(f"  {R}ACCEPTED{X}  connecting while expecting the wrong role")
        except HandshakeError:
            print(f"  {G}rejected{X}  connecting while expecting a TA (server is an RSU)")
        server.close()
        await server.wait_closed()

    asyncio.run(run())


def part_attacks(suite) -> None:
    from qrcav.eval.attacks import run_attacks
    title(f"eval/attacks.py  -  attack harness ({suite.name})")
    rows = run_attacks(suite.name)
    for r in rows:
        print(f"  {G + 'rejected' if r['rejected'] else R + 'ACCEPTED'}{X}  {r['attack']:<55} {D}{r['mechanism']}{X}")
    print(f"  {sum(r['rejected'] for r in rows)}/{len(rows)} rejected")
    if not suite.is_post_quantum:
        print(f"  {D}the downgrade test means nothing here: this suite is already the classical one{X}")


PARTS = {
    "suites": part_suites, "codec": part_codec, "kdf": part_kdf, "records": part_records,
    "pki": part_pki, "handshake": part_handshake, "certcache": part_certcache,
    "secure": part_secure, "attacks": part_attacks,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("part", choices=[*PARTS, "all"])
    ap.add_argument("--suite", default="DECK")
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")              # turn on colours in the Windows console
    suite = get_suite(args.suite)
    for name, fn in PARTS.items():
        if args.part in (name, "all"):
            fn(suite)
    print()


if __name__ == "__main__":
    main()
