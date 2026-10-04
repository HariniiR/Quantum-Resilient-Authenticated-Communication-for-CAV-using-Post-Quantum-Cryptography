import os

import pytest

from qrcav import codec
from qrcav.crypto import (
    FIRST_DATA_CTR, RecordError, RecordReceiver, RecordSender, derive_session_keys, get_suite,
    hkdf_expand, hkdf_extract, make_nonce,
)
from qrcav.crypto.records import WINDOW
from qrcav.crypto.suites import HAVE_OPENSSL_PQC, HAVE_PURE_PQC

SUITES = ["DECK", "L1", "L3", "L5", "CLASSIC"]


# ---- codec -------------------------------------------------------------------

def test_codec_roundtrip_and_canonical():
    obj = {"b": b"\x00\x01", "a": [1, -2, 3.5, "x", None, True, False, {"z": 1, "y": b""}]}
    raw = codec.encode(obj)
    assert codec.decode(raw) == obj
    # key order does not matter for the encoding
    assert codec.encode({"a": 1, "b": 2}) == codec.encode({"b": 2, "a": 1})


def test_codec_rejects_malformed():
    raw = codec.encode({"a": 1})
    with pytest.raises(codec.CodecError):
        codec.decode(raw + b"\x00")          # trailing bytes
    with pytest.raises(codec.CodecError):
        codec.decode(raw[:-3])               # truncated


# ---- suites ------------------------------------------------------------------

@pytest.mark.parametrize("name", SUITES)
def test_kem_and_signature_roundtrip(name):
    s = get_suite(name)
    ek, dk = s.kem.keygen()
    assert len(ek) == s.kem.pk_len
    ss, ct = s.kem.encaps(ek)
    assert len(ct) == s.kem.ct_len
    assert s.kem.decaps(dk, ct) == ss
    pk, sk = s.sig.keygen()
    sig = s.sig.sign(sk, b"hello")
    assert s.sig.verify(pk, b"hello", sig)
    assert not s.sig.verify(pk, b"hellO", sig)
    assert not s.sig.verify(pk, b"hello", sig[:-1] + bytes([sig[-1] ^ 1]))


@pytest.mark.skipif(not (HAVE_OPENSSL_PQC and HAVE_PURE_PQC), reason="needs both backends")
@pytest.mark.parametrize("name", ["L3", "DECK", "L5"])
def test_backends_interoperate(name):
    """OpenSSL and the pure-Python libraries implement the same FIPS 203/204 encodings."""
    o, p = get_suite(name, "openssl"), get_suite(name, "pure")
    ek, dk = o.kem.keygen()
    ss, ct = p.kem.encaps(ek)
    assert o.kem.decaps(dk, ct) == ss
    ek2, dk2 = p.kem.keygen()
    ss2, ct2 = o.kem.encaps(ek2)
    assert p.kem.decaps(dk2, ct2) == ss2
    pk, sk = o.sig.keygen()
    assert p.sig.verify(pk, b"m", o.sig.sign(sk, b"m"))
    pk2, sk2 = p.sig.keygen()
    assert o.sig.verify(pk2, b"m", p.sig.sign(sk2, b"m"))


def test_fips_sizes():
    assert get_suite("DECK").kem.pk_len == 1568 and get_suite("DECK").kem.ct_len == 1568
    pk, sk = get_suite("DECK").sig.keygen()
    assert len(pk) == 1952
    assert len(get_suite("DECK").sig.sign(sk, b"x")) == 3309      # FIPS 204, ML-DSA-65


def test_private_key_serialisation():
    s = get_suite("DECK")
    pk, sk = s.sig.keygen()
    sk2 = s.sig.sk_from_bytes(s.sig.sk_to_bytes(sk))
    assert s.sig.verify(pk, b"m", s.sig.sign(sk2, b"m"))


# ---- KDF ---------------------------------------------------------------------

def test_derive_session_keys_shape_and_binding():
    ss = os.urandom(32)
    k1 = derive_session_keys(ss, b"transcript-1")
    k2 = derive_session_keys(ss, b"transcript-2")
    assert len(k1.k_c2s) == 32 and len(k1.v_c2s) == 12 and len(k1.k_s2c) == 32 and len(k1.v_s2c) == 12
    assert len({k1.k_c2s, k1.k_s2c}) == 2 and k1.v_c2s != k1.v_s2c
    assert k1.k_c2s != k2.k_c2s          # any transcript change changes every key


def test_hkdf_expand_lengths():
    prk = hkdf_extract(b"", b"ikm")
    assert len(prk) == 32
    assert hkdf_expand(prk, b"info", 100)[:32] == hkdf_expand(prk, b"info", 32)


# ---- record layer ----------------------------------------------------------------

def _pair():
    k, iv = os.urandom(32), os.urandom(12)
    return RecordSender(k, iv, b"c2s"), RecordReceiver(k, iv, b"c2s")


def test_nonce_construction():
    iv = bytes(range(12))
    assert make_nonce(iv, 0) == iv
    assert make_nonce(iv, 1)[-1] == iv[-1] ^ 1
    assert make_nonce(iv, 1)[:4] == iv[:4]   # top 32 bits untouched (0^32 || be64(ctr))


def test_data_counter_starts_at_one():
    tx, rx = _pair()
    rec = tx.seal(b"x")
    assert int.from_bytes(rec[:8], "big") == FIRST_DATA_CTR == 1


def test_finished_and_data_never_share_a_nonce():
    tx, rx = _pair()
    fin = tx.seal_finished(b"f")
    data = tx.seal(b"d")
    assert fin[:8] != data[:8]
    with pytest.raises(RecordError):
        rx.open(fin)                         # a Finished record is not accepted as data


def test_replay_rejected_reordering_accepted():
    tx, rx = _pair()
    recs = [tx.seal(bytes([i])) for i in range(10)]
    for i in (3, 1, 2, 0, 9, 5):
        assert rx.open(recs[i])[1] == bytes([i])
    for i in (3, 9):
        with pytest.raises(RecordError):
            rx.open(recs[i])


def test_window_rejects_very_old():
    tx, rx = _pair()
    recs = [tx.seal(b"x") for _ in range(WINDOW + 5)]
    rx.open(recs[-1])
    with pytest.raises(RecordError):
        rx.open(recs[0])


def test_tamper_rejected():
    tx, rx = _pair()
    rec = bytearray(tx.seal(b"hello"))
    rec[10] ^= 1
    with pytest.raises(RecordError):
        rx.open(bytes(rec))
    hdr = bytearray(tx.seal(b"hello"))
    hdr[7] ^= 1                              # counter is authenticated too
    with pytest.raises(RecordError):
        rx.open(bytes(hdr))
