"""Certificate caching: size savings, fallback, and that it never weakens a check."""

import pytest

from qrcav import codec
from qrcav.certcache import CertCache, cert_ref
from qrcav.crypto import get_suite
from qrcav.handshake import ClientHandshake, HandshakeError, ServerHandshake, handshake_in_memory
from qrcav.pki import TrustedAuthority, enrol_all


@pytest.fixture()
def net():
    ta = TrustedAuthority(get_suite("DECK"))
    ids = enrol_all(ta, [("CAV_01", "CAV"), ("CAV_02", "CAV"), ("RSU_01", "RSU"), ("RSU_02", "RSU")])
    return ta, ids


def _warm(ids, rsu="RSU_01"):
    """One full handshake so both sides hold each other's certificate."""
    cc, sc = CertCache(), CertCache()
    handshake_in_memory(ids["CAV_01"], ids[rsu], client_cache=cc, server_cache=sc)
    return cc, sc


def test_first_handshake_is_unchanged(net):
    _, ids = net
    plain, _ = handshake_in_memory(ids["CAV_01"], ids["RSU_01"])
    first, _ = handshake_in_memory(ids["CAV_01"], ids["RSU_01"], client_cache=CertCache(),
                                   server_cache=CertCache())
    assert abs(first.handshake_bytes - plain.handshake_bytes) <= 8      # only nonce/timestamp noise
    assert first.cert_cache == {"client_ref": False, "server_ref": False, "retry": False}


def test_cached_handshake_halves_the_bytes(net):
    _, ids = net
    cc, sc = _warm(ids)
    c, s = handshake_in_memory(ids["CAV_01"], ids["RSU_01"], client_cache=cc, server_cache=sc)
    assert c.cert_cache == {"client_ref": True, "server_ref": True, "retry": False}
    assert s.cert_cache["client_ref"] and s.cert_cache["server_ref"]
    assert c.handshake_bytes < 0.55 * 20_773
    assert c.flight_sizes["client_hello"] < 200
    assert s.open(c.seal({"ok": 1})) == {"ok": 1}


def test_unknown_reference_falls_back_with_hello_retry(net):
    _, ids = net
    cc, _ = _warm(ids)                                  # client now sends references
    c, s = handshake_in_memory(ids["CAV_01"], ids["RSU_02"], client_cache=cc, server_cache=CertCache())
    assert c.cert_cache["retry"] and s.cert_cache["retry"]
    assert {"client_hello_ref", "hello_retry"} <= set(c.flight_sizes)
    assert c.peer_id == "RSU_02"


def test_cached_certificate_is_still_checked_against_the_crl(net):
    ta, ids = net
    cc, sc = _warm(ids)
    ids["RSU_01"].anchor.update_crl(ta.revoke("CAV_01"))
    with pytest.raises(HandshakeError):
        handshake_in_memory(ids["CAV_01"], ids["RSU_01"], client_cache=cc, server_cache=sc)


def test_reference_to_someone_elses_certificate_is_rejected(net):
    """An attacker holding only CAV_02's public certificate cannot use its reference."""
    _, ids = net
    sc = CertCache()
    sc.put(ids["CAV_02"].cert.encode(), "CAV_02")       # the RSU has seen CAV_02 before
    c = ClientHandshake(ids["CAV_01"], expected_id="RSU_01")
    ch = codec.decode(c.client_hello())
    ch.pop("cert")
    ch["cref"] = cert_ref(ids["CAV_02"].cert.encode())  # claim to be CAV_02
    forged = codec.encode(ch)
    s = ServerHandshake(ids["RSU_01"], cache=sc)
    sh = s.on_client_hello(forged)
    c._ch = forged                                       # client signs the forged transcript
    ck = c.on_server_hello(sh)                           # ...but with CAV_01's key
    with pytest.raises(HandshakeError):
        s.on_client_key(ck)


def test_forged_hello_retry_only_costs_a_round_trip(net):
    _, ids = net
    cc, sc = _warm(ids)
    c = ClientHandshake(ids["CAV_01"], expected_id="RSU_01", cache=cc)
    ch = codec.decode(c.client_hello())
    # wrong nonce: rejected outright
    with pytest.raises(HandshakeError):
        c.on_server_hello(codec.encode({"t": "HRR", "nonce": b"\x00" * 32}))
    # right nonce (an on-path attacker can copy it): the client sends the full
    # certificate and the handshake still completes correctly
    c = ClientHandshake(ids["CAV_01"], expected_id="RSU_01", cache=cc)
    ch = codec.decode(c.client_hello())
    full = c.on_server_hello(codec.encode({"t": "HRR", "nonce": ch["nonce"]}))
    assert "cert" in codec.decode(full)
    s = ServerHandshake(ids["RSU_01"], cache=sc)
    out = c.on_server_hello(s.on_client_hello(full))
    fs, s_sess = s.on_client_key(out)
    c_sess = c.on_server_finished(fs)
    assert c_sess.t_hash == s_sess.t_hash


def test_only_one_hello_retry(net):
    _, ids = net
    cc, _ = _warm(ids)
    c = ClientHandshake(ids["CAV_01"], expected_id="RSU_01", cache=cc)
    ch = codec.decode(c.client_hello())
    c.on_server_hello(codec.encode({"t": "HRR", "nonce": ch["nonce"]}))
    nonce2 = codec.decode(c._ch)["nonce"]
    with pytest.raises(HandshakeError):
        c.on_server_hello(codec.encode({"t": "HRR", "nonce": nonce2}))


def test_server_cert_reference_bound_by_signature(net):
    """Swapping the server's reference for another RSU's makes sig_S fail."""
    _, ids = net
    cc, sc = _warm(ids)
    cc.put(ids["RSU_02"].cert.encode(), "RSU_02")
    c = ClientHandshake(ids["CAV_01"], expected_id="RSU_01", cache=cc)
    s = ServerHandshake(ids["RSU_01"], cache=sc)
    sh = codec.decode(s.on_client_hello(c.client_hello()))
    assert "cref" in sh
    sh["cref"] = cert_ref(ids["RSU_02"].cert.encode())
    with pytest.raises(HandshakeError):
        c.on_server_hello(codec.encode(sh))


def test_lru_is_bounded():
    cache = CertCache(max_entries=3)
    refs = [cache.put(bytes([i]) * 10, f"E{i}") for i in range(5)]
    assert len(cache) == 3
    assert cache.get(refs[0]) is None and cache.get(refs[4]) is not None
    assert cache.ref_for("E0") == b"" and cache.ref_for("E4") == refs[4]
