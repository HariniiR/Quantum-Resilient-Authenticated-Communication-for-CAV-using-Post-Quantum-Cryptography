import time

import pytest

from qrcav.crypto import get_suite
from qrcav.eval.attacks import run_attacks
from qrcav.handshake import ClientHandshake, HandshakeError, ServerHandshake, handshake_in_memory
from qrcav.pki import Identity, RegistrationError, TrustedAuthority, enrol_all


@pytest.fixture(scope="module")
def net():
    ta = TrustedAuthority(get_suite("DECK"))
    return ta, enrol_all(ta, [("CAV_01", "CAV"), ("CAV_02", "CAV"), ("RSU_01", "RSU")])


# ---- registration --------------------------------------------------------------

def test_ta_never_sees_private_key(net):
    ta, ids = net
    req = ids["CAV_01"].registration_request()
    sk_bytes = ids["CAV_01"].suite.sig.sk_to_bytes(ids["CAV_01"].sk)
    assert sk_bytes not in req


def test_registration_requires_proof_of_possession(net):
    ta, ids = net
    m = Identity.generate("CAV_77", "CAV", ta.suite)
    req = m.registration_request()
    victim_pk = ids["CAV_01"].pk
    import qrcav.codec as codec
    d = codec.decode(req)
    d["pk"] = victim_pk                      # try to certify someone else's key
    with pytest.raises(RegistrationError):
        ta.register(codec.encode(d))


def test_roster_and_duplicate_key():
    ta = TrustedAuthority(get_suite("DECK"), roster={"CAV_01": "CAV"})
    ok = Identity.generate("CAV_01", "CAV", ta.suite)
    ta.enrol(ok)
    with pytest.raises(RegistrationError):
        ta.enrol(Identity.generate("CAV_02", "CAV", ta.suite))      # not on roster
    with pytest.raises(RegistrationError):
        ta.enrol(Identity.generate("CAV_01", "CAV", ta.suite))      # same id, different key


def test_identity_persistence(tmp_path, net):
    ta, ids = net
    p = tmp_path / "k"
    ids["CAV_01"].save(p)
    back = Identity.load(p)
    assert back.cert == ids["CAV_01"].cert
    c, s = handshake_in_memory(back, ids["RSU_01"])
    assert c.peer_id == "RSU_01"


# ---- handshake -----------------------------------------------------------------

@pytest.mark.parametrize("name", ["DECK", "L1", "L3", "L5", "CLASSIC"])
def test_handshake_all_suites(name):
    ta = TrustedAuthority(get_suite(name))
    ids = enrol_all(ta, [("CAV_01", "CAV"), ("RSU_01", "RSU")])
    c, s = handshake_in_memory(ids["CAV_01"], ids["RSU_01"], allowed_roles=("CAV",), expected_role="RSU")
    assert c.t_hash == s.t_hash
    assert c.peer_id == "RSU_01" and s.peer_id == "CAV_01"
    assert s.open(c.seal({"hello": 1})) == {"hello": 1}
    assert c.open(s.seal({"back": 2})) == {"back": 2}
    assert c.sender.key != s.sender.key       # per-direction keys


def test_four_flights_and_sizes(net):
    _, ids = net
    c, _ = handshake_in_memory(ids["CAV_01"], ids["RSU_01"])
    assert set(c.flight_sizes) == {"client_hello", "server_hello", "client_key", "server_finished"}
    assert c.handshake_bytes == sum(c.flight_sizes.values())


def test_server_rejects_disallowed_role(net):
    _, ids = net
    with pytest.raises(HandshakeError):
        handshake_in_memory(ids["CAV_01"], ids["CAV_02"], allowed_roles=("RSU",))


def test_out_of_order_flights_rejected(net):
    _, ids = net
    c = ClientHandshake(ids["CAV_01"])
    with pytest.raises(HandshakeError):
        c.on_server_finished(b"\x00")
    s = ServerHandshake(ids["RSU_01"])
    with pytest.raises(HandshakeError):
        s.on_client_key(b"\x00")


def test_fresh_keys_every_session(net):
    _, ids = net
    a, _ = handshake_in_memory(ids["CAV_01"], ids["RSU_01"])
    b, _ = handshake_in_memory(ids["CAV_01"], ids["RSU_01"])
    assert a.sender.key != b.sender.key


def test_all_attacks_rejected():
    rows = run_attacks("DECK")
    failed = [r["attack"] for r in rows if not r["rejected"]]
    assert not failed, failed
    assert len(rows) >= 19
