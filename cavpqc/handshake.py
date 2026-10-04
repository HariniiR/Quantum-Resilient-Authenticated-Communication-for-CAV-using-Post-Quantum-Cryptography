"""
Authenticated key establishment -- corrected Algorithm 1.

Paper section 5.3 covers V2R (vehicle to RSU) and V2V (vehicle to vehicle,
relayed through RSUs) authentication and session key establishment.

DEVIATIONS D2 and D3.

Algorithm 1 as printed:

    25:  Encapsulate: (c, k_i) <- (NTT^-1(A^T . r + e), H(k_i || H(c)))
    28:  k'_j <- H(k_i || H(c))
    32:  Both parties compute K <- H(k_i || k'_j)

Line 25 defines k_i in terms of k_i, so it has no value. Line 28 requires the
decapsulating party to use k_i, which it does not possess -- recovering it is
the entire purpose of decapsulation. Line 32 concatenates k_i with k'_j, but a
correct KEM guarantees these are equal, so it hashes a value against itself.

The corrected flow below follows the standard KEM interface plus an ML-DSA
signature over the transcript. The signature is what actually prevents an
active man-in-the-middle: without it, an attacker substitutes their own
encapsulation key and both parties complete the handshake successfully while
the attacker holds the session key.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .crypto import DEFAULT_KEM, H, SecureChannel, channel_pair
from .entities import Entity, TrustedAuthority


class HandshakeError(Exception):
    """
    Uniform abort.

    No reason is exposed to the peer and no distinguishing detail is logged at
    the protocol level, so a probing adversary cannot tell whether a token, a
    signature or a key confirmation failed.
    """


@dataclass
class Session:
    """An established bidirectional channel plus the metrics we measure."""

    peer: str
    send: SecureChannel
    recv: SecureChannel
    transcript_hash: bytes
    handshake_bytes: int
    elapsed_ms: float

    def frames(self, mtu: int = 1500) -> int:
        """802.11p frames needed to carry the handshake flight."""
        return -(-self.handshake_bytes // mtu)


# ---------------------------------------------------------------------------
# V2R / V2I handshake
# ---------------------------------------------------------------------------

def establish(
    initiator: Entity,
    responder: Entity,
    ta: TrustedAuthority,
    now: int | None = None,
) -> tuple[Session, Session]:
    """
    Mutually authenticated session key establishment.

    Returns (initiator_session, responder_session). Both hold the same keys,
    with directions separated.

    Steps, mapping to the paper's intent:
      1. responder generates an EPHEMERAL ML-KEM keypair (forward secrecy)
      2. responder signs identity + token + timestamp + ephemeral key  [D1]
      3. initiator checks the registration token against the TA, then the
         signature, before touching the key material
      4. initiator encapsulates                                        [D2]
      5. responder decapsulates                                        [D2]
      6. both derive per-direction traffic keys over the transcript     [D3]
      7. AEAD key confirmation
    """
    t0 = time.perf_counter()

    if not initiator.is_registered() or not responder.is_registered():
        raise HandshakeError()

    # -- 1. ephemeral KEM keypair, one per session -------------------------
    kem_ek, kem_dk = DEFAULT_KEM.keygen()

    # -- 2. responder authenticates itself and binds the ephemeral key -----
    context = (
        responder.identity.encode()
        + responder.sig_pk
        + responder.token
        + str(responder.ts).encode()
        + kem_ek
    )
    signature = responder.sign(context)

    # -- 3. initiator validates, in this order -----------------------------
    if not ta.verify_registration(
        responder.identity, responder.sig_pk, responder.token, responder.ts, now
    ):
        raise HandshakeError()
    if not Entity.verify(responder.sig_pk, context, signature):
        raise HandshakeError()

    transcript = context + signature

    # -- 4. initiator encapsulates ----------------------------------------
    shared_i, kem_ct = DEFAULT_KEM.encaps(kem_ek)
    transcript += kem_ct

    # -- initiator authenticates itself too (mutual authentication) --------
    init_context = (
        initiator.identity.encode()
        + initiator.sig_pk
        + initiator.token
        + str(initiator.ts).encode()
        + kem_ct
    )
    init_signature = initiator.sign(init_context)
    transcript += init_context + init_signature

    if not ta.verify_registration(
        initiator.identity, initiator.sig_pk, initiator.token, initiator.ts, now
    ):
        raise HandshakeError()
    if not Entity.verify(initiator.sig_pk, init_context, init_signature):
        raise HandshakeError()

    # -- 5. responder decapsulates ----------------------------------------
    shared_r = DEFAULT_KEM.decaps(kem_dk, kem_ct)

    # -- 6. transcript-bound key derivation -------------------------------
    th = H(b"cavpqc-transcript-v1", transcript)
    i_send, i_recv = channel_pair(shared_i, th)
    r_send, r_recv = channel_pair(shared_r, th)

    # -- 7. AEAD key confirmation -----------------------------------------
    # Detects a decapsulation mismatch before any application data flows.
    if i_send.key != r_send.key or i_recv.key != r_recv.key:
        raise HandshakeError()

    # Erase ephemeral secrets. Forward secrecy is only real if this happens.
    del kem_dk, shared_i, shared_r

    nbytes = len(transcript)
    elapsed = (time.perf_counter() - t0) * 1000

    return (
        Session(responder.identity, i_send, i_recv, th, nbytes, elapsed),
        Session(initiator.identity, r_recv, r_send, th, nbytes, elapsed),
    )


# ---------------------------------------------------------------------------
# V2V handshake, relayed through RSUs (paper section 5.3.3)
# ---------------------------------------------------------------------------

def establish_v2v(
    vehicle_a: Entity,
    rsu_a: Entity,
    vehicle_b: Entity,
    rsu_b: Entity,
    ta: TrustedAuthority,
) -> dict:
    """
    Paper section 5.3.3.

    "If vehicles CAVs_i and CAVs_j communicate through their respective RSUs
    rsu_i and rsu_j ... rsu_i encapsulates K_rsu_i,CAVs_i for rsu_j, which on
    decapsulation re-encapsulates it for CAVs_j."

    Note that this design means the RSUs learn the vehicle-to-vehicle key, so
    it provides confidentiality against outsiders but not against the
    infrastructure. The paper does not state this; we record it as a finding.
    """
    total_bytes = 0
    t0 = time.perf_counter()

    sess_a, _ = establish(vehicle_a, rsu_a, ta)      # CAV_a <-> RSU_a
    total_bytes += sess_a.handshake_bytes

    sess_r, _ = establish(rsu_a, rsu_b, ta)          # RSU_a <-> RSU_b
    total_bytes += sess_r.handshake_bytes

    sess_b, _ = establish(rsu_b, vehicle_b, ta)      # RSU_b <-> CAV_b
    total_bytes += sess_b.handshake_bytes

    return {
        "hops": 3,
        "handshake_bytes": total_bytes,
        "elapsed_ms": (time.perf_counter() - t0) * 1000,
        "frames": -(-total_bytes // 1500),
        "note": "RSUs learn the V2V key; not end-to-end confidential",
    }
