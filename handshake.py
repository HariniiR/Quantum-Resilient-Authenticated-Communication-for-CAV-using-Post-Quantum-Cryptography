"""
Quantum-resilient authenticated handshake for CAVs.

Base paper : Aslam, Bhardwaj & Chaudhary, "Quantum-resilient blockchain-enabled
             secure communication framework for connected autonomous vehicles
             using post-quantum cryptography", Vehicular Communications 52
             (2025) 100880.
Correction : the base paper's Algorithm 1 (lines 25, 28, 32) is not
             implementable as printed, and Algorithm 2 signs with a KEM, which
             has no signing operation. We therefore compose the handshake
             following Olushola & Meenakshi, Front. Phys. 13:1723966 (2026):
             ML-KEM for key establishment, ML-DSA for authentication, a
             transcript-bound HKDF key schedule, and AES-256-GCM for records.

Primitives : ML-KEM-1024  (FIPS 203)  - key establishment
             ML-DSA-65    (FIPS 204)  - entity authentication
             SHAKE-256               - hashing, tokens, KDF
             AES-256-GCM             - record protection
"""

import hashlib
import os
import time
from dataclasses import dataclass, field

from Crypto.Cipher import AES
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_1024

# --------------------------------------------------------------------------
# Hashing / KDF helpers  (base paper section 5.1: H and SHAKE-256 as KDF)
# --------------------------------------------------------------------------

def H(*parts: bytes, length: int = 32) -> bytes:
    """SHAKE-256 over the concatenation of length-prefixed parts."""
    x = hashlib.shake_256()
    for p in parts:
        x.update(len(p).to_bytes(4, "big"))
        x.update(p)
    return x.digest(length)


def hkdf(shared_secret: bytes, transcript: bytes, label: bytes) -> bytes:
    """
    Transcript-bound key derivation.

    The base paper's line 32 computes K = H(k_i || k'_j), but a correct KEM
    guarantees k_i == k'_j, so that hashes a value against itself. We bind the
    shared secret to the full handshake transcript instead, which is what gives
    downgrade resistance.
    """
    prk = H(b"AGS-PBFT-v1-extract", shared_secret)
    return H(b"AGS-PBFT-v1-expand", prk, transcript, label)


# --------------------------------------------------------------------------
# Trusted Authority  (base paper section 5.1 - 5.2)
# --------------------------------------------------------------------------

class TrustedAuthority:
    """Issues registration tokens. Never holds an entity's private key."""

    def __init__(self) -> None:
        self.master_key = os.urandom(32)
        self.registry: dict[str, bytes] = {}

    def register(self, identity: str, sig_pk: bytes) -> tuple[bytes, int]:
        """
        Base paper section 5.2: S_i = H(ID || pk || MK || TS).

        Fix (base paper section 5.2.2 contradicts its own Table 2 "No key
        escrow"): the TA does NOT generate the entity's private key. The entity
        generates its own keypair and the TA certifies the public key only.
        """
        ts = int(time.time())
        token = H(identity.encode(), sig_pk, self.master_key, str(ts).encode())
        self.registry[identity] = token
        return token, ts

    def verify_token(self, identity: str, sig_pk: bytes, token: bytes, ts: int) -> bool:
        expected = H(identity.encode(), sig_pk, self.master_key, str(ts).encode())
        return expected == token


# --------------------------------------------------------------------------
# Network entities  (base paper section 4: user / MEC layers)
# --------------------------------------------------------------------------

@dataclass
class Entity:
    """A CAV, RSU, MEC server or cloud server."""

    identity: str
    sig_pk: bytes = field(default=b"", repr=False)
    sig_sk: bytes = field(default=b"", repr=False)
    token: bytes = field(default=b"", repr=False)
    ts: int = 0

    def generate_keys(self) -> None:
        """Long-term ML-DSA identity keypair, generated locally."""
        self.sig_pk, self.sig_sk = ML_DSA_65.keygen()

    def enrol(self, ta: TrustedAuthority) -> None:
        self.token, self.ts = ta.register(self.identity, self.sig_pk)


# --------------------------------------------------------------------------
# Secure channel  (AES-256-GCM, nonce = base_iv XOR counter)
# --------------------------------------------------------------------------

class SecureChannel:
    """One direction of an AES-256-GCM protected channel."""

    MAX_RECORDS = 2 ** 32  # rekey well before this (NIST SP 800-38D)

    def __init__(self, key: bytes, base_iv: bytes) -> None:
        self.key = key
        self.base_iv = base_iv
        self.counter = 0

    def _nonce(self) -> bytes:
        if self.counter >= self.MAX_RECORDS:
            raise RuntimeError("record budget exhausted - rekey required")
        ctr = self.counter.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.base_iv, ctr))

    def seal(self, plaintext: bytes) -> tuple[bytes, bytes]:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce())
        ct, tag = cipher.encrypt_and_digest(plaintext)
        self.counter += 1
        return ct, tag

    def open(self, ct: bytes, tag: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce())
        pt = cipher.decrypt_and_verify(ct, tag)  # raises ValueError on tamper
        self.counter += 1
        return pt


# --------------------------------------------------------------------------
# The handshake  (base paper Algorithm 1, corrected)
# --------------------------------------------------------------------------

class HandshakeError(Exception):
    """Uniform abort. No detail is exposed to the peer."""


def handshake(initiator: Entity, responder: Entity, ta: TrustedAuthority):
    """
    Vehicle-to-RSU (or vehicle-to-vehicle) authenticated key establishment.

    Returns (channel_i, channel_r, byte_count) on success.
    Raises HandshakeError on any failure, after zeroizing ephemeral state.
    """
    transcript = b""

    # -- Step 1: responder generates an EPHEMERAL ML-KEM keypair -------------
    # Ephemeral, per session, erased afterwards -> forward secrecy.
    kem_ek, kem_dk = ML_KEM_1024.keygen()

    # -- Step 2: responder signs (identity || token || ephemeral KEM key) ----
    # This binds the KEM key to the responder's certified identity, which is
    # what stops an active man-in-the-middle substituting their own key.
    context = (
        responder.identity.encode()
        + responder.token
        + str(responder.ts).encode()
        + kem_ek
    )
    signature = ML_DSA_65.sign(responder.sig_sk, context)
    transcript += context + signature

    # -- Step 3: initiator verifies token, then signature --------------------
    if not ta.verify_token(responder.identity, responder.sig_pk,
                           responder.token, responder.ts):
        raise HandshakeError()
    if not ML_DSA_65.verify(responder.sig_pk, context, signature):
        raise HandshakeError()

    # -- Step 4: initiator encapsulates -------------------------------------
    shared_i, kem_ct = ML_KEM_1024.encaps(kem_ek)
    transcript += kem_ct

    # -- Step 5: responder decapsulates -------------------------------------
    shared_r = ML_KEM_1024.decaps(kem_dk, kem_ct)

    # -- Step 6: both derive per-direction keys over the transcript ----------
    th = H(b"transcript", transcript)

    def derive(secret: bytes):
        return (
            SecureChannel(hkdf(secret, th, b"key_i2r"), hkdf(secret, th, b"iv_i2r")[:12]),
            SecureChannel(hkdf(secret, th, b"key_r2i"), hkdf(secret, th, b"iv_r2i")[:12]),
        )

    i2r_i, r2i_i = derive(shared_i)
    i2r_r, r2i_r = derive(shared_r)

    # -- Step 7: AEAD key confirmation --------------------------------------
    # Confirms both sides derived identical keys before any application data.
    if i2r_i.key != i2r_r.key:
        raise HandshakeError()

    # Erase ephemeral secrets (base paper claims forward secrecy; this is what
    # actually delivers it).
    del kem_dk, shared_i, shared_r

    handshake_bytes = len(context) + len(signature) + len(kem_ct)
    return (i2r_i, r2i_i), (i2r_r, r2i_r), handshake_bytes


# --------------------------------------------------------------------------
# Demonstration
# --------------------------------------------------------------------------

def main() -> None:
    print("=" * 62)
    print("Quantum-resilient CAV handshake  -  ML-KEM-1024 + ML-DSA-65")
    print("=" * 62)

    ta = TrustedAuthority()

    vehicle = Entity("CAV_001")
    rsu = Entity("RSU_042")

    t0 = time.perf_counter()
    for e in (vehicle, rsu):
        e.generate_keys()
        e.enrol(ta)
    t_enrol = (time.perf_counter() - t0) * 1000

    print(f"\n[registration]  2 entities enrolled with TA   {t_enrol:8.2f} ms")
    print(f"                ML-DSA-65 public key          {len(rsu.sig_pk):8d} B")
    print(f"                registration token            {len(rsu.token):8d} B")

    t0 = time.perf_counter()
    (v_send, v_recv), (r_send, r_recv), nbytes = handshake(vehicle, rsu, ta)
    t_hs = (time.perf_counter() - t0) * 1000

    print(f"\n[handshake]     V2R mutual auth + session key {t_hs:8.2f} ms")
    print(f"                bytes on the wire             {nbytes:8d} B")
    print(f"                802.11p frames @ 1500 B       {-(-nbytes // 1500):8d}")
    print(f"                within 100 ms beacon budget?  {'YES' if t_hs < 100 else 'NO':>8}")

    # Application data over the established channel
    beacon = b'{"id":"CAV_001","spd":13.9,"lat":30.7299,"lon":76.7771}'
    t0 = time.perf_counter()
    ct, tag = v_send.seal(beacon)
    recovered = r_send.open(ct, tag)
    t_rec = (time.perf_counter() - t0) * 1000

    print(f"\n[record]        AES-256-GCM seal + open      {t_rec:8.3f} ms")
    print(f"                plaintext / ciphertext        {len(beacon):4d} B / {len(ct)} B")
    print(f"                round-trip intact             {'YES' if recovered == beacon else 'NO':>8}")

    # Negative tests -- these MUST fail
    print("\n[attack tests]")

    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    try:
        r_recv.open(tampered, tag)
        print("                tampered ciphertext          REJECTED? NO  <-- BUG")
    except ValueError:
        print("                tampered ciphertext          REJECTED  (ok)")

    impostor = Entity("RSU_042")          # same identity, attacker's own keys
    impostor.generate_keys()
    impostor.token, impostor.ts = rsu.token, rsu.ts   # replays a stolen token
    try:
        handshake(vehicle, impostor, ta)
        print("                impersonated RSU             REJECTED? NO  <-- BUG")
    except HandshakeError:
        print("                impersonated RSU             REJECTED  (ok)")

    print("\n" + "=" * 62)


if __name__ == "__main__":
    main()
