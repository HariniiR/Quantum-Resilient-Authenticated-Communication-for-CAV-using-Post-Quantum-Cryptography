"""
Cryptographic layer.

Paper section 5.1 (Preparation phase) specifies:
  - polynomial ring R_q = Z_q[X]/(X^n + 1)
  - private key components sampled from a centered binomial distribution
  - a hash function H : {0,1}* -> {0,1}^l
  - SHAKE-256 as the key derivation function
  - public parameters {n, q, eta, H} published by the Trusted Authority

Table 5 gives n=256, k=4, q=3329, eta1=eta2=2, sk 3168 B, pk 1568 B, c 1568 B.
Those are the ML-KEM-1024 parameters, so ML_KEM_1024 is used throughout.

DEVIATION D1: the paper signs with "KYBER-PQC". ML-KEM has no signing
operation, so ML-DSA-65 (FIPS 204) is introduced here.

DEVIATION D3: the paper's session key K = H(k_i || k'_j) hashes a value
against itself. Traffic keys are derived with a transcript-bound extract-then-
expand schedule instead, which additionally provides downgrade resistance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from Crypto.Cipher import AES
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# ---------------------------------------------------------------------------
# Published system parameters (paper section 5.1, Table 5)
# ---------------------------------------------------------------------------

SYSTEM_PARAMS = {"n": 256, "k": 4, "q": 3329, "eta1": 2, "eta2": 2}

# Named suites so the evaluation can sweep security levels (objective 7).
SUITES = {
    "L1": ("ML-KEM-512", ML_KEM_512, "ML-DSA-44", ML_DSA_44),
    "L3": ("ML-KEM-768", ML_KEM_768, "ML-DSA-65", ML_DSA_65),
    "L5": ("ML-KEM-1024", ML_KEM_1024, "ML-DSA-87", ML_DSA_87),
}

# The paper's own configuration: Table 5 is ML-KEM-1024.
DEFAULT_KEM_NAME, DEFAULT_KEM = "ML-KEM-1024", ML_KEM_1024
DEFAULT_SIG_NAME, DEFAULT_SIG = "ML-DSA-65", ML_DSA_65


# ---------------------------------------------------------------------------
# Hashing (paper section 5.1: H, and SHAKE-256 as KDF)
# ---------------------------------------------------------------------------

def H(*parts: bytes, length: int = 32) -> bytes:
    """
    SHAKE-256 over length-prefixed parts.

    Length prefixing prevents ambiguity: without it, H(b"ab", b"c") and
    H(b"a", b"bc") would collide, which is exploitable when hashing
    attacker-influenced fields such as identities.
    """
    x = hashlib.shake_256()
    for p in parts:
        x.update(len(p).to_bytes(4, "big"))
        x.update(p)
    return x.digest(length)


def extract(salt: bytes, secret: bytes) -> bytes:
    """HKDF-Extract, instantiated with SHAKE-256 via HMAC."""
    return hmac.new(salt, secret, hashlib.sha3_256).digest()


def expand(prk: bytes, label: bytes, transcript: bytes, length: int = 32) -> bytes:
    """HKDF-Expand with domain-separated labels bound to the transcript."""
    return H(b"cavpqc/v1", prk, label, transcript, length=length)


def derive_traffic_secret(
    shared_secret: bytes, transcript_hash: bytes, label: bytes, length: int = 32
) -> bytes:
    """
    DEVIATION D3.

    Paper Algorithm 1 line 32: K <- H(k_i || k'_j). A correct KEM guarantees
    k_i == k'_j, so that concatenates a value with itself and adds nothing.

    Here the shared secret is bound to a hash of the entire handshake
    transcript, so keys are unique to the exact negotiated configuration and a
    downgraded or substituted transcript yields different keys.
    """
    prk = extract(b"cavpqc-extract-v1", shared_secret)
    return expand(prk, label, transcript_hash, length)


# ---------------------------------------------------------------------------
# Registration token (paper section 5.2)
# ---------------------------------------------------------------------------

def registration_token(identity: str, public_key: bytes, master_key: bytes, ts: int) -> bytes:
    """S_i = H(ID_i || pk_i || MK || TS_i)   -- paper section 5.2."""
    return H(identity.encode(), public_key, master_key, str(ts).encode())


# ---------------------------------------------------------------------------
# Record protection: AES-256-GCM, nonce = base_iv XOR counter
# ---------------------------------------------------------------------------

class NonceExhausted(RuntimeError):
    """Record budget for this key is spent; a rekey is mandatory."""


@dataclass
class SecureChannel:
    """
    One direction of an AES-256-GCM protected channel.

    GCM fails catastrophically if a (key, nonce) pair is ever reused, so the
    counter is monotonic, never wraps, and exhaustion is a hard error rather
    than a wrap-around.
    """

    key: bytes
    base_iv: bytes
    counter: int = 0
    MAX_RECORDS: int = 2 ** 32  # NIST SP 800-38D guidance

    def _nonce(self) -> bytes:
        if self.counter >= self.MAX_RECORDS:
            raise NonceExhausted("rekey required")
        ctr = self.counter.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.base_iv, ctr))

    def seal(self, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce())
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        self.counter += 1
        return ct, tag

    def open(self, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce())
        if aad:
            cipher.update(aad)
        pt = cipher.decrypt_and_verify(ct, tag)  # ValueError on tamper
        self.counter += 1
        return pt


def channel_pair(shared_secret: bytes, transcript_hash: bytes) -> tuple[SecureChannel, SecureChannel]:
    """Derive independent initiator->responder and responder->initiator channels."""
    return (
        SecureChannel(
            derive_traffic_secret(shared_secret, transcript_hash, b"key_i2r"),
            derive_traffic_secret(shared_secret, transcript_hash, b"iv_i2r", 12),
        ),
        SecureChannel(
            derive_traffic_secret(shared_secret, transcript_hash, b"key_r2i"),
            derive_traffic_secret(shared_secret, transcript_hash, b"iv_r2i", 12),
        ),
    )


# ---------------------------------------------------------------------------
# Artifact sizes, for the size/bandwidth analysis
# ---------------------------------------------------------------------------

def artifact_sizes(suite: str = "L3") -> dict[str, int]:
    kem_name, kem, sig_name, sig = SUITES[suite]
    ek, dk = kem.keygen()
    _, ct = kem.encaps(ek)
    pk, sk = sig.keygen()
    signature = sig.sign(sk, b"probe")
    return {
        "kem": kem_name,
        "sig": sig_name,
        "kem_pk": len(ek),
        "kem_sk": len(dk),
        "kem_ct": len(ct),
        "sig_pk": len(pk),
        "sig_sk": len(sk),
        "sig_len": len(signature),
    }
