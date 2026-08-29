"""Hashing helpers, HKDF functions, and registration tokens."""

import hashlib
import hmac

def H(*parts: bytes, length: int = 32) -> bytes:
    """SHAKE-256 with 4-byte length prefixing to avoid collisions."""
    x = hashlib.shake_256()
    for p in parts:
        x.update(len(p).to_bytes(4, "big"))
        x.update(p)
    return x.digest(length)

def extract(salt: bytes, secret: bytes) -> bytes:
    """HKDF-Extract using SHAKE-256 via HMAC."""
    return hmac.new(salt, secret, hashlib.sha3_256).digest()

def expand(prk: bytes, label: bytes, transcript: bytes, length: int = 32) -> bytes:
    """HKDF-Expand bound to the transcript."""
    return H(b"cavpqc/v1", prk, label, transcript, length=length)

def derive_traffic_secret(
    shared_secret: bytes, transcript_hash: bytes, label: bytes, length: int = 32
) -> bytes:
    """Transcript-bound traffic key derivation (Deviation D3)."""
    prk = extract(b"cavpqc-extract-v1", shared_secret)
    return expand(prk, label, transcript_hash, length)

def registration_token(identity: str, public_key: bytes, master_key: bytes, ts: int) -> bytes:
    """Registration token S_i = H(ID_i || pk_i || MK || TS_i) from Section 5.2."""
    return H(identity.encode(), public_key, master_key, str(ts).encode())