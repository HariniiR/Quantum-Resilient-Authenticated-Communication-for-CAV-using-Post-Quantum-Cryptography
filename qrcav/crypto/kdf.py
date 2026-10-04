"""
Hashing and key derivation.

  H    SHAKE-256, 32-byte output by default             (deck slide 12)
  KDF  HKDF (RFC 5869) instantiated with HMAC-SHA3-256 = "HKDF-SHA3-256"

One name is used consistently everywhere: HKDF-SHA3-256. (The Review 1 deck
says "HKDF-SHA-256" in one place and "HKDF-SHA3-256" in two others; this is
the one the code implements.)

DERIVE_SESSION_KEYS is a line-for-line implementation of deck slide 14.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

HASH_LEN = 32


def H(*parts: bytes, length: int = HASH_LEN) -> bytes:
    """
    SHAKE-256 over length-prefixed parts.

    Length prefixing makes the encoding injective: H(b"ab", b"c") differs from
    H(b"a", b"bc"). Plain concatenation would make those collide.
    """
    x = hashlib.shake_256()
    for p in parts:
        x.update(len(p).to_bytes(4, "big"))
        x.update(p)
    return x.digest(length)


def hmac_sha3(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2 with HMAC-SHA3-256. Empty salt means zeros."""
    if not salt:
        salt = bytes(HASH_LEN)
    return hmac_sha3(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3 with HMAC-SHA3-256."""
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF output too long")
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac_sha3(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


@dataclass(frozen=True)
class SessionKeys:
    k_c2s: bytes   # AES-256-GCM key, client -> server
    v_c2s: bytes   # 96-bit base IV, client -> server
    k_s2c: bytes   # AES-256-GCM key, server -> client
    v_s2c: bytes   # 96-bit base IV, server -> client
    t_hash: bytes  # transcript hash these keys are bound to


def derive_session_keys(ss: bytes, transcript: bytes) -> SessionKeys:
    """
    Algorithm DERIVE_SESSION_KEYS(ss, T), deck slide 14.

      1. T_hash <- H(T)
      2. PRK    <- HKDF-Extract(salt = 0x00..0, ikm = ss)
      3. k_c2s  <- HKDF-Expand(PRK, "key_c2s" || T_hash, 32)
         v_c2s  <- HKDF-Expand(PRK, "iv_c2s"  || T_hash, 12)
         k_s2c  <- HKDF-Expand(PRK, "key_s2c" || T_hash, 32)
         v_s2c  <- HKDF-Expand(PRK, "iv_s2c"  || T_hash, 12)
      4. delete ss, PRK
      5. return the four values

    Binding every key to the transcript hash means that if an attacker changes
    any byte of any handshake message, the two sides derive different keys and
    the Finished check fails.
    """
    t_hash = H(b"transcript", transcript)
    prk = hkdf_extract(bytes(HASH_LEN), ss)
    keys = SessionKeys(
        k_c2s=hkdf_expand(prk, b"key_c2s" + t_hash, 32),
        v_c2s=hkdf_expand(prk, b"iv_c2s" + t_hash, 12),
        k_s2c=hkdf_expand(prk, b"key_s2c" + t_hash, 32),
        v_s2c=hkdf_expand(prk, b"iv_s2c" + t_hash, 12),
        t_hash=t_hash,
    )
    # Python cannot zeroise immutable bytes; dropping the references is the
    # best available. A C implementation would explicit_bzero these.
    del prk, ss
    return keys
