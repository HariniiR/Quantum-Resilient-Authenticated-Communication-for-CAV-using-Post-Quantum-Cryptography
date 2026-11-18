"""
Cryptographic suites: one KEM plus one signature scheme.

Post-quantum primitives use native OpenSSL via cryptography.

Suites
------
  DECK     ML-KEM-1024 + ML-DSA-65   the parameter choice on the Review 1 slides
  CLASSIC  ECDH-P256   + ECDSA-P256  what V2X uses today (IEEE 1609.2); the baseline

ECDH is wrapped as a KEM (ephemeral-static Diffie-Hellman, as in RFC 9180's
DHKEM) so the classical baseline runs through exactly the same protocol code
as the post-quantum suites. That makes the comparison like-for-like.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Callable

try:  # native ML-KEM / ML-DSA (cryptography >= 47 with OpenSSL >= 3.5)
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
except ImportError as e:  # pragma: no cover - depends on the installed version
    raise ImportError(
        "this project needs native ML-KEM / ML-DSA: pip install -U 'cryptography>=47'"
    ) from e

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ---------------------------------------------------------------------------
# KEM
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KEM:
    name: str
    pk_len: int
    ct_len: int
    _keygen: Callable[[], tuple[bytes, Any]]
    _encaps: Callable[[bytes], tuple[bytes, bytes]]
    _decaps: Callable[[Any, bytes], bytes]

    def keygen(self) -> tuple[bytes, Any]:
        """Return (encapsulation key bytes, opaque decapsulation key)."""
        return self._keygen()

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        """Return (shared secret, ciphertext)."""
        if len(ek) != self.pk_len:
            raise ValueError("bad encapsulation key length")
        return self._encaps(ek)

    def decaps(self, dk: Any, ct: bytes) -> bytes:
        if len(ct) != self.ct_len:
            raise ValueError("bad ciphertext length")
        return self._decaps(dk, ct)


def _mlkem1024_kem() -> KEM:
    def keygen():
        dk = _mlkem.MLKEM1024PrivateKey.generate()
        return dk.public_key().public_bytes_raw(), dk

    def encaps(ek):
        ss, ct = _mlkem.MLKEM1024PublicKey.from_public_bytes(ek).encapsulate()
        return ss, ct

    def decaps(dk, ct):
        return dk.decapsulate(ct)

    return KEM("ML-KEM-1024", 1568, 1568, keygen, encaps, decaps)


def _ecdh_kem() -> KEM:
    """
    ECDH P-256 as a KEM (ephemeral-static DH, the DHKEM construction).

    encaps(pk_R): generate ephemeral e, ss = KDF(DH(e, pk_R) || e_pub || pk_R),
    ct = e_pub. decaps(sk_R, ct): ss = KDF(DH(sk_R, ct) || ct || pk_R).
    """
    curve = ec.SECP256R1()
    enc = serialization.Encoding.X962
    fmt = serialization.PublicFormat.UncompressedPoint

    def _kdf(z: bytes, epub: bytes, rpub: bytes) -> bytes:
        return hashlib.sha3_256(b"dhkem-p256" + z + epub + rpub).digest()

    def keygen():
        sk = ec.generate_private_key(curve)
        return sk.public_key().public_bytes(enc, fmt), sk

    def encaps(ek):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, ek)
        e = ec.generate_private_key(curve)
        epub = e.public_key().public_bytes(enc, fmt)
        z = e.exchange(ec.ECDH(), peer)
        return _kdf(z, epub, ek), epub

    def decaps(dk, ct):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, ct)
        z = dk.exchange(ec.ECDH(), peer)
        return _kdf(z, ct, dk.public_key().public_bytes(enc, fmt))

    return KEM("ECDH-P256", 65, 65, keygen, encaps, decaps)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    name: str
    pk_len: int
    sig_len: int          # maximum; ECDSA DER signatures vary by a few bytes
    _keygen: Callable[[], tuple[bytes, Any]]
    _sign: Callable[[Any, bytes], bytes]
    _verify: Callable[[bytes, bytes, bytes], bool]
    _sk_to_bytes: Callable[[Any], bytes]
    _sk_from_bytes: Callable[[bytes], Any]

    def keygen(self) -> tuple[bytes, Any]:
        """Return (public key bytes, opaque private key)."""
        return self._keygen()

    def sign(self, sk: Any, msg: bytes) -> bytes:
        return self._sign(sk, msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Never raises on bad input; returns False instead."""
        try:
            return bool(self._verify(pk, msg, sig))
        except Exception:
            return False

    def sk_to_bytes(self, sk: Any) -> bytes:
        return self._sk_to_bytes(sk)

    def sk_from_bytes(self, raw: bytes) -> Any:
        return self._sk_from_bytes(raw)


# FIPS 204 context string. Domain-separates this protocol's signatures from any
# other use of the same key.
SIG_CONTEXT = b"qrcav-v1"


def _mldsa65_sig() -> Signature:
    priv = _mldsa.MLDSA65PrivateKey
    pub = _mldsa.MLDSA65PublicKey

    def keygen():
        sk = priv.generate()
        return sk.public_key().public_bytes_raw(), sk

    def sign(sk, m):
        return sk.sign(m, SIG_CONTEXT)

    def verify(pk, m, s):
        try:
            pub.from_public_bytes(pk).verify(s, m, SIG_CONTEXT)
            return True
        except InvalidSignature:
            return False

    return Signature(
        "ML-DSA-65", 1952, 3309, keygen, sign, verify,
        lambda sk: sk.private_bytes_raw(),          # 32-byte seed
        lambda raw: priv.from_seed_bytes(raw),
    )


def _ecdsa_sig() -> Signature:
    curve = ec.SECP256R1()
    enc = serialization.Encoding.X962
    fmt = serialization.PublicFormat.UncompressedPoint

    def keygen():
        sk = ec.generate_private_key(curve)
        return sk.public_key().public_bytes(enc, fmt), sk

    def sign(sk, m):
        return sk.sign(SIG_CONTEXT + m, ec.ECDSA(hashes.SHA256()))

    def verify(pk, m, s):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curve, pk).verify(
                s, SIG_CONTEXT + m, ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def to_bytes(sk):
        return sk.private_numbers().private_value.to_bytes(32, "big")

    def from_bytes(raw):
        return ec.derive_private_key(int.from_bytes(raw, "big"), curve)

    return Signature("ECDSA-P256", 65, 72, keygen, sign, verify, to_bytes, from_bytes)


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------

SUITE_DEFS = {
    "DECK": ("ML-KEM-1024", "ML-DSA-65"),
    "CLASSIC": ("ECDH-P256", "ECDSA-P256"),
}

DEFAULT_SUITE = os.environ.get("QRCAV_SUITE", "DECK")


@dataclass(frozen=True)
class Suite:
    name: str
    kem: KEM
    sig: Signature

    @property
    def label(self) -> str:
        return f"{self.kem.name} + {self.sig.name}"

    @property
    def is_post_quantum(self) -> bool:
        return self.name != "CLASSIC"


_cache: dict[str, Suite] = {}


def get_suite(name: str | None = None) -> Suite:
    """Return a suite by name ('DECK' or 'CLASSIC')."""
    name = (name or DEFAULT_SUITE).upper()
    if name not in SUITE_DEFS:
        raise ValueError(f"unknown suite {name!r}; choose from {sorted(SUITE_DEFS)}")
    if name not in _cache:
        if name == "DECK":
            _cache[name] = Suite(name, _mlkem1024_kem(), _mldsa65_sig())
        else:
            _cache[name] = Suite(name, _ecdh_kem(), _ecdsa_sig())
    return _cache[name]
