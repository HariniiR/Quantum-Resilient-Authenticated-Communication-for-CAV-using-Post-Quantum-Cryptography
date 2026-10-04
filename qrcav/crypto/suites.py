"""
Cryptographic suites: one KEM plus one signature scheme.

Two interchangeable backends implement the same NIST algorithms:

  openssl  -- `cryptography` >= 47 bundling OpenSSL >= 3.5. Native code,
              constant-time, the backend a deployment would use. Default.
  pure     -- `kyber-py` / `dilithium-py`. Pure Python, documented by their
              authors as educational and NOT constant-time. Kept because it is
              readable, it is what Review 1 demonstrated, and it gives a second
              independent implementation to cross-check against.

Both backends are byte-compatible (FIPS 203 / FIPS 204 encodings), which
tests/test_crypto.py checks by encapsulating with one and decapsulating with
the other.

Suites
------
  DECK     ML-KEM-1024 + ML-DSA-65   the parameter choice on the Review 1 slides
  L1       ML-KEM-512  + ML-DSA-44   NIST category 1 / 2
  L3       ML-KEM-768  + ML-DSA-65   NIST category 3
  L5       ML-KEM-1024 + ML-DSA-87   NIST category 5
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

# ---------------------------------------------------------------------------
# backend discovery
# ---------------------------------------------------------------------------

try:  # native ML-KEM / ML-DSA (cryptography >= 47 with OpenSSL >= 3.5)
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem

    HAVE_OPENSSL_PQC = True
except Exception:  # pragma: no cover - depends on installed wheel
    _mldsa = _mlkem = None
    HAVE_OPENSSL_PQC = False

try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

    HAVE_PURE_PQC = True
except Exception:  # pragma: no cover
    HAVE_PURE_PQC = False

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CryptoUnavailable(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# KEM
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KEM:
    name: str
    backend: str
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


_KEM_SIZES = {
    "ML-KEM-512": (800, 768),
    "ML-KEM-768": (1184, 1088),
    "ML-KEM-1024": (1568, 1568),
}


def _openssl_kem(name: str) -> KEM:
    cls_priv = {
        "ML-KEM-768": _mlkem.MLKEM768PrivateKey,
        "ML-KEM-1024": _mlkem.MLKEM1024PrivateKey,
    }[name]
    cls_pub = {
        "ML-KEM-768": _mlkem.MLKEM768PublicKey,
        "ML-KEM-1024": _mlkem.MLKEM1024PublicKey,
    }[name]

    def keygen():
        dk = cls_priv.generate()
        return dk.public_key().public_bytes_raw(), dk

    def encaps(ek):
        ss, ct = cls_pub.from_public_bytes(ek).encapsulate()
        return ss, ct

    def decaps(dk, ct):
        return dk.decapsulate(ct)

    pk, ct = _KEM_SIZES[name]
    return KEM(name, "openssl", pk, ct, keygen, encaps, decaps)


def _pure_kem(name: str) -> KEM:
    impl = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}[name]

    def keygen():
        ek, dk = impl.keygen()
        return ek, dk

    def encaps(ek):
        ss, ct = impl.encaps(ek)
        return ss, ct

    def decaps(dk, ct):
        return impl.decaps(dk, ct)

    pk, ct = _KEM_SIZES[name]
    return KEM(name, "pure", pk, ct, keygen, encaps, decaps)


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

    return KEM("ECDH-P256", "openssl", 65, 65, keygen, encaps, decaps)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    name: str
    backend: str
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


_SIG_SIZES = {
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
}

# FIPS 204 context string. Domain-separates this protocol's signatures from any
# other use of the same key.
SIG_CONTEXT = b"qrcav-v1"


def _openssl_sig(name: str) -> Signature:
    priv = {
        "ML-DSA-44": _mldsa.MLDSA44PrivateKey,
        "ML-DSA-65": _mldsa.MLDSA65PrivateKey,
        "ML-DSA-87": _mldsa.MLDSA87PrivateKey,
    }[name]
    pub = {
        "ML-DSA-44": _mldsa.MLDSA44PublicKey,
        "ML-DSA-65": _mldsa.MLDSA65PublicKey,
        "ML-DSA-87": _mldsa.MLDSA87PublicKey,
    }[name]

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

    pk, sl = _SIG_SIZES[name]
    return Signature(
        name, "openssl", pk, sl, keygen, sign, verify,
        lambda sk: sk.private_bytes_raw(),          # 32-byte seed
        lambda raw: priv.from_seed_bytes(raw),
    )


def _pure_sig(name: str) -> Signature:
    impl = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}[name]

    def keygen():
        pk, sk = impl.keygen()
        return pk, sk

    def sign(sk, m):
        return impl.sign(sk, m, ctx=SIG_CONTEXT)

    def verify(pk, m, s):
        return impl.verify(pk, m, s, ctx=SIG_CONTEXT)

    pk, sl = _SIG_SIZES[name]
    return Signature(name, "pure", pk, sl, keygen, sign, verify, lambda sk: sk, lambda raw: raw)


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

    return Signature("ECDSA-P256", "openssl", 65, 72, keygen, sign, verify, to_bytes, from_bytes)


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------

SUITE_DEFS = {
    "DECK": ("ML-KEM-1024", "ML-DSA-65"),
    "L1": ("ML-KEM-512", "ML-DSA-44"),
    "L3": ("ML-KEM-768", "ML-DSA-65"),
    "L5": ("ML-KEM-1024", "ML-DSA-87"),
    "CLASSIC": ("ECDH-P256", "ECDSA-P256"),
}

DEFAULT_SUITE = os.environ.get("QRCAV_SUITE", "DECK")
DEFAULT_BACKEND = os.environ.get("QRCAV_BACKEND", "auto")


@dataclass(frozen=True)
class Suite:
    name: str
    kem: KEM
    sig: Signature

    @property
    def backend(self) -> str:
        if self.kem.backend == self.sig.backend:
            return self.kem.backend
        return f"{self.kem.backend}+{self.sig.backend}"

    @property
    def label(self) -> str:
        return f"{self.kem.name} + {self.sig.name}"

    @property
    def is_post_quantum(self) -> bool:
        return self.name != "CLASSIC"


def _make_kem(name: str, backend: str) -> KEM:
    if name == "ECDH-P256":
        return _ecdh_kem()
    want_openssl = backend in ("openssl", "auto")
    if want_openssl and HAVE_OPENSSL_PQC and name != "ML-KEM-512":
        return _openssl_kem(name)
    if backend == "openssl" and name != "ML-KEM-512":
        raise CryptoUnavailable("OpenSSL ML-KEM not available; install cryptography>=47")
    if not HAVE_PURE_PQC:
        raise CryptoUnavailable("kyber-py not installed")
    # OpenSSL does not ship ML-KEM-512, so L1 always uses the pure backend for its KEM.
    return _pure_kem(name)


def _make_sig(name: str, backend: str) -> Signature:
    if name == "ECDSA-P256":
        return _ecdsa_sig()
    if backend in ("openssl", "auto") and HAVE_OPENSSL_PQC:
        return _openssl_sig(name)
    if backend == "openssl":
        raise CryptoUnavailable("OpenSSL ML-DSA not available; install cryptography>=47")
    if not HAVE_PURE_PQC:
        raise CryptoUnavailable("dilithium-py not installed")
    return _pure_sig(name)


_cache: dict[tuple[str, str], Suite] = {}


def get_suite(name: str | None = None, backend: str | None = None) -> Suite:
    """Return a suite by name ('DECK', 'L1', 'L3', 'L5', 'CLASSIC')."""
    name = (name or DEFAULT_SUITE).upper()
    backend = (backend or DEFAULT_BACKEND).lower()
    if name not in SUITE_DEFS:
        raise ValueError(f"unknown suite {name!r}; choose from {sorted(SUITE_DEFS)}")
    if backend not in ("auto", "openssl", "pure"):
        raise ValueError("backend must be auto, openssl or pure")
    key = (name, backend)
    if key not in _cache:
        kem_name, sig_name = SUITE_DEFS[name]
        _cache[key] = Suite(name, _make_kem(kem_name, backend), _make_sig(sig_name, backend))
    return _cache[key]
