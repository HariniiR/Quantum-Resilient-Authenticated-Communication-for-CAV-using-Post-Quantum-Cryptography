"""
Signed consensus message envelopes.

Every consensus message is  {t, from, body, sig}  where
    sig = ML-DSA.sign(sk_from, "qrcav-cons" || encode({t, from, body}))

This is Sign_c / Sign_l / Sign_r from the base paper's Table 3, made with a
signature scheme (ML-DSA) rather than with Kyber, which cannot sign (D1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import codec
from ..crypto.kdf import H
from ..pki import Certificate, Identity, TrustAnchor

REQUEST = "REQUEST"
PRE_PREPARE = "PRE-PREPARE"
PREPARE = "PREPARE"
RESPONSE = "RESPONSE"
SHADOW = "SHADOW-RESPONSE"
COMMIT = "COMMIT"          # AGS-PBFT: leader -> all, carries the certified block
PBFT_COMMIT = "PBFT-COMMIT"  # textbook PBFT commit phase (baseline only)
REPLY = "REPLY"
VIEW_CHANGE = "VIEW-CHANGE"
NEW_VIEW = "NEW-VIEW"
SYNC_REQ = "SYNC-REQ"
SYNC_RESP = "SYNC-RESP"

DOMAIN = b"qrcav-cons"


@dataclass(frozen=True)
class Envelope:
    t: str
    sender: str
    body: dict
    raw: bytes

    @property
    def digest(self) -> bytes:
        return H(b"env", self.raw)


def seal(identity: Identity, t: str, body: dict) -> bytes:
    payload = codec.encode({"t": t, "from": identity.id, "body": body})
    sig = identity.sign(DOMAIN + payload)
    return codec.encode({"t": t, "from": identity.id, "body": body, "sig": sig})


class Directory:
    """id -> certificate for every party that may send consensus messages."""

    def __init__(self, suite, ta_pk: bytes | None = None) -> None:
        self.suite = suite
        self.certs: dict[str, Certificate] = {}
        self.verified = 0
        # Used to validate certificates carried inside requests. Deliberately has no
        # CRL: nodes may hold different CRL versions, and execution must be deterministic.
        # Revocation is enforced at the handshake instead.
        self.anchor = TrustAnchor(ta_pk, suite) if ta_pk is not None else None

    def add(self, cert: Certificate) -> None:
        self.certs[cert.id] = cert

    def role(self, ident: str) -> str | None:
        c = self.certs.get(ident)
        return c.role if c else None

    def open(self, raw: bytes, expect_type: str | None = None) -> Envelope | None:
        """Decode and verify. Returns None for anything invalid."""
        try:
            d = codec.decode_dict(raw, "t", "from", "body", "sig")
            if expect_type is not None and d["t"] != expect_type:
                return None
            cert = self.certs.get(d["from"])
            if cert is None or not isinstance(d["body"], dict):
                return None
            payload = codec.encode({"t": d["t"], "from": d["from"], "body": d["body"]})
            self.verified += 1
            if not self.suite.sig.verify(cert.pk, DOMAIN + payload, d["sig"]):
                return None
            return Envelope(d["t"], d["from"], d["body"], raw)
        except Exception:
            return None


def request_digest(req_raw: bytes) -> bytes:
    return H(b"request", req_raw)
