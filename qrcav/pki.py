"""
Trusted Authority, certificates, revocation (deck slides 12-13).

Preparation phase (slide 12)
    (TA_sig_pk, TA_sig_sk) <- ML-DSA.keygen()
    publish({n, q, eta1, eta2, H, KDF, TA_sig_pk})

Registration phase (slide 13)
    entity:  (pk_DSA, sk_DSA) <- ML-DSA.keygen()        entity's own key; TA never sees sk
    entity -> TA:  (ID, role, pk_DSA, proof-of-possession signature)
    TA:      Cert <- ML-DSA.sign(sk_TA, cert_payload)
    TA -> entity:  Cert
    entity:  assert ML-DSA.verify(pk_TA, cert_payload, Cert)
    TA:      store(ID, pk_DSA, Cert) in the registry DB

Differences from the slide, each deliberate:

  * cert_payload is (ID, role, pk_DSA, serial, validity, algorithm), not just
    ID || pk_DSA. Binding the role stops a registered vehicle presenting its
    certificate as an RSU. Validity lets certificates expire.
  * The request carries a proof-of-possession signature over the request, so
    an attacker cannot get the TA to certify somebody else's public key under
    the attacker's identity.
  * The slide's master key MK is not needed once registration uses
    certificates, so the TA does not create one.
  * Revocation is a signed CRL. Any node can verify it offline with pk_TA.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import codec
from .crypto.suites import Suite, get_suite

ROLES = ("CAV", "RSU", "MEC", "NODE", "CLOUD")
DEFAULT_VALIDITY_S = 365 * 24 * 3600

# ML-KEM public parameters published by the TA (FIPS 203, Table 2). These are
# fixed by the standard; publishing them is informational.
MLKEM_PARAMS = {
    "ML-KEM-512": {"n": 256, "q": 3329, "k": 2, "eta1": 3, "eta2": 2},
    "ML-KEM-768": {"n": 256, "q": 3329, "k": 3, "eta1": 2, "eta2": 2},
    "ML-KEM-1024": {"n": 256, "q": 3329, "k": 4, "eta1": 2, "eta2": 2},
}


class RegistrationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Certificate:
    id: str
    role: str
    pk: bytes
    alg: str
    serial: int
    not_before: int
    not_after: int
    sig: bytes = b""

    def payload(self) -> bytes:
        """The canonical bytes the TA signs."""
        return codec.encode({
            "type": "qrcav-cert-v1",
            "id": self.id,
            "role": self.role,
            "pk": self.pk,
            "alg": self.alg,
            "serial": self.serial,
            "nb": self.not_before,
            "na": self.not_after,
        })

    def to_dict(self) -> dict:
        return {
            "id": self.id, "role": self.role, "pk": self.pk, "alg": self.alg,
            "serial": self.serial, "nb": self.not_before, "na": self.not_after,
            "sig": self.sig,
        }

    def encode(self) -> bytes:
        return codec.encode(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        try:
            return cls(
                str(d["id"]), str(d["role"]), bytes(d["pk"]), str(d["alg"]),
                int(d["serial"]), int(d["nb"]), int(d["na"]), bytes(d["sig"]),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("malformed certificate") from e

    @classmethod
    def decode(cls, raw: bytes) -> "Certificate":
        return cls.from_dict(codec.decode_dict(raw))


@dataclass(frozen=True)
class CRL:
    version: int
    issued_at: int
    revoked_serials: tuple[int, ...]
    sig: bytes = b""

    def payload(self) -> bytes:
        return codec.encode({
            "type": "qrcav-crl-v1",
            "version": self.version,
            "issued_at": self.issued_at,
            "revoked": list(self.revoked_serials),
        })

    def encode(self) -> bytes:
        return codec.encode({
            "version": self.version, "issued_at": self.issued_at,
            "revoked": list(self.revoked_serials), "sig": self.sig,
        })

    @classmethod
    def decode(cls, raw: bytes) -> "CRL":
        d = codec.decode_dict(raw, "version", "issued_at", "revoked", "sig")
        return cls(int(d["version"]), int(d["issued_at"]), tuple(int(x) for x in d["revoked"]), bytes(d["sig"]))

    def is_revoked(self, serial: int) -> bool:
        return serial in self.revoked_serials


class TrustAnchor:
    """
    What every entity holds after the preparation phase: pk_TA, the suite, and
    the latest CRL it has accepted. Verifies certificates offline.
    """

    def __init__(self, ta_pk: bytes, suite: Suite) -> None:
        self.ta_pk = ta_pk
        self.suite = suite
        self.crl = CRL(0, 0, ())

    def update_crl(self, crl: CRL) -> bool:
        """Accept a newer CRL only if the TA signed it."""
        if crl.version < self.crl.version:
            return False
        if not self.suite.sig.verify(self.ta_pk, crl.payload(), crl.sig):
            return False
        self.crl = crl
        return True

    def verify_cert(
        self,
        cert: Certificate,
        now: int | None = None,
        expected_role: str | tuple[str, ...] | None = None,
        expected_id: str | None = None,
    ) -> bool:
        """
        ML_DSA.verify(pk_TA, cert_payload, Cert) plus validity, revocation,
        algorithm and role checks. Returns False on any failure, never raises.
        """
        try:
            now = int(time.time()) if now is None else now
            if cert.alg != self.suite.sig.name:
                return False
            if len(cert.pk) != self.suite.sig.pk_len:
                return False
            if not cert.not_before <= now <= cert.not_after:
                return False
            if expected_role is not None:
                roles = (expected_role,) if isinstance(expected_role, str) else expected_role
                if cert.role not in roles:
                    return False
            if expected_id is not None and cert.id != expected_id:
                return False
            if self.crl.is_revoked(cert.serial):
                return False
            return self.suite.sig.verify(self.ta_pk, cert.payload(), cert.sig)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Entity identity
# ---------------------------------------------------------------------------

@dataclass
class Identity:
    """An entity's own credentials. The private key never leaves this object."""

    id: str
    role: str
    suite: Suite
    sk: Any
    pk: bytes
    cert: Certificate | None = None
    anchor: TrustAnchor | None = None

    @classmethod
    def generate(cls, ident: str, role: str, suite: Suite | None = None) -> "Identity":
        """Registration step 3: the entity generates its own ML-DSA keypair."""
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        suite = suite or get_suite()
        pk, sk = suite.sig.keygen()
        return cls(ident, role, suite, sk, pk)

    def sign(self, msg: bytes) -> bytes:
        return self.suite.sig.sign(self.sk, msg)

    def registration_request(self) -> bytes:
        """Step 4: send(ID, pk_DSA), with proof of possession of sk_DSA."""
        body = {"id": self.id, "role": self.role, "pk": self.pk, "alg": self.suite.sig.name}
        pop = self.sign(b"qrcav-pop" + codec.encode(body))
        return codec.encode({**body, "pop": pop})

    def accept_certificate(self, cert: Certificate, anchor: TrustAnchor) -> None:
        """Step 7: assert ML_DSA.verify(pk_TA, ID || pk_DSA, Cert), abort if invalid."""
        if cert.id != self.id or cert.pk != self.pk or cert.role != self.role:
            raise RegistrationError("certificate does not match this identity")
        if not anchor.verify_cert(cert):
            raise RegistrationError("certificate signature invalid")
        self.cert = cert
        self.anchor = anchor

    @property
    def registered(self) -> bool:
        return self.cert is not None and self.anchor is not None

    # -- persistence (a keystore file per entity) --------------------------

    def save(self, path: Path) -> None:
        d = {
            "id": self.id, "role": self.role, "suite": self.suite.name,
            "backend": self.suite.backend, "pk": self.pk,
            "sk": self.suite.sig.sk_to_bytes(self.sk),
            "cert": self.cert.encode() if self.cert else None,
            "ta_pk": self.anchor.ta_pk if self.anchor else None,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(codec.encode(d))

    @classmethod
    def load(cls, path: Path) -> "Identity":
        d = codec.decode_dict(path.read_bytes())
        backend = d["backend"] if d["backend"] in ("openssl", "pure") else "auto"
        suite = get_suite(d["suite"], backend)
        ident = cls(d["id"], d["role"], suite, suite.sig.sk_from_bytes(d["sk"]), d["pk"])
        if d["cert"] and d["ta_pk"]:
            ident.cert = Certificate.decode(d["cert"])
            ident.anchor = TrustAnchor(d["ta_pk"], suite)
        return ident


# ---------------------------------------------------------------------------
# Trusted Authority
# ---------------------------------------------------------------------------

class TrustedAuthority:
    """
    The TA. Holds sk_TA, issues certificates, maintains the registry DB and
    the CRL. It never generates or sees an entity's private key.
    """

    def __init__(
        self,
        suite: Suite | None = None,
        db_path: str | Path = ":memory:",
        roster: dict[str, str] | None = None,
        validity_s: int = DEFAULT_VALIDITY_S,
    ) -> None:
        self.suite = suite or get_suite()
        # Preparation phase: (TA_sig_pk, TA_sig_sk) <- ML_DSA.keygen()
        self.pk, self._sk = self.suite.sig.keygen()
        self.validity_s = validity_s
        # Identities vetted out-of-band (vehicle manufacturer records, RSU
        # deployment list). None = open enrolment, used in simulations.
        self.roster = roster
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS registry ("
            " id TEXT PRIMARY KEY, role TEXT, pk BLOB, cert BLOB, serial INTEGER,"
            " registered_at INTEGER, revoked INTEGER DEFAULT 0)"
        )
        self._db.commit()
        self._serial = 1 + (self._db.execute("SELECT MAX(serial) FROM registry").fetchone()[0] or 0)
        self._crl_version = 0
        self._crl = self._sign_crl()

    # -- preparation phase ------------------------------------------------

    def public_parameters(self) -> dict:
        """publish({n, q, eta1, eta2, H, KDF, TA_sig_pk})"""
        return {
            "suite": self.suite.name,
            "kem": self.suite.kem.name,
            "sig": self.suite.sig.name,
            "kem_params": MLKEM_PARAMS.get(self.suite.kem.name, {}),
            "H": "SHAKE-256",
            "KDF": "HKDF-SHA3-256",
            "AEAD": "AES-256-GCM",
            "ta_pk": self.pk,
        }

    def anchor(self) -> TrustAnchor:
        a = TrustAnchor(self.pk, self.suite)
        a.update_crl(self._crl)
        return a

    # -- registration phase ---------------------------------------------

    def register(self, request: bytes, now: int | None = None) -> Certificate:
        """Steps 5 and 8: verify the request, sign the certificate, store it."""
        try:
            d = codec.decode_dict(request, "id", "role", "pk", "alg", "pop")
        except Exception as e:
            raise RegistrationError("malformed request") from e
        ident, role, pk = str(d["id"]), str(d["role"]), bytes(d["pk"])
        if role not in ROLES:
            raise RegistrationError("unknown role")
        if d["alg"] != self.suite.sig.name or len(pk) != self.suite.sig.pk_len:
            raise RegistrationError("wrong algorithm")
        if self.roster is not None and self.roster.get(ident) != role:
            raise RegistrationError("identity not on the TA roster")
        body = {"id": ident, "role": role, "pk": pk, "alg": d["alg"]}
        if not self.suite.sig.verify(pk, b"qrcav-pop" + codec.encode(body), d["pop"]):
            raise RegistrationError("proof of possession failed")

        now = int(time.time()) if now is None else now
        with self._lock:
            row = self._db.execute(
                "SELECT pk, cert, revoked FROM registry WHERE id = ?", (ident,)
            ).fetchone()
            if row is not None:
                if row[2]:
                    raise RegistrationError("identity revoked")
                if bytes(row[0]) != pk:
                    raise RegistrationError("identity already registered with another key")
                return Certificate.decode(bytes(row[1]))
            cert = Certificate(ident, role, pk, self.suite.sig.name, self._serial,
                               now - 60, now + self.validity_s)
            cert = Certificate(**{**cert.__dict__, "sig": self.suite.sig.sign(self._sk, cert.payload())})
            self._db.execute(
                "INSERT INTO registry (id, role, pk, cert, serial, registered_at) VALUES (?,?,?,?,?,?)",
                (ident, role, pk, cert.encode(), cert.serial, now),
            )
            self._db.commit()
            self._serial += 1
            return cert

    def enrol(self, identity: Identity, now: int | None = None) -> None:
        """In-process convenience: request, certificate, acceptance."""
        cert = self.register(identity.registration_request(), now)
        identity.accept_certificate(cert, self.anchor())

    # -- revocation ----------------------------------------------------

    def _sign_crl(self) -> CRL:
        serials = tuple(sorted(
            r[0] for r in self._db.execute("SELECT serial FROM registry WHERE revoked = 1")
        ))
        crl = CRL(self._crl_version, int(time.time()), serials)
        return CRL(crl.version, crl.issued_at, crl.revoked_serials,
                   self.suite.sig.sign(self._sk, crl.payload()))

    def revoke(self, ident: str) -> CRL:
        with self._lock:
            cur = self._db.execute("UPDATE registry SET revoked = 1 WHERE id = ?", (ident,))
            self._db.commit()
            if cur.rowcount == 0:
                raise RegistrationError("unknown identity")
            self._crl_version += 1
            self._crl = self._sign_crl()
            return self._crl

    @property
    def crl(self) -> CRL:
        return self._crl

    def registry(self) -> list[tuple[str, str, int, bool]]:
        return [
            (r[0], r[1], r[2], bool(r[3]))
            for r in self._db.execute("SELECT id, role, serial, revoked FROM registry ORDER BY serial")
        ]


def enrol_all(ta: TrustedAuthority, specs: list[tuple[str, str]]) -> dict[str, Identity]:
    """Generate and enrol many identities in-process. Returns id -> Identity."""
    out = {}
    for ident, role in specs:
        i = Identity.generate(ident, role, ta.suite)
        ta.enrol(i)
        out[ident] = i
    return out
