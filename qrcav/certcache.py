"""
Certificate caching for the handshake (in the spirit of TLS cached-info,
RFC 7924).

Why it matters: with ML-DSA-65 a certificate is about 5.3 KB, because it holds
a 1,952-byte public key and the TA's 3,309-byte signature. A full handshake
sends two of them (the client's in ClientHello, the server's in ServerHello),
so about half of the 20.8 KB DECK handshake is certificates. Both peers
usually already hold those certificates:

  * RSU certificates are few and change rarely, so they are distributed to
    vehicles ahead of time, alongside the CRL.
  * A vehicle's certificate is stored at the edge (a directory at the MEC,
    reachable from every RSU over the wired backhaul) after its first
    handshake, so the next RSU can look it up instead of receiving it over
    the air.

When a peer is known to hold the certificate, the handshake sends a 32-byte
reference instead: cert_ref = H("qrcav-cert", encoded certificate).

Security
--------
  * A cached certificate is still verified in full on every handshake: TA
    signature, validity period, role, and the current CRL. The cache saves
    bytes on the air, never checks, so revocation still takes effect at the
    next CRL refresh.
  * The reference is a collision-resistant hash of the exact certificate
    bytes, and it is inside the transcript both signatures cover. Signing the
    reference therefore binds the same certificate as signing the bytes.
  * Servers add a certificate only after a handshake with its owner has fully
    succeeded (signature verified, Finished checked), and the cache is a
    bounded LRU, so unauthenticated clients cannot fill it.
  * If the server does not hold the referenced certificate it answers with a
    HelloRetry, and the client resends ClientHello with the full certificate.
    An attacker who forges a HelloRetry only forces that slower path, which
    is the same property as TLS 1.3's HelloRetryRequest.
"""

from __future__ import annotations

from collections import OrderedDict

from .crypto.kdf import H

REF_LEN = 32


def cert_ref(cert_bytes: bytes) -> bytes:
    """32-byte reference to an encoded certificate."""
    return H(b"qrcav-cert", cert_bytes, length=REF_LEN)


class CertCache:
    """
    Bounded LRU store: cert_ref -> encoded certificate, plus an index from
    entity ID to its latest reference (used by clients to say which server
    certificate they already hold).
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self.max_entries = max_entries
        self._certs: OrderedDict[bytes, bytes] = OrderedDict()
        self._by_id: dict[str, bytes] = {}
        # Set once this entity's own certificate is known to the edge
        # directory (after its first successful handshake as a client).
        self.mine_known = False
        self.hits = 0
        self.misses = 0

    def put(self, cert_bytes: bytes, ident: str | None = None) -> bytes:
        ref = cert_ref(cert_bytes)
        self._certs[ref] = cert_bytes
        self._certs.move_to_end(ref)
        if ident is not None:
            self._by_id[ident] = ref
        while len(self._certs) > self.max_entries:
            old, _ = self._certs.popitem(last=False)
            for k in [k for k, v in self._by_id.items() if v == old]:
                del self._by_id[k]
        return ref

    def get(self, ref: bytes) -> bytes | None:
        cert = self._certs.get(ref)
        if cert is None:
            self.misses += 1
            return None
        self.hits += 1
        self._certs.move_to_end(ref)
        return cert

    def ref_for(self, ident: str | None) -> bytes:
        """Reference of the cached certificate for `ident`, or b"" if none."""
        if ident is None:
            return b""
        ref = self._by_id.get(ident, b"")
        return ref if ref in self._certs else b""

    def __contains__(self, ref: bytes) -> bool:
        return ref in self._certs

    def __len__(self) -> int:
        return len(self._certs)
