"""
AES-256-GCM record layer (deck slide 17).

Record on the wire:   ctr (8 bytes, big-endian) || ciphertext || tag (16 bytes)
Nonce:                nonce = v_dir XOR (0^32 || be64(ctr))

Counter 0 is reserved for the Finished message of the handshake. Application
data starts at counter 1.

    Why this matters: the deck encrypts Finished with nonce v XOR be96(0) and
    leaves the starting value of the data counter unspecified. If data also
    started at 0, the first data record would reuse (key, nonce) with
    Finished. Under GCM a single nonce reuse leaks the GHASH authentication
    key and the XOR of the two plaintexts, after which an attacker can forge
    records. Reserving 0 rules that out by construction.

The receiver keeps a 64-record sliding window (as in IPsec, RFC 4303 s3.4.3),
so records that arrive out of order over a radio link are accepted once and
replays are rejected. The window check runs before decryption so a flood of
replayed records costs a table lookup, not an AES-GCM operation.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CTR_LEN = 8
TAG_LEN = 16
RECORD_OVERHEAD = CTR_LEN + TAG_LEN
FINISHED_CTR = 0
FIRST_DATA_CTR = 1
WINDOW = 64
# Re-key well before any GCM usage bound. A new handshake is required after this.
MAX_RECORDS = 2**32


class RecordError(Exception):
    """Uniform failure: bad tag, replay, malformed record. No detail leaks."""


class NonceExhausted(RecordError):
    pass


def make_nonce(base_iv: bytes, ctr: int) -> bytes:
    if len(base_iv) != 12:
        raise ValueError("base IV must be 12 bytes")
    if not 0 <= ctr < 2**64:
        raise ValueError("counter out of range")
    pad = bytes(4) + ctr.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(base_iv, pad))


class RecordSender:
    """One direction of a session. Never reuses a counter."""

    def __init__(self, key: bytes, base_iv: bytes, label: bytes = b"") -> None:
        self._aead = AESGCM(key)
        self._iv = base_iv
        self._label = label
        self._ctr = FIRST_DATA_CTR
        self.key = key  # exposed for tests only

    @property
    def next_ctr(self) -> int:
        return self._ctr

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if self._ctr >= MAX_RECORDS:
            raise NonceExhausted("session exhausted; run a new handshake")
        ctr = self._ctr
        self._ctr += 1
        hdr = ctr.to_bytes(CTR_LEN, "big")
        ct = self._aead.encrypt(make_nonce(self._iv, ctr), plaintext, self._label + hdr + aad)
        return hdr + ct

    def seal_finished(self, plaintext: bytes) -> bytes:
        """Counter 0, used exactly once by the handshake."""
        hdr = FINISHED_CTR.to_bytes(CTR_LEN, "big")
        ct = self._aead.encrypt(make_nonce(self._iv, FINISHED_CTR), plaintext, self._label + hdr)
        return hdr + ct


class RecordReceiver:
    def __init__(self, key: bytes, base_iv: bytes, label: bytes = b"") -> None:
        self._aead = AESGCM(key)
        self._iv = base_iv
        self._label = label
        self._top = 0          # highest counter accepted so far
        self._bitmap = 0       # bit i set => (top - i) already accepted
        self.key = key
        self.rejected = 0

    def _seen(self, ctr: int) -> bool:
        if ctr > self._top:
            return False
        diff = self._top - ctr
        if diff >= WINDOW:
            return True  # too old to tell; treat as replay
        return bool(self._bitmap >> diff & 1)

    def _mark(self, ctr: int) -> None:
        if ctr > self._top:
            shift = ctr - self._top
            self._bitmap = ((self._bitmap << shift) | 1) & ((1 << WINDOW) - 1)
            self._top = ctr
        else:
            self._bitmap |= 1 << (self._top - ctr)

    def open(self, record: bytes, aad: bytes = b"") -> tuple[int, bytes]:
        """Return (counter, plaintext) or raise RecordError."""
        if len(record) < RECORD_OVERHEAD:
            self.rejected += 1
            raise RecordError()
        ctr = int.from_bytes(record[:CTR_LEN], "big")
        if ctr < FIRST_DATA_CTR or self._seen(ctr):
            self.rejected += 1
            raise RecordError()
        try:
            pt = self._aead.decrypt(
                make_nonce(self._iv, ctr), record[CTR_LEN:], self._label + record[:CTR_LEN] + aad
            )
        except InvalidTag:
            self.rejected += 1
            raise RecordError() from None
        self._mark(ctr)
        return ctr, pt

    def open_finished(self, record: bytes) -> bytes:
        if len(record) < RECORD_OVERHEAD or int.from_bytes(record[:CTR_LEN], "big") != FINISHED_CTR:
            raise RecordError()
        try:
            return self._aead.decrypt(
                make_nonce(self._iv, FINISHED_CTR), record[CTR_LEN:], self._label + record[:CTR_LEN]
            )
        except InvalidTag:
            raise RecordError() from None
