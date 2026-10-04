"""
Authenticated key establishment between any two registered entities.

Implements deck slides 15-16, with three corrections:

  (a) A ClientHello opens the handshake. The deck's server signs "T || pk_kem"
      but nothing initialises T. Here T starts with the ClientHello, which
      carries the client's certificate, a fresh 32-byte nonce, a timestamp
      and the suite. The server's signature therefore covers a value the
      client just chose, so a recorded ServerHello cannot be replayed to it.

  (b) The client signs too (mutual authentication). In the deck only the
      server signs, so nothing proves the client owns the private key behind
      the certificate it presents: anyone holding a copy of a vehicle's
      certificate could open a session as that vehicle.

  (c) Application records start at counter 1; Finished uses counter 0
      (see crypto/records.py for why).

Flights (C = client/initiator, S = server/responder):

  1. C -> S  ClientHello  {suite, Cert_C, nonce_C, ts}
  2. S -> C  ServerHello  {Cert_S, pk_kem, nonce_S, sig_S}
             sig_S = ML-DSA.sign(sk_S, "sh" || H(CH || SH_body))
  3. C -> S  ClientKey    {c, sig_C, record_C}
             (ss, c) = ML-KEM.encaps(pk_kem)
             sig_C   = ML-DSA.sign(sk_C, "ck" || H(CH || SH || CK_body))
             keys    = DERIVE_SESSION_KEYS(ss, T)
             record_C = AES-GCM(k_c2s, v_c2s ^ 0, H("client_finished" || T_hash))
  4. S -> C  ServerFinished {record_S}
             record_S = AES-GCM(k_s2c, v_s2c ^ 0, H("server_finished" || T_hash))

Every check failure raises the same HandshakeError with no detail, so a
probing attacker cannot tell which check failed.

The state machines are "sans-IO": they consume and produce bytes and never
touch a socket. The same code runs over TCP in the distributed system, in
memory in the tests and benchmarks, and supplies exact message sizes to the
ns-3 simulation.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from . import codec
from .crypto.kdf import H, derive_session_keys
from .crypto.records import RecordReceiver, RecordSender
from .pki import Certificate, Identity

PROTOCOL_VERSION = 1
NONCE_LEN = 32
FRESHNESS_WINDOW_S = 30


class HandshakeError(Exception):
    """Uniform abort. Deliberately carries no reason."""


class _Timer:
    """Accumulates the time spent in each cryptographic operation."""

    def __init__(self) -> None:
        self.ops: dict[str, float] = {}

    def run(self, name: str, fn, *args):
        t0 = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.ops[name] = self.ops.get(name, 0.0) + (time.perf_counter() - t0) * 1000


class ReplayCache:
    """Server-side memory of ClientHello nonces inside the freshness window."""

    def __init__(self, window_s: int = FRESHNESS_WINDOW_S) -> None:
        self.window_s = window_s
        self._seen: dict[bytes, float] = {}

    def check_and_add(self, nonce: bytes, now: float) -> bool:
        if len(self._seen) > 10000:
            self._seen = {n: t for n, t in self._seen.items() if t > now}
        exp = self._seen.get(nonce)
        if exp is not None and exp > now:
            return False
        self._seen[nonce] = now + 2 * self.window_s
        return True


@dataclass
class Session:
    """An established, mutually authenticated channel."""

    peer: Certificate
    is_client: bool
    sender: RecordSender
    receiver: RecordReceiver
    t_hash: bytes
    bytes_sent: int = 0
    bytes_received: int = 0
    crypto_ms: dict[str, float] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    flight_sizes: dict[str, int] = field(default_factory=dict)

    @property
    def peer_id(self) -> str:
        return self.peer.id

    @property
    def handshake_bytes(self) -> int:
        return sum(self.flight_sizes.values())

    def seal(self, obj: Any) -> bytes:
        return self.sender.seal(codec.encode(obj))

    def open(self, record: bytes) -> Any:
        _, pt = self.receiver.open(record)
        return codec.decode(pt)


def _finished(label: bytes, t_hash: bytes) -> bytes:
    return H(label, t_hash)


# ---------------------------------------------------------------------------
# Client (initiator)
# ---------------------------------------------------------------------------

class ClientHandshake:
    def __init__(
        self,
        me: Identity,
        expected_role: str | tuple[str, ...] | None = None,
        expected_id: str | None = None,
        now: float | None = None,
    ) -> None:
        if not me.registered:
            raise HandshakeError()
        self.me = me
        self.suite = me.suite
        self.expected_role = expected_role
        self.expected_id = expected_id
        self._now = now
        self.timer = _Timer()
        self.sizes: dict[str, int] = {}
        self._t0 = time.perf_counter()
        self._state = "start"

    def _clock(self) -> float:
        return time.time() if self._now is None else self._now

    def client_hello(self) -> bytes:
        if self._state != "start":
            raise HandshakeError()
        self._ch = codec.encode({
            "t": "CH",
            "v": PROTOCOL_VERSION,
            "suite": self.suite.name,
            "cert": self.me.cert.encode(),
            "nonce": os.urandom(NONCE_LEN),
            "ts": int(self._clock()),
        })
        self.sizes["client_hello"] = len(self._ch)
        self._state = "sent_ch"
        return self._ch

    def on_server_hello(self, sh_bytes: bytes) -> bytes:
        """Verify the server, encapsulate, sign, derive keys. Returns flight 3."""
        if self._state != "sent_ch":
            raise HandshakeError()
        self._state = "failed"
        try:
            sh = codec.decode_dict(sh_bytes, "t", "cert", "pk_kem", "nonce", "sig")
            if sh["t"] != "SH" or len(sh["nonce"]) != NONCE_LEN:
                raise HandshakeError()
            cert_s = Certificate.decode(sh["cert"])
            anchor = self.me.anchor
            # 6. verify server certificate against pk_TA (+ CRL, role, expiry)
            if not self.timer.run("verify_cert", anchor.verify_cert, cert_s, int(self._clock()),
                                  self.expected_role, self.expected_id):
                raise HandshakeError()
            # 7. verify server signature over the transcript including pk_kem
            sh_body = codec.encode({"t": "SH", "cert": sh["cert"], "pk_kem": sh["pk_kem"],
                                    "nonce": sh["nonce"]})
            signed = b"qrcav-sh" + H(self._ch, sh_body)
            if not self.timer.run("verify_sig", self.suite.sig.verify, cert_s.pk, signed, sh["sig"]):
                raise HandshakeError()
            # 8. encapsulate to the server's ephemeral key
            ss, ct = self.timer.run("kem_encaps", self.suite.kem.encaps, sh["pk_kem"])
            # client authentication: sign the transcript including c
            ck_body = codec.encode({"t": "CK", "ct": ct})
            transcript = self._ch + sh_bytes + ck_body
            sig_c = self.timer.run("sign", self.me.sign, b"qrcav-ck" + H(transcript))
            transcript += sig_c
            # 13. derive session keys
            keys = self.timer.run("kdf", derive_session_keys, ss, transcript)
            del ss
            # 14. Finished_C under k_c2s, counter 0
            self._sender = RecordSender(keys.k_c2s, keys.v_c2s, b"c2s")
            self._receiver = RecordReceiver(keys.k_s2c, keys.v_s2c, b"s2c")
            fin = self.timer.run("aead", self._sender.seal_finished,
                                 _finished(b"client_finished", keys.t_hash))
            ck = codec.encode({"t": "CK", "ct": ct, "sig": sig_c, "fin": fin})
            self._t_hash = keys.t_hash
            self._peer = cert_s
            self.sizes["server_hello"] = len(sh_bytes)
            self.sizes["client_key"] = len(ck)
            self._state = "sent_ck"
            return ck
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError() from None

    def on_server_finished(self, fs_bytes: bytes) -> Session:
        if self._state != "sent_ck":
            raise HandshakeError()
        self._state = "failed"
        try:
            fs = codec.decode_dict(fs_bytes, "t", "fin")
            if fs["t"] != "FS":
                raise HandshakeError()
            # 19. verify Finished_S
            pt = self.timer.run("aead", self._receiver.open_finished, fs["fin"])
            if pt != _finished(b"server_finished", self._t_hash):
                raise HandshakeError()
            self.sizes["server_finished"] = len(fs_bytes)
            self._state = "done"
            s = Session(self._peer, True, self._sender, self._receiver, self._t_hash,
                        crypto_ms=dict(self.timer.ops), flight_sizes=dict(self.sizes))
            s.elapsed_ms = (time.perf_counter() - self._t0) * 1000
            return s
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError() from None


# ---------------------------------------------------------------------------
# Server (responder)
# ---------------------------------------------------------------------------

class ServerHandshake:
    def __init__(
        self,
        me: Identity,
        allowed_roles: tuple[str, ...] | None = None,
        replay_cache: ReplayCache | None = None,
        now: float | None = None,
        freshness_s: int = FRESHNESS_WINDOW_S,
    ) -> None:
        if not me.registered:
            raise HandshakeError()
        self.me = me
        self.suite = me.suite
        self.allowed_roles = allowed_roles
        self.replay_cache = replay_cache if replay_cache is not None else ReplayCache(freshness_s)
        self.freshness_s = freshness_s
        self._now = now
        self.timer = _Timer()
        self.sizes: dict[str, int] = {}
        self._t0 = time.perf_counter()
        self._state = "start"

    def _clock(self) -> float:
        return time.time() if self._now is None else self._now

    def on_client_hello(self, ch_bytes: bytes) -> bytes:
        if self._state != "start":
            raise HandshakeError()
        self._state = "failed"
        try:
            ch = codec.decode_dict(ch_bytes, "t", "v", "suite", "cert", "nonce", "ts")
            now = self._clock()
            if ch["t"] != "CH" or ch["v"] != PROTOCOL_VERSION:
                raise HandshakeError()
            # Downgrade protection: the suite must match exactly, and it is in
            # the transcript both signatures cover.
            if ch["suite"] != self.suite.name or len(ch["nonce"]) != NONCE_LEN:
                raise HandshakeError()
            if abs(now - ch["ts"]) > self.freshness_s:
                raise HandshakeError()
            cert_c = Certificate.decode(ch["cert"])
            if not self.timer.run("verify_cert", self.me.anchor.verify_cert, cert_c, int(now),
                                  self.allowed_roles):
                raise HandshakeError()
            if not self.replay_cache.check_and_add(ch["nonce"], now):
                raise HandshakeError()
            # 1. ephemeral ML-KEM keypair, one per session (forward secrecy)
            pk_kem, self._sk_kem = self.timer.run("kem_keygen", self.suite.kem.keygen)
            nonce_s = os.urandom(NONCE_LEN)
            cert_s = self.me.cert.encode()
            sh_body = codec.encode({"t": "SH", "cert": cert_s, "pk_kem": pk_kem, "nonce": nonce_s})
            # 2. sign the transcript so far plus the ephemeral key
            sig = self.timer.run("sign", self.me.sign, b"qrcav-sh" + H(ch_bytes, sh_body))
            sh = codec.encode({"t": "SH", "cert": cert_s, "pk_kem": pk_kem, "nonce": nonce_s, "sig": sig})
            self._ch, self._sh, self._peer = ch_bytes, sh, cert_c
            self.sizes["client_hello"] = len(ch_bytes)
            self.sizes["server_hello"] = len(sh)
            self._state = "sent_sh"
            return sh
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError() from None

    def on_client_key(self, ck_bytes: bytes) -> tuple[bytes, Session]:
        """Verify the client, decapsulate, check Finished_C. Returns (flight 4, session)."""
        if self._state != "sent_sh":
            raise HandshakeError()
        self._state = "failed"
        try:
            ck = codec.decode_dict(ck_bytes, "t", "ct", "sig", "fin")
            if ck["t"] != "CK":
                raise HandshakeError()
            ck_body = codec.encode({"t": "CK", "ct": ck["ct"]})
            transcript = self._ch + self._sh + ck_body
            if not self.timer.run("verify_sig", self.suite.sig.verify, self._peer.pk,
                                  b"qrcav-ck" + H(transcript), ck["sig"]):
                raise HandshakeError()
            transcript += ck["sig"]
            # 12. decapsulate, then erase the ephemeral private key
            ss = self.timer.run("kem_decaps", self.suite.kem.decaps, self._sk_kem, ck["ct"])
            self._sk_kem = None
            keys = self.timer.run("kdf", derive_session_keys, ss, transcript)
            del ss
            receiver = RecordReceiver(keys.k_c2s, keys.v_c2s, b"c2s")
            sender = RecordSender(keys.k_s2c, keys.v_s2c, b"s2c")
            # 16. verify Finished_C
            pt = self.timer.run("aead", receiver.open_finished, ck["fin"])
            if pt != _finished(b"client_finished", keys.t_hash):
                raise HandshakeError()
            # 17. Finished_S
            fin = self.timer.run("aead", sender.seal_finished, _finished(b"server_finished", keys.t_hash))
            fs = codec.encode({"t": "FS", "fin": fin})
            self.sizes["client_key"] = len(ck_bytes)
            self.sizes["server_finished"] = len(fs)
            self._state = "done"
            s = Session(self._peer, False, sender, receiver, keys.t_hash,
                        crypto_ms=dict(self.timer.ops), flight_sizes=dict(self.sizes))
            s.elapsed_ms = (time.perf_counter() - self._t0) * 1000
            return fs, s
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError() from None


def handshake_in_memory(
    client: Identity,
    server: Identity,
    allowed_roles: tuple[str, ...] | None = None,
    expected_role: str | tuple[str, ...] | None = None,
    replay_cache: ReplayCache | None = None,
) -> tuple[Session, Session]:
    """Run all four flights in one process. Used by tests and benchmarks."""
    c = ClientHandshake(client, expected_role=expected_role)
    s = ServerHandshake(server, allowed_roles=allowed_roles, replay_cache=replay_cache)
    sh = s.on_client_hello(c.client_hello())
    ck = c.on_server_hello(sh)
    fs, s_sess = s.on_client_key(ck)
    c_sess = c.on_server_finished(fs)
    return c_sess, s_sess
