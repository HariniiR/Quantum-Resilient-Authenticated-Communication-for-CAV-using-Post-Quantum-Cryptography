"""
Secure channels over TCP (asyncio).

Framing: every frame is a 4-byte big-endian length followed by that many
bytes. The four handshake flights travel as frames; once the session is up,
every frame is one AES-256-GCM record  <ctr, ciphertext, tag>.

These are thin wrappers around the sans-IO handshake in qrcav/handshake.py.
"""

from __future__ import annotations

import asyncio
import struct
import time
from typing import Any, Awaitable, Callable

from .. import codec
from ..handshake import ClientHandshake, HandshakeError, ReplayCache, ServerHandshake, Session
from ..pki import Identity

MAX_FRAME = 8 * 1024 * 1024
HANDSHAKE_TIMEOUT = 10.0


class ChannelClosed(Exception):
    pass


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        hdr = await reader.readexactly(4)
        (n,) = struct.unpack(">I", hdr)
        if n > MAX_FRAME:
            raise ChannelClosed("frame too large")
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
        raise ChannelClosed(str(e)) from None


async def write_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    try:
        writer.write(struct.pack(">I", len(data)) + data)
        await writer.drain()
    except (ConnectionError, OSError, RuntimeError) as e:
        raise ChannelClosed(str(e)) from None


class SecureChannel:
    """A mutually authenticated, encrypted, replay-protected link to one peer."""

    def __init__(self, session: Session, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.session = session
        self.reader = reader
        self.writer = writer
        self._lock = asyncio.Lock()
        self.closed = False
        self.records_sent = 0
        self.records_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0

    @property
    def peer_id(self) -> str:
        return self.session.peer.id

    @property
    def peer_role(self) -> str:
        return self.session.peer.role

    @property
    def peer_serial(self) -> int:
        return self.session.peer.serial

    async def send(self, obj: Any) -> None:
        if self.closed:
            raise ChannelClosed("closed")
        async with self._lock:
            rec = self.session.seal(obj)
            await write_frame(self.writer, rec)
            self.records_sent += 1
            self.bytes_sent += len(rec) + 4

    async def recv(self) -> Any:
        """Next valid record. Tampered or replayed records are dropped silently."""
        while True:
            rec = await read_frame(self.reader)
            self.bytes_received += len(rec) + 4
            try:
                obj = self.session.open(rec)
            except Exception:
                continue  # slide 17 steps 8-9: discard invalid or replayed records
            self.records_received += 1
            return obj

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.writer.close()
            except Exception:
                pass


async def secure_connect(
    host: str, port: int, me: Identity,
    expected_role: str | tuple[str, ...] | None = None,
    expected_id: str | None = None,
    timeout: float = HANDSHAKE_TIMEOUT,
) -> SecureChannel:
    """Open TCP, run the client side of the handshake, return the channel."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        hs = ClientHandshake(me, expected_role=expected_role, expected_id=expected_id)
        await write_frame(writer, hs.client_hello())
        sh = await asyncio.wait_for(read_frame(reader), timeout)
        await write_frame(writer, hs.on_server_hello(sh))
        fs = await asyncio.wait_for(read_frame(reader), timeout)
        session = hs.on_server_finished(fs)
        return SecureChannel(session, reader, writer)
    except BaseException:
        writer.close()
        raise


async def secure_accept(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, me: Identity,
    allowed_roles: tuple[str, ...] | None, replay_cache: ReplayCache,
    timeout: float = HANDSHAKE_TIMEOUT,
) -> SecureChannel:
    hs = ServerHandshake(me, allowed_roles=allowed_roles, replay_cache=replay_cache)
    ch = await asyncio.wait_for(read_frame(reader), timeout)
    await write_frame(writer, hs.on_client_hello(ch))
    ck = await asyncio.wait_for(read_frame(reader), timeout)
    fs, session = hs.on_client_key(ck)
    await write_frame(writer, fs)
    return SecureChannel(session, reader, writer)


async def start_secure_server(
    host: str, port: int, me: Identity, allowed_roles: tuple[str, ...] | None,
    on_channel: Callable[[SecureChannel], Awaitable[None]],
    on_reject: Callable[[str], None] | None = None,
) -> asyncio.base_events.Server:
    cache = ReplayCache()

    async def _handle(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            chan = await secure_accept(reader, writer, me, allowed_roles, cache)
        except (HandshakeError, ChannelClosed, asyncio.TimeoutError, ConnectionError, OSError):
            if on_reject:
                on_reject(str(peer))
            writer.close()
            return
        try:
            await on_channel(chan)
        finally:
            chan.close()

    return await asyncio.start_server(_handle, host, port)


# ---------------------------------------------------------------------------
# Plain (unencrypted) request/response, used only for TA registration and CRL
# distribution. Both are safe in the clear: the certificate and the CRL are
# signed by the TA and verified by the receiver with pk_TA.
# ---------------------------------------------------------------------------

async def plain_request(host: str, port: int, obj: Any, timeout: float = 10.0) -> Any:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        await write_frame(writer, codec.encode(obj))
        return codec.decode(await asyncio.wait_for(read_frame(reader), timeout))
    finally:
        writer.close()
