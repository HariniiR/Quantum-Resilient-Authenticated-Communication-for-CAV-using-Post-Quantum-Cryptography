"""
Common machinery for every entity process: configuration, logging,
registration with the TA, CRL refresh, and secure channel management.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .. import codec
from ..crypto.suites import get_suite
from ..handshake import HandshakeError
from ..net.secure import ChannelClosed, SecureChannel, plain_request, secure_connect, start_secure_server
from ..pki import CRL, Certificate, Identity, RegistrationError, TrustAnchor

COLORS = {
    "TA": "\033[95m", "CLOUD": "\033[94m", "MEC": "\033[96m", "NODE": "\033[93m",
    "RSU": "\033[92m", "CAV": "\033[97m",
}
RESET = "\033[0m"


def load_config(path: str | Path) -> dict:
    cfg = json.loads(Path(path).read_text())
    cfg.setdefault("run_dir", "run")
    cfg.setdefault("suite", "DECK")
    cfg.setdefault("backend", "auto")
    cfg.setdefault("host", "127.0.0.1")
    return cfg


def all_entities(cfg: dict) -> dict[str, dict]:
    """id -> {role, port, ...} for every entity in the config."""
    out = {}
    out[cfg["cloud"]["id"]] = {**cfg["cloud"], "role": "CLOUD"}
    for m in cfg["mec"]:
        out[m["id"]] = {**m, "role": "MEC"}
    for n in cfg["consensus"]["nodes"]:
        out[n["id"]] = {**n, "role": "NODE"}
    for r in cfg["rsus"]:
        out[r["id"]] = {**r, "role": "RSU"}
    for c in cfg["cavs"]:
        out[c["id"]] = {**c, "role": "CAV"}
    return out


class NodeLogger:
    def __init__(self, node_id: str, role: str, log_dir: Path) -> None:
        self.node_id = node_id
        self.color = COLORS.get(role, "")
        log_dir.mkdir(parents=True, exist_ok=True)
        self._f = open(log_dir / f"{node_id}.jsonl", "a", buffering=1)
        self.quiet = os.environ.get("QRCAV_QUIET") == "1"

    def __call__(self, event: str, msg: str = "", **fields: Any) -> None:
        now = time.time()
        rec = {"t": now, "node": self.node_id, "event": event, **fields}
        self._f.write(json.dumps(rec, default=_json_default) + "\n")
        if msg and not self.quiet:
            stamp = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now % 1 * 1000):03d}"
            print(f"{stamp} {self.color}[{self.node_id:<8}]{RESET} {msg}", flush=True)


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    return str(o)


class NodeBase:
    ROLE = ""
    ALLOWED_PEERS: tuple[str, ...] = ()

    def __init__(self, cfg: dict, node_id: str) -> None:
        self.cfg = cfg
        self.id = node_id
        self.entities = all_entities(cfg)
        self.me_cfg = self.entities.get(node_id, {})
        self.host = cfg["host"]
        self.run_dir = Path(cfg["run_dir"])
        self.suite = get_suite(cfg["suite"], cfg["backend"])
        self.log = NodeLogger(node_id, self.ROLE, self.run_dir / "logs")
        self.identity: Identity | None = None
        self.channels: dict[str, SecureChannel] = {}
        self._connecting: dict[str, asyncio.Lock] = {}
        self.t0 = time.time()
        self.stopping = False

    # -- bootstrap: preparation + registration phases -------------------------

    async def bootstrap(self) -> None:
        pub_path = self.run_dir / "ta_public.bin"
        for _ in range(600):
            if pub_path.exists():
                break
            await asyncio.sleep(0.05)
        params = codec.decode(pub_path.read_bytes())
        if params["suite"] != self.suite.name:
            raise SystemExit(f"{self.id}: TA suite {params['suite']} != configured {self.suite.name}")
        anchor = TrustAnchor(params["ta_pk"], self.suite)

        key_path = self.run_dir / "keys" / f"{self.id}.key"
        if key_path.exists():
            ident = Identity.load(key_path)
        else:
            # Registration step 3: the entity generates its own keypair.
            ident = Identity.generate(self.id, self.ROLE, self.suite)
        if ident.cert is None:
            t = time.perf_counter()
            resp = await self._ta_call({"op": "register", "req": ident.registration_request()})
            if not resp.get("ok"):
                raise SystemExit(f"{self.id}: registration refused: {resp.get('error')}")
            ident.accept_certificate(Certificate.decode(resp["cert"]), anchor)
            ident.save(key_path)
            self.log("registered", f"registered with TA, cert serial {ident.cert.serial} "
                     f"({len(ident.cert.encode())} B, {(time.perf_counter() - t) * 1000:.1f} ms)",
                     serial=ident.cert.serial, cert_bytes=len(ident.cert.encode()))
        else:
            ident.anchor = anchor
        self.identity = ident
        await self.refresh_crl()

    async def _ta_call(self, obj: dict) -> dict:
        ta = self.cfg["ta"]
        for attempt in range(50):
            try:
                return await plain_request(self.host, ta["port"], obj)
            except (ConnectionError, OSError, ChannelClosed, asyncio.TimeoutError):
                await asyncio.sleep(0.2)
        raise SystemExit(f"{self.id}: TA unreachable")

    async def refresh_crl(self) -> None:
        try:
            resp = await self._ta_call({"op": "crl"})
            crl = CRL.decode(resp["crl"])
        except Exception:
            return
        old = self.identity.anchor.crl.version
        if self.identity.anchor.update_crl(crl) and crl.version != old:
            self.log("crl", f"CRL v{crl.version} accepted ({len(crl.revoked_serials)} revoked)",
                     version=crl.version)
            await self.on_crl_update(crl)

    async def crl_loop(self) -> None:
        interval = self.cfg.get("crl_interval", 1.0)
        while not self.stopping:
            await asyncio.sleep(interval)
            await self.refresh_crl()

    async def on_crl_update(self, crl: CRL) -> None:
        """Drop any open session whose peer is now revoked."""
        for pid, ch in list(self.channels.items()):
            if crl.is_revoked(ch.peer_serial):
                self.log("revoked-peer", f"closing session with revoked {pid}", peer=pid)
                ch.close()
                self.channels.pop(pid, None)

    # -- channels -------------------------------------------------------------

    def addr(self, peer_id: str) -> tuple[str, int]:
        return self.host, int(self.entities[peer_id]["port"])

    async def connect(self, peer_id: str, retries: int = 40) -> SecureChannel | None:
        ch = self.channels.get(peer_id)
        if ch and not ch.closed:
            return ch
        lock = self._connecting.setdefault(peer_id, asyncio.Lock())
        async with lock:
            ch = self.channels.get(peer_id)
            if ch and not ch.closed:
                return ch
            role = self.entities[peer_id]["role"]
            for attempt in range(retries):
                if self.stopping:
                    return None
                try:
                    host, port = self.addr(peer_id)
                    ch = await secure_connect(host, port, self.identity, expected_role=role,
                                              expected_id=peer_id)
                    self._log_handshake(ch, "initiator")
                    self.channels[peer_id] = ch
                    asyncio.ensure_future(self._reader(ch))
                    return ch
                except HandshakeError:
                    self.log("handshake-failed", f"handshake with {peer_id} rejected", peer=peer_id)
                    await asyncio.sleep(min(2.0, 0.2 * (attempt + 1)))
                except (ConnectionError, OSError, ChannelClosed, asyncio.TimeoutError):
                    await asyncio.sleep(min(1.0, 0.1 * (attempt + 1)))
            return None

    def _log_handshake(self, ch: SecureChannel, side: str) -> None:
        s = ch.session
        self.log(
            "handshake", f"secure session with {ch.peer_id} ({ch.peer_role}) as {side}: "
            f"{s.handshake_bytes} B in 4 flights, {s.elapsed_ms:.1f} ms",
            peer=ch.peer_id, side=side, bytes=s.handshake_bytes, ms=s.elapsed_ms,
            crypto_ms=s.crypto_ms, flights=s.flight_sizes,
        )

    async def _reader(self, ch: SecureChannel) -> None:
        try:
            while not ch.closed:
                msg = await ch.recv()
                try:
                    await self.on_message(ch, msg)
                except Exception as e:  # never let one bad message kill the link
                    self.log("error", f"handler error from {ch.peer_id}: {e!r}")
        except ChannelClosed:
            pass
        finally:
            ch.close()
            if self.channels.get(ch.peer_id) is ch:
                self.channels.pop(ch.peer_id, None)
            await self.on_disconnect(ch)

    async def _on_inbound(self, ch: SecureChannel) -> None:
        self._log_handshake(ch, "responder")
        old = self.channels.get(ch.peer_id)
        if old is not None and old is not ch:
            old.close()
        self.channels[ch.peer_id] = ch
        await self.on_connect(ch)
        await self._reader(ch)

    async def serve(self) -> None:
        port = int(self.me_cfg["port"])

        def rejected(peer: str) -> None:
            self.log("handshake-rejected", f"rejected handshake from {peer}", peer=peer)

        self._server = await start_secure_server(self.host, port, self.identity, self.ALLOWED_PEERS,
                                                 self._on_inbound, rejected)

    async def send(self, peer_id: str, obj: Any) -> bool:
        ch = await self.connect(peer_id)
        if ch is None:
            return False
        try:
            await ch.send(obj)
            return True
        except ChannelClosed:
            self.channels.pop(peer_id, None)
            return False

    # -- hooks ------------------------------------------------------------------

    async def on_message(self, ch: SecureChannel, msg: Any) -> None:
        pass

    async def on_connect(self, ch: SecureChannel) -> None:
        pass

    async def on_disconnect(self, ch: SecureChannel) -> None:
        pass

    async def run(self) -> None:
        raise NotImplementedError

    def elapsed(self) -> float:
        return time.time() - self.t0


def main_for(cls) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--id", required=True)
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")  # enable ANSI colours in Windows terminals
    cfg = load_config(args.config)
    node = cls(cfg, args.id)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass
