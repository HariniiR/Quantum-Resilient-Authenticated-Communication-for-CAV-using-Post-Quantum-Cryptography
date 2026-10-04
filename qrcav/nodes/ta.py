"""
Trusted Authority process.

  * preparation phase: generates (pk_TA, sk_TA) and publishes the public
    parameters to run/ta_public.bin (the out-of-band "publish(pk_TA)" step:
    in a deployment this is the root key installed in every OBU and RSU)
  * registration service: certifies entity public keys (plain TCP; the
    certificate is signed, so it needs no confidentiality)
  * revocation: signed CRL served to any node that asks
  * registry DB: run/ta_registry.db (SQLite)

Admin operations (revoke) need the token in run/admin.token.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from pathlib import Path

from .. import codec
from ..crypto.suites import get_suite
from ..net.secure import ChannelClosed, read_frame, write_frame
from ..pki import RegistrationError, TrustedAuthority
from .base import NodeLogger, all_entities, main_for


class TANode:
    ROLE = "TA"

    def __init__(self, cfg: dict, node_id: str = "TA") -> None:
        self.cfg = cfg
        self.id = node_id
        self.run_dir = Path(cfg["run_dir"])
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.log = NodeLogger("TA", "TA", self.run_dir / "logs")
        suite = get_suite(cfg["suite"], cfg["backend"])
        roster = None
        if cfg.get("ta", {}).get("use_roster", True):
            roster = {eid: e["role"] for eid, e in all_entities(cfg).items()}
        t = time.perf_counter()
        self.ta = TrustedAuthority(suite, self.run_dir / "ta_registry.db", roster=roster)
        params = self.ta.public_parameters()
        (self.run_dir / "ta_public.bin").write_bytes(codec.encode(params))
        self.token = secrets.token_hex(16)
        (self.run_dir / "admin.token").write_text(self.token)
        self.log("prepared", f"preparation phase done: {suite.label} [{suite.backend}], "
                 f"pk_TA {len(self.ta.pk)} B, H=SHAKE-256, KDF=HKDF-SHA3-256 "
                 f"({(time.perf_counter() - t) * 1000:.1f} ms)", suite=suite.name)

    async def handle(self, reader, writer) -> None:
        try:
            req = codec.decode(await read_frame(reader))
            op = req.get("op")
            if op == "register":
                try:
                    cert = self.ta.register(req["req"])
                    self.log("certified", f"certified {cert.id} ({cert.role}) serial {cert.serial}",
                             id=cert.id, role=cert.role, serial=cert.serial)
                    resp = {"ok": True, "cert": cert.encode()}
                except RegistrationError as e:
                    self.log("refused", f"registration refused: {e}", error=str(e))
                    resp = {"ok": False, "error": str(e)}
            elif op == "crl":
                resp = {"ok": True, "crl": self.ta.crl.encode()}
            elif op == "revoke":
                if req.get("token") != self.token:
                    resp = {"ok": False, "error": "unauthorised"}
                else:
                    resp = self._revoke(req["id"])
            elif op == "registry":
                resp = {"ok": True, "registry": [list(r) for r in self.ta.registry()]}
            elif op == "certs":
                rows = self.ta._db.execute("SELECT cert FROM registry").fetchall()
                resp = {"ok": True, "certs": [bytes(r[0]) for r in rows]}
            else:
                resp = {"ok": False, "error": "unknown op"}
            await write_frame(writer, codec.encode(resp))
        except (ChannelClosed, Exception):
            pass
        finally:
            writer.close()

    def _revoke(self, ident: str) -> dict:
        try:
            crl = self.ta.revoke(ident)
            self.log("revoked", f"REVOKED {ident}; CRL now v{crl.version}", id=ident, version=crl.version)
            return {"ok": True, "version": crl.version}
        except RegistrationError as e:
            return {"ok": False, "error": str(e)}

    async def scheduled(self) -> None:
        t0 = time.time()
        for item in sorted(self.cfg.get("ta", {}).get("revoke", []), key=lambda x: x["at"]):
            await asyncio.sleep(max(0, t0 + item["at"] - time.time()))
            self._revoke(item["id"])

    async def run(self) -> None:
        port = int(self.cfg["ta"]["port"])
        server = await asyncio.start_server(self.handle, self.cfg["host"], port)
        self.log("listening", f"TA listening on {port}")
        asyncio.ensure_future(self.scheduled())
        async with server:
            await server.serve_forever()


def main() -> None:
    main_for(TANode)


if __name__ == "__main__":
    main()
