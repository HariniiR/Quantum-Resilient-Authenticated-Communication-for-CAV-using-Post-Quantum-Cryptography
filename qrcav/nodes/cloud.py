"""
Cloud server: the non-critical path (deck slides 21, 31).

Receives routine data from the MEC over a secure channel and archives it in
SQLite (run/cloud.db) for storage and analytics.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time

from .base import NodeBase, main_for


class CloudNode(NodeBase):
    ROLE = "CLOUD"
    ALLOWED_PEERS = ("MEC",)

    async def run(self) -> None:
        await self.bootstrap()
        self.db = sqlite3.connect(str(self.run_dir / "cloud.db"))
        self.db.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, src TEXT, kind TEXT,"
                        " received REAL, body TEXT)")
        self.db.commit()
        await self.serve()
        self.log("ready", f"cloud ready on {self.me_cfg['port']}")
        asyncio.ensure_future(self.crl_loop())
        while True:
            await asyncio.sleep(3600)

    async def on_message(self, ch, msg) -> None:
        if msg.get("type") != "store":
            return
        rec = msg["record"]
        self.db.execute("INSERT OR IGNORE INTO records VALUES (?,?,?,?,?)",
                        (rec["event_id"], rec.get("src"), rec.get("kind"), time.time(),
                         json.dumps(rec, default=str)))
        self.db.commit()
        n = self.db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        self.log("stored", f"archived non-critical {rec.get('kind')} from {rec.get('src')} "
                 f"(total {n})", event_id=rec["event_id"], src=rec.get("src"))
        await ch.send({"type": "stored", "event_id": rec["event_id"]})


def main() -> None:
    main_for(CloudNode)


if __name__ == "__main__":
    main()
