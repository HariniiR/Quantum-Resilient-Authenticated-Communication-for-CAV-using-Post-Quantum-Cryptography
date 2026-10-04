"""
Consensus-layer node process (deck slides 22-30).

Wraps the sans-IO Replica with:
  * a full mesh of secure channels to the other consensus nodes
    (the lower id initiates each pair, so there is exactly one channel per pair)
  * a listener for the MEC (the consensus client)
  * a 10 ms timer tick for leader grace periods and view-change timeouts
  * a persisted ledger in run/ledger/<id>.jsonl

Fault injection for demonstrations, from the node's config entry:
  "behaviour": "wrong_result" | "silent"     Byzantine from the start
  "crash_at": seconds                        process exits at that time
"""

from __future__ import annotations

import asyncio
import os
import time

from .. import codec
from ..consensus.agspbft import ConsensusConfig, Replica, leader_of
from ..consensus.messages import Directory
from ..ledger import Ledger
from ..pki import Certificate
from .base import NodeBase, main_for


def consensus_config(cfg: dict) -> ConsensusConfig:
    c = cfg["consensus"]
    return ConsensusConfig(
        nodes=[n["id"] for n in c["nodes"]],
        mode=c.get("mode", "ags"),
        initial_consensus=c.get("initial_consensus"),
        seed=c.get("seed", 7),
        regroup_interval=c.get("regroup_interval", 50),
        view_change_timeout=c.get("view_change_timeout", 3.0),
        response_grace=c.get("response_grace", 0.05),
        load_low=c.get("load_low", 2.0),
        load_high=c.get("load_high", 20.0),
        adaptive_size=c.get("adaptive_size", True),
        clients=tuple(m["id"] for m in cfg["mec"]),
    )


async def build_directory(node: NodeBase, wanted: set[str]) -> Directory:
    """Fetch certificates from the TA and keep only ones that verify with pk_TA."""
    d = Directory(node.suite, node.identity.anchor.ta_pk)
    for _ in range(300):
        resp = await node._ta_call({"op": "certs"})
        for raw in resp.get("certs", []):
            c = Certificate.decode(raw)
            if node.identity.anchor.verify_cert(c):
                d.add(c)
        if wanted <= set(d.certs):
            return d
        await asyncio.sleep(0.2)
    raise SystemExit(f"{node.id}: not all consensus participants registered")


class ConsensusNode(NodeBase):
    ROLE = "NODE"
    ALLOWED_PEERS = ("NODE", "MEC")

    async def run(self) -> None:
        await self.bootstrap()
        self.ccfg = consensus_config(self.cfg)
        self.dir = await build_directory(self, set(self.ccfg.nodes) | set(self.ccfg.clients))
        ledger = Ledger(self.run_dir / "ledger" / f"{self.id}.jsonl")
        behaviour = self.me_cfg.get("behaviour", "honest")
        self.replica = Replica(self.identity, self.ccfg, self.dir, ledger, behaviour=behaviour)
        await self.serve()
        role = "CONSENSUS" if self.replica.is_consensus else "candidate"
        lead = " (LEADER)" if self.replica.leader == self.id else ""
        self.log("ready", f"AGS-PBFT {self.ccfg.mode} replica up as {role}{lead}; behaviour={behaviour}; "
                 f"consensus set {self.replica.consensus}", consensus=self.replica.consensus)
        self._ev = 0
        asyncio.ensure_future(self.crl_loop())
        # proactively open the mesh to higher-id nodes
        for n in self.ccfg.nodes:
            if n > self.id:
                asyncio.ensure_future(self.connect(n))
        crash_at = self.me_cfg.get("crash_at")
        while True:
            await asyncio.sleep(0.01)
            if crash_at is not None and self.elapsed() >= crash_at:
                self.log("crash", f"*** simulated crash at t={self.elapsed():.1f}s ***")
                os._exit(0)
            await self._emit(self.replica.tick(time.time()))
            self._drain_events()

    async def _send_to(self, dest: str, raw: bytes) -> None:
        msg = {"type": "cons", "raw": raw}
        if dest in self.channels:
            if await self.send(dest, msg):
                return
        if dest in self.ccfg.clients or self.id < dest:
            await self.send(dest, msg)
            return
        for _ in range(100):  # wait for the lower-id peer to connect to us
            if dest in self.channels:
                await self.send(dest, msg)
                return
            await asyncio.sleep(0.05)

    async def _emit(self, out) -> None:
        for dest, raw in out:
            asyncio.ensure_future(self._send_to(dest, raw))

    def _drain_events(self) -> None:
        evs = self.replica.events[self._ev:]
        self._ev = len(self.replica.events)
        for kind, info in evs:
            if kind == "commit":
                b = self.replica.ledger.blocks[-1]
                s = b.summary()
                self.log("commit", f"block #{b.b_id} committed (view {b.view}, leader {b.leader}, "
                         f"txn {s['txn_id']}, cert {len(b.cert)} sigs, hash {s['hash']})", **s)
            elif kind == "regroup":
                self.log("regroup", f"REGROUP at block {info['b_id']}: promoted {info['promoted']} "
                         f"demoted {info['demoted']} -> consensus {info['consensus']}", **info)
            elif kind in ("view-change-sent", "new-view", "new-view-accepted"):
                self.log(kind, f"{kind.upper()} {info}", **info)
            elif kind.startswith("dbg-"):
                self.log(kind, **info)
            elif kind in ("reject-block", "equivocation"):
                self.log(kind, f"{kind}: {info}", **info)

    async def on_message(self, ch, msg) -> None:
        if msg.get("type") != "cons":
            return
        out = self.replica.handle(msg["raw"], time.time())
        if os.environ.get("QRCAV_DEBUG"):
            from .. import codec as _c
            d = _c.decode(msg["raw"])
            self.log("rx", mtype=d.get("t"), frm=d.get("from"), out=[(x, _c.decode(r).get("t")) for x, r in out])
        await self._emit(out)
        self._drain_events()


def main() -> None:
    main_for(ConsensusNode)


if __name__ == "__main__":
    main()
