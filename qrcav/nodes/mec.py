"""
MEC (edge) server: the routing point of deck slide 21.

  CRITICALITY == 1 (safety-critical, time-sensitive)
      1. immediately send an actuation / alert back to the RSUs, so vehicles
         are warned without waiting for consensus
      2. submit the event to the consensus layer as a signed REQUEST; when the
         block is certified, tell the originating RSU (and so the vehicle)
         which block recorded it
  CRITICALITY == 0 (routine)
      forward to the cloud for archiving

Consensus must never sit on the actuation path: a PBFT round with an ML-DSA
signature at every phase costs tens to hundreds of milliseconds, more than a
safety warning can wait. The ledger records what happened; it does not gate
the response.
"""

from __future__ import annotations

import asyncio
import time

from ..consensus.client import ConsensusClient
from .base import NodeBase, main_for
from .consensus_node import build_directory, consensus_config


class MECNode(NodeBase):
    ROLE = "MEC"
    ALLOWED_PEERS = ("RSU",)

    async def run(self) -> None:
        await self.bootstrap()
        self.ccfg = consensus_config(self.cfg)
        self.dir = await build_directory(self, set(self.ccfg.nodes) | {self.id})
        self.client = ConsensusClient(self.identity, self.ccfg, self.dir,
                                      timeout=self.cfg["consensus"].get("client_timeout", 4.0))
        self.origin: dict[str, tuple[str, float, dict]] = {}   # txn -> (rsu, t_received, event)
        self.served_rsus = [r["id"] for r in self.cfg["rsus"] if r.get("mec") == self.id]
        await self.serve()
        self.log("ready", f"MEC ready; serving RSUs {self.served_rsus}; consensus leader "
                 f"{self.client.leader}")
        asyncio.ensure_future(self.crl_loop())
        for n in self.ccfg.nodes:
            asyncio.ensure_future(self.connect(n))
        asyncio.ensure_future(self.connect(self.cfg["cloud"]["id"]))
        while True:
            await asyncio.sleep(0.05)
            for dest, raw in self.client.tick(time.time()):
                asyncio.ensure_future(self.send(dest, {"type": "cons", "raw": raw}))
                self.log("retransmit", f"consensus timeout -> rebroadcast request to {dest}", dest=dest)

    async def on_message(self, ch, msg) -> None:
        t = msg.get("type")
        if t == "event" and ch.peer_role == "RSU":
            await self._on_event(ch.peer_id, msg)
        elif t == "cons" and ch.peer_role == "NODE":
            done = self.client.on_reply(msg["raw"], time.time())
            if done is not None:
                rsu, t_rx, ev = self.origin.pop(done.txn_id, (None, None, {}))
                self.log("committed", f"event {done.txn_id} committed in block #{done.b_id} "
                         f"(view {done.view}) {done.latency * 1000:.0f} ms after submission",
                         event_id=done.txn_id, b_id=done.b_id, view=done.view,
                         latency_ms=done.latency * 1000, retries=done.retries)
                if rsu:
                    await self.send(rsu, {"type": "recorded", "event_id": done.txn_id, "b_id": done.b_id,
                                          "src": ev.get("src"), "t_event": ev.get("ts")})
        elif t == "stored":
            pass

    async def _on_event(self, rsu: str, msg: dict) -> None:
        ev = msg["event"]
        reporter_cert = msg.get("reporter_cert")
        t_rx = time.time()
        if int(ev.get("criticality", 0)) == 1:
            # critical path: actuate first ...
            alert = {"type": "actuate", "event_id": ev["event_id"], "kind": ev["kind"],
                     "src": ev["src"], "pos": ev.get("pos"), "t_event": ev["ts"], "t_mec": t_rx}
            targets = [rsu] + [r for r in self.served_rsus if r != rsu]
            for r in targets:
                asyncio.ensure_future(self.send(r, alert))
            self.log("critical", f"CRITICAL {ev['kind']} from {ev['src']} via {rsu}: alert -> {targets}; "
                     f"submitting to consensus", event_id=ev["event_id"],
                     mec_delay_ms=(t_rx - ev["ts"]) * 1000)
            # ... then record on the ledger
            self.origin[ev["event_id"]] = (rsu, t_rx, ev)
            for dest, raw in self.client.submit(ev["event_id"], ev["src"],
                                                {"kind": ev["kind"], "pos": ev.get("pos"),
                                                 "rsu": rsu, "data": ev.get("data"),
                                                 "reporter_cert": reporter_cert}, time.time()):
                await self.send(dest, {"type": "cons", "raw": raw})
        else:
            self.log("non-critical", f"routine {ev['kind']} from {ev['src']} -> cloud",
                     event_id=ev["event_id"])
            await self.send(self.cfg["cloud"]["id"], {"type": "store", "record": {**ev, "rsu": rsu}})


def main() -> None:
    main_for(MECNode)


if __name__ == "__main__":
    main()
