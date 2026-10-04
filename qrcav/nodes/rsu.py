"""
Roadside unit (deck slides 11, 19, 20).

  * accepts secure sessions from vehicles and from neighbouring RSUs
  * keeps a secure session to its MEC server
  * beacons: verifies and counts them (they are protected by the session's
    AEAD, so no per-beacon signature is needed)
  * events: forwards them to the MEC
  * V2V: CAV -> RSU -> (neighbour RSU) -> CAV, re-encrypted on every hop.
    The RSUs see the plaintext, so this is confidential against outsiders
    but not end-to-end against the infrastructure; the deck's design has
    the same property.
  * actuation from the MEC: broadcast an alert to every connected vehicle
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from .base import NodeBase, main_for


class RSUNode(NodeBase):
    ROLE = "RSU"
    ALLOWED_PEERS = ("CAV", "RSU")

    async def run(self) -> None:
        await self.bootstrap()
        self.mec = self.me_cfg["mec"]
        self.neighbours = self.me_cfg.get("neighbours", [])
        self.seen_v2v: deque[str] = deque(maxlen=2000)
        self.beacons: dict[str, int] = {}
        self.beacon_lat: list[float] = []
        await self.serve()
        self.log("ready", f"RSU up at {self.me_cfg.get('pos')}; MEC {self.mec}; neighbours {self.neighbours}")
        asyncio.ensure_future(self.crl_loop())
        asyncio.ensure_future(self.connect(self.mec))
        for n in self.neighbours:
            if self.id < n:
                asyncio.ensure_future(self.connect(n))
        while True:
            await asyncio.sleep(5)
            if self.beacons:
                lat = sorted(self.beacon_lat) or [0.0]
                self.log("beacon-stats", f"beacons: {dict(self.beacons)}; median receive delay "
                         f"{lat[len(lat) // 2] * 1000:.2f} ms",
                         counts=dict(self.beacons), median_ms=lat[len(lat) // 2] * 1000)
                self.beacon_lat.clear()

    def _cavs(self) -> list[str]:
        return [p for p, ch in self.channels.items() if ch.peer_role == "CAV"]

    async def on_connect(self, ch) -> None:
        if ch.peer_role == "CAV":
            await ch.send({"type": "welcome", "rsu": self.id, "pos": self.me_cfg.get("pos")})

    async def on_message(self, ch, msg) -> None:
        t = msg.get("type")
        now = time.time()
        if ch.peer_role == "CAV":
            if msg.get("src") != ch.peer_id:
                self.log("spoof", f"{ch.peer_id} claimed src={msg.get('src')}; dropped")
                return  # the session is bound to an identity; a CAV cannot speak for another
            if t == "beacon":
                self.beacons[ch.peer_id] = self.beacons.get(ch.peer_id, 0) + 1
                self.beacon_lat.append(now - msg["ts"])
            elif t == "event":
                self.log("event", f"event {msg['kind']} (crit={msg['criticality']}) from {ch.peer_id} "
                         f"-> MEC", event_id=msg["event_id"], criticality=msg["criticality"])
                # attach the reporter's TA-signed certificate (held from the handshake) so
                # consensus nodes can check the reporter is registered without a lookup
                await self.send(self.mec, {"type": "event", "event": msg,
                                           "reporter_cert": ch.session.peer.encode()})
                await ch.send({"type": "ack", "event_id": msg["event_id"]})
            elif t == "v2v":
                await self._route_v2v(msg, ttl=2)
        elif ch.peer_role == "RSU" and t == "v2v_relay":
            await self._route_v2v(msg["msg"], ttl=int(msg.get("ttl", 0)))
        elif ch.peer_role == "MEC":
            if t == "actuate":
                cavs = self._cavs()
                for c in cavs:
                    asyncio.ensure_future(self.channels[c].send({**msg, "type": "alert", "rsu": self.id}))
                self.log("actuate", f"ALERT {msg['kind']} (event {msg['event_id']}) broadcast to {cavs}",
                         event_id=msg["event_id"], to=cavs)
            elif t == "recorded":
                if msg.get("src") in self.channels:
                    await self.channels[msg["src"]].send(msg)

    async def _route_v2v(self, m: dict, ttl: int) -> None:
        if m["msg_id"] in self.seen_v2v:
            return
        self.seen_v2v.append(m["msg_id"])
        dst = m["dst"]
        if dst in self.channels and self.channels[dst].peer_role == "CAV":
            await self.channels[dst].send(m)
            self.log("v2v", f"delivered V2V {m['msg_id']} {m['src']} -> {dst}", msg_id=m["msg_id"])
            return
        if ttl <= 0:
            return
        for n in self.neighbours:
            await self.send(n, {"type": "v2v_relay", "msg": m, "ttl": ttl - 1})
        self.log("v2v", f"relayed V2V {m['msg_id']} for {dst} to neighbours {self.neighbours}",
                 msg_id=m["msg_id"])


def main() -> None:
    main_for(RSUNode)


if __name__ == "__main__":
    main()
