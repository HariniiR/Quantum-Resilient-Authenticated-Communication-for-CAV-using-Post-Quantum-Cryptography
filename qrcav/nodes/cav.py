"""
Connected autonomous vehicle (CAV) process.

  * registers with the TA, opens a secure session to its RSU
  * sends 10 Hz beacons (position, speed, heading) as AEAD records
  * runs a script of actions from its config entry, e.g.
        {"at": 4.0, "action": "event", "kind": "collision_ahead", "criticality": 1}
        {"at": 6.0, "action": "event", "kind": "road_condition", "criticality": 0}
        {"at": 8.0, "action": "v2v", "dst": "CAV_03", "text": "merging left"}
        {"at": 12.0, "action": "handover", "rsu": "RSU_02"}
  * logs alerts, V2V messages and ledger confirmations it receives
"""

from __future__ import annotations

import asyncio
import math
import time

from .base import NodeBase, main_for


class CAVNode(NodeBase):
    ROLE = "CAV"
    ALLOWED_PEERS = ()  # vehicles only initiate

    async def run(self) -> None:
        await self.bootstrap()
        self.rsu = self.me_cfg["rsu"]
        self.seq = 0
        self.ev = 0
        self.hz = float(self.me_cfg.get("beacon_hz", self.cfg.get("beacon_hz", 10)))
        x0, y0 = self.me_cfg.get("start", [0.0, 0.0])
        self.pos = [float(x0), float(y0)]
        self.speed = float(self.me_cfg.get("speed", 13.9))
        self.heading = float(self.me_cfg.get("heading", 0.0))
        self.log("ready", f"vehicle up; associating with {self.rsu}")
        asyncio.ensure_future(self.crl_loop())
        await self._associate(self.rsu)
        asyncio.ensure_future(self.script())
        period = 1.0 / self.hz
        nxt = time.time()
        while True:
            nxt += period
            await asyncio.sleep(max(0, nxt - time.time()))
            self.pos[0] += self.speed * period * math.cos(math.radians(self.heading))
            self.pos[1] += self.speed * period * math.sin(math.radians(self.heading))
            ch = self.channels.get(self.rsu)
            if ch is None or ch.closed:
                continue
            self.seq += 1
            await self.send(self.rsu, {"type": "beacon", "src": self.id, "seq": self.seq, "ts": time.time(),
                                       "pos": [round(self.pos[0], 1), round(self.pos[1], 1)],
                                       "speed": self.speed, "heading": self.heading})

    async def _associate(self, rsu: str) -> bool:
        ch = await self.connect(rsu, retries=3)
        if ch is None:
            self.log("assoc-failed", f"could not establish a session with {rsu} (rejected or unreachable)",
                     rsu=rsu)
            return False
        return True

    async def script(self) -> None:
        steps = []
        for st in self.me_cfg.get("script", []):
            for k in range(int(st.get("repeat", 1))):
                steps.append({**st, "at": st["at"] + k * float(st.get("every", 1.0))})
        for step in sorted(steps, key=lambda s: s["at"]):
            await asyncio.sleep(max(0, self.t0 + step["at"] - time.time()))
            a = step["action"]
            if a == "event":
                self.ev += 1
                eid = f"{self.id}-E{self.ev}"
                ok = await self.send(self.rsu, {
                    "type": "event", "event_id": eid, "src": self.id, "kind": step["kind"],
                    "criticality": int(step.get("criticality", 1)), "ts": time.time(),
                    "pos": [round(self.pos[0], 1), round(self.pos[1], 1)], "data": step.get("data", {}),
                })
                crit = "CRITICAL" if int(step.get("criticality", 1)) else "routine"
                self.log("event-sent", f"reported {crit} event {step['kind']} as {eid}"
                         + ("" if ok else " (FAILED: no session)"), event_id=eid, ok=ok)
            elif a == "v2v":
                self.ev += 1
                mid = f"{self.id}-M{self.ev}"
                await self.send(self.rsu, {"type": "v2v", "msg_id": mid, "src": self.id, "dst": step["dst"],
                                           "text": step.get("text", ""), "ts": time.time()})
                self.log("v2v-sent", f"V2V {mid} -> {step['dst']}: {step.get('text', '')!r}", msg_id=mid)
            elif a == "handover":
                old = self.rsu
                ch = self.channels.pop(old, None)
                if ch:
                    ch.close()
                self.rsu = step["rsu"]
                t = time.perf_counter()
                ok = await self._associate(self.rsu)
                self.log("handover", f"handover {old} -> {self.rsu}: "
                         f"{'ok' if ok else 'FAILED'} in {(time.perf_counter() - t) * 1000:.1f} ms",
                         old=old, new=self.rsu, ok=ok)
            elif a == "reconnect":
                ch = self.channels.pop(self.rsu, None)
                if ch:
                    ch.close()
                await self._associate(self.rsu)

    async def on_message(self, ch, msg) -> None:
        t = msg.get("type")
        now = time.time()
        if t == "alert":
            own = msg.get("src") == self.id
            self.log("alert", f"ALERT received: {msg['kind']} reported by {msg['src']} "
                     f"({(now - msg['t_event']) * 1000:.1f} ms after the event)",
                     event_id=msg["event_id"], latency_ms=(now - msg["t_event"]) * 1000, own=own)
        elif t == "v2v":
            self.log("v2v-recv", f"V2V from {msg['src']}: {msg.get('text')!r} "
                     f"({(now - msg['ts']) * 1000:.1f} ms)", msg_id=msg["msg_id"],
                     latency_ms=(now - msg["ts"]) * 1000)
        elif t == "recorded":
            self.log("recorded", f"event {msg['event_id']} is on the ledger in block #{msg['b_id']} "
                     f"({(now - msg['t_event']) * 1000:.0f} ms after the event)",
                     event_id=msg["event_id"], b_id=msg["b_id"], latency_ms=(now - msg["t_event"]) * 1000)

    async def on_disconnect(self, ch) -> None:
        if not self.stopping and ch.peer_id == self.rsu:
            self.log("disconnected", f"session with {ch.peer_id} closed; re-associating")
            await asyncio.sleep(0.5)
            await self._associate(self.rsu)


def main() -> None:
    main_for(CAVNode)


if __name__ == "__main__":
    main()
