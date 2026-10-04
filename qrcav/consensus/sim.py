"""
In-process discrete-event harness for the consensus layer.

Runs real Replica and ConsensusClient objects with real ML-DSA signatures and
verifications. Time is simulated: each message spends

    link latency + size / bandwidth   on the wire, then
    the measured wall-clock time of the handler that processes it

so latency figures include true cryptographic cost without needing a real
network. Every node processes one message at a time (a queue per node), which
is what a single-threaded validator does.

Used by the evaluation (message counts, bytes, latency, fault tolerance,
score dynamics, view change) and by the unit tests.
"""

from __future__ import annotations

import heapq
import itertools
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .. import codec
from ..crypto.suites import Suite, get_suite
from ..pki import TrustedAuthority, enrol_all
from .agspbft import ConsensusConfig, Replica, verify_chain
from .client import ConsensusClient, CompletedRequest
from .messages import Directory


@dataclass
class NetStats:
    msgs: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def total_msgs(self) -> int:
        return sum(self.msgs.values())

    @property
    def total_bytes(self) -> int:
        return sum(self.bytes.values())


class ConsensusSim:
    def __init__(
        self,
        n_nodes: int = 8,
        mode: str = "ags",
        suite: Suite | None = None,
        behaviours: dict[str, str] | None = None,
        latency_ms: float = 1.0,
        bandwidth_mbps: float = 1000.0,
        measure_compute: bool = True,
        tick_ms: float = 5.0,
        seed: int = 1,
        jitter_ms: float = 0.0,
        **cfg_kwargs,
    ) -> None:
        self.suite = suite or get_suite()
        self.rng = random.Random(seed)
        self.ta = TrustedAuthority(self.suite)
        names = [f"NODE_{i:02d}" for i in range(1, n_nodes + 1)]
        ids = enrol_all(self.ta, [(n, "NODE") for n in names] + [("MEC_01", "MEC")])
        self.directory = Directory(self.suite, self.ta.pk)
        for i in ids.values():
            self.directory.add(i.cert)
        cfg_kwargs.setdefault("seed", seed)
        self.cfg = ConsensusConfig(nodes=names, mode=mode, clients=("MEC_01",), **cfg_kwargs)
        behaviours = behaviours or {}
        self.now = 0.0
        self.replicas = {
            n: Replica(ids[n], self.cfg, self.directory, behaviour=behaviours.get(n, "honest"),
                       clock=lambda: self.now)
            for n in names
        }
        self.client = ConsensusClient(ids["MEC_01"], self.cfg, self.directory,
                                      timeout=max(1.0, self.cfg.view_change_timeout * 1.5))
        self.latency = latency_ms / 1000
        self.bw = bandwidth_mbps * 1e6
        self.measure = measure_compute
        self.tick = tick_ms / 1000
        self.q: list = []
        self._ctr = itertools.count()
        self.busy: dict[str, float] = defaultdict(float)
        self.stats = NetStats()
        self.done: list[CompletedRequest] = []
        self.compute_s: dict[str, float] = defaultdict(float)
        self.partitioned: set[str] = set()
        self.jitter = jitter_ms / 1000
        self._last_arrival: dict = {}

    # -- scheduling -----------------------------------------------------------

    def _push(self, t: float, kind: str, dest: str, raw: bytes | None, src: str = "") -> None:
        heapq.heappush(self.q, (t, next(self._ctr), kind, dest, raw, src))

    def _emit(self, src: str, out, t: float) -> None:
        for dest, raw in out:
            if src in self.partitioned or dest in self.partitioned:
                continue
            t_type = codec.decode_dict(raw, "t")["t"]
            self.stats.msgs[t_type] += 1
            self.stats.bytes[t_type] += len(raw)
            arrival = t + self.latency + len(raw) * 8 / self.bw
            if self.jitter:
                # per-link FIFO like TCP: never deliver before the previous message on this link
                key = (src, dest)
                arrival = max(arrival + self.rng.random() * self.jitter, self._last_arrival.get(key, 0.0))
                self._last_arrival[key] = arrival
            self._push(arrival, "msg", dest, raw, src)

    def _process(self, node: str, fn, arrival: float):
        start = max(arrival, self.busy[node])
        self.now = start
        t0 = time.perf_counter()
        out = fn(start)
        dt = time.perf_counter() - t0 if self.measure else 0.0
        self.compute_s[node] += dt
        end = start + dt
        self.busy[node] = end
        return out, end

    # -- driving --------------------------------------------------------------

    def submit(self, at: float, txn_id: str, entity_id: str = "MEC_01", data=None) -> None:
        self._push(at, "submit", "MEC_01", codec.encode({"txn": txn_id, "entity": entity_id,
                                                          "data": data or {"event": "hazard"}}))

    def run(self, until: float) -> None:
        """Advance simulated time to `until`. May be called repeatedly."""
        t = getattr(self, "_ticked_to", 0.0)
        self._ticked_to = until + self.tick
        while t <= until:
            for n in self.replicas:
                self._push(t, "tick", n, None)
            self._push(t, "tick", "MEC_01", None)
            t += self.tick
        while self.q:
            at, _, kind, dest, raw, src = self.q[0]
            if at > until:
                break
            heapq.heappop(self.q)
            if kind == "submit":
                d = codec.decode(raw)
                out = self.client.submit(d["txn"], d["entity"], d["data"], at)
                self._emit("MEC_01", out, at)
            elif dest == "MEC_01":
                if kind == "tick":
                    self._emit("MEC_01", self.client.tick(at), at)
                else:
                    c = self.client.on_reply(raw, at)
                    if c is not None:
                        self.done.append(c)
            else:
                r = self.replicas[dest]
                if kind == "tick":
                    if self.busy[dest] > at:
                        continue
                    out, end = self._process(dest, r.tick, at)
                else:
                    out, end = self._process(dest, lambda now, raw=raw: r.handle(raw, now), at)
                self._emit(dest, out, end)
        self.now = until

    # -- results ---------------------------------------------------------------

    def heights(self) -> dict[str, int]:
        return {n: r.ledger.height for n, r in self.replicas.items()}

    def chains_consistent(self, honest_only: bool = True) -> bool:
        heads = {}
        for n, r in self.replicas.items():
            if honest_only and r.behaviour != "honest":
                continue
            heads[n] = [b.hash for b in r.ledger.blocks]
        if not heads:
            return True
        ref = max(heads.values(), key=len)
        return all(h == ref[: len(h)] for h in heads.values())

    def chain_valid(self) -> bool:
        honest = [r for r in self.replicas.values() if r.behaviour == "honest"]
        best = max(honest, key=lambda r: r.ledger.height)
        return verify_chain(best.ledger, self.directory, self.cfg)

    def events(self, kind: str | None = None) -> list[tuple[str, str, dict]]:
        out = []
        for n, r in self.replicas.items():
            for k, info in r.events:
                if kind is None or k == kind:
                    out.append((n, k, info))
        return out
