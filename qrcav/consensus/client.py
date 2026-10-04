"""
Consensus client (the MEC server's side of slides 18, 22 and 30).

Sends signed REQUESTs to the current leader, accepts the result once it is
provably committed, and on timeout re-broadcasts to the whole consensus set,
which is what lets replicas notice a faulty leader and start a view change.

  AGS-PBFT : one REPLY is enough, because it carries the block with its
             commit certificate (2f+1 signed RESPONSEs) that the client checks.
  PBFT     : wait for f+1 matching REPLYs from distinct replicas (textbook).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .. import codec
from ..ledger import Block
from ..pki import Identity
from .agspbft import ConsensusConfig, f_of, leader_of, make_request, quorum
from .messages import REPLY, RESPONSE, Directory, request_digest

Out = list[tuple[str, bytes]]


@dataclass
class PendingRequest:
    txn_id: str
    raw: bytes
    sent_at: float
    deadline: float
    retries: int = 0
    replies: dict[str, bytes] = field(default_factory=dict)


@dataclass
class CompletedRequest:
    txn_id: str
    result: bytes
    b_id: int
    view: int
    latency: float
    retries: int
    block: Block | None


class ConsensusClient:
    def __init__(
        self, identity: Identity, cfg: ConsensusConfig, directory: Directory, timeout: float = 3.0,
    ) -> None:
        self.me = identity
        self.cfg = cfg
        self.dir = directory
        self.timeout = timeout
        self.view = 0
        self.consensus = list(cfg.initial_consensus)
        self.pending: dict[str, PendingRequest] = {}
        self.completed: list[CompletedRequest] = []
        self.sent = 0
        self.sent_bytes = 0

    @property
    def leader(self) -> str:
        return leader_of(self.view, self.consensus)

    def submit(self, txn_id: str, entity_id: str, data: Any, now: float, criticality: int = 1) -> Out:
        raw = make_request(self.me, txn_id, entity_id, data, now, criticality)
        self.pending[txn_id] = PendingRequest(txn_id, raw, now, now + self.timeout)
        self.sent += 1
        self.sent_bytes += len(raw)
        return [(self.leader, raw)]

    def tick(self, now: float) -> Out:
        out: Out = []
        for p in self.pending.values():
            if now >= p.deadline:
                p.retries += 1
                p.deadline = now + self.timeout * (2 ** min(p.retries, 4))
                for n in self.consensus:   # broadcast: lets backups detect a faulty leader
                    out.append((n, p.raw))
                    self.sent += 1
                    self.sent_bytes += len(p.raw)
        return out

    def _verify_cert(self, block: Block) -> bool:
        cons = set(self.consensus)
        q = quorum(len(cons))
        agree = set()
        for raw in block.cert:
            e = self.dir.open(raw, RESPONSE)
            if e is None:
                continue
            if e.sender in cons and bytes(e.body["result"]) == block.result \
                    and int(e.body["n"]) == block.seq and int(e.body["v"]) == block.view:
                agree.add(e.sender)
        return len(agree) >= q

    def on_reply(self, raw: bytes, now: float) -> CompletedRequest | None:
        env = self.dir.open(raw, REPLY)
        if env is None:
            return None
        txn = env.body.get("txn_id")
        p = self.pending.get(txn)
        if p is None:
            return None
        if self.cfg.mode == "ags":
            try:
                block = Block.decode(env.body["block"])
            except Exception:
                return None
            if request_digest(block.request) != request_digest(p.raw) or block.leader != env.sender:
                return None
            if not self._verify_cert(block):
                return None
            self.view = max(self.view, block.view)
            self.consensus = list(block.consensus)
            done = CompletedRequest(txn, block.result, block.b_id, block.view, now - p.sent_at, p.retries, block)
        else:
            if env.sender not in self.consensus:
                return None
            p.replies[env.sender] = bytes(env.body["result"])
            counts: dict[bytes, int] = defaultdict(int)
            for r in p.replies.values():
                counts[r] += 1
            res, c = max(counts.items(), key=lambda kv: kv[1])
            if c < f_of(len(self.consensus)) + 1:
                return None
            self.view = max(self.view, int(env.body.get("view", 0)))
            done = CompletedRequest(txn, res, int(env.body.get("B_ID", 0)), self.view, now - p.sent_at,
                                    p.retries, None)
        del self.pending[txn]
        self.completed.append(done)
        return done
