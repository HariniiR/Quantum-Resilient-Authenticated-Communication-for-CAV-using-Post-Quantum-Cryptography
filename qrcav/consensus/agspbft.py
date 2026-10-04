"""
AGS-PBFT: Adaptive Grouping Score Practical Byzantine Fault Tolerance.

Implements deck slides 22-29 (the base paper's Algorithm 2 and section 5.4),
plus view change, as a "sans-IO" state machine: a Replica consumes signed
messages and timer ticks and returns the messages it wants to send. It never
touches a socket, so the same code runs

  * over TCP between real processes            (qrcav/nodes/consensus_node.py)
  * in an in-process discrete-event simulator  (qrcav/consensus/sim.py)

Normal case (slides 22-24, 28)
------------------------------
  REQUEST      client (MEC) -> leader            signed Sign_c
  PRE-PREPARE  leader -> consensus set (+ candidates as shadow validators)
  PREPARE      every consensus node -> every consensus node
  RESPONSE     after 2f+1 matching PREPAREs, each node -> leader, carrying its
               own execution result for the request
  COMMIT       after 2f+1 matching RESPONSEs the leader builds the block,
               whose commit certificate is those signed RESPONSEs, and sends
               it to every node; each node re-verifies before appending
  REPLY        leader -> client, with the certified block

Score update and regrouping (slide 25)
--------------------------------------
  +1  for a node whose result matches the committed result
  -5  for a node whose result differs
   0  for a node that did not respond (see D7 below)
  Every `regroup_interval` committed requests:
      mu, sigma over all scores
      consensus nodes with score < mu - sigma  -> candidate set
      candidates      with score > mu + sigma  -> consensus set
      resize the consensus set to 3f+1 for the f chosen from load (D8)

View change (slides 26-27, 29)
-----------------------------
  A consensus node that has seen a request but not its commit within the
  timeout multicasts VIEW-CHANGE(v+1) with its prepared certificates. A node
  that sees f+1 VIEW-CHANGEs for a higher view joins it. The new leader, on
  2f+1, sends NEW-VIEW with re-issued PRE-PREPAREs for every prepared request
  (no-ops for gaps); replicas recompute and check them, then resume at PREPARE.

Design decisions where the paper / deck leave things undefined
---------------------------------------------------------------
  D6  sigma = 0 (every node starts at 100): mu - sigma == mu + sigma, so every
      node is both above and below threshold. Regrouping is skipped while
      sigma == 0; nothing distinguishes the nodes yet.
  D7  Candidates cannot earn score if they never take part, so they could
      never be promoted. Candidates receive the PRE-PREPARE and send a signed
      SHADOW-RESPONSE with their own result. It is scored but does not count
      towards quorum. A node that sends nothing scores 0 for that request;
      since honest nodes gain +1 per request, silent nodes sink below mu-sigma
      and are demoted. (Scoring absence as -5 would let a Byzantine leader
      punish honest nodes by leaving their responses out of the block.)
  D8  "Group size adjusted based on network activity" is made concrete: over
      the last interval, request rate r (from request timestamps, so every
      node computes the same value). r <= load_low -> f = f_max (more
      redundancy when quiet); r >= load_high -> f = f_min (fewer messages
      under load); linear in between. Consensus set size = 3f + 1.
  D9  Deck slide 24 counts 2f+1 PREPAREs. Here the leader also issues a
      PREPARE for its own proposal, so 2f+1 is reachable with f faulty
      backups.

The textbook PBFT baseline (mode="pbft") reuses the same code with every node
in the consensus set, a real all-to-all COMMIT phase in place of
RESPONSE-to-leader, replies from every replica, and no scoring.
"""

from __future__ import annotations

import random
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import codec
from ..crypto.kdf import H
from ..ledger import Block, Ledger
from ..pki import Certificate, Identity
from .messages import (
    COMMIT, NEW_VIEW, PBFT_COMMIT, PRE_PREPARE, PREPARE, REPLY, REQUEST, RESPONSE,
    SHADOW, SYNC_REQ, SYNC_RESP, VIEW_CHANGE, Directory, Envelope, request_digest, seal,
)

Out = list[tuple[str, bytes]]


@dataclass
class ConsensusConfig:
    nodes: list[str]
    mode: str = "ags"                      # "ags" or "pbft"
    initial_consensus: list[str] | None = None
    seed: int = 7
    initial_score: int = 100
    agree_delta: int = 1
    disagree_delta: int = -5
    regroup_interval: int = 50
    shadow_candidates: bool = True         # D7
    adaptive_size: bool = True             # D8
    f_min: int = 1
    f_max: int | None = None               # default: largest f with 3f+1 <= N/2
    load_low: float = 2.0                  # requests per second
    load_high: float = 20.0
    view_change_timeout: float = 2.0       # seconds
    response_grace: float = 0.02           # leader waits this long after quorum for stragglers
    clients: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.nodes = sorted(self.nodes)
        n = len(self.nodes)
        if self.mode not in ("ags", "pbft"):
            raise ValueError("mode must be ags or pbft")
        if self.mode == "pbft":
            self.initial_consensus = list(self.nodes)
        if self.f_max is None:
            self.f_max = max(1, (n // 2 - 1) // 3) if self.mode == "ags" else (n - 1) // 3
        if self.initial_consensus is None:
            # Paper: nodes split randomly, half of them candidates, CN >= 3f+1.
            size = max(4, 3 * self.f_max + 1)
            rng = random.Random(self.seed)
            self.initial_consensus = sorted(rng.sample(self.nodes, min(size, n)))
        if len(self.initial_consensus) < 4:
            raise ValueError("consensus set needs at least 4 nodes (f >= 1)")


def f_of(size: int) -> int:
    return (size - 1) // 3


def quorum(size: int) -> int:
    return 2 * f_of(size) + 1


def leader_of(view: int, consensus: list[str]) -> str:
    """ALGORITHM LeaderSelection (slide 22): p <- v mod |R|; leader <- R[p]."""
    r = sorted(consensus)
    return r[view % len(r)]


# ---------------------------------------------------------------------------
# Deterministic application logic: the "individual result" each node computes
# ---------------------------------------------------------------------------

def execute(request_body: dict, ledger: Ledger, directory: Directory) -> bytes:
    """
    Validate a transaction. Honest nodes compute the same verdict:
      - required fields present
      - the reporting entity is a registered identity
      - the transaction id has not been committed before
    The result is H(verdict) so it is fixed-size.
    """
    try:
        if request_body.get("noop"):
            return H(b"result", b"NOOP")
        for k in ("txn_id", "entity_id", "data", "ts"):
            if k not in request_body:
                return H(b"result", b"REJECT:missing-" + k.encode())
        # The reporting entity must be registered. This is decided from the request
        # itself, not from each node's local view of the registry: the RSU attaches
        # the vehicle's TA-signed certificate (which it holds from the handshake), and
        # every node verifies it against pk_TA. A local lookup made honest nodes
        # disagree whenever a node had fetched the registry before the vehicle enrolled.
        data = request_body.get("data") if isinstance(request_body.get("data"), dict) else {}
        raw_cert = data.get("reporter_cert")
        if raw_cert is not None and directory.anchor is not None:
            cert = Certificate.decode(raw_cert)
            ts = float(request_body["ts"])
            ref = int(ts) if ts > 1e9 else None    # simulations use simulated time, not epoch time
            if cert.id != str(request_body["entity_id"]) or not directory.anchor.verify_cert(cert, now=ref):
                return H(b"result", b"REJECT:bad-reporter-certificate")
        elif directory.role(str(request_body["entity_id"])) is None:
            return H(b"result", b"REJECT:unknown-entity")
        txn = str(request_body["txn_id"])
        for b in ledger.blocks[-500:]:
            body = codec.decode(b.request).get("body", {})
            if body.get("txn_id") == txn:
                return H(b"result", b"REJECT:duplicate")
        return H(b"result", b"ACCEPT")
    except Exception:
        return H(b"result", b"REJECT:malformed")


def apply_scores(
    scores: dict[str, int], final_result: bytes, responses: dict[str, bytes],
    agree: int, disagree: int,
) -> dict[str, int]:
    """SCORE_UPDATE steps 1-2 (slide 25). Absent nodes are unchanged (D7)."""
    new = dict(scores)
    for node, res in responses.items():
        if node in new:
            new[node] += agree if res == final_result else disagree
    return new


def regroup(
    scores: dict[str, int], consensus: list[str], cfg: ConsensusConfig, rate: float | None,
) -> list[str]:
    """SCORE_UPDATE step 3-4 (slide 25), with D6 and D8."""
    nodes = sorted(scores)
    vals = [scores[n] for n in nodes]
    mu = statistics.fmean(vals)
    sigma = statistics.pstdev(vals)
    cons = set(consensus)
    if sigma > 0:  # D6
        t_low, t_high = mu - sigma, mu + sigma
        cons -= {n for n in cons if scores[n] < t_low}
        cons |= {n for n in nodes if n not in cons and scores[n] > t_high}
    # target size (D8)
    if cfg.adaptive_size and rate is not None:
        if rate <= cfg.load_low:
            f = cfg.f_max
        elif rate >= cfg.load_high:
            f = cfg.f_min
        else:
            frac = (rate - cfg.load_low) / (cfg.load_high - cfg.load_low)
            f = round(cfg.f_max - frac * (cfg.f_max - cfg.f_min))
    else:
        f = f_of(len(consensus))
    target = min(len(nodes), max(4, 3 * f + 1))
    rank = sorted(nodes, key=lambda n: (-scores[n], n))   # best first, ties by id
    cur = [n for n in rank if n in cons]
    if len(cur) > target:
        cur = cur[:target]                                # drop the lowest scorers
    elif len(cur) < target:
        for n in rank:
            if len(cur) >= target:
                break
            if n not in cur:
                cur.append(n)                             # promote the best candidates
    return sorted(cur)


def request_rate(blocks: list[Block]) -> float | None:
    ts = []
    for b in blocks:
        body = codec.decode(b.request).get("body", {})
        if "ts" in body and not body.get("noop"):
            ts.append(float(body["ts"]))
    if len(ts) < 2 or max(ts) <= min(ts):
        return None
    return (len(ts) - 1) / (max(ts) - min(ts))


# ---------------------------------------------------------------------------
# Replica
# ---------------------------------------------------------------------------

@dataclass
class Slot:
    view: int
    seq: int
    pp: Envelope | None = None
    req_raw: bytes = b""
    req_body: dict = field(default_factory=dict)
    digest: bytes = b""
    prepares: dict[str, Envelope] = field(default_factory=dict)
    responses: dict[str, Envelope] = field(default_factory=dict)
    shadow: dict[str, Envelope] = field(default_factory=dict)
    pbft_commits: dict[str, Envelope] = field(default_factory=dict)
    prepared: bool = False
    responded: bool = False
    quorum_at: float | None = None
    finalized: bool = False
    my_result: bytes = b""


class Replica:
    """One consensus-layer node (consensus or candidate)."""

    def __init__(
        self,
        identity: Identity,
        cfg: ConsensusConfig,
        directory: Directory,
        ledger: Ledger | None = None,
        behaviour: str = "honest",
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.me = identity
        self.id = identity.id
        self.cfg = cfg
        self.dir = directory
        self.ledger = ledger if ledger is not None else Ledger()
        self.behaviour = behaviour   # honest | silent | wrong_result | bad_leader | crash
        self.view = 0
        self.scores = {n: cfg.initial_score for n in cfg.nodes}
        self.consensus = list(cfg.initial_consensus)
        # replay state from a persisted ledger
        for b in self.ledger.blocks:
            self.scores = dict(b.scores)
            self.consensus = list(b.consensus)
            self.view = max(self.view, b.view)
        self.slots: dict[int, Slot] = {}
        self.next_seq = self.ledger.last_seq + 1
        self.pending_commits: dict[int, Block] = {}
        self.timers: dict[bytes, float] = {}        # request digest -> deadline
        self.seen_requests: dict[bytes, bytes] = {} # digest -> raw (leader dedupe + forwarding)
        self.committed_digests: dict[bytes, int] = {}
        self.vc_msgs: dict[int, dict[str, Envelope]] = defaultdict(dict)
        self.vc_sent_for = 0
        self.in_view_change = False
        self.vc_timeout = cfg.view_change_timeout
        self.future: list[Envelope] = []            # messages for a view we have not entered yet
        self.events: list[tuple[str, dict]] = []
        self.sent: dict[str, int] = defaultdict(int)
        self.sent_bytes: dict[str, int] = defaultdict(int)
        self._clock = clock

    # -- helpers -----------------------------------------------------------

    def log(self, kind: str, **info) -> None:
        self.events.append((kind, info))

    @property
    def is_consensus(self) -> bool:
        return self.id in self.consensus

    @property
    def leader(self) -> str:
        return leader_of(self.view, self.consensus)

    @property
    def f(self) -> int:
        return f_of(len(self.consensus))

    @property
    def q(self) -> int:
        return quorum(len(self.consensus))

    def _send(self, out: Out, dest: str, raw: bytes, t: str) -> None:
        if self.behaviour in ("silent", "crash"):
            return
        out.append((dest, raw))
        self.sent[t] += 1
        self.sent_bytes[t] += len(raw)

    def _bcast(self, out: Out, dests, raw: bytes, t: str) -> None:
        for d in dests:
            if d != self.id:
                self._send(out, d, raw, t)

    def _others(self, group) -> list[str]:
        return [n for n in group if n != self.id]

    def _candidates(self) -> list[str]:
        return [n for n in self.cfg.nodes if n not in self.consensus]

    def _slot(self, view: int, seq: int) -> Slot:
        s = self.slots.get(seq)
        if s is None or s.view < view:   # a newer view replaces stale state for this seq
            s = Slot(view, seq)
            self.slots[seq] = s
        return s

    # -- entry points --------------------------------------------------------

    def handle(self, raw: bytes, now: float) -> Out:
        """Process one inbound message. Returns messages to send."""
        out: Out = []
        if self.behaviour == "crash":
            return out
        try:
            t = codec.decode_dict(raw, "t")["t"]
        except Exception:
            return out
        env = self.dir.open(raw)
        if env is None:
            self.log("reject", reason="bad signature or unknown sender")
            return out
        handler = {
            REQUEST: self._on_request,
            PRE_PREPARE: self._on_pre_prepare,
            PREPARE: self._on_prepare,
            RESPONSE: self._on_response,
            SHADOW: self._on_response,
            COMMIT: self._on_commit,
            PBFT_COMMIT: self._on_pbft_commit,
            VIEW_CHANGE: self._on_view_change,
            NEW_VIEW: self._on_new_view,
            SYNC_REQ: self._on_sync_req,
            SYNC_RESP: self._on_sync_resp,
        }.get(env.t)
        if handler is not None:
            handler(env, now, out)
        return out

    def tick(self, now: float) -> Out:
        """Drive timers: leader finalisation grace and view-change timeouts."""
        out: Out = []
        if self.behaviour == "crash":
            return out
        if self.cfg.mode == "ags" and self.id == self.leader and not self.in_view_change:
            for seq in sorted(self.slots):
                s = self.slots.get(seq)
                if s is None:
                    continue
                if s.quorum_at is not None and not s.finalized and now >= s.quorum_at + self.cfg.response_grace:
                    self._finalize(s, now, out)
        if self.is_consensus and self.timers:
            expired = [d for d, dl in self.timers.items() if now >= dl]
            if expired:
                target = max(self.view, self.vc_sent_for) + 1
                self._start_view_change(target, now, out)
        return out

    # -- REQUEST (slide 22) --------------------------------------------------

    def _on_request(self, env: Envelope, now: float, out: Out) -> None:
        if self.dir.role(env.sender) != "MEC":
            return
        d = request_digest(env.raw)
        if d in self.committed_digests:
            return  # already done; the client will get the reply from the block
        if not self.is_consensus:
            return
        self.seen_requests[d] = env.raw
        if self.id == self.leader and not self.in_view_change:
            if any(s.digest == d for s in self.slots.values() if s.view == self.view):
                return
            self._propose(env.raw, env.body, now, out)
        else:
            # forward to the leader and watch for it to be committed (view-change trigger)
            self.timers.setdefault(d, now + self.vc_timeout)
            if env.sender in self.cfg.clients or self.dir.role(env.sender) == "MEC":
                self._send(out, self.leader, env.raw, REQUEST)

    def _propose(self, req_raw: bytes, req_body: dict, now: float, out: Out) -> None:
        """ALGORITHM PRE-PREPARE (slide 23), leader side."""
        seq = max(self.next_seq, self.ledger.last_seq + 1)
        self.next_seq = seq + 1
        d = request_digest(req_raw)
        if self.behaviour == "bad_leader":
            return  # a leader that never proposes: forces a view change
        body = {"v": self.view, "n": seq, "d": d, "req": req_raw}
        pp = seal(self.me, PRE_PREPARE, body)
        targets = list(self.consensus)
        if self.cfg.mode == "ags" and self.cfg.shadow_candidates:
            targets += self._candidates()
        self._bcast(out, targets, pp, PRE_PREPARE)
        self._on_pre_prepare(Envelope(PRE_PREPARE, self.id, body, pp), now, out)

    # -- PRE-PREPARE ---------------------------------------------------------

    def _on_pre_prepare(self, env: Envelope, now: float, out: Out) -> None:
        b = env.body
        try:
            v, n, d, req_raw = int(b["v"]), int(b["n"]), bytes(b["d"]), bytes(b["req"])
        except Exception:
            return
        if v > self.view or (v == self.view and self.in_view_change):
            self._buffer(env)
            return
        if v != self.view:
            return
        if env.sender != leader_of(v, self.consensus):
            return
        if n <= self.ledger.last_seq:
            return
        if request_digest(req_raw) != d:
            return
        req = self.dir.open(req_raw, REQUEST)
        if req is None:
            return
        if req.body.get("noop"):
            if req.sender != env.sender:
                return  # only the proposing leader may fill a gap with a no-op
        elif self.dir.role(req.sender) != "MEC":
            return
        s = self._slot(v, n)
        if s.pp is not None and s.digest != d:
            self.log("equivocation", leader=env.sender, seq=n)
            return  # conflicting assignment for (v, n)
        if s.pp is not None:
            return
        s.pp, s.req_raw, s.req_body, s.digest = env, req_raw, req.body, d
        self.timers.setdefault(d, now + self.vc_timeout)
        s.my_result = execute(req.body, self.ledger, self.dir)
        if self.behaviour == "wrong_result":
            s.my_result = H(b"result", b"BYZANTINE-COLLUDED-VALUE")

        if self.is_consensus:
            # ALGORITHM PREPARE (slide 23)
            pd = H(b"result", b"BYZANTINE-COLLUDED-VALUE") if self.behaviour == "wrong_result" else d
            body = {"v": v, "n": n, "d": pd}
            raw = seal(self.me, PREPARE, body)
            self._bcast(out, self.consensus, raw, PREPARE)
            self._on_prepare(Envelope(PREPARE, self.id, body, raw), now, out)
        elif self.cfg.mode == "ags" and self.cfg.shadow_candidates:
            body = {"v": v, "n": n, "d": d, "result": s.my_result}
            self._send(out, env.sender, seal(self.me, SHADOW, body), SHADOW)

    # -- PREPARE -------------------------------------------------------------

    def _on_prepare(self, env: Envelope, now: float, out: Out) -> None:
        b = env.body
        try:
            v, n, d = int(b["v"]), int(b["n"]), bytes(b["d"])
        except Exception:
            return
        if v > self.view or (v == self.view and self.in_view_change):
            self._buffer(env)
            return
        if v != self.view or env.sender not in self.consensus or n <= self.ledger.last_seq:
            return
        s = self._slot(v, n)
        s.prepares.setdefault(env.sender, env)
        self._check_prepared(s, now, out)

    def _check_prepared(self, s: Slot, now: float, out: Out) -> None:
        if s.pp is None or s.prepared:
            return
        matching = [e for e in s.prepares.values() if bytes(e.body["d"]) == s.digest]
        if len(matching) < self.q:
            return
        s.prepared = True
        if self.cfg.mode == "ags":
            # ALGORITHM RESPONSE (slide 24)
            body = {"v": s.view, "n": s.seq, "d": s.digest, "result": s.my_result}
            raw = seal(self.me, RESPONSE, body)
            leader = leader_of(s.view, self.consensus)
            if leader == self.id:
                self._on_response(Envelope(RESPONSE, self.id, body, raw), now, out)
            else:
                self._send(out, leader, raw, RESPONSE)
        else:
            # textbook PBFT: all-to-all COMMIT
            body = {"v": s.view, "n": s.seq, "d": s.digest}
            raw = seal(self.me, PBFT_COMMIT, body)
            self._bcast(out, self.consensus, raw, PBFT_COMMIT)
            self._on_pbft_commit(Envelope(PBFT_COMMIT, self.id, body, raw), now, out)

    # -- RESPONSE / SHADOW (leader) ------------------------------------------

    def _on_response(self, env: Envelope, now: float, out: Out) -> None:
        b = env.body
        try:
            v, n, d = int(b["v"]), int(b["n"]), bytes(b["d"])
            bytes(b["result"])
        except Exception:
            return
        if v != self.view or self.id != leader_of(v, self.consensus) or n <= self.ledger.last_seq:
            return
        s = self._slot(v, n)
        if s.finalized or d != s.digest:
            return
        if env.t == RESPONSE and env.sender in self.consensus:
            s.responses.setdefault(env.sender, env)
        elif env.t == SHADOW and env.sender not in self.consensus:
            s.shadow.setdefault(env.sender, env)
        else:
            return
        counts: dict[bytes, int] = defaultdict(int)
        for e in s.responses.values():
            counts[bytes(e.body["result"])] += 1
        if s.quorum_at is None and counts and max(counts.values()) >= self.q:
            s.quorum_at = now
        all_in = len(s.responses) == len(self.consensus) and (
            not self.cfg.shadow_candidates or len(s.shadow) == len(self._candidates()))
        if s.quorum_at is not None and (all_in or self.cfg.response_grace <= 0):
            self._finalize(s, now, out)

    def _finalize(self, s: Slot, now: float, out: Out) -> None:
        """ALGORITHM REPLY (slide 24) + SCORE_UPDATE (slide 25), leader side."""
        if s.finalized or s.seq != self.ledger.last_seq + 1:
            return  # commit strictly in order; a later tick retries
        counts: dict[bytes, int] = defaultdict(int)
        for e in s.responses.values():
            counts[bytes(e.body["result"])] += 1
        result, c = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
        if c < self.q:
            return
        s.finalized = True
        cert = tuple(e.raw for e in sorted(
            list(s.responses.values()) + list(s.shadow.values()), key=lambda e: e.sender))
        block = self._build_block(s, result, cert, now)
        block = Block(**{**block.__dict__, "leader_sig": self.me.sign(b"qrcav-block" + block.header())})
        raw = seal(self.me, COMMIT, {"block": block.encode()})
        self._bcast(out, self.cfg.nodes, raw, COMMIT)
        self._apply_block(block, now, out)
        self._reply(block, out)
        self._drain_pending(now, out)

    def _build_block(self, s: Slot, result: bytes, cert: tuple[bytes, ...], now: float) -> Block:
        responses = {}
        for raw in cert:
            e = self.dir.open(raw)
            if e is not None:
                responses[e.sender] = bytes(e.body["result"])
        scores = apply_scores(self.scores, result, responses, self.cfg.agree_delta, self.cfg.disagree_delta)
        consensus = list(self.consensus)
        if s.seq % self.cfg.regroup_interval == 0:
            window = self.ledger.blocks[-(self.cfg.regroup_interval - 1):] if self.cfg.regroup_interval > 1 else []
            rate = request_rate(window + [_shim(s.req_raw)])
            consensus = regroup(scores, consensus, self.cfg, rate)
        return Block(
            b_id=self.ledger.height + 1, prev_hash=self.ledger.head_hash,
            t_block=int(now * 1000), view=s.view, seq=s.seq, request=s.req_raw,
            result=result, cert=cert, scores=tuple(sorted(scores.items())),
            consensus=tuple(consensus), leader=self.id,
        )

    def _reply(self, block: Block, out: Out) -> None:
        req = self.dir.open(block.request)
        if req is None or req.body.get("noop"):
            return
        body = {"txn_id": req.body.get("txn_id"), "result": block.result, "view": block.view,
                "B_ID": block.b_id, "block": block.encode()}
        self._send(out, req.sender, seal(self.me, REPLY, body), REPLY)

    # -- COMMIT (all nodes) --------------------------------------------------

    def verify_block(self, block: Block) -> bool:
        """Re-derive everything in the block from its contents."""
        if block.b_id != self.ledger.height + 1 or block.prev_hash != self.ledger.head_hash:
            return False
        if block.leader != leader_of(block.view, self.consensus):
            return False
        lc = self.dir.certs.get(block.leader)
        if lc is None or not self.dir.suite.sig.verify(lc.pk, b"qrcav-block" + block.header(), block.leader_sig):
            return False
        req = self.dir.open(block.request, REQUEST)
        if req is None:
            return False
        d = request_digest(block.request)
        responses: dict[str, bytes] = {}
        agree = 0
        for raw in block.cert:
            e = self.dir.open(raw)
            if e is None or e.t not in (RESPONSE, SHADOW):
                return False
            if int(e.body["v"]) != block.view or int(e.body["n"]) != block.seq or bytes(e.body["d"]) != d:
                return False
            if e.t == RESPONSE and e.sender not in self.consensus:
                return False
            if e.t == SHADOW and e.sender in self.consensus:
                return False
            if e.sender in responses:
                return False
            responses[e.sender] = bytes(e.body["result"])
            if e.t == RESPONSE and responses[e.sender] == block.result:
                agree += 1
        if agree < self.q:
            return False
        scores = apply_scores(self.scores, block.result, responses, self.cfg.agree_delta, self.cfg.disagree_delta)
        if tuple(sorted(scores.items())) != block.scores:
            return False
        consensus = list(self.consensus)
        if block.seq % self.cfg.regroup_interval == 0:
            window = self.ledger.blocks[-(self.cfg.regroup_interval - 1):] if self.cfg.regroup_interval > 1 else []
            consensus = regroup(scores, consensus, self.cfg, request_rate(window + [block]))
        return tuple(consensus) == block.consensus

    def _on_commit(self, env: Envelope, now: float, out: Out) -> None:
        try:
            block = Block.decode(env.body["block"])
        except Exception:
            return
        if block.b_id <= self.ledger.height:
            return
        if block.b_id > self.ledger.height + 1:
            self.pending_commits[block.b_id] = block
            self._send(out, env.sender, seal(self.me, SYNC_REQ, {"from": self.ledger.height + 1}), SYNC_REQ)
            return
        if env.sender != block.leader:
            return
        if not self.verify_block(block):
            self.log("reject-block", b_id=block.b_id, leader=block.leader)
            return
        self._apply_block(block, now, out)
        self._drain_pending(now, out)

    def _drain_pending(self, now: float, out: Out) -> None:
        while self.ledger.height + 1 in self.pending_commits:
            b = self.pending_commits.pop(self.ledger.height + 1)
            if self.verify_block(b):
                self._apply_block(b, now, out)
            else:
                break
        # leader: finalise any later slots that were waiting for order
        if self.cfg.mode == "ags" and self.id == self.leader:
            nxt = self.slots.get(self.ledger.last_seq + 1)
            if nxt is not None and nxt.quorum_at is not None and not nxt.finalized:
                if now >= nxt.quorum_at + self.cfg.response_grace:
                    self._finalize(nxt, now, out)

    def _apply_block(self, block: Block, now: float, out: Out | None = None) -> None:
        self.ledger.append(block)
        before = set(self.consensus)
        self.scores = dict(block.scores)
        self.consensus = list(block.consensus)
        d = request_digest(block.request)
        self.committed_digests[d] = block.b_id
        self.timers.pop(d, None)
        self.seen_requests.pop(d, None)
        self.slots.pop(block.seq, None)
        self.next_seq = max(self.next_seq, block.seq + 1)
        if not self.timers:
            self.vc_timeout = self.cfg.view_change_timeout
        if set(self.consensus) != before:
            self.log("regroup", b_id=block.b_id,
                     promoted=sorted(set(self.consensus) - before),
                     demoted=sorted(before - set(self.consensus)),
                     consensus=list(self.consensus))
            # Slots opened under the old membership are void. Their requests are
            # re-proposed by the leader of the new set (or forwarded to it).
            dropped = []
            for seq in sorted(k for k in self.slots if k > block.seq):
                sl = self.slots.pop(seq)
                if sl.req_raw and request_digest(sl.req_raw) not in self.committed_digests:
                    dropped.append(sl.req_raw)
            self.next_seq = block.seq + 1
            if out is not None and self.is_consensus and not self.in_view_change:
                for raw_req in dropped:
                    req = self.dir.open(raw_req, REQUEST)
                    if req is None or req.body.get("noop"):
                        continue
                    self.seen_requests[request_digest(raw_req)] = raw_req
                    if self.id == self.leader:
                        self._propose(raw_req, req.body, now, out)
                    else:
                        self._send(out, self.leader, raw_req, REQUEST)
        self.log("commit", b_id=block.b_id, seq=block.seq, view=block.view, leader=block.leader)

    # -- PBFT baseline commit -------------------------------------------------

    def _on_pbft_commit(self, env: Envelope, now: float, out: Out) -> None:
        b = env.body
        try:
            v, n, d = int(b["v"]), int(b["n"]), bytes(b["d"])
        except Exception:
            return
        if self.cfg.mode != "pbft" or v != self.view or env.sender not in self.consensus:
            return
        if n <= self.ledger.last_seq:
            return
        s = self._slot(v, n)
        s.pbft_commits.setdefault(env.sender, env)
        self._pbft_try_execute(now, out)

    def _pbft_try_execute(self, now: float, out: Out) -> None:
        while True:
            s = self.slots.get(self.ledger.last_seq + 1)
            if s is None or not s.prepared or s.pp is None:
                return
            ok = [e for e in s.pbft_commits.values() if bytes(e.body["d"]) == s.digest]
            if len(ok) < self.q:
                return
            block = Block(
                b_id=self.ledger.height + 1, prev_hash=self.ledger.head_hash,
                t_block=int(s.req_body.get("ts", 0) * 1000) if isinstance(s.req_body.get("ts", 0), (int, float)) else 0,
                view=s.view, seq=s.seq, request=s.req_raw, result=s.my_result, cert=(),
                scores=tuple(sorted(self.scores.items())), consensus=tuple(self.consensus),
                leader=leader_of(s.view, self.consensus), leader_sig=s.pp.raw,
            )
            self._apply_block(block, now, out)
            req = self.dir.open(block.request)
            if req is not None and not req.body.get("noop"):
                body = {"txn_id": req.body.get("txn_id"), "result": block.result, "view": block.view,
                        "B_ID": block.b_id}
                self._send(out, req.sender, seal(self.me, REPLY, body), REPLY)

    # -- VIEW CHANGE (slides 26-27) ------------------------------------------

    def _start_view_change(self, new_view: int, now: float, out: Out) -> None:
        """ALGORITHM TRIGGER."""
        if new_view <= self.vc_sent_for:
            return
        self.in_view_change = True
        self.vc_sent_for = new_view
        prepared = []
        for seq in sorted(self.slots):
            s = self.slots[seq]
            if s.prepared and s.pp is not None and seq > self.ledger.last_seq:
                prepared.append({
                    "pp": s.pp.raw,
                    "prepares": [e.raw for e in s.prepares.values() if bytes(e.body["d"]) == s.digest][: self.q],
                })
        body = {"nv": new_view, "h": self.ledger.height, "head": self.ledger.head_hash, "P": prepared}
        raw = seal(self.me, VIEW_CHANGE, body)
        self._bcast(out, self.consensus, raw, VIEW_CHANGE)
        self.log("view-change-sent", new_view=new_view)
        # back off: double the timeout so successive failed views get more time
        self.vc_timeout = min(self.vc_timeout * 2, 30.0)
        for d in list(self.timers):
            self.timers[d] = now + self.vc_timeout
        self._on_view_change(Envelope(VIEW_CHANGE, self.id, body, raw), now, out)

    def _valid_prepared_cert(self, pc: dict) -> tuple[int, int, bytes, bytes] | None:
        pp = self.dir.open(pc["pp"], PRE_PREPARE)
        if pp is None:
            return None
        v, n, d = int(pp.body["v"]), int(pp.body["n"]), bytes(pp.body["d"])
        if pp.sender != leader_of(v, self.consensus) or request_digest(bytes(pp.body["req"])) != d:
            return None
        signers = set()
        for raw in pc["prepares"]:
            e = self.dir.open(raw, PREPARE)
            if e and e.sender in self.consensus and int(e.body["v"]) == v and int(e.body["n"]) == n \
                    and bytes(e.body["d"]) == d:
                signers.add(e.sender)
        if len(signers) < self.q:
            return None
        return v, n, d, bytes(pp.body["req"])

    def _on_view_change(self, env: Envelope, now: float, out: Out) -> None:
        b = env.body
        try:
            nv = int(b["nv"])
        except Exception:
            return
        if nv <= self.view or env.sender not in self.consensus or not self.is_consensus:
            return
        self.vc_msgs[nv][env.sender] = env
        # f+1 rule: join a view change others have started
        if len(self.vc_msgs[nv]) >= self.f + 1 and self.vc_sent_for < nv:
            self._start_view_change(nv, now, out)
        if leader_of(nv, self.consensus) == self.id and len(self.vc_msgs[nv]) >= self.q:
            self._send_new_view(nv, now, out)

    def _reissue_set(self, nv: int, vcs: list[Envelope]) -> tuple[int, dict[int, bytes]]:
        """Deterministic O-set: for each seq above the checkpoint, the prepared request (or no-op)."""
        h = max(int(e.body["h"]) for e in vcs)
        chosen: dict[int, tuple[int, bytes]] = {}
        for e in vcs:
            for pc in e.body.get("P", []):
                r = self._valid_prepared_cert(pc)
                if r is None:
                    continue
                v, n, d, req = r
                if n > h and (n not in chosen or v > chosen[n][0]):
                    chosen[n] = (v, req)
        top = max(chosen) if chosen else h
        o = {}
        for n in range(h + 1, top + 1):
            o[n] = chosen[n][1] if n in chosen else b""
        return h, o

    def _send_new_view(self, nv: int, now: float, out: Out) -> None:
        """ALGORITHM New-View Formation."""
        if self.view >= nv:
            return
        vcs = list(self.vc_msgs[nv].values())[: self.q]
        _, o = self._reissue_set(nv, vcs)
        pps = []
        for n, req in sorted(o.items()):
            if not req:  # fill a gap with a no-op
                req = seal(self.me, REQUEST, {"noop": True, "n": n, "ts": now})
            body = {"v": nv, "n": n, "d": request_digest(req), "req": req}
            pps.append(seal(self.me, PRE_PREPARE, body))
        body = {"nv": nv, "V": [e.raw for e in vcs], "O": pps}
        raw = seal(self.me, NEW_VIEW, body)
        self._bcast(out, self.consensus, raw, NEW_VIEW)
        self._enter_view(nv, now, out)
        if o:
            self.next_seq = max(self.next_seq, max(o) + 1)   # fresh proposals go after the re-issued ones
        self.log("new-view", view=nv, leader=self.id, reissued=len(pps))
        for pp in pps:
            self._on_pre_prepare(self.dir.open(pp), now, out)
            if self.cfg.shadow_candidates and self.cfg.mode == "ags":
                self._bcast(out, self._candidates(), pp, PRE_PREPARE)
        self._replay_future(now, out)
        # requests seen but never prepared: propose them in the new view
        for d, raw_req in list(self.seen_requests.items()):
            if d not in self.committed_digests and not any(s.digest == d for s in self.slots.values() if s.view == nv):
                req = self.dir.open(raw_req, REQUEST)
                if req:
                    self._propose(raw_req, req.body, now, out)

    def _buffer(self, env: Envelope) -> None:
        if len(self.future) < 2000:
            self.future.append(env)

    def _replay_future(self, now: float, out: Out) -> None:
        pending, self.future = self.future, []
        for env in pending:
            v = int(env.body.get("v", -1))
            if v > self.view:
                self.future.append(env)
            elif v == self.view:
                (self._on_pre_prepare if env.t == PRE_PREPARE else self._on_prepare)(env, now, out)

    def _enter_view(self, nv: int, now: float, out: Out) -> None:
        self.view = nv
        self.in_view_change = False
        self.slots = {k: s for k, s in self.slots.items() if k <= self.ledger.last_seq}
        self.next_seq = self.ledger.last_seq + 1
        for d in list(self.timers):
            self.timers[d] = now + self.vc_timeout
        for v in [v for v in self.vc_msgs if v <= nv]:
            self.vc_msgs.pop(v)

    def _on_new_view(self, env: Envelope, now: float, out: Out) -> None:
        """ALGORITHM NEW_LEADER: verify, recompute, re-enter PREPARE."""
        b = env.body
        try:
            nv = int(b["nv"])
        except Exception:
            return
        if nv <= self.view or env.sender != leader_of(nv, self.consensus):
            return
        vcs = []
        for raw in b.get("V", []):
            e = self.dir.open(raw, VIEW_CHANGE)
            if e and e.sender in self.consensus and int(e.body["nv"]) == nv:
                vcs.append(e)
        if len({e.sender for e in vcs}) < self.q:
            return
        _, expected = self._reissue_set(nv, vcs)
        got = {}
        pps = []
        for raw in b.get("O", []):
            e = self.dir.open(raw, PRE_PREPARE)
            if e is None or e.sender != env.sender or int(e.body["v"]) != nv:
                return
            got[int(e.body["n"])] = bytes(e.body["req"])
            pps.append(e)
        if set(got) != set(expected):
            return
        for n, req in expected.items():
            if req and got[n] != req:
                return
            if not req:
                r = self.dir.open(got[n], REQUEST)
                if r is None or not r.body.get("noop"):
                    return
        self._enter_view(nv, now, out)
        if expected:
            self.next_seq = max(self.next_seq, max(expected) + 1)
        self.log("new-view-accepted", view=nv, leader=env.sender)
        for e in pps:
            self._on_pre_prepare(e, now, out)
        self._replay_future(now, out)
        # forward requests we still hold to the new leader
        for d, raw_req in self.seen_requests.items():
            if d not in self.committed_digests:
                self._send(out, self.leader, raw_req, REQUEST)

    # -- state transfer --------------------------------------------------------

    def _on_sync_req(self, env: Envelope, now: float, out: Out) -> None:
        try:
            start = int(env.body["from"])
        except Exception:
            return
        blocks = [b.encode() for b in self.ledger.blocks[start - 1: start - 1 + 50]]
        if blocks:
            self._send(out, env.sender, seal(self.me, SYNC_RESP, {"blocks": blocks}), SYNC_RESP)

    def _on_sync_resp(self, env: Envelope, now: float, out: Out) -> None:
        for raw in env.body.get("blocks", []):
            try:
                block = Block.decode(raw)
            except Exception:
                return
            if block.b_id <= self.ledger.height:
                continue
            if block.b_id != self.ledger.height + 1:
                return
            ok = self.verify_block(block) if self.cfg.mode == "ags" else True
            if not ok:
                return
            self._apply_block(block, now, out)
        self._drain_pending(now, out)


def _shim(req_raw: bytes) -> Block:
    """A stand-in block so request_rate() can include the request being committed."""
    return Block(0, b"", 0, 0, 0, req_raw, b"", (), (), (), "")


def make_request(client: Identity, txn_id: str, entity_id: str, data: Any, ts: float,
                 criticality: int = 1) -> bytes:
    """ALGORITHM REQUEST (slide 22): client signs REQ = {txn_id, entity_id, service_details}."""
    return seal(client, REQUEST, {
        "txn_id": txn_id, "entity_id": entity_id, "data": data, "ts": ts,
        "criticality": criticality,
    })


def verify_chain(ledger: Ledger, directory: Directory, cfg: ConsensusConfig) -> bool:
    """Replay a ledger from genesis on a fresh verifier."""
    if not ledger.validate():
        return False
    if cfg.mode == "pbft":
        return True
    probe = Replica.__new__(Replica)
    probe.cfg, probe.dir, probe.ledger = cfg, directory, Ledger()
    probe.scores = {n: cfg.initial_score for n in cfg.nodes}
    probe.consensus = list(cfg.initial_consensus)
    for b in ledger.blocks:
        if not Replica.verify_block(probe, b):
            return False
        probe.ledger.append(b)
        probe.scores, probe.consensus = dict(b.scores), list(b.consensus)
    return True
