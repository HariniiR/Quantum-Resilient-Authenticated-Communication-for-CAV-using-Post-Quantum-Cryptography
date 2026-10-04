"""
AGS-PBFT -- Adaptive Grouping Score Practical Byzantine Fault Tolerance.

Implementation of paper Algorithm 2 and section 5.4.

Specified behaviour:
  - all nodes initialised with a score of 100
  - nodes split randomly into a consensus set and a candidate set; half the
    total are candidates, and the consensus set satisfies CN >= 3f + 1
  - leader (primary) selected as p = v mod CN
  - four phases: Request, Pre-Prepare, Prepare, Response, then Reply
  - agreement with the consensus result raises a score by 1; disagreement
    lowers it by 5
  - every 50 requests, thresholds T_low = mu - sigma and T_high = mu + sigma are
    computed over all scores; nodes below T_low move to the candidate set,
    nodes above T_high move to the consensus set
  - consensus group size adapts to network load

DEVIATION D1.
Algorithm 2 signs every message "using KYBER-PQC" and Table 3 lists Sign_c,
Sign_l and Sign_r. ML-KEM is a key encapsulation mechanism with no signing
operation, so the protocol cannot authenticate any message as written. All
signatures here use ML-DSA-65 (FIPS 204).

DEVIATION D6.
Section 5.4 sets T_low = mu - sigma and T_high = mu + sigma, but every node
starts at 100, so on the first reassignment sigma = 0 and mu = 100, making
T_low == T_high == 100. Every node is then simultaneously at-or-below T_low and
at-or-above T_high, and the rule is undefined. We require a strict spread
(sigma > 0) before applying the thresholds and otherwise fall back to rank
order, which is what the paper's prose describes ("move the lowest-scoring
nodes ... move the highest-scoring nodes").

The paper also omits PBFT's commit phase, running
Pre-Prepare -> Prepare -> Response -> Reply. We implement it as specified and
record the omission, since it is the likely source of the reduced
communication-round count reported in section 7.4.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field
from enum import Enum

from .crypto import H
from .entities import Entity
from .ledger import Ledger, Transaction


class NodeSet(str, Enum):
    CONSENSUS = "consensus"
    CANDIDATE = "candidate"


@dataclass
class ConsensusNode:
    """A validator. Wraps a registered entity with consensus state."""

    entity: Entity
    score: int = 100                      # paper section 5.4: initial score
    group: NodeSet = NodeSet.CANDIDATE
    byzantine: bool = False               # for fault-tolerance experiments
    ledger: Ledger = field(default_factory=Ledger)

    @property
    def identity(self) -> str:
        return self.entity.identity

    def sign(self, message: bytes) -> bytes:
        """DEVIATION D1: ML-DSA-65, not a KEM."""
        return self.entity.sign(message)

    def vote(self, digest: bytes) -> bytes:
        """
        A node's opinion of a request digest.

        An honest node echoes the digest.

        A Byzantine node returns a single agreed false value, shared by all
        faulty nodes. This matters: if each faulty node returned a *different*
        wrong value they would split their own vote, and the honest plurality
        would win even beyond the 3f+1 bound, making the protocol look more
        robust than PBFT theory permits. Colluding on one false digest is the
        adversary model the 3f+1 bound is actually stated against.
        """
        if self.byzantine:
            return H(b"byzantine-collusion", digest)
        return digest


@dataclass
class ConsensusResult:
    sequence: int
    view: int
    leader: str
    committed: bool
    block: object | None
    messages: int
    prepare_votes: int
    response_votes: int
    agreeing: list[str]
    dissenting: list[str]


class AGSPBFT:
    """
    The consensus engine.

    Message counting is exact so that the communication-overhead comparison
    against textbook PBFT in section 7.4 is meaningful.
    """

    REASSIGN_INTERVAL = 50   # paper section 5.4: "every 50 requests"
    SCORE_AGREE = +1
    SCORE_DISAGREE = -5

    def __init__(
        self,
        nodes: list[Entity],
        byzantine_count: int = 0,
        seed: int | None = 42,
        high_activity: bool = False,
    ) -> None:
        if len(nodes) < 4:
            raise ValueError("PBFT needs at least 4 nodes to tolerate one fault")

        self.rng = random.Random(seed)
        self.nodes: list[ConsensusNode] = [ConsensusNode(e) for e in nodes]
        self.ledger = Ledger()
        self.view = 0
        self.sequence = 0
        self.request_count = 0
        self.high_activity = high_activity
        self.total_messages = 0
        self.reassignments = 0
        self.score_history: list[dict[str, int]] = []

        for n in self.rng.sample(self.nodes, min(byzantine_count, len(self.nodes))):
            n.byzantine = True

        self._initial_split()

    # -- grouping ----------------------------------------------------------
    def _initial_split(self) -> None:
        """
        Paper section 5.4: "Half of the total nodes, N/2 are candidate nodes,
        and the number of consensus nodes CN satisfies CN >= 3f + 1."
        """
        shuffled = self.nodes[:]
        self.rng.shuffle(shuffled)
        half = len(shuffled) // 2
        for n in shuffled[:half]:
            n.group = NodeSet.CANDIDATE
        for n in shuffled[half:]:
            n.group = NodeSet.CONSENSUS
        self._enforce_quorum()

    def _enforce_quorum(self) -> None:
        """Maintain CN >= 3f + 1, promoting candidates by score if short."""
        while len(self.consensus_set) < self.required_consensus_size:
            spare = sorted(self.candidate_set, key=lambda n: -n.score)
            if not spare:
                break
            spare[0].group = NodeSet.CONSENSUS

    @property
    def consensus_set(self) -> list[ConsensusNode]:
        return [n for n in self.nodes if n.group is NodeSet.CONSENSUS]

    @property
    def candidate_set(self) -> list[ConsensusNode]:
        return [n for n in self.nodes if n.group is NodeSet.CANDIDATE]

    @property
    def f(self) -> int:
        """Byzantine nodes tolerable by the current consensus set."""
        return max((len(self.consensus_set) - 1) // 3, 1)

    @property
    def required_consensus_size(self) -> int:
        """
        Paper Table 4 gives 10-15 consensus nodes. Section 5.4's worked example
        instead describes groups of 25 or 50 out of 100, which is inconsistent.
        We follow the constraint CN >= 3f + 1 with the group size scaled by
        network activity, and record the inconsistency.
        """
        target = len(self.nodes) // 2 if self.high_activity else len(self.nodes) // 4
        return max(4, target)

    @property
    def leader(self) -> ConsensusNode:
        """p = v mod CN  -- paper section 5.4."""
        cs = self.consensus_set
        return cs[self.view % len(cs)]

    # -- one consensus round ----------------------------------------------
    def submit(self, client: Entity, transactions: list[Transaction]) -> ConsensusResult:
        """
        Run one AGS-PBFT round.

        Phases follow Algorithm 2 lines 13-36.
        """
        cs = self.consensus_set
        leader = self.leader
        f = self.f
        quorum = 2 * f + 1
        messages = 0

        # -- Request (lines 13-16): client signs and sends to the primary ----
        req_body = b"|".join(t.digest() for t in transactions)
        request = H(b"REQ", client.identity.encode(), req_body)
        sign_c = client.sign(request)
        messages += 1
        if not Entity.verify(client.sig_pk, request, sign_c):
            return self._failed(leader, messages)

        # -- Pre-Prepare (lines 17-20): leader broadcasts to replicas --------
        self.sequence += 1
        pre_prepare = H(
            b"PRE-PREPARE",
            self.view.to_bytes(4, "big"),
            self.sequence.to_bytes(8, "big"),
            request,
        )
        sign_l = leader.sign(pre_prepare)
        replicas = [n for n in cs if n is not leader]
        messages += len(replicas)

        # -- Prepare (lines 21-24): replicas verify, then broadcast ----------
        prepares: dict[str, bytes] = {}
        for r in replicas:
            if not Entity.verify(leader.entity.sig_pk, pre_prepare, sign_l):
                continue
            prepares[r.identity] = r.vote(pre_prepare)
            messages += len(cs) - 1        # broadcast to the consensus set

        # -- Response (lines 25-28): tally prepares, broadcast response ------
        tally: dict[bytes, list[str]] = {}
        for ident, v in prepares.items():
            tally.setdefault(v, []).append(ident)
        tally.setdefault(pre_prepare, []).append(leader.identity)  # leader agrees

        majority_vote, agreeing = max(tally.items(), key=lambda kv: len(kv[1]))
        responses = len(agreeing)
        if responses >= quorum:
            messages += len(cs) * (len(cs) - 1)

        # -- Reply (lines 29-36): commit if 2f+1 responses -------------------
        committed = responses >= quorum and majority_vote == pre_prepare
        block = None
        if committed:
            block = self.ledger.append(transactions, view=self.view, sequence=self.sequence)
            for n in self.nodes:                       # candidates update state too
                n.ledger.append(transactions, view=self.view, sequence=self.sequence)
            messages += 1                              # reply to client
        else:
            self.view += 1                             # view change, new leader

        dissenting = [n.identity for n in cs if n.identity not in agreeing]

        # -- Score update and group adjustment (lines 37-53) -----------------
        self._update_scores(agreeing, dissenting, committed)
        self.request_count += 1
        self.total_messages += messages
        if self.request_count % self.REASSIGN_INTERVAL == 0:
            self._reassign()

        return ConsensusResult(
            sequence=self.sequence,
            view=self.view,
            leader=leader.identity,
            committed=committed,
            block=block,
            messages=messages,
            prepare_votes=len(prepares),
            response_votes=responses,
            agreeing=agreeing,
            dissenting=dissenting,
        )

    def _failed(self, leader: ConsensusNode, messages: int) -> ConsensusResult:
        self.view += 1
        return ConsensusResult(
            self.sequence, self.view, leader.identity, False, None, messages, 0, 0, [], []
        )

    # -- scoring (paper Algorithm 2 lines 37-44) ---------------------------
    def _update_scores(self, agreeing: list[str], dissenting: list[str], committed: bool) -> None:
        """
        "For nodes with consistent confirmation results, increase scores by 1.
         For nodes with inconsistent results, reduce scores by 5."
        """
        if not committed:
            return
        agree = set(agreeing)
        for n in self.consensus_set:
            n.score += self.SCORE_AGREE if n.identity in agree else self.SCORE_DISAGREE

    # -- periodic regrouping (paper Algorithm 2 lines 45-53) ---------------
    def _reassign(self) -> None:
        """
        DEVIATION D6.

        Thresholds T_low = mu - sigma and T_high = mu + sigma are only
        meaningful once scores have spread. Before that we fall back to rank
        order, which is what the paper's prose describes.
        """
        self.reassignments += 1
        scores = [n.score for n in self.nodes]
        mu = statistics.mean(scores)
        sigma = statistics.pstdev(scores)

        if sigma > 0:
            t_low, t_high = mu - sigma, mu + sigma
            demote = [n for n in self.consensus_set if n.score < t_low]
            promote = [n for n in self.candidate_set if n.score > t_high]
        else:
            # D6 fallback: no spread, so use rank order.
            cs = sorted(self.consensus_set, key=lambda n: n.score)
            cd = sorted(self.candidate_set, key=lambda n: -n.score)
            k = max(1, len(cs) // 10)
            demote, promote = cs[:k], cd[:k]

        for n in demote:
            n.group = NodeSet.CANDIDATE
        for n in promote:
            n.group = NodeSet.CONSENSUS

        self._enforce_quorum()
        self.score_history.append({n.identity: n.score for n in self.nodes})

    # -- reporting ---------------------------------------------------------
    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "consensus_set": len(self.consensus_set),
            "candidate_set": len(self.candidate_set),
            "f_tolerated": self.f,
            "byzantine_actual": sum(n.byzantine for n in self.nodes),
            "view": self.view,
            "requests": self.request_count,
            "blocks": len(self.ledger),
            "transactions": self.ledger.transaction_count,
            "total_messages": self.total_messages,
            "messages_per_request": (
                self.total_messages / self.request_count if self.request_count else 0
            ),
            "reassignments": self.reassignments,
            "chain_valid": self.ledger.validate(),
        }

    def score_table(self) -> list[tuple[str, int, str, bool]]:
        return sorted(
            ((n.identity, n.score, n.group.value, n.byzantine) for n in self.nodes),
            key=lambda r: -r[1],
        )


# ---------------------------------------------------------------------------
# Baseline: textbook PBFT, for the communication-overhead comparison
# ---------------------------------------------------------------------------

class PlainPBFT:
    """
    Standard PBFT with all nodes participating and the commit phase present.

    Used only as the comparison baseline for section 7.4. Message count per
    request is O(n^2) across prepare and commit.
    """

    def __init__(self, nodes: list[Entity]) -> None:
        self.nodes = [ConsensusNode(e) for e in nodes]
        self.ledger = Ledger()
        self.view = 0
        self.sequence = 0
        self.request_count = 0
        self.total_messages = 0

    @property
    def f(self) -> int:
        return max((len(self.nodes) - 1) // 3, 1)

    def submit(self, client: Entity, transactions: list[Transaction]) -> ConsensusResult:
        n = len(self.nodes)
        leader = self.nodes[self.view % n]
        self.sequence += 1

        messages = 1                     # request
        messages += n - 1                # pre-prepare
        messages += (n - 1) * (n - 1)    # prepare, all-to-all
        messages += n * (n - 1)          # commit, all-to-all  (present here)
        messages += 1                    # reply

        block = self.ledger.append(transactions, view=self.view, sequence=self.sequence)
        self.request_count += 1
        self.total_messages += messages

        return ConsensusResult(
            self.sequence, self.view, leader.identity, True, block,
            messages, n - 1, n - 1, [x.identity for x in self.nodes], [],
        )

    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "requests": self.request_count,
            "total_messages": self.total_messages,
            "messages_per_request": (
                self.total_messages / self.request_count if self.request_count else 0
            ),
            "blocks": len(self.ledger),
        }
