"""
Hash-linked ledger.

Paper section 5.4 and Algorithm 2 lines 31-34 define the block structure:

    Block = (B_ID, Pr_B_Hash, T_Block)

where B_ID is a unique block identifier, Pr_B_Hash is the hash of the previous
block, and T_Block is the set of transactions validated in this block.

DEVIATION D5.

Table 4 lists "Hyperledger Fabric 2.2" as the blockchain framework alongside
AGS-PBFT as the consensus algorithm. Fabric 2.2 orders transactions using Raft
and provides no mechanism to substitute a PBFT-family protocol, so the two
cannot coexist as described. Since AGS-PBFT is the paper's actual contribution,
the ledger is implemented directly here and consensus drives it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from .crypto import H


@dataclass(frozen=True)
class Transaction:
    """
    A traffic record submitted by a CAV or RSU.

    Paper section 5.4: "the transaction ID, entity ID, and service request
    details", covering vehicle status, authentication logs and traffic
    information.
    """

    tx_id: str
    entity_id: str
    payload: dict
    timestamp: float = field(default_factory=time.time)

    def digest(self) -> bytes:
        canonical = json.dumps(
            {
                "tx_id": self.tx_id,
                "entity_id": self.entity_id,
                "payload": self.payload,
                "timestamp": round(self.timestamp, 6),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return H(b"tx", canonical)


@dataclass
class Block:
    """Block = (B_ID, Pr_B_Hash, T_Block)  -- paper Algorithm 2 line 32."""

    b_id: int
    prev_hash: bytes
    transactions: list[Transaction]
    view: int = 0
    sequence: int = 0
    timestamp: float = field(default_factory=time.time)

    def merkle_root(self) -> bytes:
        """
        Not in the paper, which hashes the transaction set implicitly. A binary
        Merkle root lets a vehicle verify one transaction without downloading
        the whole block, which matters on a 6 Mbps link.
        """
        if not self.transactions:
            return H(b"empty")
        layer = [t.digest() for t in self.transactions]
        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])
            layer = [H(b"node", layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        return layer[0]

    def hash(self) -> bytes:
        """Cryptographic link to the previous block."""
        return H(
            b"block",
            self.b_id.to_bytes(8, "big"),
            self.prev_hash,
            self.merkle_root(),
            self.view.to_bytes(4, "big"),
            self.sequence.to_bytes(8, "big"),
        )

    def __repr__(self) -> str:
        return (
            f"Block(id={self.b_id}, txs={len(self.transactions)}, "
            f"hash={self.hash().hex()[:12]}...)"
        )


class Ledger:
    """
    An append-only chain of blocks, replicated at every consensus node.

    Paper section 5.4: "This block is then linked cryptographically to previous
    blocks, thereby ensuring the integrity and continuity of the blockchain."
    """

    GENESIS_HASH = b"\x00" * 32

    def __init__(self) -> None:
        self.blocks: list[Block] = []

    def append(
        self, transactions: list[Transaction], view: int = 0, sequence: int = 0
    ) -> Block:
        block = Block(
            b_id=len(self.blocks),
            prev_hash=self.head_hash(),
            transactions=list(transactions),
            view=view,
            sequence=sequence,
        )
        self.blocks.append(block)
        return block

    def head_hash(self) -> bytes:
        return self.blocks[-1].hash() if self.blocks else self.GENESIS_HASH

    def validate(self) -> bool:
        """Recompute every link. Any tampered block breaks the chain from there on."""
        prev = self.GENESIS_HASH
        for i, b in enumerate(self.blocks):
            if b.b_id != i or b.prev_hash != prev:
                return False
            prev = b.hash()
        return True

    @property
    def transaction_count(self) -> int:
        return sum(len(b.transactions) for b in self.blocks)

    def __len__(self) -> int:
        return len(self.blocks)

    def __repr__(self) -> str:
        return f"Ledger(blocks={len(self.blocks)}, txs={self.transaction_count})"
