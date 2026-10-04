"""
Hash-linked ledger (deck slide 24: Block = (B_ID, Pr_B_Hash, T_Block)).

Each block carries the deck's three header fields plus what is needed to make
the chain independently checkable:

  B_ID        height
  Pr_B_Hash   hash of the previous block
  T_Block     timestamp assigned by the leader
  view, seq   PBFT view and sequence number it was committed in
  request     the client's signed REQUEST envelope
  result      the agreed execution result
  cert        2f+1 signed RESPONSE envelopes (the commit certificate)
  scores      AGS score table after this block
  consensus   consensus-set membership after this block
  leader      id of the leader that proposed it
  leader_sig  leader's signature over the header

Any node can re-verify the whole chain with only the TA's public key: every
hash link, every leader signature, every commit certificate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import codec
from .crypto.kdf import H

GENESIS_PREV = bytes(32)


@dataclass(frozen=True)
class Block:
    b_id: int
    prev_hash: bytes
    t_block: int
    view: int
    seq: int
    request: bytes
    result: bytes
    cert: tuple[bytes, ...]
    scores: tuple[tuple[str, int], ...]
    consensus: tuple[str, ...]
    leader: str
    leader_sig: bytes = b""

    def header(self) -> bytes:
        return codec.encode({
            "B_ID": self.b_id,
            "Pr_B_Hash": self.prev_hash,
            "T_Block": self.t_block,
            "view": self.view,
            "seq": self.seq,
            "req": H(b"req", self.request),
            "result": self.result,
            "cert": H(b"cert", *self.cert),
            "scores": [list(x) for x in self.scores],
            "consensus": list(self.consensus),
            "leader": self.leader,
        })

    @property
    def hash(self) -> bytes:
        return H(b"block", self.header(), self.leader_sig)

    def to_dict(self) -> dict:
        return {
            "b_id": self.b_id, "prev": self.prev_hash, "t": self.t_block,
            "view": self.view, "seq": self.seq, "request": self.request,
            "result": self.result, "cert": list(self.cert),
            "scores": [list(x) for x in self.scores], "consensus": list(self.consensus),
            "leader": self.leader, "leader_sig": self.leader_sig,
        }

    def encode(self) -> bytes:
        return codec.encode(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            int(d["b_id"]), bytes(d["prev"]), int(d["t"]), int(d["view"]), int(d["seq"]),
            bytes(d["request"]), bytes(d["result"]), tuple(bytes(x) for x in d["cert"]),
            tuple((str(a), int(b)) for a, b in d["scores"]), tuple(str(x) for x in d["consensus"]),
            str(d["leader"]), bytes(d["leader_sig"]),
        )

    @classmethod
    def decode(cls, raw: bytes) -> "Block":
        return cls.from_dict(codec.decode_dict(raw))

    def summary(self) -> dict:
        req = codec.decode(self.request)
        body = req.get("body", {}) if isinstance(req, dict) else {}
        return {
            "B_ID": self.b_id,
            "Pr_B_Hash": self.prev_hash.hex()[:16],
            "hash": self.hash.hex()[:16],
            "T_Block": self.t_block,
            "view": self.view,
            "seq": self.seq,
            "txn_id": body.get("txn_id"),
            "entity_id": body.get("entity_id"),
            "leader": self.leader,
            "cert_size": len(self.cert),
        }


class Ledger:
    """An append-only chain of blocks, optionally persisted as JSON lines."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.blocks: list[Block] = []
        self.path = Path(path) if path else None
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self.blocks.append(Block.decode(bytes.fromhex(line)))

    def __len__(self) -> int:
        return len(self.blocks)

    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def head_hash(self) -> bytes:
        return self.blocks[-1].hash if self.blocks else GENESIS_PREV

    @property
    def last_seq(self) -> int:
        return self.blocks[-1].seq if self.blocks else 0

    def append(self, block: Block) -> None:
        if block.b_id != self.height + 1 or block.prev_hash != self.head_hash:
            raise ValueError("block does not extend the chain")
        self.blocks.append(block)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(block.encode().hex() + "\n")

    def validate(self) -> bool:
        """Hash links only. Signatures are checked by consensus.verify_chain."""
        prev = GENESIS_PREV
        for i, b in enumerate(self.blocks, start=1):
            if b.b_id != i or b.prev_hash != prev:
                return False
            prev = b.hash
        return True

    def __iter__(self) -> Iterable[Block]:
        return iter(self.blocks)
