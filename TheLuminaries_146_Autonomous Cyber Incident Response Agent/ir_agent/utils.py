from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class UnionFind:
    parent: dict[int, int]
    rank: dict[int, int]

    @classmethod
    def from_items(cls, items: Iterable[int]) -> "UnionFind":
        parent = {i: i for i in items}
        rank = {i: 0 for i in items}
        return cls(parent=parent, rank=rank)

    def find(self, x: int) -> int:
        p = self.parent[x]
        if p != x:
            self.parent[x] = self.find(p)
        return self.parent[x]

    def union(self, a: int, b: int) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1

