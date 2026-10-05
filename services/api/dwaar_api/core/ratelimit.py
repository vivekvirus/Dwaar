"""Postgres token-bucket rate limiting (OTP requests, API budgets).

REQ: IAM-06 (OTP rate limits and abuse protection), ARCH-05 (rate budgets), PRD 12.2 (429 ``rate_limited``
with retry information).

Each call runs in its OWN short transaction so a denied attempt is counted even if the surrounding request
later fails. Keys are opaque strings: never put a raw phone number, token or OTP in one (use a keyed hash).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from sqlalchemy import text

from dwaar_common.errors import RateLimited

from .db import Database


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: float
    retry_after_ms: int

    @property
    def retry_after_seconds(self) -> int:
        return max(1, math.ceil(self.retry_after_ms / 1000))


def take(
    db: Database, key: str, *, capacity: int, refill_per_second: float, cost: int = 1
) -> RateDecision:
    """Try to take ``cost`` tokens from bucket ``key`` (created full on first use)."""
    with db.app_tx() as conn:
        row = conn.execute(
            text(
                "SELECT allowed, remaining, retry_after_ms FROM dwaar_rate_limit_take(:k, :c, :r, :n)"
            ),
            {"k": key, "c": capacity, "r": refill_per_second, "n": cost},
        ).one()
    return RateDecision(bool(row[0]), float(row[1]), int(row[2]))


def enforce(
    db: Database, key: str, *, capacity: int, refill_per_second: float, cost: int = 1
) -> RateDecision:
    """Like :func:`take` but raises :class:`RateLimited` (429 with ``Retry-After``) when denied."""
    decision = take(db, key, capacity=capacity, refill_per_second=refill_per_second, cost=cost)
    if not decision.allowed:
        raise RateLimited(retry_after=decision.retry_after_seconds)
    return decision
