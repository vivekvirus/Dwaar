"""Deterministic identifiers for the seed (fixed seed, fixed UUIDv7 time).

REQ: D-10 (UUIDv7 ids), DB-08/seed (a seed run is reproducible: the same dataset gets the same ids).

The domain services mint ids with ``dwaar_common.ids.uuid7()``. For the length of one *scope* (one seed step, keyed by a
stable string such as ``"society:mh"``) this module swaps the process-wide generator for one whose clock is the fixed
``FIXED_MS`` and whose random bits come from ``random.Random(sha256(scope))``. Every id minted inside the scope is
therefore a pure function of the scope key and the order of calls inside it. Different scopes draw different random
bits, so ids never collide across steps, and a step that already ran is skipped on a re-run (it never regenerates).

Only the ids made through ``uuid7()`` are covered. A few identity paths still use ``uuid.uuid4()`` (membership and case
ids in ``identity.members.create_membership``); those stay random and are looked up by natural key on a re-run.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from dwaar_common import ids as _ids
from dwaar_common.ids import UuidV7Generator

#: 2026-01-01T00:00:00Z in milliseconds: the fixed UUIDv7 time of every seeded id.
FIXED_MS: Final = 1_767_225_600_000


@contextmanager
def deterministic_ids(scope: str) -> Iterator[None]:
    """Make ``uuid7()`` deterministic inside the ``with`` block (not thread-safe: the seed is single-threaded)."""
    rng = random.Random(hashlib.sha256(f"dwaar-seed-v1|{scope}".encode()).digest())  # noqa: S311 (not a secret)
    previous = _ids._default  # noqa: SLF001 (the documented injection point of the generator)
    _ids._default = UuidV7Generator(clock_ms=lambda: FIXED_MS, randbits=rng.getrandbits)  # noqa: SLF001
    try:
        yield
    finally:
        _ids._default = previous  # noqa: SLF001


def scoped_uuid(scope: str) -> uuid.UUID:
    """One UUIDv7 that is a pure function of ``scope``."""
    with deterministic_ids(scope):
        return _ids.uuid7()
