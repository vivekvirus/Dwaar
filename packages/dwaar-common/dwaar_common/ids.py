"""UUIDv7 identifiers (RFC 9562 section 5.7).

REQ: D-10 (UUIDv7 time-ordered identifiers). Event and financial IDs are never recycled.

Layout: 48-bit unix time in milliseconds | 4-bit version (7) | 12-bit rand_a |
2-bit variant (0b10) | 62-bit rand_b.  Monotonicity inside a process is guaranteed by
treating rand_a || rand_b (74 bits) as a counter within a millisecond (RFC 9562 method 3
style): same or earlier clock reading => previous value + random positive step.
"""

from __future__ import annotations

import secrets
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

_RAND_BITS = 74
_RAND_MASK = (1 << _RAND_BITS) - 1
_MS_MASK = (1 << 48) - 1
# Seed new milliseconds below the top quarter so there is always counter headroom.
_SEED_BITS = _RAND_BITS - 2
_MAX_STEP = 1 << 24
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _clock_ms() -> int:
    return time.time_ns() // 1_000_000


class UuidV7Generator:
    """Thread-safe, strictly monotonic UUIDv7 generator.

    `clock_ms` and `randbits` are injectable so tests are deterministic.
    """

    def __init__(
        self,
        clock_ms: Callable[[], int] = _clock_ms,
        randbits: Callable[[int], int] = secrets.randbits,
    ) -> None:
        self._clock_ms = clock_ms
        self._randbits = randbits
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def next(self) -> uuid.UUID:
        with self._lock:
            now = self._clock_ms()
            if now > self._last_ms:
                self._last_ms = now
                self._last_rand = self._randbits(_SEED_BITS)
            else:
                # Same millisecond, or the wall clock stepped backwards: keep the
                # previous timestamp and advance the counter so order is preserved.
                self._last_rand += 1 + self._randbits(24) % _MAX_STEP
                if self._last_rand > _RAND_MASK:
                    self._last_ms += 1
                    self._last_rand = self._randbits(_SEED_BITS)
            return _compose(self._last_ms, self._last_rand)


def _compose(ms: int, rand74: int) -> uuid.UUID:
    if not 0 <= ms <= _MS_MASK:
        raise ValueError("timestamp out of 48-bit range")
    rand_a = (rand74 >> 62) & 0xFFF
    rand_b = rand74 & ((1 << 62) - 1)
    value = (ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return uuid.UUID(int=value)


_default = UuidV7Generator()


def uuid7() -> uuid.UUID:
    """New UUIDv7, strictly increasing within this process."""
    return _default.next()


def uuid7_str() -> str:
    return str(uuid7())


def uuid7_at(moment: datetime) -> uuid.UUID:
    """UUIDv7 stamped with `moment` (random low bits). Not monotonic; for tests and backfills."""
    return _compose(_to_ms(moment), secrets.randbits(_RAND_BITS))


def uuid7_floor(moment: datetime) -> uuid.UUID:
    """Smallest possible UUIDv7 at `moment`; useful as a range-scan lower bound."""
    return _compose(_to_ms(moment), 0)


def parse_uuid(value: str | uuid.UUID) -> uuid.UUID:
    """Parse a canonical UUID string (or pass a UUID through); raises ValueError otherwise."""
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str) or len(value) != 36:
        raise ValueError("not a canonical UUID string")
    return uuid.UUID(value)


def is_uuid7(value: str | uuid.UUID) -> bool:
    try:
        parsed = parse_uuid(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 7 and parsed.variant == uuid.RFC_4122


def uuid7_timestamp_ms(value: str | uuid.UUID) -> int:
    """Embedded unix time in milliseconds; raises ValueError if not a UUIDv7."""
    parsed = parse_uuid(value)
    if not is_uuid7(parsed):
        raise ValueError("not a UUIDv7")
    return parsed.int >> 80


def uuid7_timestamp(value: str | uuid.UUID) -> datetime:
    """Embedded creation time as a timezone-aware UTC datetime (millisecond precision)."""
    try:
        return _EPOCH + timedelta(milliseconds=uuid7_timestamp_ms(value))
    except OverflowError:
        raise ValueError("embedded timestamp is beyond year 9999") from None


def _to_ms(moment: datetime) -> int:
    """Whole milliseconds since the Unix epoch, in exact integer arithmetic (no floats)."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("naive datetime not allowed; use a timezone-aware datetime")
    delta = moment - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000
