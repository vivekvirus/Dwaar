"""Time helpers: store UTC, present Asia/Kolkata.

REQ: PRD section 3/19 conventions (UTC storage, IST presentation). Naive datetimes are
rejected everywhere; there is no implicit local time.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def utc_now() -> datetime:
    """Current time, timezone-aware, in UTC."""
    return datetime.now(UTC)


def is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def assert_utc(value: datetime) -> datetime:
    """Return `value` unchanged if it is aware with a zero UTC offset, else raise ValueError."""
    if not is_aware(value):
        raise ValueError("naive datetime not allowed; expected timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"expected UTC, got offset {value.utcoffset()}")
    return value


def ensure_utc(value: datetime) -> datetime:
    """Convert an aware datetime to UTC (rejects naive values)."""
    if not is_aware(value):
        raise ValueError("naive datetime not allowed; expected timezone-aware datetime")
    return value.astimezone(UTC)


def to_ist(value: datetime) -> datetime:
    """Convert an aware datetime to Asia/Kolkata for presentation."""
    if not is_aware(value):
        raise ValueError("naive datetime not allowed; expected timezone-aware datetime")
    return value.astimezone(IST)


def ist_date(value: datetime) -> date:
    """Calendar date in IST for an aware datetime."""
    return to_ist(value).date()


def start_of_ist_day(day: date) -> datetime:
    """UTC instant at which the given IST calendar day begins."""
    return datetime(day.year, day.month, day.day, tzinfo=IST).astimezone(UTC)


def parse_iso_utc(text: str) -> datetime:
    """Parse an ISO-8601 timestamp that carries an offset (or Z); returns UTC."""
    if not isinstance(text, str):
        raise TypeError("timestamp must be a string")
    return ensure_utc(datetime.fromisoformat(text))


def format_iso_utc(value: datetime) -> str:
    """Canonical wire format: UTC, millisecond precision, `Z` suffix (e.g. 2026-10-05T13:41:07.250Z)."""
    utc = ensure_utc(value)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"
