"""SLA arithmetic on a society business calendar (OPS-01). Pure functions: no database, no clock.

REQ: OPS-01 (acknowledgement and resolution clocks, business calendar, pause), INV-10 (every number is configuration),
PRD 9.7 "SLA pilot defaults" (emergency 2-minute acknowledgement, urgent 15 minutes, normal 4 working hours, resolution
targets such as 2 working days; the product never implies that rescue is guaranteed).

A target is ``{"mode": "clock"|"working", "minutes": N}`` or ``{"mode": "working", "days": N}`` (a working day is the length of
the calendar's opening window). ``clock`` runs around the clock (an emergency does not wait for Monday); ``working`` only counts
time inside the opening hours of working days that are not holidays. All instants are timezone-aware UTC.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dwaar_common.errors import InvalidSchema

PRIORITIES: Final = ("emergency", "urgent", "normal", "low")
PRIORITY_RANK: Final = {"emergency": 0, "urgent": 1, "normal": 2, "low": 3}
Mode = Literal["clock", "working"]
_MAX_DAYS_SCANNED: Final = 4000

#: PILOT DEFAULTS (PRD 9.7). Labelled as such in the database (``sla_source = 'pilot_default'``); a society replaces them.
#: The emergency and urgent RESOLUTION numbers and the low-priority numbers are placeholders [TBD]: the PRD gives only the
#: acknowledgement targets and "for example 2 working days" for a normal resolution.
PILOT_SLA: Final[dict[str, dict[str, dict[str, Any]]]] = {
    "emergency": {"ack": {"mode": "clock", "minutes": 2}, "fix": {"mode": "clock", "minutes": 240}},
    "urgent": {"ack": {"mode": "clock", "minutes": 15}, "fix": {"mode": "working", "days": 1}},
    "normal": {"ack": {"mode": "working", "minutes": 240}, "fix": {"mode": "working", "days": 2}},
    "low": {"ack": {"mode": "working", "minutes": 480}, "fix": {"mode": "working", "days": 5}},
}


@dataclass(frozen=True)
class Target:
    mode: Mode
    minutes: int | None = None
    days: int | None = None

    def seconds(self, calendar: BusinessCalendar) -> int:
        if self.days is not None:
            return self.days * calendar.day_seconds
        assert self.minutes is not None  # noqa: S101  (validated on construction)
        return self.minutes * 60


def parse_target(raw: Any, field: str) -> Target:
    if not isinstance(raw, Mapping):
        raise InvalidSchema.for_fields([(field, "invalid_target")])
    mode = raw.get("mode")
    minutes, days = raw.get("minutes"), raw.get("days")
    if mode not in ("clock", "working") or set(raw) - {"mode", "minutes", "days"}:
        raise InvalidSchema.for_fields([(field, "invalid_target")])
    if (minutes is None) == (days is None):
        raise InvalidSchema.for_fields([(field, "minutes_or_days")])
    if minutes is not None and (
        isinstance(minutes, bool)
        or not isinstance(minutes, int)
        or not 1 <= minutes <= 60 * 24 * 60
    ):
        raise InvalidSchema.for_fields([(field, "invalid_minutes")])
    if days is not None and (
        mode != "working"
        or isinstance(days, bool)
        or not isinstance(days, int)
        or not 1 <= days <= 90
    ):
        raise InvalidSchema.for_fields([(field, "invalid_days")])
    return Target(mode, minutes, days)


def validate_sla(doc: Any) -> dict[str, dict[str, dict[str, Any]]]:
    """A complete, well-formed SLA document (every priority has an ``ack`` and a ``fix`` target) or ``InvalidSchema``."""
    if not isinstance(doc, Mapping) or set(doc) != set(PRIORITIES):
        raise InvalidSchema.for_fields([("sla", "all_priorities_required")])
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for priority in PRIORITIES:
        entry = doc[priority]
        if not isinstance(entry, Mapping) or set(entry) != {"ack", "fix"}:
            raise InvalidSchema.for_fields([(f"sla.{priority}", "ack_and_fix_required")])
        out[priority] = {}
        for clock in ("ack", "fix"):
            parse_target(entry[clock], f"sla.{priority}.{clock}")
            out[priority][clock] = dict(entry[clock])
    return out


@dataclass(frozen=True)
class BusinessCalendar:
    tz: ZoneInfo
    working_days: frozenset[int]  # ISO weekday 1..7
    opens: dt.time
    closes: dt.time
    holidays: frozenset[dt.date]

    @classmethod
    def build(
        cls,
        timezone: str,
        working_days: Iterable[int],
        opens: dt.time,
        closes: dt.time,
        holidays: Iterable[dt.date] = (),
    ) -> BusinessCalendar:
        try:
            tz = ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise InvalidSchema.for_fields([("timezone", "unknown_timezone")]) from None
        days = frozenset(int(d) for d in working_days)
        if not days or not days <= {1, 2, 3, 4, 5, 6, 7} or closes <= opens:
            raise InvalidSchema.for_fields([("calendar", "invalid_calendar")])
        return cls(tz, days, opens, closes, frozenset(holidays))

    @property
    def day_seconds(self) -> int:
        a = dt.datetime.combine(dt.date(2000, 1, 3), self.opens)
        b = dt.datetime.combine(dt.date(2000, 1, 3), self.closes)
        return int((b - a).total_seconds())

    def is_working_day(self, day: dt.date) -> bool:
        return day.isoweekday() in self.working_days and day not in self.holidays

    def window(self, day: dt.date) -> tuple[dt.datetime, dt.datetime] | None:
        """The opening window of a local day as UTC instants, or None for a non-working day."""
        if not self.is_working_day(day):
            return None
        start = dt.datetime.combine(day, self.opens, tzinfo=self.tz).astimezone(dt.UTC)
        end = dt.datetime.combine(day, self.closes, tzinfo=self.tz).astimezone(dt.UTC)
        return start, end

    def add_working_seconds(self, start: dt.datetime, seconds: int) -> dt.datetime:
        """The instant at which ``seconds`` of working time have elapsed since ``start`` (waiting for the next opening)."""
        if seconds < 0:
            raise ValueError("seconds must be >= 0")
        if seconds == 0:
            return start
        remaining = seconds
        day = start.astimezone(self.tz).date()
        cursor = start
        for _ in range(_MAX_DAYS_SCANNED):
            win = self.window(day)
            if win is not None:
                opens, closes = win
                begin = max(cursor, opens)
                if begin < closes:
                    available = int((closes - begin).total_seconds())
                    if remaining <= available:
                        return begin + dt.timedelta(seconds=remaining)
                    remaining -= available
            day += dt.timedelta(days=1)
        raise InvalidSchema.for_fields([("calendar", "no_working_time")])

    def working_seconds_between(self, start: dt.datetime, end: dt.datetime) -> int:
        if end <= start:
            return 0
        total = 0
        day = start.astimezone(self.tz).date()
        last = end.astimezone(self.tz).date()
        while day <= last:
            win = self.window(day)
            if win is not None:
                lo, hi = max(start, win[0]), min(end, win[1])
                if lo < hi:
                    total += int((hi - lo).total_seconds())
            day += dt.timedelta(days=1)
        return total


def due_at(start: dt.datetime, target: Target, calendar: BusinessCalendar) -> dt.datetime:
    seconds = target.seconds(calendar)
    if target.mode == "clock":
        return start + dt.timedelta(seconds=seconds)
    return calendar.add_working_seconds(start, seconds)


def extend_for_pause(
    due: dt.datetime,
    target: Target,
    calendar: BusinessCalendar,
    paused_from: dt.datetime,
    paused_to: dt.datetime,
) -> dt.datetime:
    """Move a due instant by the time the clock was stopped (clock time for ``clock`` targets, working time otherwise)."""
    if paused_to <= paused_from:
        return due
    if target.mode == "clock":
        return due + (paused_to - paused_from)
    return calendar.add_working_seconds(
        due, calendar.working_seconds_between(paused_from, paused_to)
    )


def targets_for(
    sla: Mapping[str, Any], priority: str, start: dt.datetime, calendar: BusinessCalendar
) -> tuple[dt.datetime, dt.datetime, Target, Target]:
    """(ack due, fix due, ack target, fix target) of ``priority`` counted from ``start`` (no pauses applied)."""
    entry = sla[priority]
    ack = parse_target(entry["ack"], f"sla.{priority}.ack")
    fix = parse_target(entry["fix"], f"sla.{priority}.fix")
    return due_at(start, ack, calendar), due_at(start, fix, calendar), ack, fix
