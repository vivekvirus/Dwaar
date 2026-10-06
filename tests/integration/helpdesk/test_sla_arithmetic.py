"""OPS-01 SLA arithmetic on the society business calendar (pure functions, no database)."""

from __future__ import annotations

import datetime as dt

import pytest

from dwaar_api.modules.helpdesk import sla
from dwaar_common.errors import InvalidSchema

UTC = dt.UTC
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def cal(**kw):
    base = {
        "timezone": "Asia/Kolkata",
        "working_days": [1, 2, 3, 4, 5, 6],
        "opens": dt.time(9),
        "closes": dt.time(18),
        "holidays": [],
    }
    base.update(kw)
    return sla.BusinessCalendar.build(
        base["timezone"], base["working_days"], base["opens"], base["closes"], base["holidays"]
    )


def ist(y, m, d, hh, mm=0):
    return dt.datetime(y, m, d, hh, mm, tzinfo=IST).astimezone(UTC)


# 2026-10-05 is a Monday, 2026-10-11 a Sunday
@pytest.mark.req("OPS-01")
def test_working_time_counts_only_opening_hours() -> None:
    c = cal()
    # Monday 17:00 + 4 working hours = 1 h that day + 3 h on Tuesday morning -> Tuesday 12:00
    assert c.add_working_seconds(ist(2026, 10, 5, 17), 4 * 3600) == ist(2026, 10, 6, 12)
    # started out of hours (Monday 07:00): the clock starts at the opening
    assert c.add_working_seconds(ist(2026, 10, 5, 7), 3600) == ist(2026, 10, 5, 10)
    # Saturday 17:00 + 2 h skips Sunday -> Monday 10:00
    assert c.add_working_seconds(ist(2026, 10, 10, 17), 2 * 3600) == ist(2026, 10, 12, 10)


@pytest.mark.req("OPS-01")
def test_holidays_and_non_working_days_are_skipped() -> None:
    c = cal(holidays=[dt.date(2026, 10, 6)])
    assert c.add_working_seconds(ist(2026, 10, 5, 17), 4 * 3600) == ist(2026, 10, 7, 12)
    only_weekdays = cal(working_days=[1, 2, 3, 4, 5])
    assert only_weekdays.add_working_seconds(ist(2026, 10, 9, 17), 2 * 3600) == ist(
        2026, 10, 12, 10
    )


@pytest.mark.req("OPS-01")
def test_working_seconds_between_and_day_length() -> None:
    c = cal()
    assert c.day_seconds == 9 * 3600
    assert c.working_seconds_between(ist(2026, 10, 5, 8), ist(2026, 10, 5, 20)) == 9 * 3600
    assert (
        c.working_seconds_between(ist(2026, 10, 10, 12), ist(2026, 10, 12, 10)) == 6 * 3600 + 3600
    )
    assert c.working_seconds_between(ist(2026, 10, 11, 9), ist(2026, 10, 11, 18)) == 0  # Sunday
    assert c.working_seconds_between(ist(2026, 10, 5, 12), ist(2026, 10, 5, 10)) == 0


@pytest.mark.req("OPS-01")
def test_pilot_defaults_follow_prd_9_7() -> None:
    c = cal()
    start = ist(2026, 10, 5, 10)
    ack, fix, ack_t, fix_t = sla.targets_for(sla.PILOT_SLA, "emergency", start, c)
    assert ack - start == dt.timedelta(minutes=2) and ack_t.mode == "clock"
    ack, _fix, *_ = sla.targets_for(sla.PILOT_SLA, "urgent", start, c)
    assert ack - start == dt.timedelta(minutes=15)
    ack, fix, ack_t, fix_t = sla.targets_for(sla.PILOT_SLA, "normal", start, c)
    assert ack == ist(2026, 10, 5, 14) and ack_t.mode == "working"  # 4 working hours
    assert fix == ist(2026, 10, 7, 10)  # 2 working days of 9 h counted from Monday 10:00
    assert fix_t.days == 2


@pytest.mark.req("OPS-01")
def test_emergency_does_not_wait_for_the_calendar() -> None:
    c = cal()
    sunday_night = ist(2026, 10, 11, 23)
    ack, _fix, *_ = sla.targets_for(sla.PILOT_SLA, "emergency", sunday_night, c)
    assert ack == sunday_night + dt.timedelta(minutes=2)


@pytest.mark.req("OPS-01")
def test_pause_extends_the_due_instant_by_the_stopped_time() -> None:
    c = cal()
    due = ist(2026, 10, 6, 12)
    clock = sla.Target("clock", minutes=60)
    working = sla.Target("working", minutes=60)
    paused_from, paused_to = ist(2026, 10, 5, 17), ist(2026, 10, 6, 10)
    assert sla.extend_for_pause(due, clock, c, paused_from, paused_to) == due + (
        paused_to - paused_from
    )
    # 1 h on Monday + 1 h on Tuesday of working time was stopped: 2 working hours added
    assert sla.extend_for_pause(due, working, c, paused_from, paused_to) == ist(2026, 10, 6, 14)
    assert sla.extend_for_pause(due, working, c, paused_to, paused_from) == due


@pytest.mark.req("OPS-01", "INV-10")
@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"emergency": {}},
        {**sla.PILOT_SLA, "extra": {}},
        {
            **sla.PILOT_SLA,
            "normal": {
                "ack": {"mode": "clock", "minutes": 0},
                "fix": {"mode": "clock", "minutes": 5},
            },
        },
        {
            **sla.PILOT_SLA,
            "normal": {"ack": {"mode": "clock", "days": 1}, "fix": {"mode": "clock", "minutes": 5}},
        },
        {
            **sla.PILOT_SLA,
            "normal": {
                "ack": {"mode": "weekly", "minutes": 5},
                "fix": {"mode": "clock", "minutes": 5},
            },
        },
        {
            **sla.PILOT_SLA,
            "normal": {
                "ack": {"mode": "clock", "minutes": True},
                "fix": {"mode": "clock", "minutes": 5},
            },
        },
        {
            **sla.PILOT_SLA,
            "normal": {
                "ack": {"mode": "clock", "minutes": 5, "days": 1},
                "fix": {"mode": "clock", "minutes": 5},
            },
        },
    ],
)
def test_malformed_sla_documents_are_rejected(doc) -> None:
    with pytest.raises(InvalidSchema):
        sla.validate_sla(doc)


@pytest.mark.req("INV-10")
def test_a_valid_document_round_trips_and_a_bad_calendar_is_refused() -> None:
    assert sla.validate_sla(sla.PILOT_SLA) == sla.PILOT_SLA
    with pytest.raises(InvalidSchema):
        sla.BusinessCalendar.build("Mars/Olympus", [1], dt.time(9), dt.time(18))
    with pytest.raises(InvalidSchema):
        sla.BusinessCalendar.build("Asia/Kolkata", [1], dt.time(18), dt.time(9))
    with pytest.raises(InvalidSchema):
        sla.BusinessCalendar.build("Asia/Kolkata", [], dt.time(9), dt.time(18))
