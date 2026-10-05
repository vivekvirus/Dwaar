from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from dwaar_common.timeutil import (
    IST,
    assert_utc,
    ensure_utc,
    format_iso_utc,
    ist_date,
    parse_iso_utc,
    start_of_ist_day,
    to_ist,
    utc_now,
)


def test_utc_now_is_aware_utc() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)
    assert assert_utc(now) is now


def test_assert_utc_rejects_naive_and_non_utc() -> None:
    with pytest.raises(ValueError, match="naive"):
        assert_utc(datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="expected UTC"):
        assert_utc(datetime(2026, 1, 1, tzinfo=IST))


def test_to_ist_offset_and_date_rollover() -> None:
    moment = datetime(2026, 10, 5, 20, 0, tzinfo=UTC)
    local = to_ist(moment)
    assert local.utcoffset() == timedelta(hours=5, minutes=30)
    assert (local.hour, local.minute) == (1, 30)
    assert ist_date(moment) == date(2026, 10, 6)
    with pytest.raises(ValueError, match="naive"):
        to_ist(datetime(2026, 1, 1))


def test_start_of_ist_day() -> None:
    assert start_of_ist_day(date(2026, 10, 6)) == datetime(2026, 10, 5, 18, 30, tzinfo=UTC)


def test_ensure_utc_converts() -> None:
    plus_two = timezone(timedelta(hours=2))
    out = ensure_utc(datetime(2026, 1, 1, 12, tzinfo=plus_two))
    assert out == datetime(2026, 1, 1, 10, tzinfo=UTC)
    assert out.utcoffset() == timedelta(0)


def test_iso_format_roundtrip_matches_prd_example() -> None:
    text = "2026-10-05T13:41:07.250Z"
    parsed = parse_iso_utc(text)
    assert parsed == datetime(2026, 10, 5, 13, 41, 7, 250_000, tzinfo=UTC)
    assert format_iso_utc(parsed) == text


def test_format_iso_truncates_to_milliseconds_and_normalises_offset() -> None:
    moment = datetime(2026, 10, 5, 19, 11, 7, 250_999, tzinfo=IST)
    assert format_iso_utc(moment) == "2026-10-05T13:41:07.250Z"


def test_parse_rejects_naive_text() -> None:
    with pytest.raises(ValueError, match="naive"):
        parse_iso_utc("2026-10-05T13:41:07")
