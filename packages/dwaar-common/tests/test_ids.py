import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dwaar_common.ids import (
    UuidV7Generator,
    is_uuid7,
    parse_uuid,
    uuid7,
    uuid7_at,
    uuid7_floor,
    uuid7_str,
    uuid7_timestamp,
    uuid7_timestamp_ms,
)


def test_version_and_variant() -> None:
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122
    assert is_uuid7(value)
    assert is_uuid7(uuid7_str())


def test_timestamp_roundtrip_is_close_to_now() -> None:
    before = datetime.now(UTC) - timedelta(seconds=1)
    stamp = uuid7_timestamp(uuid7())
    assert before <= stamp <= datetime.now(UTC) + timedelta(seconds=1)
    assert stamp.tzinfo is not None


def test_strictly_monotonic_in_process() -> None:
    values = [uuid7() for _ in range(20_000)]
    assert values == sorted(values)
    assert len(set(values)) == len(values)
    assert [str(v) for v in values] == sorted(str(v) for v in values)


def test_monotonic_when_clock_is_frozen_or_goes_backwards() -> None:
    clock = iter([1_000, 1_000, 1_000, 999, 500, 1_001])
    gen = UuidV7Generator(clock_ms=lambda: next(clock))
    values = [gen.next() for _ in range(6)]
    assert values == sorted(values)
    assert len(set(values)) == 6
    # timestamp never moves backwards even if the wall clock does
    stamps = [uuid7_timestamp_ms(v) for v in values]
    assert stamps == sorted(stamps)
    assert stamps[-1] == 1_001


def test_counter_overflow_advances_timestamp() -> None:
    gen = UuidV7Generator(clock_ms=lambda: 5)
    first = gen.next()
    gen._last_rand = (1 << 74) - 1  # counter exhausted within this millisecond
    second = gen.next()
    assert second > first
    assert uuid7_timestamp_ms(second) == 6


def test_thread_safety_unique() -> None:
    results: list[list[uuid.UUID]] = []

    def work() -> None:
        results.append([uuid7() for _ in range(2_000)])

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    flat = [v for chunk in results for v in chunk]
    assert len(set(flat)) == len(flat)
    for chunk in results:
        assert chunk == sorted(chunk)


def test_uuid7_at_and_floor() -> None:
    moment = datetime(2026, 10, 5, 13, 41, 7, 250_000, tzinfo=UTC)
    stamped = uuid7_at(moment)
    assert uuid7_timestamp(stamped) == moment
    assert uuid7_floor(moment) <= stamped
    assert is_uuid7(uuid7_floor(moment))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError, match="naive"):
        uuid7_at(datetime(2026, 1, 1))


def test_prd_example_ids_are_uuid7() -> None:
    sample = "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11"
    assert is_uuid7(sample)
    assert uuid7_timestamp(sample).year == 2024


def test_rejects_non_v7() -> None:
    assert not is_uuid7(uuid.uuid4())
    assert not is_uuid7("not-a-uuid")
    with pytest.raises(ValueError, match="UUIDv7"):
        uuid7_timestamp_ms(uuid.uuid4())
    with pytest.raises(ValueError, match="canonical"):
        parse_uuid("0192f3a17c4e7a109b2e5d1c0f6a2b11")


@given(st.integers(min_value=0, max_value=253_402_300_799_999))  # up to 9999-12-31T23:59:59.999Z
def test_compose_roundtrip_property(ms: int) -> None:
    moment = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=ms)
    assert uuid7_timestamp_ms(uuid7_at(moment)) == ms
