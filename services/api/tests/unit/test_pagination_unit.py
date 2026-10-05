"""Pagination building blocks without a database: cursor codec, filters, date ranges, sort columns."""

from __future__ import annotations

import datetime as dt
import decimal
import uuid

import pytest

from dwaar_api.core.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    FilterDef,
    PageParams,
    Paginator,
    SortColumn,
    bounded_range,
    decode_cursor,
    encode_cursor,
    parse_filters,
)
from dwaar_common.errors import InvalidSchema

pytestmark = pytest.mark.req("ARCH-03", "INV-01")

KEY = b"unit-test-cursor-key"
SOCIETY = uuid.UUID("0192f300-0000-7000-8000-00000000000a")
SORT = [SortColumn("created_at", "timestamptz"), SortColumn("id", "uuid")]


def issues(exc: pytest.ExceptionInfo[InvalidSchema]) -> list[tuple[str, str]]:
    return [(f["field"], f["issue"]) for f in exc.value.details["fields"]]


def test_constants() -> None:
    assert MAX_LIMIT == 100
    assert 1 <= DEFAULT_LIMIT <= MAX_LIMIT


def test_cursor_round_trip_for_every_supported_type() -> None:
    moment = dt.datetime(2026, 10, 5, 13, 41, 7, 250_000, tzinfo=dt.UTC)
    values = [
        moment,
        uuid.UUID(int=5),
        42,
        "text",
        decimal.Decimal("1.50"),
        dt.date(2026, 10, 5),
        None,
        True,
    ]
    token = encode_cursor(values, key=KEY, binding="b1")
    assert decode_cursor(token, key=KEY, binding="b1", width=len(values)) == [
        moment.isoformat(),
        str(uuid.UUID(int=5)),
        42,
        "text",
        "1.50",
        "2026-10-05",
        None,
        True,
    ]


def test_cursor_rejects_floats_and_unknown_types() -> None:
    with pytest.raises(TypeError):
        encode_cursor([object()], key=KEY, binding="b")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t + "x",
        lambda t: "x" + t,
        lambda t: t.split(".")[0],
        lambda t: t.split(".")[0] + ".",
        lambda t: "." + t.split(".")[1],
        lambda t: t.replace(".", ".."),
        lambda t: "",
        lambda t: "!!!.???",
    ],
)
def test_cursor_tampering_is_always_the_same_invalid_cursor_error(mutate) -> None:  # type: ignore[no-untyped-def]
    token = encode_cursor([1, 2], key=KEY, binding="b")
    with pytest.raises(InvalidSchema) as exc:
        decode_cursor(mutate(token), key=KEY, binding="b", width=2)
    assert issues(exc) == [("cursor", "invalid_cursor")]


def test_cursor_is_bound_to_key_binding_and_arity() -> None:
    token = encode_cursor([1, 2], key=KEY, binding="b")
    for kwargs in ({"key": b"other"}, {"binding": "other"}, {"width": 3}):
        full = {"key": KEY, "binding": "b", "width": 2, **kwargs}
        with pytest.raises(InvalidSchema):
            decode_cursor(token, **full)  # type: ignore[arg-type]


def test_binding_changes_with_society_filters_sort_and_direction() -> None:
    paginator = Paginator(KEY)
    base = paginator.binding(SOCIETY, {"state": "open"}, SORT, True)
    assert base == paginator.binding(SOCIETY, {"state": "open"}, SORT, True)
    assert base != paginator.binding(uuid.UUID(int=1), {"state": "open"}, SORT, True)
    assert base != paginator.binding(SOCIETY, {"state": "closed"}, SORT, True)
    assert base != paginator.binding(SOCIETY, {}, SORT, True)
    assert base != paginator.binding(SOCIETY, {"state": "open"}, SORT[:1], True)
    assert base != paginator.binding(SOCIETY, {"state": "open"}, SORT, False)


def test_paginator_validates_limit_before_touching_the_database() -> None:
    paginator = Paginator(KEY)
    for limit in (0, -1, MAX_LIMIT + 1):
        with pytest.raises(InvalidSchema):
            paginator.fetch(
                None,  # type: ignore[arg-type]
                select_sql="SELECT 1",
                where=[],
                params={},
                sort=SORT,
                page=PageParams(limit=limit),
                society_id=SOCIETY,
            )
    with pytest.raises(ValueError, match="sort column"):
        paginator.fetch(
            None,
            select_sql="x",
            where=[],
            params={},
            sort=[],
            page=PageParams(),
            society_id=SOCIETY,
        )  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty"):
        Paginator(b"")
    assert Paginator(KEY, max_limit=500).max_limit == 100  # never above the PRD ceiling


def test_sort_columns_are_code_owned_identifiers() -> None:
    for name in ("created_at; DROP TABLE x", "a b", "x--", "a'b", ""):
        with pytest.raises(ValueError, match="unsafe"):
            SortColumn(name, "uuid")
    with pytest.raises(ValueError, match="unsupported"):
        SortColumn("id", "uuid; DROP")
    assert SortColumn("t.created_at", "timestamptz").name == "t.created_at"


ALLOWED = {
    "state": FilterDef("enum", frozenset({"open", "closed"})),
    "unit": FilterDef("uuid"),
    "n": FilterDef("int"),
    "flag": FilterDef("bool"),
    "q": FilterDef("str", max_length=5),
}


def test_parse_filters_converts_types_and_skips_reserved_names() -> None:
    parsed = parse_filters(
        {
            "state": "open",
            "unit": str(uuid.UUID(int=3)),
            "n": "7",
            "flag": "TRUE",
            "q": "abc",
            "limit": "5",
            "cursor": "x",
            "from": "y",
        },
        ALLOWED,
    )
    assert parsed == {"state": "open", "unit": uuid.UUID(int=3), "n": 7, "flag": True, "q": "abc"}
    assert parse_filters({"flag": "0"}, ALLOWED) == {"flag": False}


def test_parse_filters_collects_every_problem_and_never_raises_value_errors() -> None:
    with pytest.raises(InvalidSchema) as exc:
        parse_filters(
            {
                "state": "weird",
                "unit": "nope",
                "n": "1.5",
                "flag": "maybe",
                "q": "toolong",
                "society_id": "x",
                "order": "id",
            },
            ALLOWED,
        )
    assert sorted(issues(exc)) == sorted(
        [
            ("state", "invalid_value"),
            ("unit", "invalid_value"),
            ("n", "invalid_value"),
            ("flag", "invalid_value"),
            ("q", "too_long"),
            ("society_id", "unknown_filter"),
            ("order", "unknown_filter"),
        ]
    )


NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def test_bounded_range_defaults_and_conversion() -> None:
    default = bounded_range(None, None, max_days=30, now=NOW)
    assert (default.end, default.end - default.start) == (NOW, dt.timedelta(days=30))
    start_only = bounded_range(NOW - dt.timedelta(days=3), None, max_days=30, now=NOW)
    assert start_only.end == NOW
    ist = bounded_range(
        dt.datetime(2026, 10, 1, 5, 30, tzinfo=IST),
        dt.datetime(2026, 10, 2, 5, 30, tzinfo=IST),
        max_days=30,
        now=NOW,
    )
    assert ist.start == dt.datetime(2026, 10, 1, 0, 0, tzinfo=dt.UTC)
    assert ist.start.utcoffset() == dt.timedelta(0)


def test_bounded_range_rejects_wide_inverted_empty_and_naive_ranges() -> None:
    cases = {
        "too wide": (NOW - dt.timedelta(days=31), NOW, "range_exceeds_30_days"),
        "inverted": (NOW, NOW - dt.timedelta(days=1), "must_precede_to"),
        "empty": (NOW, NOW, "must_precede_to"),
    }
    for label, (start, end, issue) in cases.items():
        with pytest.raises(InvalidSchema) as exc:
            bounded_range(start, end, max_days=30, now=NOW)
        assert issues(exc) == [("from", issue)], label
    with pytest.raises(InvalidSchema) as exc:
        bounded_range(dt.datetime(2026, 10, 1), NOW, max_days=30, now=NOW)  # noqa: DTZ001
    assert issues(exc) == [("from", "timezone_required")]
    with pytest.raises(InvalidSchema) as exc:
        bounded_range(None, dt.datetime(2026, 10, 1), max_days=30, now=NOW)  # noqa: DTZ001
    assert issues(exc) == [("to", "timezone_required")]
    exactly = bounded_range(NOW - dt.timedelta(days=30), NOW, max_days=30, now=NOW)
    assert exactly.end - exactly.start == dt.timedelta(days=30)  # the bound itself is allowed
