"""Cursor (keyset) pagination, allow-listed filters, bounded date ranges.

REQ: PRD 7.4 / 12 (cursor pagination, at most 100 rows per page, allow-listed filters, bounded date ranges),
INV-01 (a cursor is bound to the society it was issued for and cannot be replayed elsewhere).

* Cursors are opaque: ``base64url(json).base64url(hmac-sha256)``. They are signed with the server's cursor
  key and bound to (society, filter fingerprint, sort), so a client cannot forge, edit or move one.
* ``limit`` is validated (1..100), never silently clamped. Unknown filters are rejected.
* Keyset paging needs a total order: ``SortColumn`` lists the order-by columns, the LAST one must be unique
  (normally ``id``). Identifiers are never taken from the client: columns and SQL types come from code.
* Sort columns may be NULL. NULLs always sort LAST (``NULLS LAST``, both directions) and the keyset
  predicate is NULL-aware, so no row is ever skipped at a page boundary. Declare ``nullable=False`` for
  columns that are NOT NULL to get the plain, index-friendly row-value comparison.
"""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal

from fastapi import Query, Request
from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema
from dwaar_common.timeutil import utc_now

DEFAULT_LIMIT: Final = 50
MAX_LIMIT: Final = 100
_CURSOR_VERSION: Final = 1
_SQL_TYPES: Final = {"uuid", "timestamptz", "bigint", "integer", "text", "date", "numeric"}


@dataclass(frozen=True)
class PageParams:
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


def page_params(
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Rows per page (1-100)")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[
        str | None, Query(max_length=1024, description="Opaque cursor from a previous page")
    ] = None,
) -> PageParams:
    """FastAPI dependency. Out-of-range ``limit`` yields 400 ``invalid_schema``."""
    return PageParams(limit, cursor)


# --------------------------------------------------------------------------------------- cursor codec
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text_: str) -> bytes:
    return base64.urlsafe_b64decode(text_ + "=" * (-len(text_) % 4))


def _wire(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return str(value)
    raise TypeError(f"cannot put {type(value).__name__} into a cursor")


def _invalid_cursor() -> InvalidSchema:
    return InvalidSchema.for_fields([("cursor", "invalid_cursor")])


def encode_cursor(values: Sequence[Any], *, key: bytes, binding: str) -> str:
    body = json.dumps(
        {"v": _CURSOR_VERSION, "b": binding, "k": [_wire(v) for v in values]}, separators=(",", ":")
    )
    raw = body.encode("utf-8")
    sig = hmac.new(key, raw, hashlib.sha256).digest()
    return f"{_b64e(raw)}.{_b64e(sig)}"


def decode_cursor(token: str, *, key: bytes, binding: str, width: int) -> list[Any]:
    """Verify signature, version, binding and arity. Any problem is the same 400 (no oracle)."""
    try:
        body_part, sig_part = token.split(".", 1)
        raw, sig = _b64d(body_part), _b64d(sig_part)
        if not hmac.compare_digest(sig, hmac.new(key, raw, hashlib.sha256).digest()):
            raise _invalid_cursor()
        data = json.loads(raw)
    except (ValueError, TypeError):
        raise _invalid_cursor() from None
    if (
        not isinstance(data, dict)
        or data.get("v") != _CURSOR_VERSION
        or data.get("b") != binding
        or not isinstance(data.get("k"), list)
        or len(data["k"]) != width
    ):
        raise _invalid_cursor()
    return list(data["k"])


# --------------------------------------------------------------------------------------- filters
FilterKind = Literal["str", "int", "bool", "uuid", "enum"]


@dataclass(frozen=True)
class FilterDef:
    kind: FilterKind = "str"
    choices: frozenset[str] = frozenset()
    max_length: int = 100


def parse_filters(
    query: Mapping[str, str],
    allowed: Mapping[str, FilterDef],
    *,
    reserved: frozenset[str] = frozenset({"limit", "cursor", "from", "to"}),
) -> dict[str, Any]:
    """Return typed filters. Any parameter that is neither reserved nor allow-listed is rejected."""
    problems: list[tuple[str, str]] = []
    out: dict[str, Any] = {}
    for name, raw in query.items():
        if name in reserved:
            continue
        definition = allowed.get(name)
        if definition is None:
            problems.append((name, "unknown_filter"))
            continue
        if len(raw) > definition.max_length:
            problems.append((name, "too_long"))
            continue
        try:
            out[name] = _convert(raw, definition)
        except ValueError:
            problems.append((name, "invalid_value"))
    if problems:
        raise InvalidSchema.for_fields(problems)
    return out


def _convert(raw: str, definition: FilterDef) -> Any:
    kind = definition.kind
    if kind == "str":
        return raw
    if kind == "int":
        return int(raw)
    if kind == "bool":
        if raw.lower() in {"true", "1"}:
            return True
        if raw.lower() in {"false", "0"}:
            return False
        raise ValueError(raw)
    if kind == "uuid":
        return uuid.UUID(raw)
    if raw not in definition.choices:
        raise ValueError(raw)
    return raw


# --------------------------------------------------------------------------------------- date ranges
@dataclass(frozen=True)
class DateRange:
    start: dt.datetime
    end: dt.datetime


def bounded_range(
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    max_days: int,
    now: dt.datetime | None = None,
) -> DateRange:
    """Aware UTC range, at most ``max_days`` wide. Missing ends default to the most recent window."""
    moment = now or utc_now()
    for label, value in (("from", start), ("to", end)):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise InvalidSchema.for_fields([(label, "timezone_required")])
    try:  # year 1 / year 9999 plus an offset or the default window overflows datetime arithmetic
        end_utc = end.astimezone(dt.UTC) if end else moment
        start_utc = start.astimezone(dt.UTC) if start else end_utc - dt.timedelta(days=max_days)
    except OverflowError:
        raise InvalidSchema.for_fields([("from" if start else "to", "out_of_range")]) from None
    if start_utc >= end_utc:
        raise InvalidSchema.for_fields([("from", "must_precede_to")])
    if end_utc - start_utc > dt.timedelta(days=max_days):
        raise InvalidSchema.for_fields([("from", f"range_exceeds_{max_days}_days")])
    return DateRange(start_utc, end_utc)


def date_range_params(
    request: Request,
    start: Annotated[
        dt.datetime | None, Query(alias="from", description="UTC ISO-8601, inclusive")
    ] = None,
    end: Annotated[
        dt.datetime | None, Query(alias="to", description="UTC ISO-8601, exclusive")
    ] = None,
) -> DateRange:
    """FastAPI dependency using the configured maximum span."""
    max_days = int(getattr(request.app.state.settings, "max_date_range_days", 92))
    return bounded_range(start, end, max_days=max_days)


# --------------------------------------------------------------------------------------- keyset paging
@dataclass(frozen=True)
class SortColumn:
    name: str
    sql_type: str
    nullable: bool = True

    def __post_init__(self) -> None:
        if not self.name.replace("_", "").replace(".", "").isalnum():
            raise ValueError(f"unsafe sort column name {self.name!r}")
        if self.sql_type not in _SQL_TYPES:
            raise ValueError(f"unsupported sort column type {self.sql_type!r}")


@dataclass(frozen=True)
class Page:
    items: list[dict[str, Any]]
    next_cursor: str | None


class Paginator:
    """Builds keyset queries and signs cursors. One instance per app (key from settings)."""

    def __init__(self, key: bytes, max_limit: int = MAX_LIMIT) -> None:
        if not key:
            raise ValueError("cursor key must not be empty")
        self._key = key
        self.max_limit = min(max_limit, MAX_LIMIT)

    def binding(
        self,
        society_id: uuid.UUID,
        filters: Mapping[str, Any],
        sort: Sequence[SortColumn],
        descending: bool,
    ) -> str:
        material = json.dumps(
            {
                "s": str(society_id),
                "f": {k: _wire_filter(v) for k, v in sorted(filters.items())},
                "o": [(c.name, c.sql_type) for c in sort],
                "d": descending,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    def fetch(
        self,
        conn: Connection,
        *,
        select_sql: str,
        where: Sequence[str],
        params: Mapping[str, Any],
        sort: Sequence[SortColumn],
        page: PageParams,
        society_id: uuid.UUID,
        filters: Mapping[str, Any] | None = None,
        descending: bool = True,
    ) -> Page:
        """Run one page. ``select_sql`` (``SELECT cols FROM t``) and ``where`` fragments are code-owned text
        using bind parameters only; the cursor adds the keyset predicate, ORDER BY and LIMIT.

        ``select_sql`` must return every sort column under its bare name (the next cursor is read from the
        last row), and the final sort column must be unique so the order is total."""
        if not sort:
            raise ValueError("at least one sort column is required")
        if page.limit < 1 or page.limit > self.max_limit:
            raise InvalidSchema.for_fields([("limit", f"must_be_between_1_and_{self.max_limit}")])
        bind = self.binding(society_id, filters or {}, sort, descending)
        clauses = list(where)
        values = dict(params)
        if page.cursor:
            last = decode_cursor(page.cursor, key=self._key, binding=bind, width=len(sort))
            clauses.append(_keyset_predicate(sort, last, descending))
            for i, value in enumerate(last):
                if value is not None:
                    values[f"_k{i}"] = value
        direction = "DESC" if descending else "ASC"
        order = ", ".join(
            f"{c.name} {direction}{' NULLS LAST' if c.nullable else ''}" for c in sort
        )
        sql = f"{select_sql} WHERE {' AND '.join(clauses) if clauses else 'true'} ORDER BY {order} LIMIT :_limit"  # noqa: S608
        values["_limit"] = page.limit + 1
        rows = [dict(r) for r in conn.execute(text(sql), values).mappings()]
        more = len(rows) > page.limit
        rows = rows[: page.limit]
        next_cursor = None
        if more and rows:
            next_cursor = encode_cursor(
                [rows[-1][c.name.split(".")[-1]] for c in sort], key=self._key, binding=bind
            )
        return Page(rows, next_cursor)


def _keyset_predicate(sort: Sequence[SortColumn], last: Sequence[Any], descending: bool) -> str:
    """SQL for "strictly after the cursor row" in the order ``col [DESC] [NULLS LAST], ...``.

    Expanded as ``(c1 after v1) OR (c1 = v1 AND c2 after v2) OR ...`` with NULL handling per column:
    after a NULL value nothing follows within that column (NULLs are last and equal), after a non-NULL
    value come the strictly greater/smaller values and, for nullable columns, the NULLs. Column names come
    from code; values are bind parameters.
    """
    op = "<" if descending else ">"
    terms: list[str] = []
    for i, column in enumerate(sort):
        value = last[i]
        equal = [
            f"{c.name} IS NULL" if last[j] is None else f"{c.name} = CAST(:_k{j} AS {c.sql_type})"
            for j, c in enumerate(sort[:i])
        ]
        if value is None:
            continue
        after = f"{column.name} {op} CAST(:_k{i} AS {column.sql_type})"
        if column.nullable:
            after = f"({after} OR {column.name} IS NULL)"
        terms.append("(" + " AND ".join([*equal, after]) + ")")
    return "(" + " OR ".join(terms) + ")" if terms else "false"


def _wire_filter(value: Any) -> Any:
    return _wire(value)


def get_paginator(request: Request) -> Paginator:
    paginator: Paginator = request.app.state.paginator
    return paginator
