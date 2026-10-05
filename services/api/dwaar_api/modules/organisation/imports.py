"""Bulk unit import from CSV: strict validation report, all-or-nothing.

REQ: SOC-03 (subset: units; members arrive with the identity module): validation report, NO partial rows created,
duplicate detection, dry-run; SOC-02 field rules; INV-01 (blocks resolved only inside the caller's society).

Contract
--------
Columns (header required, any order, lower-case names): ``block, label, floor`` required; optional
``carpet_area_sqft, builtup_area_sqft, undivided_interest_pct, construction_cost_paise``. Unknown or repeated
columns are errors. UTF-8 (a BOM is tolerated). Cells starting with ``= + - @`` in text columns are refused
(spreadsheet formula injection). Money is integer paise; areas have at most 2 decimals, interest at most 6.
The whole file is validated first; if there is a single error NOTHING is written. ``dry_run`` validates and reports
only. Duplicate detection covers (a) the same (block, label) twice in the file and (b) a unit that already exists
(archived units count: their label stays reserved). The undivided interest of all active units must not exceed 100.
"""

from __future__ import annotations

import csv
import io
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.errors import InvalidSchema, PolicyViolation
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from .service import translate_integrity

MAX_ROWS: Final = 5000
MAX_REPORTED_ERRORS: Final = 200
REQUIRED: Final = ("block", "label", "floor")
OPTIONAL: Final = (
    "carpet_area_sqft",
    "builtup_area_sqft",
    "undivided_interest_pct",
    "construction_cost_paise",
)
_INT_RE: Final = re.compile(r"^-?[0-9]{1,4}\Z")
_PAISE_RE: Final = re.compile(r"^[0-9]{1,15}\Z")
_FORMULA_START: Final = ("=", "+", "-", "@", "\t", "\r")
_TOTAL_INTEREST_LIMIT: Final = Decimal(100)


@dataclass(frozen=True)
class ParsedRow:
    line: int
    block: str
    label: str
    floor: int
    carpet: Decimal | None
    builtup: Decimal | None
    pct: Decimal | None
    cost: int | None


@dataclass
class ParseResult:
    rows: list[ParsedRow] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    total_rows: int = 0

    def error(self, line: int, column: str, code: str) -> None:
        self.errors.append({"row": line, "field": column, "code": code})


def _decimal(raw: str, *, max_int_digits: int, max_places: int) -> Decimal:
    value = Decimal(raw)  # InvalidOperation handled by the caller
    if not value.is_finite():
        raise InvalidOperation
    if -value.as_tuple().exponent > max_places:  # type: ignore[operator]
        raise ValueError("too_many_decimals")
    if len(value.as_tuple().digits) + value.as_tuple().exponent > max_int_digits:  # type: ignore[operator]
        raise ValueError("too_large")
    return value


def _text_ok(value: str, limit: int) -> str | None:
    if not value:
        return "required"
    if len(value) > limit:
        return "too_long"
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return "control_characters"
    if value.startswith(_FORMULA_START):
        return "unsafe_cell"
    return None


def parse_csv(raw: bytes) -> ParseResult:
    """Parse and validate cell by cell. Never raises on bad content: problems become report entries."""
    result = ParseResult()
    try:
        text_body = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        result.error(0, "file", "not_utf8")
        return result
    if "\x00" in text_body:
        result.error(0, "file", "nul_byte")
        return result
    reader = csv.reader(io.StringIO(text_body, newline=""), strict=True)
    try:
        header_raw = next(reader)
    except StopIteration:
        result.error(0, "file", "empty_file")
        return result
    except csv.Error:
        result.error(1, "file", "malformed_csv")
        return result
    header = [h.strip().lower() for h in header_raw]
    allowed = set(REQUIRED) | set(OPTIONAL)
    seen: set[str] = set()
    for name in header:
        if name not in allowed:
            result.error(1, name or "(blank)", "unknown_column")
        elif name in seen:
            result.error(1, name, "duplicate_column")
        seen.add(name)
    for name in REQUIRED:
        if name not in seen:
            result.error(1, name, "missing_column")
    if result.errors:
        return result
    index = {name: i for i, name in enumerate(header)}
    try:
        for cells in reader:
            line = reader.line_num
            if not cells or all(not c.strip() for c in cells):
                continue  # a blank line is not a row
            result.total_rows += 1
            if result.total_rows > MAX_ROWS:
                result.rows.clear()
                result.errors.clear()
                result.error(0, "file", "too_many_rows")
                return result
            _parse_row(result, line, cells, index, len(header))
    except csv.Error:
        result.error(reader.line_num, "file", "malformed_csv")
    return result


def _parse_row(
    result: ParseResult, line: int, cells: list[str], index: dict[str, int], width: int
) -> None:
    if len(cells) != width:
        result.error(line, "row", "column_count")
        return
    problems = len(result.errors)

    def cell(name: str) -> str:
        return cells[index[name]].strip() if name in index else ""

    block, label = cell("block"), cell("label")
    for column, value, limit in (("block", block, 100), ("label", label, 40)):
        issue = _text_ok(value, limit)
        if issue:
            result.error(line, column, issue)
    floor_raw = cell("floor")
    floor = 0
    if not _INT_RE.match(floor_raw):
        result.error(line, "floor", "invalid_integer")
    else:
        floor = int(floor_raw)
        if not -10 <= floor <= 300:
            result.error(line, "floor", "out_of_range")

    def optional_decimal(
        name: str, places: int, digits: int, lo: Decimal, hi: Decimal | None
    ) -> Decimal | None:
        raw = cell(name)
        if raw == "":
            return None
        try:
            value = _decimal(raw, max_int_digits=digits, max_places=places)
        except InvalidOperation:
            result.error(line, name, "invalid_number")
            return None
        except ValueError as exc:
            result.error(line, name, str(exc))
            return None
        if (
            value < lo
            or (name != "undivided_interest_pct" and value == 0)
            or (hi is not None and value > hi)
        ):
            result.error(line, name, "out_of_range")
            return None
        return value

    carpet = optional_decimal("carpet_area_sqft", 2, 10, Decimal(0), None)
    builtup = optional_decimal("builtup_area_sqft", 2, 10, Decimal(0), None)
    pct = optional_decimal("undivided_interest_pct", 6, 3, Decimal(0), Decimal(100))
    if carpet is not None and builtup is not None and builtup < carpet:
        result.error(line, "builtup_area_sqft", "builtup_area_below_carpet_area")
    cost: int | None = None
    cost_raw = cell("construction_cost_paise")
    if cost_raw != "":
        if _PAISE_RE.match(cost_raw):
            cost = int(cost_raw)
        else:
            result.error(line, "construction_cost_paise", "invalid_integer_paise")
    if len(result.errors) == problems:
        result.rows.append(ParsedRow(line, block, label, floor, carpet, builtup, pct, cost))


def _key(value: str) -> str:
    return value.strip().lower()


def validate_against_db(
    conn: Connection, parsed: ParseResult, *, create_missing_blocks: bool
) -> dict[str, Any]:
    """Cross-checks that need the database; returns the plan (blocks to create, per-row block ids)."""
    blocks = {
        _key(r["name"]): dict(r)
        for r in conn.execute(text("SELECT id, name, floors, status FROM blocks")).mappings()
    }
    existing = {
        (r["block_id"], _key(r["label"]))
        for r in conn.execute(text("SELECT block_id, label FROM units")).mappings()
    }
    existing_interest = conn.execute(
        text("SELECT coalesce(sum(undivided_interest_pct), 0) FROM units WHERE status = 'active'")
    ).scalar_one()
    seen: dict[tuple[str, str], int] = {}
    new_blocks: dict[str, dict[str, Any]] = {}
    interest = Decimal(existing_interest)
    for row in parsed.rows:
        bkey = _key(row.block)
        block = blocks.get(bkey)
        if block is not None and block["status"] != "active":
            parsed.error(row.line, "block", "block_archived")
            continue
        if block is None:
            if not create_missing_blocks:
                parsed.error(row.line, "block", "unknown_block")
                continue
            planned = new_blocks.setdefault(bkey, {"name": row.block, "floors": 0})
            planned["floors"] = max(planned["floors"], row.floor, 0)
        elif row.floor > block["floors"]:
            parsed.error(row.line, "floor", "floor_exceeds_block_floors")
            continue
        dup_key = (bkey, _key(row.label))
        if dup_key in seen:
            parsed.error(row.line, "label", "duplicate_in_file")
            parsed.errors[-1]["first_row"] = seen[dup_key]
            continue
        seen[dup_key] = row.line
        if block is not None and (block["id"], _key(row.label)) in existing:
            parsed.error(row.line, "label", "already_exists")
            continue
        if row.pct is not None:
            interest += row.pct
    if interest > _TOTAL_INTEREST_LIMIT:
        parsed.error(0, "undivided_interest_pct", "undivided_interest_total_exceeds_100")
    return {"blocks": blocks, "new_blocks": new_blocks}


def report(
    parsed: ParseResult, *, dry_run: bool, created: int, blocks_created: list[str]
) -> dict[str, Any]:
    errors = parsed.errors[:MAX_REPORTED_ERRORS]
    return {
        "dry_run": dry_run,
        "valid": not parsed.errors,
        "rows_total": parsed.total_rows,
        "rows_valid": len(parsed.rows) if not parsed.errors else 0,
        "units_created": created,
        "blocks_created": blocks_created,
        "errors": errors,
        "errors_total": len(parsed.errors),
        "errors_truncated": len(parsed.errors) > MAX_REPORTED_ERRORS,
    }


def run_import(
    conn: Connection,
    ctx: RequestContext,
    society_id: uuid.UUID,
    raw: bytes,
    *,
    dry_run: bool,
    create_missing_blocks: bool,
) -> dict[str, Any]:
    """Validate everything; write only if the report is clean and this is not a dry run."""
    parsed = parse_csv(raw)
    plan: dict[str, Any] = {"blocks": {}, "new_blocks": {}}
    if not parsed.errors:
        plan = validate_against_db(conn, parsed, create_missing_blocks=create_missing_blocks)
    if parsed.errors:
        body = report(parsed, dry_run=dry_run, created=0, blocks_created=[])
        if dry_run:
            return body
        raise PolicyViolation(details={"reason": "import_validation_failed", "report": body})
    new_block_names = [b["name"] for b in plan["new_blocks"].values()]
    if dry_run:
        return report(parsed, dry_run=True, created=0, blocks_created=new_block_names)
    batch_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        block_ids: dict[str, uuid.UUID] = {k: v["id"] for k, v in plan["blocks"].items()}
        for key, planned in plan["new_blocks"].items():
            new_id = uuid7()
            c.execute(
                text(
                    "INSERT INTO blocks (id, society_id, name, floors, has_lift, created_by)"
                    " VALUES (:id, :s, :name, :floors, false, :by)"
                ),
                {
                    "id": new_id,
                    "s": society_id,
                    "name": planned["name"],
                    "floors": planned["floors"],
                    "by": ctx.person_id,
                },
            )
            block_ids[key] = new_id
        c.execute(
            text(
                "INSERT INTO units (id, society_id, block_id, label, floor, carpet_area_sqft,"
                " builtup_area_sqft, undivided_interest_pct, construction_cost_paise, created_by)"
                " VALUES (:id, :s, :b, :label, :floor, :carpet, :builtup, :pct, :cost, :by)"
            ),
            [
                {
                    "id": uuid7(),
                    "s": society_id,
                    "b": block_ids[_key(r.block)],
                    "label": r.label,
                    "floor": r.floor,
                    "carpet": r.carpet,
                    "builtup": r.builtup,
                    "pct": r.pct,
                    "cost": r.cost,
                    "by": ctx.person_id,
                }
                for r in parsed.rows
            ],
        )
        return MutationResult(
            object_id=batch_id,
            object_version=1,
            after={
                "units_created": len(parsed.rows),
                "blocks_created": new_block_names,
                "source": "csv",
            },
            event_payload={
                "units_created": len(parsed.rows),
                "blocks_created": len(new_block_names),
            },
        )

    try:
        mutation(
            conn,
            ctx,
            operation="unit.import",
            object_type="unit_import",
            event_type="UnitsImported",
            apply=apply,
        )
    except (
        IntegrityError
    ) as exc:  # a concurrent writer won a race: still all-or-nothing, report as a conflict
        raise translate_integrity(exc) or InvalidSchema.for_fields(
            [("file", "conflict_retry")]
        ) from None
    return report(parsed, dry_run=False, created=len(parsed.rows), blocks_created=new_block_names)
