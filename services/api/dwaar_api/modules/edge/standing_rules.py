"""Standing rules per household (GATE-14): create, list, end. Published to the edge in the signed snapshot.

REQ: GATE-14 (standing rules per household, evaluated locally by the edge policy; e.g. food delivery after 10 PM: leave at gate; milk
vendor daily 6 to 7 AM: allowed), INV-03 (a rule pre-authorises a CATEGORY inside a window and never replaces guard confirmation; a
timeout never allows), INV-04 (only members who live in the unit and may decide for it), INV-10 (the allowed shapes are validated data),
PRD 12.4 (audit + outbox in the same transaction), INV-01.
"""

# ruff: noqa: S608  (SQL fragments are constants; every value is a bind parameter)

from __future__ import annotations

import datetime as dt
import re
import uuid
from collections.abc import Mapping
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import Connection, text

from dwaar_common.errors import NotAuthorised, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from ..visits import common
from ..visits.policy import json_text

MAX_ACTIVE_RULES_PER_UNIT: Final = 20
_HHMM: Final = re.compile(r"^([01]\d|2[0-3]):[0-5]\d\Z")
VisitKind = Literal["guest", "delivery", "service", "cab", "vendor", "staff"]


class StandingRuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    unit_id: uuid.UUID
    rule_kind: Literal["leave_at_gate", "allow_window"]
    visit_kind: VisitKind
    category: (
        Annotated[str, Field(min_length=2, max_length=30, pattern=r"^[a-z][a-z0-9_ -]*$")] | None
    ) = None
    days: Annotated[list[int], Field(min_length=1, max_length=7)] = [1, 2, 3, 4, 5, 6, 7]  # noqa: RUF012
    start_local: str
    end_local: str
    effective_from: dt.date | None = None
    effective_to: dt.date | None = None

    @field_validator("start_local", "end_local")
    @classmethod
    def _time(cls, value: str) -> str:
        if not _HHMM.match(value):
            raise ValueError("expected HH:MM (24 hour, society local time)")
        return value

    @field_validator("days")
    @classmethod
    def _days(cls, value: list[int]) -> list[int]:
        if any(d < 1 or d > 7 for d in value):
            raise ValueError("days are ISO weekdays 1 (Monday) to 7 (Sunday)")
        return sorted(set(value))

    @model_validator(mode="after")
    def _shape(self) -> StandingRuleCreate:
        if self.start_local == self.end_local:
            raise ValueError(
                "start_local and end_local must differ (a window wraps midnight when end < start)"
            )
        if self.rule_kind == "allow_window" and self.category is None:
            raise ValueError(
                "an allow_window rule names the category it pre-authorises (for example 'milk')"
            )
        if self.effective_from and self.effective_to and self.effective_to < self.effective_from:
            raise ValueError("effective_to is before effective_from")
        return self


def _params(body: StandingRuleCreate) -> dict[str, Any]:
    params: dict[str, Any] = {
        "visit_kind": body.visit_kind,
        "action": "leave_at_gate" if body.rule_kind == "leave_at_gate" else "allow",
        "days": body.days,
        "start_local": body.start_local,
        "end_local": body.end_local,
        "tz": "Asia/Kolkata",
    }
    if body.category:
        params["category"] = body.category
    return params


def rule_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "unit_id": row["unit_id"],
        "rule_kind": row["rule_kind"],
        "params": row["params"],
        "effective_from": row["effective_from"],
        "effective_to": row["effective_to"],
        "state": row["state"],
        "version": row["version"],
        "created_at": row["created_at"],
    }


_COLS: Final = (
    "id, unit_id, rule_kind, params, effective_from, effective_to, state, version, created_at"
)


def require_household_decider(conn: Connection, person_id: uuid.UUID, unit_id: uuid.UUID) -> None:
    """Only a member who lives in the unit and may decide for it (occupying owner, tenant, delegated family) sets its rules."""
    standing = common.member_standing(conn, person_id, unit_id)
    if standing is None or not standing.can_decide:
        raise NotAuthorised()


def create_rule(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: StandingRuleCreate
) -> dict[str, Any]:
    assert ctx.person_id is not None  # noqa: S101
    common.require_unit(conn, body.unit_id)
    require_household_decider(conn, ctx.person_id, body.unit_id)
    active = conn.execute(
        text("SELECT count(*) FROM standing_rules WHERE unit_id = :u AND state = 'active'"),
        {"u": body.unit_id},
    ).scalar_one()
    if int(active) >= MAX_ACTIVE_RULES_PER_UNIT:
        raise PolicyViolation(
            details={"reason": "too_many_standing_rules", "max": MAX_ACTIVE_RULES_PER_UNIT}
        )
    rule_id = uuid7()
    params = _params(body)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO standing_rules (id, society_id, unit_id, rule_kind, params, effective_from, effective_to, created_by)"
                " VALUES (:id, :s, :u, :k, CAST(:p AS jsonb), COALESCE(CAST(:ef AS date), (now() AT TIME ZONE 'Asia/Kolkata')::date),"
                " CAST(:et AS date), :by)"
            ),
            {
                "id": rule_id, "s": society_id, "u": body.unit_id, "k": body.rule_kind, "p": json_text(params),
                "ef": body.effective_from, "et": body.effective_to, "by": ctx.person_id,
            },
        )  # fmt: skip
        return MutationResult(
            rule_id, 1,
            after={"unit_id": body.unit_id, "rule_kind": body.rule_kind, "visit_kind": body.visit_kind, "state": "active"},
            event_payload={"rule_id": rule_id, "unit_id": body.unit_id, "rule_kind": body.rule_kind},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="standing_rule.create",
        object_type="standing_rule",
        event_type="StandingRuleCreated",
        apply=apply,
    )
    row = (
        conn.execute(text(f"SELECT {_COLS} FROM standing_rules WHERE id = :id"), {"id": rule_id})
        .mappings()
        .one()
    )  # noqa: S608
    return rule_view(row)


def list_rules(
    conn: Connection, units: list[uuid.UUID] | None, *, state: str | None = "active"
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(  # noqa: S608
            f"SELECT {_COLS} FROM standing_rules WHERE (CAST(:units AS uuid[]) IS NULL OR unit_id = ANY(CAST(:units AS uuid[])))"
            " AND (CAST(:st AS text) IS NULL OR state = CAST(:st AS text)) ORDER BY unit_id, created_at, id LIMIT 200"
        ),
        {"units": units, "st": state},
    ).mappings()
    return [rule_view(r) for r in rows]


def end_rule(
    conn: Connection, ctx: RequestContext, rule_id: uuid.UUID, covers_unit: Any
) -> dict[str, Any]:
    """End a rule (naturally idempotent: a second call returns the ended rule). ``covers_unit(unit_id)`` is the caller's scope check."""
    assert ctx.person_id is not None  # noqa: S101
    row = (
        conn.execute(
            text(f"SELECT {_COLS} FROM standing_rules WHERE id = :id FOR UPDATE"),
            {"id": rule_id},  # noqa: S608
        )
        .mappings()
        .first()
    )
    if row is None or not covers_unit(row["unit_id"]):
        raise NotFound()
    if row["state"] == "ended":
        return rule_view(row)
    require_household_decider(conn, ctx.person_id, row["unit_id"])

    def apply(c: Connection) -> MutationResult:
        updated = c.execute(
            text(
                "UPDATE standing_rules SET state = 'ended', ended_by = :by, ended_at = clock_timestamp(), version = version + 1"
                " WHERE id = :id AND state = 'active' RETURNING version"
            ),
            {"by": ctx.person_id, "id": rule_id},
        ).first()
        if updated is None:
            raise StaleVersion()
        return MutationResult(
            rule_id, int(updated[0]), before={"state": "active"}, after={"state": "ended"},
            event_payload={"rule_id": rule_id, "unit_id": row["unit_id"], "state": "ended"},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="standing_rule.end",
        object_type="standing_rule",
        event_type="StandingRuleEnded",
        apply=apply,
    )
    fresh = (
        conn.execute(text(f"SELECT {_COLS} FROM standing_rules WHERE id = :id"), {"id": rule_id})
        .mappings()
        .one()
    )  # noqa: S608
    return rule_view(fresh)
