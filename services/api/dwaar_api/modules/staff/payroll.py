"""Payroll adjustments: proposed by one party, effective only when the HOUSEHOLD approves (STAFF-02).

REQ: STAFF-02 (payroll adjustments need household approval), INV-02 (money is integer paise, never a float), INV-07 (proposed, approved and
rejected are distinct states, shown as such), INV-01. No payment is made here and no ledger is touched: an approved adjustment is the household's
recorded decision (payment and journals belong to the finance slice).

The deciding person must be a member of the engagement's household who can decide (an occupying owner or tenant); society roles have no
decide permission at all. First decision wins: a compare-and-swap on ``state = 'proposed'`` and ``version``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import AlreadyDecided, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.pagination import PageParams, Paginator, SortColumn
from ..visits import common as visits_common
from .schemas import PayrollDecision, PayrollPropose

_COLS: Final = (
    "p.id, p.engagement_id, p.kind, p.amount_paise, p.period, p.reason, p.state, p.proposed_by, p.proposer_role, p.proposed_at,"
    " p.decided_by, p.decided_at, p.decision_note, p.version, e.unit_id AS unit_id"
)
_FROM: Final = " FROM payroll_adjustments p JOIN staff_engagements e ON e.society_id = p.society_id AND e.id = p.engagement_id"


def payroll_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "engagement_id": row["engagement_id"],
        "unit_id": row["unit_id"],
        "kind": row["kind"],
        "amount_paise": int(row["amount_paise"]),
        "period": row["period"],
        "reason": row["reason"],
        "state": row["state"],
        "effective": row["state"] == "approved",
        "proposed_by": row["proposed_by"],
        "proposer_role": row["proposer_role"],
        "proposed_at": row["proposed_at"],
        "decided_by": row["decided_by"],
        "decided_at": row["decided_at"],
        "decision_note": row["decision_note"],
        "version": row["version"],
    }


def _fetch(conn: Connection, adjustment_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLS}{_FROM} WHERE p.id = :id"),  # noqa: S608
            {"id": adjustment_id},
        )
        .mappings()
        .first()
    )
    return None if row is None else dict(row)


def propose(
    conn: Connection, ctx: RequestContext, scope: Scope, body: PayrollPropose
) -> dict[str, Any]:
    eng = conn.execute(
        text("SELECT unit_id FROM staff_engagements WHERE id = :id"), {"id": body.engagement_id}
    ).first()
    if eng is None or not scope.covers_unit(eng[0]):
        raise NotFound()
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    adjustment_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO payroll_adjustments (id, society_id, engagement_id, kind, amount_paise, period, reason, proposed_by,"
                " proposer_role) VALUES (:id, :s, :e, :kind, :amt, :period, :why, :by, :role)"
            ),
            {
                "id": adjustment_id, "s": ctx.society_id, "e": body.engagement_id, "kind": body.kind, "amt": body.amount_paise,
                "period": body.period, "why": body.reason, "by": ctx.person_id, "role": ctx.actor_role or "unknown",
            },
        )  # fmt: skip
        return MutationResult(
            adjustment_id, 1,
            after={"kind": body.kind, "amount_paise": body.amount_paise, "period": body.period, "state": "proposed"},
            event_payload={
                "adjustment_id": adjustment_id, "engagement_id": body.engagement_id, "kind": body.kind,
                "amount_paise": body.amount_paise, "state": "proposed",
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.payroll_propose", object_type="payroll_adjustment",
        event_type="PayrollAdjustmentProposed", apply=apply,
    )  # fmt: skip
    row = _fetch(conn, adjustment_id)
    assert row is not None  # noqa: S101
    return payroll_view(row)


def decide(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    adjustment_id: uuid.UUID,
    body: PayrollDecision,
) -> dict[str, Any]:
    locked = conn.execute(
        text("SELECT id FROM payroll_adjustments WHERE id = :id FOR UPDATE"), {"id": adjustment_id}
    ).first()
    row = _fetch(conn, adjustment_id) if locked else None
    if row is None or not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    assert ctx.person_id is not None  # noqa: S101
    standing = visits_common.member_standing(conn, ctx.person_id, row["unit_id"])
    if standing is None or not standing.can_decide:
        raise PolicyViolation(details={"reason": "household_decider_required"})
    if row["state"] != "proposed":
        raise AlreadyDecided(details={"state": row["state"]})
    if int(row["version"]) != body.expected_version:
        raise StaleVersion(details={"current_version": int(row["version"])})
    state = "approved" if body.decision == "approve" else "rejected"

    def apply(c: Connection) -> MutationResult:
        done = c.execute(
            text(
                "UPDATE payroll_adjustments SET state = :st, decided_by = :by, decided_at = clock_timestamp(), decision_note = :note,"
                " version = version + 1 WHERE id = :id AND state = 'proposed' AND version = :v RETURNING id"
            ),
            {
                "st": state,
                "by": ctx.person_id,
                "note": body.note,
                "id": adjustment_id,
                "v": body.expected_version,
            },
        ).first()
        if done is None:  # pragma: no cover (the row is locked above)
            raise AlreadyDecided()
        return MutationResult(
            adjustment_id, int(row["version"]) + 1, before={"state": "proposed"}, after={"state": state},
            event_payload={
                "adjustment_id": adjustment_id, "engagement_id": row["engagement_id"], "state": state,
                "amount_paise": int(row["amount_paise"]),
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation=f"staff.payroll_{body.decision}", object_type="payroll_adjustment",
        event_type="PayrollAdjustmentApproved" if state == "approved" else "PayrollAdjustmentRejected", apply=apply,
        approver_id=ctx.person_id,
    )  # fmt: skip
    fresh = _fetch(conn, adjustment_id)
    assert fresh is not None  # noqa: S101
    return payroll_view(fresh)


def list_adjustments(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    ctx: RequestContext,
    scope: Scope,
    engagement_id: uuid.UUID | None,
    state: str | None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if not scope.society_wide:
        units = sorted(scope.unit_ids, key=lambda u: u.int)
        where.append("e.unit_id = ANY(:units)")
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    elif ctx.actor_role == "estate_mgr":
        # the estate manager sees only what it proposed: the household's payroll is the household's matter
        where.append("p.proposed_by = :me")
        params["me"] = ctx.person_id
        filters["me"] = str(ctx.person_id)
    if engagement_id is not None:
        where.append("p.engagement_id = :eng")
        params["eng"] = engagement_id
        filters["engagement_id"] = engagement_id
    if state is not None:
        where.append("p.state = :state")
        params["state"] = state
        filters["state"] = state
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_COLS}{_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("p.proposed_at", "timestamptz", nullable=False),
            SortColumn("p.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    return {"items": [payroll_view(r) for r in result.items], "next_cursor": result.next_cursor}
