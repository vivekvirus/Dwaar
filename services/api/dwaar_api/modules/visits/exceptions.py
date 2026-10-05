"""Gate exceptions (PRD 9.2 Exception: open -> supervisor_review -> resolved / escalated; GATE-07, GATE-11).

REQ: GATE-07 (emergency or manual entry needs a defined LOCAL AUTHORITY (the guard supervisor) and a reason, with audit; an
override never hides: it always leaves an exception that has to be reviewed; essential egress never depends on it),
GATE-11 (an overstay produces an exception), PRD 9.2 (an exception records reason, actor, evidence and whether entry
happened; no invisible bypass), INV-03 (a manual entry is a human decision with an owner, never a silent policy change).

State machine (enforced by a compare-and-swap on state AND version)::

    open --start_review--> supervisor_review --resolve--> resolved
      \\---escalate--> escalated <--escalate-- supervisor_review         escalated --resolve (secretary only)--> resolved

A manual or emergency entry cannot be resolved by the supervisor who authorised it (maker != checker) unless a secretary does.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import (
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import common, gates
from .policy import GatePolicy
from .schemas import ExceptionCreate, ExceptionTransition

PRIVILEGED_KINDS: Final = frozenset({"manual_entry", "emergency_entry"})
_COLS: Final = (
    "id, kind, visit_id, reason, actor_id, raised_by_system, evidence_ref, entry_happened, state, reviewed_by,"
    " resolved_by, resolved_at, resolution_note, version, created_at"
)


def exception_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "visit_id": row["visit_id"],
        "reason": row["reason"],
        "actor_id": row["actor_id"],
        "raised_by_system": row["raised_by_system"],
        "evidence_ref": row["evidence_ref"],
        "entry_happened": row["entry_happened"],
        "state": row["state"],
        "reviewed_by": row["reviewed_by"],
        "resolved_by": row["resolved_by"],
        "resolved_at": row["resolved_at"],
        "resolution_note": row["resolution_note"],
        "version": row["version"],
        "created_at": row["created_at"],
    }


def fetch_exception(conn: Connection, exception_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLS} FROM exceptions WHERE id = :id"),  # noqa: S608 (constant column list)
            {"id": exception_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def open_exception(
    conn: Connection,
    ctx: RequestContext,
    *,
    kind: str,
    reason: str,
    visit_id: uuid.UUID | None,
    entry_happened: bool | None,
    evidence: Mapping[Any, Any] | None = None,
    evidence_ref: str | None = None,
    system: bool = False,
) -> uuid.UUID:
    """Open an exception (its own audit + outbox row). ``system=True`` for detections (overstay), else the caller is the actor."""
    from .policy import json_text

    exception_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO exceptions (id, society_id, kind, visit_id, reason, actor_id, raised_by_system, evidence_ref,"
                " evidence, entry_happened) VALUES (:id, :s, :k, :v, :why, :actor, :sys, :eref, CAST(:ev AS jsonb), :eh)"
            ),
            {
                "id": exception_id, "s": ctx.society_id, "k": kind, "v": visit_id, "why": reason,
                "actor": None if system else ctx.person_id, "sys": system, "eref": evidence_ref,
                "ev": json_text(evidence or {}), "eh": entry_happened,
            },
        )  # fmt: skip
        return MutationResult(
            exception_id,
            1,
            after={
                "kind": kind,
                "state": "open",
                "visit_id": visit_id,
                "entry_happened": entry_happened,
            },
            event_payload={
                "exception_id": exception_id,
                "kind": kind,
                "visit_id": visit_id,
                "state": "open",
            },
        )

    mutation(
        conn, ctx, operation="exception.open", object_type="exception", event_type="ExceptionOpened",
        apply=apply, reason=reason,
    )  # fmt: skip
    return exception_id


def raise_exception(
    conn: Connection,
    ctx: RequestContext,
    society_id: uuid.UUID,
    body: ExceptionCreate,
    policy: GatePolicy,
) -> dict[str, Any]:
    """A guard raises an exception; the supervisor additionally AUTHORISES emergency/manual entry (the route checked that
    authority before calling). Manual and emergency entry create a visit authorised by ``supervisor_override`` that expires
    on the policy's override validity; it is never open-ended."""
    assert ctx.person_id is not None  # noqa: S101
    visit_id = body.visit_id
    visit_out: dict[str, Any] | None = None
    if body.kind in PRIVILEGED_KINDS:
        if not body.visitor_alias:
            raise InvalidSchema.for_fields(
                [("visitor_alias", "required_for_manual_or_emergency_entry")]
            )
        if body.unit_id is not None:
            common.require_unit(conn, body.unit_id)
        if body.gate_id is not None:
            gates.require_active_gate(conn, body.gate_id)
        visit_id = uuid7()
        stop_id = uuid7()
        override = body

        def apply_visit(c: Connection) -> MutationResult:
            c.execute(
                text(
                    "INSERT INTO visits (id, society_id, kind, state, visitor_alias, gate_id, people_count,"
                    " authorisation_source, authorised_at, authorised_until, created_by)"
                    " VALUES (:id, :s, :kind, 'authorised', :alias, :g, :n, 'supervisor_override', clock_timestamp(),"
                    " clock_timestamp() + make_interval(mins => :mins), :by)"
                ),
                {
                    "id": visit_id, "s": society_id, "kind": override.visit_kind, "alias": override.visitor_alias,
                    "g": override.gate_id, "n": override.people_count, "mins": policy.override_validity_minutes,
                    "by": ctx.person_id,
                },
            )  # fmt: skip
            if override.unit_id is not None:
                c.execute(
                    text(
                        "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq, authorised, state)"
                        " VALUES (:id, :s, :v, :u, 1, true, 'authorised')"
                    ),
                    {"id": stop_id, "s": society_id, "v": visit_id, "u": override.unit_id},
                )
            return MutationResult(
                visit_id,
                1,
                after={
                    "state": "authorised", "source": "supervisor_override", "kind": override.visit_kind,
                    "unit_id": override.unit_id, "override_minutes": policy.override_validity_minutes,
                },
                event_payload={"visit_id": visit_id, "unit_id": override.unit_id, "source": "supervisor_override"},
            )  # fmt: skip

        mutation(
            conn, ctx, operation=f"visit.{body.kind}", object_type="visit", event_type="VisitAuthorised",
            apply=apply_visit, reason=body.reason,
        )  # fmt: skip
    elif visit_id is not None:
        exists = conn.execute(text("SELECT 1 FROM visits WHERE id = :id"), {"id": visit_id}).first()
        if exists is None:
            raise NotFound()
    exception_id = open_exception(
        conn, ctx, kind=body.kind, reason=body.reason, visit_id=visit_id, entry_happened=body.entry_happened,
        evidence_ref=body.evidence_ref,
    )  # fmt: skip
    row = fetch_exception(conn, exception_id)
    assert row is not None  # noqa: S101
    if visit_id is not None and body.kind in PRIVILEGED_KINDS:
        visit_row = (
            conn.execute(
                text(f"SELECT {common.VISIT_COLUMNS} FROM visits v WHERE v.id = :id"),  # noqa: S608
                {"id": visit_id},
            )
            .mappings()
            .one()
        )
        visit_out = common.visit_views(conn, [visit_row], view="guard")[0]
    return {"exception": exception_view(row), "visit": visit_out}


def transition(
    conn: Connection,
    ctx: RequestContext,
    exception_id: uuid.UUID,
    body: ExceptionTransition,
) -> dict[str, Any]:
    """Move an exception along open -> supervisor_review -> resolved / escalated (compare-and-swap)."""
    assert ctx.person_id is not None  # noqa: S101
    current = fetch_exception(conn, exception_id)
    if current is None:
        raise NotFound()
    role = ctx.actor_role
    state = current["state"]
    note = (body.note or "").strip()
    if body.action == "start_review":
        allowed_from: tuple[str, ...] = ("open",)
        to = "supervisor_review"
    elif body.action == "escalate":
        allowed_from = ("open", "supervisor_review")
        to = "escalated"
    else:
        if len(note) < 5:
            raise InvalidSchema.for_fields([("note", "resolution_note_required")])
        if state == "open":
            raise PolicyViolation(details={"reason": "review_first"})
        allowed_from = ("supervisor_review", "escalated")
        to = "resolved"
        if state == "escalated" and role != "secretary":
            raise NotAuthorised()  # an escalated exception is closed by the committee's secretary
        if (
            current["kind"] in PRIVILEGED_KINDS
            and current["actor_id"] == ctx.person_id
            and role != "secretary"
        ):
            raise PolicyViolation(details={"reason": "maker_checker"})
    if state not in allowed_from:
        raise StaleVersion(details={"state": state, "version": current["version"]})

    def apply(c: Connection) -> MutationResult:
        updated = c.execute(
            text(
                "UPDATE exceptions SET state = :to, version = version + 1,"
                " reviewed_by = CASE WHEN :to = 'supervisor_review' THEN :by ELSE reviewed_by END,"
                " resolved_by = CASE WHEN :to = 'resolved' THEN :by ELSE resolved_by END,"
                " resolved_at = CASE WHEN :to = 'resolved' THEN clock_timestamp() ELSE resolved_at END,"
                " resolution_note = CASE WHEN :to = 'resolved' THEN :note ELSE resolution_note END"
                " WHERE id = :id AND state = :frm AND version = :v RETURNING version"
            ),
            {
                "to": to, "by": ctx.person_id, "note": note or None, "id": exception_id, "frm": state,
                "v": body.expected_version,
            },
        ).first()  # fmt: skip
        if updated is None:
            latest = fetch_exception(c, exception_id)
            raise StaleVersion(
                details={
                    "state": latest["state"] if latest else None,
                    "version": latest["version"] if latest else None,
                }
            )
        return MutationResult(
            exception_id,
            int(updated[0]),
            before={"state": state},
            after={"state": to},
            event_payload={"exception_id": exception_id, "kind": current["kind"], "state": to, "visit_id": current["visit_id"]},
        )  # fmt: skip

    mutation(
        conn, ctx, operation=f"exception.{body.action}", object_type="exception",
        event_type="ExceptionEscalated" if to == "escalated" else "ExceptionTransitioned",
        apply=apply, reason=note or None,
    )  # fmt: skip
    fresh = fetch_exception(conn, exception_id)
    assert fresh is not None  # noqa: S101
    return exception_view(fresh)


def list_exceptions(
    conn: Connection, *, state: str | None, kind: str | None, limit: int
) -> Sequence[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"SELECT {_COLS} FROM exceptions"  # noqa: S608
            " WHERE (CAST(:st AS text) IS NULL OR state = CAST(:st AS text))"
            " AND (CAST(:k AS text) IS NULL OR kind = CAST(:k AS text))"
            " ORDER BY created_at DESC, id DESC LIMIT :n"
        ),
        {"st": state, "k": kind, "n": limit},
    ).mappings()
    return [exception_view(r) for r in rows]
