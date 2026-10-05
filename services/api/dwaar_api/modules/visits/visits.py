"""Visits: observations (INV-07), multi-stop visits, cancellation, history, and the expiry/overstay sweep.

REQ: INV-07 (permission, observed movement and destination stops are separate records; an observation NEVER creates or
widens permission), GATE-05 (exit scanned, observed or reconciled-as-unknown; an exact exit time is never manufactured;
inside counts carry a confidence indicator), GATE-04, GATE-07 (essential egress is never gated: an exit is recorded for any
visit), GATE-11 (overstay thresholds produce exceptions), GATE-13 (guard views are masked and limited to the current gate's
active visits), PRD 9.3 (the gate is authoritative for physical observations: append-only, deduplicate by event id, never
overwrite), PRD 12.1 ``POST /v1/visits/{id}/observations``.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.errors import (
    DuplicatePayloadMismatch,
    InvalidSchema,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.events import payload_hash
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import approvals, common, exceptions, gates, invitations
from .policy import GatePolicy
from .schemas import ObservationIn, VisitCancel

_VISIT_LOCK = (
    "SELECT id, state, kind, authorised_until, authorised_at, entered_at, exited_at, expected_minutes, version, gate_id"
    " FROM visits WHERE id = :id FOR UPDATE"
)


class _Skip(Exception):
    """A row stopped being due between selection and update: nothing to do."""


def fetch_visit_row(conn: Connection, visit_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {common.VISIT_COLUMNS} FROM visits v WHERE v.id = :id"),  # noqa: S608
            {"id": visit_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


# ------------------------------------------------------------------------------------------ observations
@dataclass(frozen=True)
class Transition:
    changed: bool
    note: str
    exception: tuple[str, str, bool | None] | None = None  # kind, reason, entry_happened


def _event_fingerprint(visit_id: uuid.UUID, body: ObservationIn) -> dict[str, Any]:
    return {
        "visit_id": str(visit_id),
        "type": body.type,
        "gate_id": str(body.gate_id),
        "lane_id": str(body.lane_id) if body.lane_id else None,
        "device_id": str(body.device_id),
        "event_id": str(body.event_id),
        "seq": body.seq,
        "occurred_at": body.occurred_at.isoformat(),
        "clock_uncertainty_ms": body.clock_uncertainty_ms,
        "credential_kind": body.credential_kind,
        "decision_source": body.decision_source,
        "exit_basis": body.exit_basis,
        "policy_version": body.policy_version,
    }


def _event_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "type": row["event_type"],
        "visit_id": row["visit_id"],
        "gate_id": row["gate_id"],
        "lane_id": row["lane_id"],
        "device_id": row["device_id"],
        "seq": row["seq"],
        "occurred_at": row["occurred_at"],
        "received_at": row["received_at"],
        "clock_uncertainty_ms": row["clock_uncertainty_ms"],
        "decision_source": row["decision_source"],
        "credential_kind": row["credential_kind"],
        "payload_hash": row["payload_hash"],
    }


def _stored_event(conn: Connection, event_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT id, event_id, event_type, visit_id, gate_id, lane_id, device_id, seq, occurred_at, received_at,"
                " clock_uncertainty_ms, decision_source, credential_kind, payload_hash FROM access_events"
                " WHERE event_id = :e"
            ),
            {"e": event_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def observe(
    conn: Connection,
    ctx: RequestContext,
    society_id: uuid.UUID,
    visit_id: uuid.UUID,
    body: ObservationIn,
) -> tuple[dict[str, Any], bool]:
    """Record one physical observation. Returns (response body, newly_recorded).

    The observation is a FACT and is always recorded (append-only), including an entry nobody authorised: refusing to record
    would hide the movement. What it can NOT do is create permission: an entry observed for a visit that is not authorised
    leaves the visit exactly as it was and opens an ``unauthorised_entry`` exception for a supervisor (INV-07, GATE-07).
    Exits are never gated (essential egress): any visit can be marked exited, and an exit that has no matching observed
    entry says so in an exception.
    """
    visit = conn.execute(text(_VISIT_LOCK), {"id": visit_id}).mappings().first()
    if visit is None:
        raise NotFound()
    gates.require_active_gate(conn, body.gate_id)
    device = conn.execute(
        text("SELECT state, gate_id FROM devices WHERE id = :id"), {"id": body.device_id}
    ).first()
    if device is None or device[0] != "active":
        raise InvalidSchema.for_fields([("device_id", "unknown_or_inactive_device")])
    if device[1] is not None and device[1] != body.gate_id:
        raise PolicyViolation(details={"reason": "device_wrong_gate"})
    if body.lane_id is not None:
        lane = conn.execute(
            text("SELECT gate_id FROM lanes WHERE id = :id AND status = 'active'"),
            {"id": body.lane_id},
        ).first()
        if lane is None or lane[0] != body.gate_id:
            raise InvalidSchema.for_fields([("lane_id", "unknown_lane")])
    if body.type == "exit" and body.exit_basis is None:
        raise InvalidSchema.for_fields([("exit_basis", "required_for_exit")])
    if body.type == "entry" and body.exit_basis is not None:
        raise InvalidSchema.for_fields([("exit_basis", "only_for_exit")])
    fingerprint = _event_fingerprint(visit_id, body)
    digest = payload_hash(fingerprint)
    earlier = _stored_event(conn, body.event_id)
    if earlier is not None:
        if earlier["payload_hash"] != digest:
            raise DuplicatePayloadMismatch()  # the same event id with different content: flagged, never overwritten
        row = fetch_visit_row(conn, visit_id)
        assert row is not None  # noqa: S101
        return (
            {
                "accepted": True, "deduplicated": True, "event": _event_view(earlier),
                "visit": common.visit_views(conn, [row], view="guard")[0], "state_changed": False,
                "permission_created": False, "exception_id": None,
            },
            False,
        )  # fmt: skip

    occurred = body.occurred_at
    tolerance = dt.timedelta(milliseconds=body.clock_uncertainty_ms)
    event_row_id = uuid7()
    holder: dict[str, Any] = {}

    def transition() -> Transition:
        state = visit["state"]
        if body.type == "entry":
            until = visit["authorised_until"]
            if state == "authorised" and (until is None or occurred <= until + tolerance):
                return Transition(True, "entered")
            if state == "inside":
                return Transition(False, "duplicate_entry")
            why = "permission_expired" if state == "authorised" else f"visit_{state}"
            return Transition(
                False, "entry_without_authorisation",
                ("unauthorised_entry", f"Entry observed without a valid authorisation ({why})", True),
            )  # fmt: skip
        if state == "exited":
            return Transition(False, "duplicate_exit")
        if state in ("inside", "authorised"):
            if body.exit_basis == "reconciled_unknown":
                return Transition(
                    True, "exit_reconciled_unknown",
                    ("exit_unknown", "Exit reconciled as unknown: the real exit time was not observed", True),
                )  # fmt: skip
            if state == "authorised":
                return Transition(
                    True, "exit_without_observed_entry",
                    ("exit_without_entry", "Exit observed for a visit whose entry was never observed", None),
                )  # fmt: skip
            return Transition(True, "exited")
        return Transition(
            False, "exit_without_entry",
            ("exit_without_entry", f"Exit observed for a visit in state {state}", None),
        )  # fmt: skip

    outcome = transition()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO access_events (id, society_id, device_id, seq, event_id, event_type, gate_id, lane_id, visit_id,"
                " credential_kind, decision_source, policy_version, occurred_at, clock_uncertainty_ms, payload_hash,"
                " payload, recorded_by) VALUES (:id, :s, :dev, :seq, :eid, :etype, :g, :lane, :v, :ck, :ds, :pv, :occ,"
                " :unc, :hash, CAST(:payload AS jsonb), :by)"
            ),
            {
                "id": event_row_id, "s": society_id, "dev": body.device_id, "seq": body.seq, "eid": body.event_id,
                "etype": "EntryObserved" if body.type == "entry" else "ExitObserved", "g": body.gate_id,
                "lane": body.lane_id, "v": visit_id, "ck": body.credential_kind, "ds": body.decision_source,
                "pv": body.policy_version, "occ": occurred, "unc": body.clock_uncertainty_ms, "hash": digest,
                "payload": json.dumps({"exit_basis": body.exit_basis} if body.exit_basis else {}), "by": ctx.person_id,
            },
        )  # fmt: skip
        new_version = int(visit["version"])
        if outcome.changed and body.type == "entry":
            row = c.execute(
                text(
                    "UPDATE visits SET state = 'inside', entered_at = :occ, confidence_inside = 'observed',"
                    " version = version + 1 WHERE id = :id AND state = 'authorised' RETURNING version"
                ),
                {"occ": occurred, "id": visit_id},
            ).first()
            if row is None:  # pragma: no cover (locked above)
                raise StaleVersion()
            new_version = int(row[0])
        elif outcome.changed:
            reconciled = body.exit_basis == "reconciled_unknown"
            row = c.execute(
                text(
                    "UPDATE visits SET state = 'exited', exit_basis = :basis,"
                    " exited_at = CASE WHEN :rec THEN NULL ELSE CAST(:occ AS timestamptz) END,"
                    " exit_reconciled_at = CASE WHEN :rec THEN CAST(:occ AS timestamptz) END,"
                    " confidence_inside = CASE WHEN :rec THEN 'unknown' ELSE 'none' END, version = version + 1"
                    " WHERE id = :id AND state IN ('inside', 'authorised') RETURNING version"
                ),
                {"basis": body.exit_basis, "rec": reconciled, "occ": occurred, "id": visit_id},
            ).first()
            if row is None:  # pragma: no cover
                raise StaleVersion()
            new_version = int(row[0])
        holder["version"] = new_version
        return MutationResult(
            event_row_id,
            1,
            after={
                "visit_id": visit_id, "type": body.type, "outcome": outcome.note, "gate_id": body.gate_id,
                "device_id": body.device_id, "seq": body.seq, "exit_basis": body.exit_basis,
                "visit_state_before": visit["state"], "permission_created": False,
            },
            event_payload={
                "event_id": body.event_id, "visit_id": visit_id, "gate_id": body.gate_id, "device_id": body.device_id,
                "seq": body.seq, "outcome": outcome.note, "occurred_at": occurred,
                "clock_uncertainty_ms": body.clock_uncertainty_ms, "exit_basis": body.exit_basis,
            },
        )  # fmt: skip

    try:
        mutation(
            conn, ctx, operation=f"visit.{body.type}_observed", object_type="access_event",
            event_type="EntryObserved" if body.type == "entry" else "ExitObserved", apply=apply,
        )  # fmt: skip
    except IntegrityError as exc:
        text_ = str(exc.orig)
        if "access_events_device_seq_uq" in text_ or "access_events_event_uq" in text_:
            raise StaleVersion(details={"reason": "device_sequence_conflict"}) from None
        raise
    exception_id: uuid.UUID | None = None
    if outcome.exception is not None:
        kind, reason, happened = outcome.exception
        exception_id = exceptions.open_exception(
            conn, ctx, kind=kind, reason=reason, visit_id=visit_id, entry_happened=happened,
            evidence={"event_id": str(body.event_id), "gate_id": str(body.gate_id)},
        )  # fmt: skip
    stored = _stored_event(conn, body.event_id)
    row = fetch_visit_row(conn, visit_id)
    assert stored is not None  # noqa: S101
    assert row is not None  # noqa: S101
    return (
        {
            "accepted": True, "deduplicated": False, "event": _event_view(stored),
            "visit": common.visit_views(conn, [row], view="guard")[0], "state_changed": outcome.changed,
            "outcome": outcome.note, "permission_created": False,  # an observation never creates permission
            "exception_id": exception_id,
        },
        True,
    )  # fmt: skip


# ------------------------------------------------------------------------------------------ cancel
def cancel_visit(
    conn: Connection, ctx: RequestContext, visit_id: uuid.UUID, body: VisitCancel
) -> dict[str, Any]:
    """The guard cancels a visit that has not entered: its pending requests are cancelled too (so alerts stop)."""
    visit = conn.execute(text(_VISIT_LOCK), {"id": visit_id}).mappings().first()
    if visit is None:
        raise NotFound()
    if visit["version"] != body.expected_version:
        raise StaleVersion(details={"version": visit["version"], "state": visit["state"]})
    if visit["state"] not in ("requested", "authorised"):
        raise PolicyViolation(details={"reason": "not_cancellable", "state": visit["state"]})

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE visits SET state = 'cancelled', closed_reason = 'cancelled_by_guard', version = version + 1"
                " WHERE id = :id AND state IN ('requested', 'authorised') RETURNING version"
            ),
            {"id": visit_id},
        ).first()
        if row is None:  # pragma: no cover
            raise StaleVersion()
        c.execute(
            text(
                "UPDATE visit_stops SET authorised = false, state = 'cancelled', closed_reason = 'cancelled_by_guard'"
                " WHERE visit_id = :id AND state IN ('pending', 'authorised')"
            ),
            {"id": visit_id},
        )
        return MutationResult(
            visit_id,
            int(row[0]),
            before={"state": visit["state"]},
            after={"state": "cancelled"},
            event_payload={"visit_id": visit_id, "state": "cancelled"},
        )

    mutation(
        conn, ctx, operation="visit.cancel", object_type="visit", event_type="VisitCancelled", apply=apply,
        reason=body.reason,
    )  # fmt: skip
    for (request_id,) in conn.execute(
        text("SELECT id FROM approval_requests WHERE visit_id = :v AND state = 'pending'"),
        {"v": visit_id},
    ).all():
        approvals.cancel_pending_for_visit(conn, ctx, request_id)
    row = fetch_visit_row(conn, visit_id)
    assert row is not None  # noqa: S101
    return common.visit_views(conn, [row], view="guard")[0]


# ------------------------------------------------------------------------------------------ sweep
@dataclass(frozen=True)
class SweepResult:
    requests_expired: int
    authorisations_expired: int
    overstays_opened: int
    invitations_expired: int

    def total(self) -> int:
        return (
            self.requests_expired
            + self.authorisations_expired
            + self.overstays_opened
            + self.invitations_expired
        )


def expire_authorisations(
    conn: Connection, ctx: RequestContext, *, now: dt.datetime | None = None, limit: int = 200
) -> int:
    """An authorised visit whose permission window has passed without entry becomes ``expired`` (never ``inside``)."""
    system = RequestContext(ctx.society_id, None, "system", ctx.request_id)
    rows = conn.execute(
        text(
            "SELECT id FROM visits WHERE state = 'authorised' AND authorised_until IS NOT NULL"
            " AND authorised_until <= COALESCE(CAST(:now AS timestamptz), clock_timestamp())"
            " ORDER BY authorised_until, id LIMIT :n FOR UPDATE SKIP LOCKED"
        ),
        {"now": now, "n": limit},
    ).all()
    done = 0
    for (visit_id,) in rows:

        def apply(c: Connection, visit_id: uuid.UUID = visit_id) -> MutationResult:
            row = c.execute(
                text(
                    "UPDATE visits SET state = 'expired', closed_reason = 'permission_expired', version = version + 1"
                    " WHERE id = :id AND state = 'authorised' RETURNING version"
                ),
                {"id": visit_id},
            ).first()
            if row is None:
                raise _Skip
            c.execute(
                text(
                    "UPDATE visit_stops SET authorised = false, state = 'expired', closed_reason = 'permission_expired'"
                    " WHERE visit_id = :id AND state = 'authorised'"
                ),
                {"id": visit_id},
            )
            return MutationResult(
                visit_id, int(row[0]), before={"state": "authorised"}, after={"state": "expired"},
                event_payload={"visit_id": visit_id, "state": "expired", "reason": "permission_expired"},
            )  # fmt: skip

        try:
            mutation(
                conn, system, operation="visit.expire", object_type="visit", event_type="VisitExpired", apply=apply
            )  # fmt: skip
        except _Skip:
            continue
        done += 1
    return done


def detect_overstays(
    conn: Connection,
    ctx: RequestContext,
    policy: GatePolicy,
    *,
    now: dt.datetime | None = None,
    limit: int = 200,
) -> int:
    """GATE-11: a time-boxed visit still inside past its threshold gets ONE overstay exception (a unique index makes the job
    idempotent) and its inside count is marked ``stale``: we know it entered, we no longer know it is still there."""
    from .policy import DEFAULT_OVERSTAY_MINUTES, json_text

    system = RequestContext(ctx.society_id, None, "system", ctx.request_id)
    rows = conn.execute(
        text(
            "SELECT v.id, v.kind, v.entered_at FROM visits v WHERE v.state = 'inside' AND v.entered_at IS NOT NULL"
            " AND v.kind = ANY(:kinds)"
            " AND NOT EXISTS (SELECT 1 FROM exceptions e WHERE e.visit_id = v.id AND e.kind = 'overstay')"
            " AND v.entered_at + make_interval(mins => COALESCE(v.expected_minutes,"
            "   (CAST(:th AS jsonb) ->> v.kind)::int)) <= COALESCE(CAST(:now AS timestamptz), clock_timestamp())"
            " ORDER BY v.entered_at, v.id LIMIT :n FOR UPDATE OF v SKIP LOCKED"
        ),
        {
            "kinds": list(DEFAULT_OVERSTAY_MINUTES), "th": json_text(policy.overstay_minutes), "now": now,
            "n": limit,
        },
    ).all()  # fmt: skip
    opened = 0
    for visit_id, kind, entered_at in rows:
        exception_id = uuid7()

        def apply(
            c: Connection,
            visit_id: uuid.UUID = visit_id,
            kind: str = kind,
            entered_at: Any = entered_at,
            exception_id: uuid.UUID = exception_id,
        ) -> MutationResult:
            created = c.execute(
                text(
                    "INSERT INTO exceptions (id, society_id, kind, visit_id, reason, raised_by_system, evidence,"
                    " entry_happened) VALUES (:id, :s, 'overstay', :v, :why, true, CAST(:ev AS jsonb), true)"
                    " ON CONFLICT (society_id, visit_id) WHERE kind = 'overstay' DO NOTHING RETURNING id"
                ),
                {
                    "id": exception_id, "s": ctx.society_id, "v": visit_id,
                    "why": f"Visit ({kind}) is still inside past its time limit",
                    "ev": json_text({"entered_at": entered_at.isoformat(), "kind": kind}),
                },
            ).first()  # fmt: skip
            if created is None:
                raise _Skip
            c.execute(
                text(
                    "UPDATE visits SET confidence_inside = 'stale', version = version + 1"
                    " WHERE id = :id AND state = 'inside'"
                ),
                {"id": visit_id},
            )
            return MutationResult(
                exception_id, 1, after={"kind": "overstay", "state": "open", "visit_id": visit_id},
                event_payload={"exception_id": exception_id, "kind": "overstay", "visit_id": visit_id, "state": "open"},
            )  # fmt: skip

        try:
            mutation(
                conn, system, operation="exception.open", object_type="exception", event_type="ExceptionOpened",
                apply=apply,
            )  # fmt: skip
        except _Skip:
            continue
        opened += 1
    return opened


def sweep(
    conn: Connection, ctx: RequestContext, policy: GatePolicy, *, now: dt.datetime | None = None
) -> SweepResult:
    """One idempotent pass of every time-driven transition of ONE society (the worker calls this per society):
    pending requests past their expiry, authorisations past their window, overstays, passes past their last window."""
    return SweepResult(
        requests_expired=approvals.expire_due_requests(conn, ctx),
        authorisations_expired=expire_authorisations(conn, ctx, now=now),
        overstays_opened=detect_overstays(conn, ctx, policy, now=now),
        invitations_expired=invitations.expire_invitations(
            conn, RequestContext(ctx.society_id, None, "system", ctx.request_id), now=now
        ),
    )
