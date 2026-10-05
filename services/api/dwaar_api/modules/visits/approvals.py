"""Approval requests (GATE-02, GATE-03): create, decide (compare-and-swap), cancel, reverse, expire.

REQ: GATE-02 (unannounced visitor: destination confirmed, notice and consent recorded, request expires on the society policy
and NEVER auto-admits), GATE-03 (a denied or expired request cannot be resurrected by a stale mobile approval: 409
``already_decided`` / ``request_expired``), PRD 9.2 (Approval request: pending -> approved / denied / expired / cancelled; the
FIRST valid decision wins by compare-and-swap; a later reversal is a NEW event), PRD 12.3 (canonical decision response,
``entry_observed: false``), INV-03, INV-07, GATE-13.

The race, in SQL
----------------
``decide`` runs ONE transaction whose first write is::

    UPDATE approval_requests SET state = :new, ..., version = version + 1
    WHERE id = :id AND state = 'pending' AND version = :expected AND expires_at > clock_timestamp()

Two household members answering at once serialise on that row lock. The second UPDATE re-evaluates the WHERE clause against
the committed row, finds ``state <> 'pending'`` and updates nothing; the code then reads the committed row and answers
409 ``already_decided`` carrying the canonical result (the other device learns the outcome), or 409 ``request_expired`` when the
request had expired. Only the winner inserts the decision row (a partial unique index backs "one valid first decision").
The permission window (``permission_expires_at``) exists ONLY on an approved request, so an expired or denied request can
never carry one (CHECK constraint).

Expiry is evaluated lazily (every read and every decide expires a due request first) and by the idempotent
``expire_due_requests`` job function, which any worker can call.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import (
    AlreadyDecided,
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    RequestExpired,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.idempotency import encode_response
from . import common, gates, tokens
from . import policy as policy_mod
from .config import VisitsConfig
from .policy import GatePolicy
from .schemas import (
    ApprovalRequestCreate,
    CancelIn,
    DecisionIn,
    ReversalIn,
    StopAdd,
)

_REQ_SELECT: Final = (
    "SELECT r.id, r.unit_id, r.visit_id, r.gate_id, r.state, r.expires_at, r.destination_confirmed, r.decision_id,"
    " r.closed_at, r.closed_reason, r.permission_expires_at, r.version, r.created_at, r.requested_by, r.cascade,"
    " EXISTS (SELECT 1 FROM access_events ae WHERE ae.society_id = r.society_id AND ae.visit_id = r.visit_id"
    "  AND ae.event_type = 'EntryObserved') AS entry_observed,"
    " d.decision AS decided_how, d.decider_role, d.decided_at, d.channel,"
    " v.kind AS visit_kind, v.visitor_alias, v.people_count, v.vehicle_plate, v.state AS visit_state,"
    " u.label AS unit_label, b.name AS block_name, clock_timestamp() AS server_time"
    " FROM approval_requests r"
    " JOIN visits v ON v.society_id = r.society_id AND v.id = r.visit_id"
    " JOIN units u ON u.society_id = r.society_id AND u.id = r.unit_id"
    " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
    " LEFT JOIN approval_decisions d ON d.society_id = r.society_id AND d.request_id = r.id AND d.valid"
)


# ------------------------------------------------------------------------------------------ views
def canonical(row: Mapping[Any, Any]) -> dict[str, Any]:
    """The PRD 12.3 canonical response. ``request_id`` is the APPROVAL REQUEST id (the PRD example), ``entry_observed`` is
    false until an entry is really observed: approval is never shown as physical entry (INV-07)."""
    return {
        "request_id": row["id"],
        "status": row["state"],
        "version": row["version"],
        "decision_id": row["decision_id"],
        "permission_expires_at": row["permission_expires_at"],
        "entry_observed": bool(row["entry_observed"]),
    }


def request_view(row: Mapping[Any, Any], *, audience: str) -> dict[str, Any]:
    """``audience`` is ``guard`` or ``household``; neither sees a resident's identity or number (GATE-13): only the unit,
    the state, WHICH KIND of household member decided, and the visitor's own details."""
    remaining = (
        max(0, int((row["expires_at"] - row["server_time"]).total_seconds()))
        if row["state"] == "pending"
        else 0
    )
    out: dict[str, Any] = {
        "id": row["id"],
        "status": row["state"],
        "version": row["version"],
        "visit_id": row["visit_id"],
        "unit_id": row["unit_id"],
        "block_name": row["block_name"],
        "unit_label": row["unit_label"],
        "gate_id": row["gate_id"],
        "visitor": {
            "kind": row["visit_kind"],
            "alias": row["visitor_alias"],
            "people_count": row["people_count"],
            "vehicle_plate": row["vehicle_plate"],
        },
        "expires_at": row["expires_at"],
        "expires_in_seconds": remaining,
        "decision": {
            "made": row["decided_how"],
            "by_role": row["decider_role"],
            "at": row["decided_at"],
        }
        if row["decided_how"]
        else None,
        "decision_id": row["decision_id"],
        "permission_expires_at": row["permission_expires_at"],
        "closed_reason": row["closed_reason"],
        "entry_observed": bool(row["entry_observed"]),
        "auto_allow_on_timeout": False,  # INV-03
        "created_at": row["created_at"],
    }
    if row["state"] == "expired":
        steps = (row["cascade"] or {}).get("steps") or []
        out["guard_options"] = steps[-1].get("guard_options", []) if steps else []
    if audience == "guard":
        out["destination_confirmed"] = row["destination_confirmed"]
    return out


def fetch_request(conn: Connection, request_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(text(_REQ_SELECT + " WHERE r.id = :id"), {"id": request_id}).mappings().first()
    )
    return dict(row) if row else None


def _lock_request_row(conn: Connection, request_id: uuid.UUID) -> None:
    conn.execute(
        text("SELECT 1 FROM approval_requests WHERE id = :id FOR NO KEY UPDATE"), {"id": request_id}
    )


# ------------------------------------------------------------------------------------------ create
def create_request(
    conn: Connection,
    ctx: RequestContext,
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    body: ApprovalRequestCreate,
    policy: GatePolicy,
) -> dict[str, Any]:
    """GATE-02: notice and consent, destination confirmation, one visit, one stop, one PENDING request."""
    assert ctx.person_id is not None  # noqa: S101
    common.require_unit(conn, body.unit_id)
    gates.require_active_gate(conn, body.gate_id)
    if not body.notice.consent_given:
        raise PolicyViolation(details={"reason": "visitor_consent_required"})
    if not body.destination_confirmed:
        raise PolicyViolation(details={"reason": "destination_not_confirmed"})
    policy_mod.check_expected_minutes(body.kind, body.expected_minutes)
    if not common.deciders(conn, body.unit_id):
        # nobody can answer: do not park a request nobody can decide (no auto-admission either: the guard uses the options)
        raise PolicyViolation(details={"reason": "no_household_approver"})
    token = (
        tokens.contact_token(cfg, society_id, body.visitor_phone) if body.visitor_phone else None
    )
    visit_id, request_id, stop_id = uuid7(), uuid7(), uuid7()
    plan = policy_mod.cascade_plan(policy.approval_expiry_seconds)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO visits (id, society_id, kind, state, visitor_alias, visitor_contact_token, photo_ref, gate_id,"
                " people_count, vehicle_plate, expected_minutes, notice_version, notice_language, consent_recorded,"
                " created_by) VALUES (:id, :s, :kind, 'requested', :alias, :tok, :photo, :g, :n, :plate, :exp, :nv, :nl,"
                " true, :by)"
            ),
            {
                "id": visit_id, "s": society_id, "kind": body.kind, "alias": body.visitor_alias, "tok": token,
                "photo": body.photo_ref, "g": body.gate_id, "n": body.people_count, "plate": body.vehicle_plate,
                "exp": body.expected_minutes, "nv": body.notice.version, "nl": body.notice.language, "by": ctx.person_id,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO approval_requests (id, society_id, unit_id, visit_id, gate_id, expires_at, cascade,"
                " destination_confirmed, requested_by) VALUES (:id, :s, :u, :v, :g,"
                " clock_timestamp() + make_interval(secs => :secs), CAST(:cascade AS jsonb), :dc, :by)"
            ),
            {
                "id": request_id, "s": society_id, "u": body.unit_id, "v": visit_id, "g": body.gate_id,
                "secs": policy.approval_expiry_seconds, "cascade": policy_mod.json_text(plan),
                "dc": body.destination_confirmed, "by": ctx.person_id,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq, approval_request_id)"
                " VALUES (:id, :s, :v, :u, 1, :r)"
            ),
            {"id": stop_id, "s": society_id, "v": visit_id, "u": body.unit_id, "r": request_id},
        )
        expires_at = c.execute(
            text("SELECT expires_at FROM approval_requests WHERE id = :id"), {"id": request_id}
        ).scalar_one()
        return MutationResult(
            request_id,
            1,
            after={
                "state": "pending", "unit_id": body.unit_id, "visit_id": visit_id, "gate_id": body.gate_id,
                "kind": body.kind, "expires_at": expires_at, "consent_recorded": True,
                "notice_version": body.notice.version, "phone_free": token is None,
            },
            event_payload={
                "request_id": request_id, "visit_id": visit_id, "unit_id": body.unit_id, "gate_id": body.gate_id,
                "expires_at": expires_at, "expiry_seconds": policy.approval_expiry_seconds,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="approval.request", object_type="approval_request", event_type="ApprovalRequested",
        apply=apply,
    )  # fmt: skip
    row = fetch_request(conn, request_id)
    assert row is not None  # noqa: S101
    return request_view(row, audience="guard")


# ------------------------------------------------------------------------------------------ side effects
def _on_approved(
    c: Connection, request_id: uuid.UUID, visit_id: uuid.UUID, permission_expires: Any
) -> None:
    c.execute(
        text(
            "UPDATE visit_stops SET authorised = true, state = 'authorised', closed_reason = NULL"
            " WHERE approval_request_id = :r"
        ),
        {"r": request_id},
    )
    c.execute(
        text(
            "UPDATE visits SET state = CASE WHEN state = 'requested' THEN 'authorised' ELSE state END,"
            " authorisation_source = COALESCE(authorisation_source, 'household_approval'),"
            " authorised_at = COALESCE(authorised_at, clock_timestamp()),"
            " authorised_until = GREATEST(COALESCE(authorised_until, :pe), :pe), version = version + 1"
            " WHERE id = :v AND state IN ('requested', 'authorised', 'inside')"
        ),
        {"v": visit_id, "pe": permission_expires},
    )


def _on_closed(
    c: Connection,
    request_id: uuid.UUID,
    visit_id: uuid.UUID,
    *,
    stop_state: str,
    visit_state: str,
    reason: str,
) -> None:
    """A request ended without permission (denied / expired / cancelled / reversed): only THAT stop is closed. The visit
    ends only if nothing else keeps it alive (another pending request or an authorised stop)."""
    c.execute(
        text(
            "UPDATE visit_stops SET authorised = false, state = :st, closed_reason = :why"
            " WHERE approval_request_id = :r"
        ),
        {"st": stop_state, "why": reason, "r": request_id},
    )
    c.execute(
        text(
            "UPDATE visits SET state = :vs, closed_reason = :why, version = version + 1"
            " WHERE id = :v AND state IN ('requested', 'authorised')"
            " AND NOT EXISTS (SELECT 1 FROM approval_requests p WHERE p.visit_id = visits.id AND p.state = 'pending'"
            "   AND p.id <> :r)"
            " AND NOT EXISTS (SELECT 1 FROM visit_stops s WHERE s.visit_id = visits.id AND s.authorised)"
        ),
        {"vs": visit_state, "why": reason, "v": visit_id, "r": request_id},
    )


def _loser(current: Mapping[Any, Any], expected_version: int) -> Exception:
    """Why a compare-and-swap found nothing to update, as the error the PRD names. ``details.canonical`` is the committed
    result, so a device that lost the race (or acted on a stale screen) learns the outcome in the same answer."""
    safe = encode_response(
        canonical(current)
    )  # error details must be JSON-safe (uuid and datetime become text)
    details = {"canonical": safe, "decided_by_role": current["decider_role"]}
    state = current["state"]
    due = state == "pending" and current["expires_at"] <= current["server_time"]
    if state == "expired" or due:
        return RequestExpired(details={"canonical": {**safe, "status": "expired"}})
    if state in ("approved", "denied", "cancelled"):
        return AlreadyDecided(details=details)
    return StaleVersion(details={"canonical": safe, "expected_version": expected_version})


# ------------------------------------------------------------------------------------------ decide
def _authorise_household(
    conn: Connection, scope: Scope, person_id: uuid.UUID, request: Mapping[Any, Any]
) -> common.Member:
    if not scope.covers_unit(request["unit_id"]):
        raise NotFound()  # another household's request: indistinguishable from an unknown id
    standing = common.member_standing(conn, person_id, request["unit_id"])
    if standing is None:
        raise NotFound()
    if not standing.can_decide:
        raise NotAuthorised()  # a household member without the delegation
    return standing


def decide(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    request_id: uuid.UUID,
    body: DecisionIn,
    policy: GatePolicy,
) -> dict[str, Any]:
    """PRD 12.3. Returns the canonical response of the winning decision, or of THIS caller's earlier identical action
    (``client_action_id``), or raises 409 with the canonical result of whoever won."""
    assert ctx.person_id is not None  # noqa: S101
    person_id = ctx.person_id
    request = fetch_request(conn, request_id)
    if request is None:
        raise NotFound()
    standing = _authorise_household(conn, scope, person_id, request)
    earlier = conn.execute(
        text(
            "SELECT d.request_version FROM approval_decisions d WHERE d.request_id = :r AND d.decided_by = :p"
            " AND d.client_action_id = :c"
        ),
        {"r": request_id, "p": person_id, "c": body.client_action_id},
    ).first()
    if earlier is not None:
        # the same client action again (a retry with a fresh Idempotency-Key): the original answer, not a second decision
        return canonical(request)
    approve = body.decision == "approve"
    new_state = "approved" if approve else "denied"
    decision_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        won = c.execute(
            text(
                "UPDATE approval_requests SET state = :st, decision_id = :did, closed_at = clock_timestamp(),"
                " closed_reason = :why,"
                " permission_expires_at = CASE WHEN :ap THEN clock_timestamp() + make_interval(mins => :mins) END,"
                " version = version + 1"
                " WHERE id = :id AND state = 'pending' AND version = :v AND expires_at > clock_timestamp()"
                " RETURNING version, permission_expires_at, visit_id"
            ),
            {
                "st": new_state, "did": decision_id, "why": "approved" if approve else "denied", "ap": approve,
                "mins": policy.permission_validity_minutes, "id": request_id, "v": body.expected_version,
            },
        ).first()  # fmt: skip
        if won is None:
            current = fetch_request(c, request_id)
            assert current is not None  # noqa: S101
            raise _loser(current, body.expected_version)
        version, permission_expires, visit_id = int(won[0]), won[1], won[2]
        c.execute(
            text(
                "INSERT INTO approval_decisions (id, society_id, request_id, decided_by, decider_role, decision, channel,"
                " client_action_id, valid, request_version) VALUES (:id, :s, :r, :by, :role, :dec, :ch, :cid, true, :ver)"
            ),
            {
                "id": decision_id, "s": ctx.society_id, "r": request_id, "by": person_id, "role": standing.role,
                "dec": body.decision, "ch": body.channel, "cid": body.client_action_id, "ver": version,
            },
        )  # fmt: skip
        if approve:
            _on_approved(c, request_id, visit_id, permission_expires)
        else:
            _on_closed(
                c,
                request_id,
                visit_id,
                stop_state="denied",
                visit_state="cancelled",
                reason="denied",
            )
        return MutationResult(
            request_id,
            version,
            before={"state": "pending", "version": body.expected_version},
            after={"state": new_state, "decision": body.decision, "channel": body.channel, "role": standing.role},
            event_payload={
                "request_id": request_id, "visit_id": visit_id, "unit_id": request["unit_id"], "status": new_state,
                "decision_id": decision_id, "decided_by_role": standing.role, "version": version,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="approval.decide", object_type="approval_request", event_type="ApprovalDecided",
        apply=apply, approver_id=person_id,
    )  # fmt: skip
    fresh = fetch_request(conn, request_id)
    assert fresh is not None  # noqa: S101
    return canonical(fresh)


def reverse(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    request_id: uuid.UUID,
    body: ReversalIn,
) -> dict[str, Any]:
    """A LATER reversal of an approval is a NEW event, never an edit of the first decision. Allowed only while the visitor
    has not been observed entering (after that the permission is spent)."""
    assert ctx.person_id is not None  # noqa: S101
    person_id = ctx.person_id
    request = fetch_request(conn, request_id)
    if request is None:
        raise NotFound()
    standing = _authorise_household(conn, scope, person_id, request)
    earlier = conn.execute(
        text(
            "SELECT 1 FROM approval_decisions WHERE request_id = :r AND decided_by = :p AND client_action_id = :c"
        ),
        {"r": request_id, "p": person_id, "c": body.client_action_id},
    ).first()
    if earlier is not None:
        return canonical(request)
    if request["state"] == "pending":
        raise PolicyViolation(details={"reason": "not_approved"})
    if request["entry_observed"] or request["visit_state"] == "inside":
        raise PolicyViolation(details={"reason": "entry_already_observed"})
    reversal_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        won = c.execute(
            text(
                "UPDATE approval_requests SET state = 'cancelled', closed_reason = 'reversed',"
                " permission_expires_at = NULL, version = version + 1"
                " WHERE id = :id AND state = 'approved' AND version = :v RETURNING version, visit_id, decision_id"
            ),
            {"id": request_id, "v": body.expected_version},
        ).first()
        if won is None:
            current = fetch_request(c, request_id)
            assert current is not None  # noqa: S101
            raise _loser(current, body.expected_version)
        version, visit_id, first_decision = int(won[0]), won[1], won[2]
        c.execute(
            text(
                "INSERT INTO approval_decisions (id, society_id, request_id, decided_by, decider_role, decision, channel,"
                " client_action_id, valid, request_version, reverses_decision_id, reason)"
                " VALUES (:id, :s, :r, :by, :role, 'reverse', 'app', :cid, false, :ver, :first, :why)"
            ),
            {
                "id": reversal_id, "s": ctx.society_id, "r": request_id, "by": person_id, "role": standing.role,
                "cid": body.client_action_id, "ver": version, "first": first_decision, "why": body.reason,
            },
        )  # fmt: skip
        _on_closed(
            c,
            request_id,
            visit_id,
            stop_state="cancelled",
            visit_state="cancelled",
            reason="reversed",
        )
        return MutationResult(
            request_id,
            version,
            before={"state": "approved"},
            after={"state": "cancelled", "reversed": True, "role": standing.role},
            event_payload={
                "request_id": request_id, "visit_id": visit_id, "unit_id": request["unit_id"], "status": "cancelled",
                "reversal_id": reversal_id, "decided_by_role": standing.role, "version": version,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="approval.reverse", object_type="approval_request", event_type="ApprovalDecided",
        apply=apply, reason=body.reason, approver_id=person_id,
    )  # fmt: skip
    fresh = fetch_request(conn, request_id)
    assert fresh is not None  # noqa: S101
    return canonical(fresh)


def cancel(
    conn: Connection, ctx: RequestContext, request_id: uuid.UUID, body: CancelIn
) -> dict[str, Any]:
    """The guard withdraws a PENDING request (visitor left). Decided or expired requests cannot be cancelled."""
    request = fetch_request(conn, request_id)
    if request is None:
        raise NotFound()

    def apply(c: Connection) -> MutationResult:
        won = c.execute(
            text(
                "UPDATE approval_requests SET state = 'cancelled', closed_at = clock_timestamp(),"
                " closed_reason = 'cancelled_by_guard', version = version + 1"
                " WHERE id = :id AND state = 'pending' AND version = :v AND expires_at > clock_timestamp()"
                " RETURNING version, visit_id"
            ),
            {"id": request_id, "v": body.expected_version},
        ).first()
        if won is None:
            current = fetch_request(c, request_id)
            assert current is not None  # noqa: S101
            raise _loser(current, body.expected_version)
        _on_closed(
            c,
            request_id,
            won[1],
            stop_state="cancelled",
            visit_state="cancelled",
            reason="cancelled_by_guard",
        )
        return MutationResult(
            request_id,
            int(won[0]),
            before={"state": "pending"},
            after={"state": "cancelled"},
            event_payload={
                "request_id": request_id, "visit_id": won[1], "unit_id": request["unit_id"], "status": "cancelled",
                "version": int(won[0]),
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="approval.cancel", object_type="approval_request", event_type="ApprovalDecided",
        apply=apply, reason=body.reason,
    )  # fmt: skip
    fresh = fetch_request(conn, request_id)
    assert fresh is not None  # noqa: S101
    return canonical(fresh)


class _Skip(Exception):
    """The row is no longer due (someone decided or expired it first): not an error, nothing to write."""


def cancel_pending_for_visit(conn: Connection, ctx: RequestContext, request_id: uuid.UUID) -> bool:
    """Cancel one pending request because its visit was cancelled (no version check: the visit's own CAS decided).
    Emits ``ApprovalDecided`` (status cancelled) so household alerts stop. Returns False if it was no longer pending."""

    def apply(c: Connection) -> MutationResult:
        won = c.execute(
            text(
                "UPDATE approval_requests SET state = 'cancelled', closed_at = clock_timestamp(),"
                " closed_reason = 'visit_cancelled', version = version + 1"
                " WHERE id = :id AND state = 'pending' RETURNING version, visit_id, unit_id"
            ),
            {"id": request_id},
        ).first()
        if won is None:
            raise _Skip
        _on_closed(
            c,
            request_id,
            won[1],
            stop_state="cancelled",
            visit_state="cancelled",
            reason="visit_cancelled",
        )
        return MutationResult(
            request_id,
            int(won[0]),
            before={"state": "pending"},
            after={"state": "cancelled", "reason": "visit_cancelled"},
            event_payload={
                "request_id": request_id, "visit_id": won[1], "unit_id": won[2], "status": "cancelled",
                "version": int(won[0]),
            },
        )  # fmt: skip

    try:
        mutation(
            conn, ctx, operation="approval.cancel", object_type="approval_request", event_type="ApprovalDecided",
            apply=apply,
        )  # fmt: skip
    except _Skip:
        return False
    return True


# ------------------------------------------------------------------------------------------ stops (GATE-04)
def add_stop(
    conn: Connection,
    ctx: RequestContext,
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    visit_id: uuid.UUID,
    body: StopAdd,
    policy: GatePolicy,
) -> dict[str, Any]:
    """Another destination of the same visit: a NEW stop and a NEW approval request. Existing authorisations are untouched
    and the new stop is NOT authorised until its own household decides (GATE-04)."""
    visit = (
        conn.execute(
            text("SELECT id, state, version, gate_id FROM visits WHERE id = :id FOR UPDATE"),
            {"id": visit_id},
        )
        .mappings()
        .first()
    )
    if visit is None:
        raise NotFound()
    if visit["state"] not in ("requested", "authorised", "inside"):
        raise PolicyViolation(details={"reason": "visit_closed", "state": visit["state"]})
    if visit["version"] != body.expected_version:
        raise StaleVersion(details={"version": visit["version"]})
    common.require_unit(conn, body.unit_id)
    if not body.destination_confirmed:
        raise PolicyViolation(details={"reason": "destination_not_confirmed"})
    existing = conn.execute(
        text(
            "SELECT count(*), max(seq), bool_or(unit_id = :u) FROM visit_stops WHERE visit_id = :v"
        ),
        {"u": body.unit_id, "v": visit_id},
    ).one()
    if existing[2]:
        raise PolicyViolation(details={"reason": "duplicate_stop"})
    if int(existing[0]) >= cfg.max_stops_per_visit:
        raise PolicyViolation(details={"reason": "too_many_stops"})
    if not common.deciders(conn, body.unit_id):
        raise PolicyViolation(details={"reason": "no_household_approver"})
    request_id, stop_id = uuid7(), uuid7()
    plan = policy_mod.cascade_plan(policy.approval_expiry_seconds)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO approval_requests (id, society_id, unit_id, visit_id, gate_id, expires_at, cascade,"
                " destination_confirmed, requested_by) VALUES (:id, :s, :u, :v, :g,"
                " clock_timestamp() + make_interval(secs => :secs), CAST(:cascade AS jsonb), true, :by)"
            ),
            {
                "id": request_id, "s": society_id, "u": body.unit_id, "v": visit_id, "g": visit["gate_id"],
                "secs": policy.approval_expiry_seconds, "cascade": policy_mod.json_text(plan), "by": ctx.person_id,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq, approval_request_id)"
                " VALUES (:id, :s, :v, :u, :seq, :r)"
            ),
            {
                "id": stop_id,
                "s": society_id,
                "v": visit_id,
                "u": body.unit_id,
                "seq": int(existing[1] or 0) + 1,
                "r": request_id,
            },
        )
        c.execute(text("UPDATE visits SET version = version + 1 WHERE id = :id"), {"id": visit_id})
        expires_at = c.execute(
            text("SELECT expires_at FROM approval_requests WHERE id = :id"), {"id": request_id}
        ).scalar_one()
        return MutationResult(
            request_id,
            1,
            after={"state": "pending", "unit_id": body.unit_id, "visit_id": visit_id, "added_stop": True},
            event_payload={
                "request_id": request_id, "visit_id": visit_id, "unit_id": body.unit_id, "gate_id": visit["gate_id"],
                "expires_at": expires_at, "expiry_seconds": policy.approval_expiry_seconds,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="approval.request_stop", object_type="approval_request",
        event_type="ApprovalRequested", apply=apply,
    )  # fmt: skip
    row = fetch_request(conn, request_id)
    assert row is not None  # noqa: S101
    return request_view(row, audience="guard")


# ------------------------------------------------------------------------------------------ expiry
def expire_due_requests(
    conn: Connection,
    ctx: RequestContext,
    *,
    request_id: uuid.UUID | None = None,
    unit_id: uuid.UUID | None = None,
    limit: int = 100,
) -> int:
    """Expire pending requests whose time is up. IDEMPOTENT and safe to run from any number of workers at once: each row is
    claimed with ``FOR UPDATE SKIP LOCKED`` and re-checked inside the update. Returns how many requests THIS call expired.

    ``conn`` must already carry the society's RLS context. The audit/outbox actor is the system, whoever triggered it.
    Emits ``ApprovalEscalated`` (reason ``expired``): the cascade ended and the guard gets the assisted options, so the
    notification worker can stop alerting (a decision emits ``ApprovalDecided`` for the same purpose). Nothing is allowed."""
    system = RequestContext(ctx.society_id, None, "system", ctx.request_id)
    due = conn.execute(
        text(
            "SELECT id FROM approval_requests WHERE state = 'pending' AND expires_at <= clock_timestamp()"
            " AND (CAST(:rid AS uuid) IS NULL OR id = CAST(:rid AS uuid))"
            " AND (CAST(:uid AS uuid) IS NULL OR unit_id = CAST(:uid AS uuid))"
            " ORDER BY expires_at, id LIMIT :n FOR UPDATE SKIP LOCKED"
        ),
        {"rid": request_id, "uid": unit_id, "n": limit},
    ).all()
    expired = 0
    for (rid,) in due:

        def apply(c: Connection, rid: uuid.UUID = rid) -> MutationResult:
            row = c.execute(
                text(
                    "UPDATE approval_requests SET state = 'expired', closed_at = clock_timestamp(),"
                    " closed_reason = 'expired', version = version + 1"
                    " WHERE id = :id AND state = 'pending' AND expires_at <= clock_timestamp()"
                    " RETURNING version, visit_id, unit_id, cascade"
                ),
                {"id": rid},
            ).first()
            if row is None:
                raise _Skip
            _on_closed(
                c, rid, row[1], stop_state="expired", visit_state="expired", reason="expired"
            )
            steps = (row[3] or {}).get("steps") or []
            return MutationResult(
                rid,
                int(row[0]),
                before={"state": "pending"},
                after={"state": "expired"},
                event_payload={
                    "request_id": rid, "visit_id": row[1], "unit_id": row[2], "status": "expired",
                    "reason": "expired", "version": int(row[0]),
                    "guard_options": steps[-1].get("guard_options", []) if steps else [],
                },
            )  # fmt: skip

        try:
            mutation(
                conn, system, operation="approval.expire", object_type="approval_request",
                event_type="ApprovalEscalated", apply=apply,
            )  # fmt: skip
        except _Skip:
            continue
        expired += 1
    return expired


def require_known(conn: Connection, request_id: uuid.UUID) -> dict[str, Any]:
    row = fetch_request(conn, request_id)
    if row is None:
        raise NotFound()
    return row


def invalid_field(name: str, issue: str) -> InvalidSchema:
    return InvalidSchema.for_fields([(name, issue)])
