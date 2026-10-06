"""Request-time operations of the notifications module (the HTTP routes call these; the worker calls ``engine`` / ``runner``).

REQ: NOTIF-02 (receipts are monotone and only the recipient's own app can report them), NOTIF-04 / NOTIF-05 (deep link fetches the CURRENT request
state; a lock-screen action re-checks membership and the decision is made by the visits service: late action -> 409 ``request_expired`` /
``already_decided``), NOTIF-03 (a supervisor starts a new attempt: the only way past one primary and one alternate call), CALL-01 (role-authorised
contact resolution, TTL-bound session, no recording, no number), INV-01, INV-03.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ..visits import approvals, common
from ..visits.permissions import GATE_STAFF
from ..visits.policy import GatePolicy
from ..visits.schemas import DecisionIn
from . import budget, engine, views
from .config import NotificationsConfig
from .planner import IVR, STEP_IVR, dedupe_key

ATTEMPT_LIMIT = 5
MIN_REMAINING_FOR_ATTEMPT = 10


def db_now(conn: Connection) -> dt.datetime:
    value = conn.execute(text("SELECT clock_timestamp()")).scalar_one()
    assert isinstance(value, dt.datetime)  # noqa: S101
    return value


# ------------------------------------------------------------------------------------------------------------ recipient side
def fetch_own(
    conn: Connection, scope: Scope, person_id: uuid.UUID, notification_id: uuid.UUID
) -> dict[str, Any]:
    """One of the caller's own notifications. Somebody else's, another society's and a made-up id are the same ``not_found``; a notification
    about a unit the caller no longer belongs to is too (NOTIF-05: membership re-checked)."""
    row = (
        conn.execute(
            text(
                f"SELECT {views.N_COLUMNS}, r.unit_id AS unit_id FROM notifications n"  # noqa: S608
                " LEFT JOIN approval_requests r ON r.society_id = n.society_id AND r.id = n.request_id WHERE n.id = :id"
            ),
            {"id": notification_id},
        )
        .mappings()
        .first()
    )
    if row is None or row["recipient_person_id"] != person_id:
        raise NotFound()
    if row["unit_id"] is not None and not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    return dict(row)


def deep_link(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    person_id: uuid.UUID,
    notification_id: uuid.UUID,
) -> dict[str, Any]:
    """NOTIF-05: open the exact request of a notification and answer with its CURRENT state, never the state at send time.

    The first authenticated fetch by the recipient is the evidence that the app received it (``app_received``): a deep link opened from an SMS
    or WhatsApp message is how those channels ever reach that state."""
    row = fetch_own(conn, scope, person_id, notification_id)
    if row["request_id"] is None:
        return {
            "notification": views.notification_view(row, audience="resident"),
            "request": None,
            "actionable": False,
        }
    approvals.expire_due_requests(conn, ctx, request_id=row["request_id"])
    request = approvals.fetch_request(conn, row["request_id"])
    if request is None:
        raise NotFound()
    now = db_now(conn)
    if row["app_received_at"] is None and row["state"] != "expired":
        engine._advance_receipt(conn, notification_id, "app_received", now)  # noqa: SLF001
        engine._attempt(
            conn,
            ctx,
            notification_id,
            "device",
            "deep_link_opened",
            now,
            {},
            provider_event_id="device:deep_link_opened",
        )  # noqa: SLF001
    fresh = fetch_own(conn, scope, person_id, notification_id)
    standing = common.member_standing(conn, person_id, request["unit_id"])
    actionable = (
        request["state"] == "pending"
        and standing is not None
        and standing.can_decide
        and fresh["state"] != "expired"
    )
    return {
        "notification": views.notification_view(fresh, audience="resident"),
        "request": approvals.request_view(request, audience="household"),
        "actionable": bool(actionable),
        "server_time": now,
    }


def receipt(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    person_id: uuid.UUID,
    notification_id: uuid.UUID,
    event: str,
    observed_at: dt.datetime | None,
) -> dict[str, Any]:
    """The recipient's app reports that it received / displayed the notification. Monotone and idempotent: a repeat or an out-of-order report
    changes nothing it should not, and a report after expiry stamps its time but never revives the notification."""
    row = fetch_own(conn, scope, person_id, notification_id)
    now = db_now(conn)
    at = now
    if observed_at is not None:
        stamp = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=dt.UTC)
        at = min(max(stamp, row["created_at"]), now)
    fresh_fact = engine._attempt(
        conn, ctx, notification_id, "device", event, at, {}, provider_event_id=f"device:{event}"
    )  # noqa: SLF001
    if fresh_fact:
        engine._advance_receipt(conn, notification_id, event, at)  # noqa: SLF001
    fresh = fetch_own(conn, scope, person_id, notification_id)
    request_state = None
    if fresh["request_id"] is not None:
        req = approvals.fetch_request(conn, fresh["request_id"])
        request_state = None if req is None else req["state"]
    return {
        "notification": views.notification_view(fresh, audience="resident"),
        "request_status": request_state,
        "actionable": request_state == "pending" and fresh["state"] != "expired",
    }


def act(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    person_id: uuid.UUID,
    notification_id: uuid.UUID,
    *,
    action: str,
    client_action_id: uuid.UUID,
    expected_version: int | None,
    policy: GatePolicy,
) -> dict[str, Any]:
    """Approve or deny from a notification. The VISITS service decides (membership re-checked there, first valid decision wins, 409 after
    expiry or an earlier decision with the canonical state); this only adds the notification's own bookkeeping."""
    row = fetch_own(conn, scope, person_id, notification_id)
    if row["request_id"] is None:
        raise NotFound()
    request = approvals.fetch_request(conn, row["request_id"])
    if request is None:
        raise NotFound()
    version = int(expected_version if expected_version is not None else request["version"])
    body = DecisionIn(
        decision=action,
        expected_version=version,
        client_action_id=client_action_id,
        channel="app",
    )
    canonical = approvals.decide(conn, ctx, scope, row["request_id"], body, policy)
    now = db_now(conn)
    conn.execute(
        text(
            "UPDATE notifications SET state = 'actioned', action = :a, actioned_at = COALESCE(actioned_at, :t),"
            " app_received_at = COALESCE(app_received_at, :t), version = version + 1 WHERE id = :id AND state <> 'expired'"
        ),
        {"a": action, "t": now, "id": notification_id},
    )
    engine._attempt(
        conn,
        ctx,
        notification_id,
        "device",
        "actioned",
        now,
        {"action": action},
        provider_event_id=f"device:action:{client_action_id}",
    )  # noqa: SLF001
    fresh = fetch_own(conn, scope, person_id, notification_id)
    return {
        "decision": canonical,
        "notification": views.notification_view(fresh, audience="resident"),
    }


# ------------------------------------------------------------------------------------------------------------ guard side
def guard_request(
    conn: Connection,
    ctx: RequestContext,
    role: str,
    request_id: uuid.UUID,
    gate_id: uuid.UUID | None,
) -> dict[str, Any]:
    """The request a guard may look at: a guard names the gate and it must be the request's (like ``GET /v1/approval-requests/{id}``); other
    society roles see any request of the society. Another gate's request is the same ``not_found`` as an unknown one."""
    approvals.expire_due_requests(conn, ctx, request_id=request_id)
    request = approvals.fetch_request(conn, request_id)
    if request is None:
        raise NotFound()
    if role in GATE_STAFF:
        if gate_id is None:
            raise InvalidSchema.for_fields([("gate_id", "required_for_guard")])
        if request["gate_id"] != gate_id:
            raise NotFound()
    return request


def status(conn: Connection, request: dict[str, Any]) -> dict[str, Any]:
    return views.status_view(conn, request, now=db_now(conn))


def start_attempt(
    conn: Connection, ctx: RequestContext, request_id: uuid.UUID, reason: str
) -> dict[str, Any]:
    """A supervisor starts a NEW attempt for a request that is still pending: a fresh cascade with its own one primary and one alternate call.
    The request's expiry is never extended (the visits service owns it); too close to expiry there is nothing left to try."""
    request = approvals.fetch_request(conn, request_id)
    if request is None:
        raise NotFound()
    if request["state"] != "pending":
        raise PolicyViolation(details={"reason": "request_not_pending", "status": request["state"]})
    now = db_now(conn)
    if (request["expires_at"] - now).total_seconds() < MIN_REMAINING_FOR_ATTEMPT:
        raise PolicyViolation(details={"reason": "too_close_to_expiry"})
    last = conn.execute(
        text("SELECT id, attempt_no, state FROM notification_cascades WHERE request_id = :r ORDER BY attempt_no DESC LIMIT 1"),
        {"r": request_id},
    ).mappings().first()  # fmt: skip
    if last is None:
        raise PolicyViolation(details={"reason": "cascade_not_started"})
    if int(last["attempt_no"]) >= ATTEMPT_LIMIT:
        raise PolicyViolation(details={"reason": "attempt_limit_reached", "max": ATTEMPT_LIMIT})
    if last["state"] == "active":
        engine.close_cascade(
            conn, ctx, last["id"], state="superseded", reason="new_attempt_started"
        )
    engine.start_cascade(
        conn,
        ctx,
        request,
        attempt_no=int(last["attempt_no"]) + 1,
        started_by=ctx.person_id,
        started_at=now,
        reason=reason,
    )
    return views.status_view(conn, request, now=now)


def start_proxy_call(
    conn: Connection,
    ctx: RequestContext,
    request: dict[str, Any],
    *,
    target: str,
    cfg: NotificationsConfig,
) -> dict[str, Any]:
    """CALL-01: a guard asks for a masked call to the household's primary (or alternate) approver.

    The callee is chosen by the server, the caller learns only a masked label, the session has a TTL, dial outcome and duration are logged and no
    audio is recorded. The notification row of the call takes the same unique slot as the cascade's IVR: a second call to the same role in the
    same attempt is refused (``call_limit_reached``) unless a supervisor starts a new attempt."""
    assert ctx.society_id is not None  # noqa: S101
    if request["state"] not in ("pending", "expired"):
        raise PolicyViolation(
            details={"reason": "request_already_decided", "status": request["state"]}
        )
    cascade = conn.execute(
        text(
            "SELECT id, request_id, unit_id, attempt_no, state FROM notification_cascades WHERE request_id = :r"
            " ORDER BY attempt_no DESC LIMIT 1"
        ),
        {"r": request["id"]},
    ).mappings().first()  # fmt: skip
    if cascade is None:
        raise PolicyViolation(details={"reason": "cascade_not_started"})
    try:
        person, label = engine.resolve_contact(
            conn, requester_role=ctx.actor_role or "", purpose="guard_call", request=request, target=target, cascade_unit=request["unit_id"]
        )  # fmt: skip
    except engine._Refused as exc:  # noqa: SLF001
        raise PolicyViolation(details={"reason": exc.reason}) from None
    key = dedupe_key(request["id"], int(cascade["attempt_no"]), STEP_IVR, IVR, target, person)
    nid = engine.notification_id_for(ctx.society_id, key + ":guard")
    now = db_now(conn)
    sid = uuid7()

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "INSERT INTO notifications (id, society_id, cascade_id, request_id, attempt_no, category, channel, content_class,"
                " cascade_step, recipient_role, recipient_person_id, dedupe_key, simulation, created_at)"
                " VALUES (:id, :s, :c, :r, :n, 'security_approval', 'ivr_call', 'transactional', 3, :role, :p, :key, :sim, :now)"
                " ON CONFLICT DO NOTHING RETURNING id"
            ),
            {"id": nid, "s": ctx.society_id, "c": cascade["id"], "r": request["id"], "n": cascade["attempt_no"], "role": target,
             "p": person, "key": key + ":guard", "sim": cfg.simulation, "now": now},
        ).first()  # fmt: skip
        if row is None:
            raise PolicyViolation(details={"reason": "call_limit_reached", "role": target})
        c.execute(
            text(
                "INSERT INTO proxy_call_sessions (id, society_id, request_id, notification_id, purpose, initiated_by, initiator_role,"
                " callee_person_id, masked_label, contact_ref, ttl_expires_at, state, simulation, created_at)"
                " VALUES (:id, :s, :r, :n, 'guard_call', :by, :role, :callee, :label, :cref, :ttl, 'created', :sim, :now)"
            ),
            {"id": sid, "s": ctx.society_id, "r": request["id"], "n": nid, "by": ctx.person_id, "role": ctx.actor_role,
             "callee": person, "label": label, "cref": f"person:{person}", "ttl": now + dt.timedelta(seconds=cfg.call_ttl_seconds),
             "sim": cfg.simulation, "now": now},
        )  # fmt: skip
        return MutationResult(
            sid,
            1,
            after={
                "request_id": request["id"],
                "target": target,
                "purpose": "guard_call",
                "recording": False,
            },
            event_payload={"request_id": request["id"], "call_id": sid, "target": target},
        )

    mutation(
        conn, ctx, operation="notification.call.start", object_type="proxy_call_session",
        event_type="notification.call_requested", apply=apply,
    )  # fmt: skip
    return call_view(conn, sid)


def call_view(conn: Connection, call_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                "SELECT id, request_id, purpose, state, dial_outcome, duration_seconds, ttl_expires_at, masked_label, created_at,"
                " completed_at, recording_enabled, simulation, provider FROM proxy_call_sessions WHERE id = :id"
            ),
            {"id": call_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return {
        "id": row["id"],
        "request_id": row["request_id"],
        "purpose": row["purpose"],
        "state": row["state"],
        "dial_outcome": row["dial_outcome"],
        "duration_seconds": row["duration_seconds"],
        "ttl_expires_at": row["ttl_expires_at"],
        "who": row["masked_label"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "audio_recorded": bool(row["recording_enabled"]),
        "simulation": row["simulation"],
        "no_number_shown": True,
    }


def call_request(conn: Connection, call_id: uuid.UUID) -> dict[str, Any]:
    row = conn.execute(
        text("SELECT request_id FROM proxy_call_sessions WHERE id = :id"), {"id": call_id}
    ).first()
    if row is None:
        raise NotFound()
    request = approvals.fetch_request(conn, row[0])
    if request is None:
        raise NotFound()
    return request


# ------------------------------------------------------------------------------------------------------------ budget
def set_budget(
    conn: Connection,
    ctx: RequestContext,
    *,
    monthly_notification_cap: int,
    monthly_call_cap: int,
    monthly_sms_cap: int,
    expected_version: int | None,
) -> dict[str, Any]:
    assert ctx.society_id is not None  # noqa: S101
    row = conn.execute(text("SELECT id, version FROM notification_budgets FOR UPDATE")).first()
    if row is not None and expected_version is not None and int(row[1]) != expected_version:
        raise StaleVersion(details={"version": int(row[1])})

    def apply(c: Connection) -> MutationResult:
        if row is None:
            bid = uuid7()
            c.execute(
                text(
                    "INSERT INTO notification_budgets (id, society_id, monthly_notification_cap, monthly_call_cap, monthly_sms_cap, updated_by)"
                    " VALUES (:id, :s, :n, :c, :m, :by)"
                ),
                {
                    "id": bid,
                    "s": ctx.society_id,
                    "n": monthly_notification_cap,
                    "c": monthly_call_cap,
                    "m": monthly_sms_cap,
                    "by": ctx.person_id,
                },
            )
            version = 1
        else:
            bid, version = row[0], int(row[1]) + 1
            c.execute(
                text(
                    "UPDATE notification_budgets SET monthly_notification_cap = :n, monthly_call_cap = :c, monthly_sms_cap = :m,"
                    " updated_by = :by, updated_at = clock_timestamp(), version = :v WHERE id = :id"
                ),
                {
                    "n": monthly_notification_cap,
                    "c": monthly_call_cap,
                    "m": monthly_sms_cap,
                    "by": ctx.person_id,
                    "v": version,
                    "id": bid,
                },
            )
        return MutationResult(
            bid,
            version,
            after={
                "monthly_notification_cap": monthly_notification_cap,
                "monthly_call_cap": monthly_call_cap,
                "monthly_sms_cap": monthly_sms_cap,
            },
            event_payload={"version": version},
        )

    mutation(
        conn, ctx, operation="notification.budget.set", object_type="notification_budget",
        event_type="notification.budget_changed", apply=apply,
    )  # fmt: skip
    return budget_view(conn)


def budget_view(conn: Connection) -> dict[str, Any]:
    out = budget.view(conn, db_now(conn))
    version = conn.execute(text("SELECT version FROM notification_budgets")).scalar()
    out["version"] = int(version) if version is not None else 0
    return out
