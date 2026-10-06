"""The cascade engine: start, advance, issue, close and invalidate (NOTIF-02/03/04/05, CALL-01, AT-40).

REQ: NOTIF-02 (states created -> provider_accepted -> app_received -> displayed -> actioned -> expired, each with its timestamp; provider acceptance
is never delivery), NOTIF-03 / AT-40 (cascade by the planner; one primary and one alternate call per attempt, backed by a unique index), NOTIF-04
(decision accepted -> remaining ringing cancelled and stale actions invalidated), NOTIF-05 (every send re-resolves the household: membership is
re-checked), NOTIF-09 (lock-screen copy without identity unless opted in), CALL-01 (TTL-bound proxy session, role-authorised contact resolution,
no recording), CALL-02 (DLT header + template, whitelisted URL), INV-03 (nothing here can allow entry: a decision is made only by the visits
service, called with the household member's own identity), INV-07.

Everything is a plain function of a connection that already carries the society's RLS context, a clock value (``now``) and a ``ProviderSet``, so
the worker (job functions, Dramatiq actors) and the tests drive the same code. Nothing sleeps and nothing reads the wall clock except where the
database stamps a decision.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import DwaarError
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, emit_event, mutation, record_audit
from ...core.authz import Scope, ScopeKind
from ...core.db import Database, RequestContext
from ..visits import approvals, common
from ..visits import policy as gate_policy
from ..visits.permissions import GATE_STAFF
from ..visits.schemas import DecisionIn
from . import budget, catalog, households
from . import categories as cat
from .config import NotificationsConfig
from .planner import (
    IVR,
    PUSH,
    SMS,
    Action,
    Household,
    Progress,
    Timings,
    dedupe_key,
    plan_cascade,
)
from .providers import Kind, OutboundMessage, ProviderEvent, ProviderSet, SendResult

log = logging.getLogger("dwaar_api.notifications")

_NS: Final = uuid.UUID("6f1d2c1e-0d63-5b3a-9c2e-4f7a1b9e6d10")
STATE_RANK: Final = {
    "created": 0,
    "provider_accepted": 1,
    "app_received": 2,
    "displayed": 3,
    "actioned": 4,
    "expired": 5,
}
OPEN_STATES: Final = ("created", "provider_accepted", "app_received", "displayed")
PROVIDER_FAILURES: Final = frozenset(
    {"provider_unavailable", "provider_error", "provider_not_configured"}
)
RELEVANT_EVENTS: Final = (
    "ApprovalRequested",
    "ApprovalDecided",
    "ApprovalEscalated",
    "identity.reverification_required",
)


def system_ctx(society_id: uuid.UUID, request_id: uuid.UUID | None = None) -> RequestContext:
    return RequestContext(society_id, None, "system", request_id or uuid7())


@dataclass
class Report:
    """What one run did, by counter (never a message: those may carry data)."""

    counts: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n

    def get(self, key: str) -> int:
        return self.counts.get(key, 0)


@dataclass(frozen=True)
class PendingDecision:
    """A keypad decision (DTMF 1 allow, 2 deny) waiting to be handed to the visits service."""

    society_id: uuid.UUID
    request_id: uuid.UUID
    person_id: uuid.UUID
    digit: str
    session_id: uuid.UUID
    notification_id: uuid.UUID


class _Skip(Exception):
    """Nothing to write (already done by someone else): not an error."""


# ------------------------------------------------------------------------------------------------------------ cascades
def notification_id_for(society_id: uuid.UUID, key: str) -> uuid.UUID:
    """A deterministic id per dedupe key: a retried send carries the SAME id, which a real provider can use as its idempotency key."""
    return uuid.uuid5(_NS, f"{society_id}|{key}")


def active_cascades(conn: Connection, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, request_id, unit_id, attempt_no, started_at, expires_at, plan, state, guard_options, started_by"
            " FROM notification_cascades WHERE state = 'active' ORDER BY started_at, id LIMIT :n"
        ),
        {"n": limit},
    ).mappings()
    return [dict(r) for r in rows]


def get_cascade(conn: Connection, cascade_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(
        text(
            "SELECT id, request_id, unit_id, attempt_no, started_at, expires_at, plan, state, guard_options, started_by,"
            " ended_at, ended_reason FROM notification_cascades WHERE id = :id"
        ),
        {"id": cascade_id},
    ).mappings().first()  # fmt: skip
    return dict(row) if row else None


def start_cascade(
    conn: Connection,
    ctx: RequestContext,
    request: Mapping[str, Any],
    *,
    attempt_no: int = 1,
    started_by: uuid.UUID | None = None,
    started_at: dt.datetime | None = None,
    reason: str | None = None,
) -> uuid.UUID | None:
    """Create the cascade of one attempt of a request. Attempt 1 starts at the request's creation time (t = 0 of the PRD cascade); a
    supervisor's later attempt starts when asked. Returns None when this attempt already exists (a duplicated event)."""
    assert ctx.society_id is not None  # noqa: S101
    cascade_id = uuid7()
    begin = started_at or request["created_at"]
    plan = request.get("cascade") or {}

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "INSERT INTO notification_cascades (id, society_id, request_id, unit_id, attempt_no, started_at, expires_at, plan,"
                " started_by) VALUES (:id, :s, :r, :u, :n, :t0, :exp, CAST(:plan AS jsonb), :by)"
                " ON CONFLICT DO NOTHING RETURNING id"
            ),
            {"id": cascade_id, "s": ctx.society_id, "r": request["id"], "u": request["unit_id"], "n": attempt_no,
             "t0": begin, "exp": request["expires_at"], "plan": gate_policy.json_text(plan), "by": started_by},
        ).first()  # fmt: skip
        if row is None:
            raise _Skip
        return MutationResult(
            cascade_id,
            1,
            after={"request_id": request["id"], "attempt_no": attempt_no, "state": "active"},
            event_payload={
                "request_id": request["id"],
                "cascade_id": cascade_id,
                "attempt_no": attempt_no,
            },
        )

    try:
        mutation(
            conn, ctx, operation="notification.cascade.start", object_type="notification_cascade",
            event_type="notification.cascade_started", apply=apply, reason=reason,
        )  # fmt: skip
    except _Skip:
        return None
    return cascade_id


def close_cascade(
    conn: Connection,
    ctx: RequestContext,
    cascade_id: uuid.UUID,
    *,
    state: str,
    reason: str,
    guard_options: list[str] | None = None,
) -> bool:
    """End a live cascade (decided / expired / cancelled / superseded). Idempotent: False when it was already ended."""

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE notification_cascades SET state = :st, ended_at = clock_timestamp(), ended_reason = :why,"
                " guard_options = CAST(:opts AS jsonb), version = version + 1 WHERE id = :id AND state = 'active'"
                " RETURNING request_id, version"
            ),
            {"st": state, "why": reason, "opts": _json_list(guard_options), "id": cascade_id},
        ).first()  # fmt: skip
        if row is None:
            raise _Skip
        return MutationResult(
            cascade_id,
            int(row[1]),
            before={"state": "active"},
            after={"state": state, "reason": reason},
            event_payload={"request_id": row[0], "cascade_id": cascade_id, "state": state},
        )

    try:
        mutation(
            conn, ctx, operation="notification.cascade.close", object_type="notification_cascade",
            event_type="notification.cascade_closed", apply=apply,
        )  # fmt: skip
    except _Skip:
        return False
    return True


def _json_list(values: list[str] | None) -> str:
    return json.dumps(list(values or []), separators=(",", ":"))


def issued_keys(conn: Connection, cascade: Mapping[str, Any]) -> frozenset[str]:
    """The planner's dedupe keys of everything already created for this cascade (rows, whatever their outcome)."""
    rows = conn.execute(
        text(
            "SELECT cascade_step, channel, recipient_role, recipient_person_id FROM notifications WHERE cascade_id = :c"
        ),
        {"c": cascade["id"]},
    ).all()
    return frozenset(
        dedupe_key(cascade["request_id"], cascade["attempt_no"], int(step), str(ch), str(role), pid)
        for step, ch, role, pid in rows
        if step is not None
    )


def _progress(conn: Connection, cascade: Mapping[str, Any], request: Mapping[str, Any]) -> Progress:
    acked = conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM notifications WHERE cascade_id = :c AND channel = 'push'"
            " AND app_received_at IS NOT NULL)"
        ),
        {"c": cascade["id"]},
    ).scalar_one()
    outcome = conn.execute(
        text(
            "SELECT s.dial_outcome FROM proxy_call_sessions s JOIN notifications n ON n.society_id = s.society_id"
            " AND n.id = s.notification_id WHERE n.cascade_id = :c AND n.recipient_role = 'primary'"
            " ORDER BY s.created_at LIMIT 1"
        ),
        {"c": cascade["id"]},
    ).first()
    return Progress(
        request_id=cascade["request_id"],
        request_state=str(request["state"]),
        started_at=cascade["started_at"],
        expires_at=cascade["expires_at"],
        attempt_no=int(cascade["attempt_no"]),
        acked=bool(acked),
        done=issued_keys(conn, cascade),
        primary_call_outcome=None if outcome is None else outcome[0],
    )


# ------------------------------------------------------------------------------------------------------------ advancing
def advance_cascade(
    conn: Connection,
    ctx: RequestContext,
    cascade: Mapping[str, Any],
    providers: ProviderSet,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    report: Report,
) -> None:
    """One step of one live cascade: ask the planner what is due at ``now`` and do it (idempotently)."""
    request = approvals.fetch_request(conn, cascade["request_id"])
    if request is None:
        close_cascade(conn, ctx, cascade["id"], state="cancelled", reason="request_missing")
        return
    timings = Timings.from_plan(cascade["plan"])
    household = households.resolve_household(conn, cascade["unit_id"])
    progress = _progress(conn, cascade, request)
    for action in plan_cascade(timings, household, progress, now):
        if action.kind == "cancel":
            close_for_request_state(conn, ctx, cascade, request, providers, now=now, report=report)
        elif action.kind == "expire":
            expire_step(conn, ctx, cascade, request, timings, providers, now=now, report=report)
        else:
            issue(
                conn,
                ctx,
                cascade,
                action,
                request,
                household,
                providers,
                now=now,
                cfg=cfg,
                report=report,
            )


def expire_step(
    conn: Connection,
    ctx: RequestContext,
    cascade: Mapping[str, Any],
    request: Mapping[str, Any],
    timings: Timings,
    providers: ProviderSet,
    *,
    now: dt.datetime,
    report: Report,
) -> None:
    """t = expiry: ask the VISITS service to expire the request (it owns the state and answers on the database clock), then show the guard
    the assisted options. If the visits service does not consider the request due yet, nothing changes now and the next run asks again.
    Never allows anything (INV-03)."""
    assert ctx.society_id is not None  # noqa: S101
    approvals.expire_due_requests(
        conn, system_ctx(ctx.society_id, ctx.request_id), request_id=cascade["request_id"]
    )
    fresh = approvals.fetch_request(conn, cascade["request_id"])
    if fresh is None or fresh["state"] == "pending":
        report.add("expiry_not_due_yet")
        return
    close_for_request_state(
        conn,
        ctx,
        cascade,
        fresh,
        providers,
        now=now,
        report=report,
        guard_options=list(timings.guard_options),
    )


def close_for_request_state(
    conn: Connection,
    ctx: RequestContext,
    cascade: Mapping[str, Any],
    request: Mapping[str, Any],
    providers: ProviderSet,
    *,
    now: dt.datetime,
    report: Report,
    guard_options: list[str] | None = None,
) -> None:
    """The request is no longer pending: end the cascade, cancel what still rings and invalidate every stale action (NOTIF-04)."""
    state = str(request["state"])
    mapping = {
        "approved": "decided",
        "denied": "decided",
        "expired": "expired",
        "cancelled": "cancelled",
    }
    cascade_state = mapping.get(state, "cancelled")
    options = guard_options
    if state == "expired" and options is None:
        options = list(Timings.from_plan(cascade["plan"]).guard_options)
    closed = close_cascade(
        conn,
        ctx,
        cascade["id"],
        state=cascade_state,
        reason=f"request_{state}",
        guard_options=options,
    )
    if closed:
        report.add(f"cascade_{cascade_state}")
    invalidate_request(conn, ctx, cascade["request_id"], request, providers, now=now, report=report)


def invalidate_request(
    conn: Connection,
    ctx: RequestContext,
    request_id: uuid.UUID,
    request: Mapping[str, Any],
    providers: ProviderSet,
    *,
    now: dt.datetime,
    report: Report,
) -> int:
    """Withdraw every open notification of a request that is no longer pending (decided, expired, cancelled).

    * the member whose app decision won gets ``actioned`` on their own notifications; everyone else's become ``expired`` with the reason, and
      a stale action on any device is refused by the decision itself (the visits service answers 409 from the committed state: that part
      is instant, it does not wait for this job);
    * calls still ringing are hung up and pushes withdrawn at the provider (the provider is told; what the phone then shows is not claimed).
    Idempotent: a second run finds nothing open."""
    state = str(request["state"])
    reason = {
        "approved": "request_decided",
        "denied": "request_decided",
        "expired": "request_expired",
        "cancelled": "request_cancelled",
    }.get(state, "request_closed")
    decider = None
    action = None
    dec_channel = None
    if state in ("approved", "denied"):
        d = conn.execute(
            text(
                "SELECT decided_by, decision, channel FROM approval_decisions WHERE request_id = :r AND valid"
            ),
            {"r": request_id},
        ).first()
        if d is not None:
            decider, action, dec_channel = d[0], str(d[1]), str(d[2])
    rows = conn.execute(
        text(
            "SELECT id, channel, provider, provider_ref, state, recipient_person_id FROM notifications"
            " WHERE request_id = :r AND state = ANY(:open) ORDER BY created_at, id FOR UPDATE"
        ),
        {"r": request_id, "open": list(OPEN_STATES)},
    ).all()
    n = 0
    for nid, channel, _prov, ref, _st, person in rows:
        won = (
            decider is not None
            and person == decider
            and (
                (dec_channel == "app" and channel in ("push", "sms", "whatsapp"))
                or (dec_channel == "ivr" and channel == "ivr_call")
            )
        )
        if won:
            conn.execute(
                text(
                    "UPDATE notifications SET state = 'actioned', action = :a, actioned_at = COALESCE(actioned_at, :t),"
                    " app_received_at = COALESCE(app_received_at, :t), version = version + 1 WHERE id = :id"
                ),
                {"a": action, "t": now, "id": nid},
            )
            _attempt(conn, ctx, nid, "system", "actioned_by_decision", now, {"decision": action})
            continue
        conn.execute(
            text(
                "UPDATE notifications SET state = 'expired', expired_at = :t, invalidated_at = :t, closed_reason = :why,"
                " version = version + 1 WHERE id = :id"
            ),
            {"t": now, "why": reason, "id": nid},
        )
        _attempt(conn, ctx, nid, "system", "invalidated", now, {"reason": reason})
        n += 1
        provider = providers.get(Kind(channel)) if ref else None
        if provider is not None and ref is not None and channel in ("push", "ivr_call"):
            try:
                provider.cancel(ref, now=now)
                report.add("provider_cancels")
            except (
                Exception
            ) as exc:  # a provider fault must not leave the stale action alive in OUR state
                log.warning("provider cancel failed", extra={"exc_type": type(exc).__name__})
                report.add("provider_cancel_errors")
    if n:
        report.add("invalidated", n)
        _log_withdrawal(conn, ctx, request_id, request, n)
    return n


def _log_withdrawal(
    conn: Connection,
    ctx: RequestContext,
    request_id: uuid.UUID,
    request: Mapping[str, Any],
    count: int,
) -> None:
    """One audit row and one event per withdrawal: the request left ``pending`` and ``count`` notifications were closed (NOTIF-04). The aggregate is
    this module's own (``notification_withdrawal``), versioned 1, 2, ... so it never collides with the visits events of the same request."""
    seen = conn.execute(
        text(
            "SELECT count(*) FROM outbox WHERE aggregate_type = 'notification_withdrawal' AND aggregate_id = :r"
        ),
        {"r": request_id},
    ).scalar_one()
    version = int(seen) + 1
    record_audit(
        conn, ctx, operation="notification.withdraw", object_type="notification_withdrawal", object_id=request_id,
        object_version=version, after={"status": str(request["state"]), "withdrawn": count},
    )  # fmt: skip
    emit_event(
        conn, ctx, aggregate_type="notification_withdrawal", aggregate_id=request_id, aggregate_version=version,
        event_type="notification.withdrawn", payload={"request_id": request_id, "status": str(request["state"]), "withdrawn": count},
    )  # fmt: skip


# ------------------------------------------------------------------------------------------------------------ issuing
def _attempt(
    conn: Connection,
    ctx: RequestContext,
    notification_id: uuid.UUID,
    source: str,
    event: str,
    observed_at: dt.datetime,
    detail: Mapping[str, Any] | None = None,
    *,
    provider_event_id: str | None = None,
) -> bool:
    """Append one fact to the delivery log. False when the same provider event id was already recorded (a duplicate callback)."""
    row = conn.execute(
        text(
            "INSERT INTO notification_attempts (id, society_id, notification_id, source, event, provider_event_id, observed_at, detail)"
            " VALUES (:id, :s, :n, :src, :ev, :pe, :t, CAST(:d AS jsonb)) ON CONFLICT DO NOTHING RETURNING id"
        ),
        {"id": uuid7(), "s": ctx.society_id, "n": notification_id, "src": source, "ev": event, "pe": provider_event_id,
         "t": observed_at, "d": json.dumps(dict(detail or {}), default=str, separators=(",", ":"))},
    ).first()  # fmt: skip
    return row is not None


def _log(
    conn: Connection,
    ctx: RequestContext,
    *,
    operation: str,
    event_type: str,
    object_type: str,
    object_id: uuid.UUID,
    after: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> None:
    """PRD 12.4 for the system's own steps: the audit row and the outbox event of a dispatch or a withdrawal, in the SAME transaction as the delivery
    row they describe (ids, state and reasons only: no number, no name, no text)."""
    version = conn.execute(
        text("SELECT version FROM notifications WHERE id = :id"), {"id": object_id}
    ).scalar()
    ver = int(version) if version is not None else 1
    record_audit(
        conn,
        ctx,
        operation=operation,
        object_type=object_type,
        object_id=object_id,
        object_version=ver,
        after=after,
    )
    emit_event(
        conn,
        ctx,
        aggregate_type=object_type,
        aggregate_id=object_id,
        aggregate_version=ver,
        event_type=event_type,
        payload=payload,
    )


def _tokens_of(conn: Connection, person_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, token_ref, notification_permission, phone_model, manufacturer, os_name, os_version FROM device_push_tokens"
            " WHERE person_id = :p AND revoked_at IS NULL ORDER BY last_seen_at DESC, id LIMIT 3"
        ),
        {"p": person_id},
    ).mappings()
    return [dict(r) for r in rows]


def _find_template(
    conn: Connection, category: str, channel: str, language: str
) -> dict[str, Any] | None:
    for lang in dict.fromkeys((language, "en")):
        row = conn.execute(
            text(
                "SELECT id, template_key, content_class, body_key, dlt_header, dlt_template_id, whitelisted_url FROM notification_templates"
                " WHERE category = :c AND channel = :ch AND language = :l AND status = 'active' ORDER BY created_at DESC LIMIT 1"
            ),
            {"c": category, "ch": channel, "l": lang},
        ).mappings().first()  # fmt: skip
        if row is not None:
            return dict(row)
    return None


def _default_template(channel: str) -> catalog.DefaultTemplate | None:
    for t in catalog.DEFAULT_TEMPLATES:
        if t.category == cat.SECURITY and t.channel == channel:
            return t
    return None


@dataclass
class _Built:
    message: OutboundMessage | None
    failure: str | None
    template_key: str | None
    content_class: str
    lockscreen_identity: bool = False


def _build_message(
    conn: Connection,
    notification_id: uuid.UUID,
    channel: str,
    person: uuid.UUID,
    request: Mapping[str, Any],
    token: Mapping[str, Any] | None,
    cfg: NotificationsConfig,
) -> _Built:
    """The final, lock-screen-safe message (NOTIF-09) or the reason it cannot be built (CALL-02)."""
    prefs = households.get_preferences(conn, person)
    lang = prefs.language
    template = _find_template(conn, cat.SECURITY, channel, lang)
    default = _default_template(channel)
    body_key = template["body_key"] if template else (default.body_key if default else None)
    if body_key is None:
        return _Built(None, "no_template", None, "transactional")
    template_key = (
        template["template_key"] if template else (default.template_key if default else None)
    )
    content_class = template["content_class"] if template else "transactional"
    contact_ref = f"person:{person}"
    expires_iso = request["expires_at"].isoformat()
    if channel == PUSH:
        title, body, identity = cat.lockscreen_copy(
            language=lang, identity_opt_in=prefs.show_identity_on_lockscreen,
            visitor=request.get("visitor_alias"), unit=f"{request.get('block_name')}-{request.get('unit_label')}",
        )  # fmt: skip
        message = OutboundMessage(
            notification_id=str(notification_id), kind=Kind.PUSH, contact_ref=contact_ref, language=lang, text=body, title=title,
            token_ref=None if token is None else str(token["token_ref"]),
            payload={"notification_id": str(notification_id), "request_id": str(request["id"]), "expires_at": expires_iso,
                     "category": cat.SECURITY, "priority": "high", "channel_id": "security"},
        )  # fmt: skip
        return _Built(message, None, template_key, content_class, identity)
    if channel == IVR:
        text_ = cat.copy(body_key, lang)
        message = OutboundMessage(
            notification_id=str(notification_id), kind=Kind.IVR, contact_ref=contact_ref, language=lang, text=text_,
            session_ttl_seconds=cfg.call_ttl_seconds,
            payload={"keys": {"1": "allow", "2": "deny", "3": "talk_to_guard"}, "speech_input": False},
        )  # fmt: skip
        return _Built(message, None, template_key, content_class)
    # sms / whatsapp: a registered template with a whitelisted URL (CALL-02)
    if template is None or not template["whitelisted_url"]:
        return _Built(None, "template_not_registered", template_key, content_class)
    if channel == SMS and (not template["dlt_header"] or not template["dlt_template_id"]):
        return _Built(None, "dlt_template_not_registered", template_key, content_class)
    link = f"{template['whitelisted_url'].rstrip('/')}/{notification_id}"
    try:
        cat.check_url(link, cfg.link_hosts)
    except DwaarError:
        return _Built(None, "url_not_whitelisted", template_key, content_class)
    text_ = cat.copy(body_key, lang, link=link)
    message = OutboundMessage(
        notification_id=str(notification_id), kind=Kind(channel), contact_ref=contact_ref, language=lang, text=text_, link=link,
        dlt_header=template["dlt_header"], dlt_template_id=template["dlt_template_id"],
    )  # fmt: skip
    return _Built(message, None, template_key, content_class)


def issue(
    conn: Connection,
    ctx: RequestContext,
    cascade: Mapping[str, Any],
    action: Action,
    request: Mapping[str, Any],
    household: Household,
    providers: ProviderSet,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    report: Report,
) -> None:
    """Create the notification row of one planned send (deduplicated), then hand it to the provider and record what the provider said.

    The row is written FIRST with the dedupe key, so a restart or a second worker finds it and does nothing; the provider call carries the
    row's deterministic id. A failure is recorded as a reason on the row (never as a delivery) and the cascade simply goes on."""
    assert ctx.society_id is not None  # noqa: S101
    assert action.person_id is not None  # noqa: S101
    person = action.person_id
    channel = action.kind
    deciders = {m.person_id for m in common.deciders(conn, cascade["unit_id"])}
    failure: str | None = None
    tokens: list[dict[str, Any]] = []
    if person not in deciders:
        failure = "recipient_not_authorised"  # NOTIF-05: membership re-checked at send time
    elif channel == PUSH:
        tokens = _tokens_of(conn, person)
        usable = [t for t in tokens if t["notification_permission"] != "denied"]
        if not tokens:
            failure = "no_active_device"
        elif not usable:
            failure = "notification_permission_denied"
        else:
            tokens = usable
    targets: list[dict[str, Any] | None] = (
        list(tokens) if (channel == PUSH and failure is None) else [tokens[0] if tokens else None]
    )
    for token in targets:
        key = action.dedupe_key + (f":{token['id']}" if token else "")
        nid = notification_id_for(ctx.society_id, key)
        row_failure = failure
        with conn.begin_nested():
            inserted = conn.execute(
                text(
                    "INSERT INTO notifications (id, society_id, cascade_id, request_id, attempt_no, category, channel, content_class,"
                    " cascade_step, recipient_role, recipient_person_id, token_id, dedupe_key, simulation, created_at, phone_model,"
                    " manufacturer, os_name, os_version) VALUES (:id, :s, :c, :r, :n, 'security_approval', :ch, 'transactional',"
                    " :step, :role, :p, :tok, :key, :sim, :now, :model, :man, :os, :osv) ON CONFLICT DO NOTHING RETURNING id"
                ),
                {"id": nid, "s": ctx.society_id, "c": cascade["id"], "r": cascade["request_id"], "n": cascade["attempt_no"],
                 "ch": channel, "step": action.step, "role": action.role, "p": person, "tok": token["id"] if token else None,
                 "key": key, "sim": cfg.simulation, "now": now, "model": token["phone_model"] if token else None,
                 "man": token["manufacturer"] if token else None, "os": token["os_name"] if token else None,
                 "osv": token["os_version"] if token else None},
            ).first()  # fmt: skip
        if inserted is None:
            report.add("skipped_duplicate")
            continue
        report.add(f"created_{channel}")
        if row_failure is None:
            built = _build_message(conn, nid, channel, person, request, token, cfg)
            row_failure = built.failure
        else:
            built = _Built(None, row_failure, None, "transactional")
        if row_failure is None and built.message is not None:
            try:
                cat.assert_sendable(
                    category=cat.SECURITY, content_class=built.content_class, text=built.message.text, title=built.message.title,
                    hosts=cfg.link_hosts,
                )  # fmt: skip
            except DwaarError:
                row_failure = "content_rejected"
        if row_failure is None and built.message is not None:
            decision = budget.authorise_send(
                conn, ctx.society_id, category=cat.SECURITY, channel=channel, now=now
            )
            if (
                not decision.allowed
            ):  # unreachable for the security category (never blocked), kept for a future category
                row_failure = "budget_exhausted"
            elif decision.over_budget:
                report.add("over_budget")
        provider = providers.get(Kind(channel))
        if row_failure is None and provider is None:
            row_failure = "provider_not_configured"
        if row_failure is not None or built.message is None or provider is None:
            conn.execute(
                text(
                    "UPDATE notifications SET failure_reason = :f, template_key = :tk, version = version + 1 WHERE id = :id"
                ),
                {"f": row_failure, "tk": built.template_key, "id": nid},
            )
            _attempt(conn, ctx, nid, "system", "not_sent", now, {"reason": row_failure})
            _log(
                conn, ctx, operation="notification.dispatch", event_type="notification.dispatched", object_type="notification",
                object_id=nid, after={"channel": channel, "state": "created", "failure": row_failure},
                payload={"notification_id": nid, "channel": channel, "outcome": "not_sent", "reason": row_failure},
            )  # fmt: skip
            report.add(f"not_sent_{row_failure}")
            if row_failure in PROVIDER_FAILURES:
                report.add("provider_failures")
            continue
        if channel == IVR:
            _open_call_session(
                conn,
                ctx,
                cascade,
                request,
                nid,
                person,
                built.message,
                now=now,
                cfg=cfg,
                purpose="cascade_ivr",
                initiator=None,
            )
        result = _send(provider, built.message, now)
        _record_send(
            conn,
            ctx,
            nid,
            provider.name,
            provider.simulation,
            result,
            built,
            now,
            report,
            channel=channel,
        )


def _send(provider: Any, message: OutboundMessage, now: dt.datetime) -> SendResult:
    try:
        return provider.send(message, now=now)  # type: ignore[no-any-return]
    except (
        Exception
    ) as exc:  # an adapter that raises is a provider failure, never a crash of the cascade
        log.warning("provider send raised", extra={"exc_type": type(exc).__name__})
        return SendResult(False, None, "provider_error", retryable=True)


def _record_send(
    conn: Connection,
    ctx: RequestContext,
    nid: uuid.UUID,
    provider_name: str,
    simulation: bool,
    result: SendResult,
    built: _Built,
    now: dt.datetime,
    report: Report,
    *,
    channel: str,
) -> None:
    if result.accepted:
        conn.execute(
            text(
                "UPDATE notifications SET state = 'provider_accepted', provider = :p, provider_ref = :ref, simulation = :sim,"
                " sent_at = :t, provider_accepted_at = :t, template_key = :tk, content_class = :cc, lockscreen_identity = :li,"
                " version = version + 1 WHERE id = :id AND state = 'created'"
            ),
            {"p": provider_name.replace("-", "_"), "ref": result.provider_ref, "sim": simulation, "t": now,
             "tk": built.template_key, "cc": built.content_class, "li": built.lockscreen_identity, "id": nid},
        )  # fmt: skip
        _attempt(conn, ctx, nid, "provider", "provider_accepted", now, {"provider": provider_name})
        _log(
            conn, ctx, operation="notification.dispatch", event_type="notification.dispatched", object_type="notification",
            object_id=nid, after={"channel": channel, "state": "provider_accepted", "simulation": simulation},
            payload={"notification_id": nid, "channel": channel, "outcome": "provider_accepted", "simulation": simulation},
        )  # fmt: skip
        report.add(f"accepted_{channel}")
        if channel == IVR:
            conn.execute(
                text(
                    "UPDATE proxy_call_sessions SET state = 'dialing', provider = :p, provider_ref = :ref, version = version + 1"
                    " WHERE notification_id = :n AND state = 'created'"
                ),
                {"p": provider_name.replace("-", "_"), "ref": result.provider_ref, "n": nid},
            )
        return
    code = result.error_code or "provider_error"
    conn.execute(
        text(
            "UPDATE notifications SET failure_reason = :f, provider = :p, simulation = :sim, sent_at = :t, template_key = :tk,"
            " version = version + 1 WHERE id = :id"
        ),
        {
            "f": _safe_code(code),
            "p": provider_name.replace("-", "_"),
            "sim": simulation,
            "t": now,
            "tk": built.template_key,
            "id": nid,
        },
    )
    _attempt(
        conn,
        ctx,
        nid,
        "provider",
        "provider_rejected",
        now,
        {"code": _safe_code(code), "retryable": result.retryable},
    )
    _log(
        conn, ctx, operation="notification.dispatch", event_type="notification.dispatched", object_type="notification",
        object_id=nid, after={"channel": channel, "state": "created", "failure": _safe_code(code)},
        payload={"notification_id": nid, "channel": channel, "outcome": "provider_rejected", "reason": _safe_code(code), "simulation": simulation},
    )  # fmt: skip
    report.add(f"rejected_{channel}")
    report.add("provider_failures")
    if channel == IVR:
        conn.execute(
            text(
                "UPDATE proxy_call_sessions SET state = 'failed', dial_outcome = 'failed', completed_at = :t, version = version + 1"
                " WHERE notification_id = :n AND state = 'created'"
            ),
            {"t": now, "n": nid},
        )
        report.add("failed_calls")


def _safe_code(code: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_]", "_", code.lower())[:60]
    return cleaned if re.match(r"^[a-z]", cleaned) else "provider_error"


# ------------------------------------------------------------------------------------------------------------ proxy calls (CALL-01)
def masked_label(request: Mapping[str, Any]) -> str:
    """What a guard may know about the callee: the household of the unit, never a name or a number."""
    return f"Household of {request.get('block_name')}-{request.get('unit_label')}"[:80]


def _open_call_session(
    conn: Connection,
    ctx: RequestContext,
    cascade: Mapping[str, Any] | None,
    request: Mapping[str, Any],
    notification_id: uuid.UUID,
    callee: uuid.UUID,
    message: OutboundMessage,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    purpose: str,
    initiator: uuid.UUID | None,
) -> uuid.UUID:
    sid = uuid7()
    conn.execute(
        text(
            "INSERT INTO proxy_call_sessions (id, society_id, request_id, notification_id, purpose, initiated_by, initiator_role,"
            " callee_person_id, masked_label, contact_ref, ttl_expires_at, state, simulation, created_at) VALUES (:id, :s, :r, :n, :pu,"
            " :by, :role, :callee, :label, :cref, :ttl, 'created', :sim, :now)"
        ),
        {"id": sid, "s": ctx.society_id, "r": request["id"], "n": notification_id, "pu": purpose, "by": initiator,
         "role": ctx.actor_role or "system", "callee": callee, "label": masked_label(request), "cref": message.contact_ref,
         "ttl": now + dt.timedelta(seconds=cfg.call_ttl_seconds), "sim": cfg.simulation, "now": now},
    )  # fmt: skip
    return sid


def resolve_contact(
    conn: Connection,
    *,
    requester_role: str,
    purpose: str,
    request: Mapping[str, Any],
    target: str,
    cascade_unit: uuid.UUID,
) -> tuple[uuid.UUID, str]:
    """Role-authorised contact resolution (CALL-01): who may be reached, by whom, and what the caller learns about them.

    * the callee is chosen by the SERVER from the household's current approvers (``primary`` or ``alternate``), never named by the caller;
    * ``system`` (the cascade) and gate staff (a guard or supervisor, for the request of their own society) may ask; nobody else;
    * the answer is an opaque reference and a masked label: no name, no number."""
    allowed = {"cascade_ivr": {"system"}, "guard_call": set(GATE_STAFF)}[purpose]
    if requester_role not in allowed:
        raise _Refused("role_not_allowed_to_resolve_contact")
    household = households.resolve_household(conn, cascade_unit)
    person = household.primary if target == "primary" else household.alternate
    if person is None:
        raise _Refused("no_such_contact")
    return person, masked_label(request)


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ------------------------------------------------------------------------------------------------------------ provider events
def match_provider_events(
    conn: Connection, events: list[ProviderEvent]
) -> dict[str, dict[str, Any]]:
    """The notifications of THIS society that these provider references belong to (RLS decides which society's)."""
    refs = sorted({e.provider_ref for e in events})
    if not refs:
        return {}
    rows = conn.execute(
        text(
            "SELECT id, provider_ref, channel, state, request_id, recipient_person_id, cascade_id FROM notifications"
            " WHERE provider_ref = ANY(:refs)"
        ),
        {"refs": refs},
    ).mappings()
    return {str(r["provider_ref"]): dict(r) for r in rows}


_OUTCOMES: Final = {"answered", "no_answer", "busy", "failed", "rejected", "cancelled"}


def apply_provider_events(
    conn: Connection,
    ctx: RequestContext,
    events: list[ProviderEvent],
    *,
    now: dt.datetime,
    report: Report,
) -> tuple[list[PendingDecision], set[str]]:
    """Record what providers (and simulated devices) reported. Duplicates are absorbed, out-of-order arrivals never move a state backwards,
    and a late report after expiry stamps its time but cannot revive anything. Returns keypad decisions to hand to the visits service and
    the ids of the events that belonged to this society."""
    assert ctx.society_id is not None  # noqa: S101
    owned = match_provider_events(conn, events)
    pending: list[PendingDecision] = []
    matched: set[str] = set()
    for ev in events:
        row = owned.get(ev.provider_ref)
        if row is None:
            continue
        matched.add(ev.event_id)
        nid = row["id"]
        fresh = _attempt(
            conn,
            ctx,
            nid,
            "provider",
            ev.event,
            ev.observed_at,
            _scrub(ev.detail),
            provider_event_id=ev.event_id,
        )
        if not fresh:
            report.add("duplicate_provider_event")
            continue
        report.add(f"provider_event_{ev.event}")
        if ev.event in ("app_received", "displayed"):
            _advance_receipt(conn, nid, ev.event, ev.observed_at, ev.detail)
        elif ev.event == "failed":
            conn.execute(
                text(
                    "UPDATE notifications SET failure_reason = COALESCE(failure_reason, :f), version = version + 1 WHERE id = :id"
                ),
                {"f": _safe_code(str(ev.detail.get("code", "provider_error"))), "id": nid},
            )
        elif row["channel"] == "ivr_call":
            decision = _apply_call_event(conn, ctx, row, ev, report)
            if decision is not None:
                pending.append(decision)
    return pending, matched


def _scrub(detail: Mapping[str, Any]) -> dict[str, Any]:
    """Provider detail kept in the log: simple scalars only, and nothing shaped like a phone number."""
    out: dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, bool | int | float):
            out[str(k)[:40]] = v
        elif isinstance(v, str):
            out[str(k)[:40]] = cat.mask_phone_like(v)[:120]
    return out


def _advance_receipt(
    conn: Connection,
    notification_id: uuid.UUID,
    event: str,
    at: dt.datetime,
    detail: Mapping[str, Any] | None = None,
) -> None:
    """Monotone: a state only moves forward, ``actioned`` and ``expired`` are final, and the first timestamp of each fact wins. A display report
    implies the app received it (it cannot show what it never got)."""
    d = detail or {}
    conn.execute(
        text(
            "UPDATE notifications SET"
            " app_received_at = COALESCE(app_received_at, :t),"
            " displayed_at = CASE WHEN :ev = 'displayed' THEN COALESCE(displayed_at, :t) ELSE displayed_at END,"
            " state = CASE WHEN state IN ('actioned', 'expired') THEN state"
            "   WHEN :ev = 'displayed' THEN 'displayed'"
            "   WHEN :ev = 'app_received' AND state IN ('created', 'provider_accepted') THEN 'app_received'"
            "   ELSE state END,"
            " phone_model = COALESCE(phone_model, :model), manufacturer = COALESCE(manufacturer, :man),"
            " os_name = COALESCE(os_name, :os), os_version = COALESCE(os_version, :osv), version = version + 1 WHERE id = :id"
        ),
        {"t": at, "ev": event, "id": notification_id, "model": _short(d.get("phone_model")),
         "man": _short(d.get("manufacturer")), "os": _short(d.get("os_name")), "osv": _short(d.get("os_version"))},
    )  # fmt: skip


def _short(value: Any) -> str | None:
    return None if value is None else str(value)[:80]


def _apply_call_event(
    conn: Connection,
    ctx: RequestContext,
    notification: Mapping[str, Any],
    ev: ProviderEvent,
    report: Report,
) -> PendingDecision | None:
    """IVR / proxy call facts: answered, key pressed, completed (outcome and duration). No audio is ever handled."""
    session = conn.execute(
        text("SELECT id, request_id, callee_person_id, state, dial_outcome, dtmf_digit FROM proxy_call_sessions WHERE notification_id = :n"),
        {"n": notification["id"]},
    ).mappings().first()  # fmt: skip
    if session is None:
        return None
    sid = session["id"]
    if ev.event == "answered":
        conn.execute(
            text(
                "UPDATE proxy_call_sessions SET dial_outcome = COALESCE(dial_outcome, 'answered'), version = version + 1"
                " WHERE id = :id AND state NOT IN ('completed', 'failed', 'expired')"
            ),
            {"id": sid},
        )
        return None
    if ev.event == "dtmf":
        digit = str(ev.detail.get("digit", ""))[:1]
        if digit not in ("1", "2", "3"):
            report.add("ignored_dtmf")
            return None
        conn.execute(
            text(
                "UPDATE proxy_call_sessions SET dtmf_digit = COALESCE(dtmf_digit, :d), dial_outcome = COALESCE(dial_outcome, 'answered'),"
                " version = version + 1 WHERE id = :id"
            ),
            {"d": digit, "id": sid},
        )
        if session["dtmf_digit"] is not None:
            return None  # the first key counts, a repeated report is the same key
        if digit == "3":
            conn.execute(
                text(
                    "UPDATE notifications SET action = 'talk_to_guard', version = version + 1 WHERE id = :id"
                ),
                {"id": notification["id"]},
            )
            report.add("talk_to_guard_requested")
            return None
        return PendingDecision(
            ctx.society_id or uuid.UUID(int=0),
            session["request_id"],
            session["callee_person_id"],
            digit,
            sid,
            notification["id"],
        )
    if ev.event == "completed":
        outcome = str(ev.detail.get("outcome", "failed"))
        outcome = outcome if outcome in _OUTCOMES else "failed"
        duration = max(0, min(int(ev.detail.get("duration_seconds", 0) or 0), 7200))
        terminal = "failed" if outcome == "failed" else "completed"
        current = session["dial_outcome"]
        final = current if (current == "answered" and outcome != "cancelled") else outcome
        conn.execute(
            text(
                "UPDATE proxy_call_sessions SET state = :st, dial_outcome = :o, duration_seconds = :d, completed_at = :t,"
                " version = version + 1 WHERE id = :id AND state NOT IN ('completed', 'failed', 'expired')"
            ),
            {"st": terminal, "o": final, "d": duration, "t": ev.observed_at, "id": sid},
        )
        if terminal == "failed":
            report.add("failed_calls")
    return None


def execute_decision(
    db: Database, pending: PendingDecision, *, now: dt.datetime, report: Report
) -> str:
    """Hand a keypad decision to the VISITS service as the household member who pressed it (membership re-checked there, first valid decision
    wins, a late key after expiry gets 409 and issues no permission). Returns ``decided`` or the refusal code."""
    outcome = "decided"
    ctx = RequestContext(pending.society_id, pending.person_id, "resident", uuid7())
    try:
        with db.app_tx(ctx) as conn:
            request = approvals.fetch_request(conn, pending.request_id)
            if request is None:
                outcome = "not_found"
            else:
                standing = common.member_standing(conn, pending.person_id, request["unit_id"])
                if standing is None:
                    outcome = "not_a_member"
                else:
                    ctx2 = RequestContext(
                        pending.society_id, pending.person_id, standing.role, ctx.request_id
                    )
                    scope = Scope(
                        society_id=pending.society_id, role=standing.role, kind=ScopeKind.UNIT, unit_id=request["unit_id"],
                        society_wide=False, unit_ids=frozenset({request["unit_id"]}),
                    )  # fmt: skip
                    body = DecisionIn.model_construct(
                        decision="approve" if pending.digit == "1" else "deny",
                        expected_version=int(request["version"]),
                        client_action_id=uuid.uuid5(_NS, f"ivr|{pending.session_id}"),
                        channel="ivr",  # type: ignore[arg-type]  # the notification slice owns the non-app channels
                    )
                    policy = gate_policy.load_policy(conn)
                    approvals.decide(conn, ctx2, scope, pending.request_id, body, policy)
    except DwaarError as exc:
        outcome = getattr(exc, "code", "refused")
    report.add(f"decision_{outcome}")
    with db.worker_tx(system_ctx(pending.society_id)) as conn:
        _attempt(
            conn,
            system_ctx(pending.society_id),
            pending.notification_id,
            "system",
            f"keypad_decision_{outcome}",
            now,
            {"digit": pending.digit},
        )
        if outcome == "decided":
            conn.execute(
                text(
                    "UPDATE notifications SET state = 'actioned', action = :a, actioned_at = COALESCE(actioned_at, :t),"
                    " version = version + 1 WHERE id = :id AND state <> 'expired'"
                ),
                {
                    "a": "approve" if pending.digit == "1" else "deny",
                    "t": now,
                    "id": pending.notification_id,
                },
            )
    return outcome


def dispatch_pending_calls(
    conn: Connection,
    ctx: RequestContext,
    providers: ProviderSet,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    report: Report,
) -> None:
    """Hand the calls a guard asked for (sessions still ``created``) to the IVR provider; a session whose TTL ran out before it could be placed
    expires instead (CALL-01: a session is TTL-bound). A provider that is down is recorded, and the guard sees the intercom or office fallback."""
    assert ctx.society_id is not None  # noqa: S101
    rows = conn.execute(
        text(
            "SELECT s.id AS sid, s.notification_id, s.callee_person_id, s.ttl_expires_at, s.request_id FROM proxy_call_sessions s"
            " JOIN notifications n ON n.society_id = s.society_id AND n.id = s.notification_id"
            " WHERE s.state = 'created' AND n.provider_ref IS NULL AND n.failure_reason IS NULL"
            " ORDER BY s.created_at, s.id LIMIT 50 FOR UPDATE OF s SKIP LOCKED"
        )
    ).mappings().all()  # fmt: skip
    for r in rows:
        nid = r["notification_id"]
        request = approvals.fetch_request(conn, r["request_id"])
        if (
            r["ttl_expires_at"] <= now
            or request is None
            or request["state"] not in ("pending", "expired")
        ):
            conn.execute(
                text(
                    "UPDATE proxy_call_sessions SET state = 'expired', completed_at = :t, version = version + 1 WHERE id = :id"
                ),
                {"t": now, "id": r["sid"]},
            )
            conn.execute(
                text(
                    "UPDATE notifications SET failure_reason = 'session_expired', version = version + 1 WHERE id = :id"
                ),
                {"id": nid},
            )
            _attempt(conn, ctx, nid, "system", "session_expired", now, {})
            report.add("call_sessions_expired")
            continue
        built = _build_message(conn, nid, IVR, r["callee_person_id"], request, None, cfg)
        provider = providers.get(Kind.IVR)
        failure = built.failure
        if failure is None and provider is None:
            failure = "provider_not_configured"
        if failure is None:
            decision = budget.authorise_send(
                conn, ctx.society_id, category=cat.SECURITY, channel=IVR, now=now
            )
            if decision.over_budget:
                report.add("over_budget")
        if failure is not None or built.message is None or provider is None:
            conn.execute(
                text(
                    "UPDATE notifications SET failure_reason = :f, version = version + 1 WHERE id = :id"
                ),
                {"f": failure, "id": nid},
            )
            conn.execute(
                text(
                    "UPDATE proxy_call_sessions SET state = 'failed', dial_outcome = 'failed', completed_at = :t, version = version + 1"
                    " WHERE id = :id"
                ),
                {"t": now, "id": r["sid"]},
            )
            _attempt(conn, ctx, nid, "system", "not_sent", now, {"reason": failure})
            report.add("failed_calls")
            if failure in PROVIDER_FAILURES:
                report.add("provider_failures")
            continue
        result = _send(provider, built.message, now)
        _record_send(
            conn,
            ctx,
            nid,
            provider.name,
            provider.simulation,
            result,
            built,
            now,
            report,
            channel=IVR,
        )
