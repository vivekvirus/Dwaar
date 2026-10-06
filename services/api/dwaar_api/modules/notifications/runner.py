"""One notification tick for one society: consume outbox events, apply provider reports, advance live cascades, hand over keypad decisions.

REQ: NOTIF-03 (cascade driven by outbox events from the visits module: ApprovalRequested starts it, ApprovalDecided / ApprovalEscalated end it),
NOTIF-04 (a decision cancels ringing and invalidates stale actions: handled FIRST in the tick), IAM-11 (``identity.reverification_required`` revokes
the person's push tokens), PRD 12.4 (at-least-once outbox: handled once per society through a ledger), INV-01 (one transaction per society, with that
society's RLS context), INV-03.

Safe under restarts, duplicate delivery and concurrent workers:

* every event is handled at most once per society (``notification_processed_events``; a duplicate finds its row and does nothing);
* every send is deduplicated by a unique key written BEFORE the provider is called (engine.issue), so a crash between "row written" and "provider
  called" at worst leaves a row whose send is recorded as not made, never a second message;
* a per-society advisory lock makes two workers take turns instead of racing; the second skips that society for this tick.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.timeutil import utc_now

from ...core.db import Database
from ..visits import approvals
from . import devices, engine
from .config import NotificationsConfig
from .engine import RELEVANT_EVENTS, PendingDecision, Report, system_ctx
from .providers import ProviderEvent, ProviderSet

log = logging.getLogger("dwaar_api.notifications")

Clock = Callable[[], dt.datetime]


class _AlreadyHandled(Exception):
    """Another worker handled this event first; roll back what this one did."""


def _lock(conn: Connection, society_id: uuid.UUID) -> bool:
    return bool(
        conn.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"notifications-tick:{society_id}"},
        ).scalar_one()
    )


def pending_events(
    conn: Connection, society_id: uuid.UUID, *, now: dt.datetime, cfg: NotificationsConfig
) -> list[dict[str, Any]]:
    since = now - dt.timedelta(hours=cfg.event_lookback_hours)
    rows = conn.execute(
        text(
            "SELECT o.event_id, o.event_type, o.aggregate_id, o.payload, o.occurred_at FROM outbox o"
            " WHERE o.society_id = :s AND o.event_type = ANY(:types) AND o.occurred_at > :since"
            " AND NOT EXISTS (SELECT 1 FROM notification_processed_events p WHERE p.society_id = o.society_id"
            "   AND p.event_id = o.event_id)"
            " ORDER BY o.occurred_at, o.event_id LIMIT :n"
        ),
        {
            "s": society_id,
            "types": list(RELEVANT_EVENTS),
            "since": since,
            "n": cfg.max_events_per_tick,
        },
    ).mappings()
    return [dict(r) for r in rows]


def ingest_events(
    conn: Connection,
    society_id: uuid.UUID,
    providers: ProviderSet,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    report: Report,
) -> int:
    """Handle every relevant outbox event of the society that has not been handled. Returns how many were handled now."""
    handled = 0
    for ev in pending_events(conn, society_id, now=now, cfg=cfg):
        ctx = system_ctx(society_id)
        try:
            with conn.begin_nested():
                outcome = _handle(conn, ctx, ev, providers, now=now, cfg=cfg, report=report)
                row = conn.execute(
                    text(
                        "INSERT INTO notification_processed_events (society_id, event_id, event_type, outcome)"
                        " VALUES (:s, :e, :t, :o) ON CONFLICT DO NOTHING RETURNING event_id"
                    ),
                    {"s": society_id, "e": ev["event_id"], "t": ev["event_type"], "o": outcome},
                ).first()
                if row is None:
                    raise _AlreadyHandled
        except _AlreadyHandled:
            report.add("event_handled_elsewhere")
            continue
        except Exception as exc:
            log.warning(
                "notification event failed",
                extra={"exc_type": type(exc).__name__, "event_type": ev["event_type"]},
            )
            report.add("event_errors")
            continue
        handled += 1
        report.add("events_handled")
    return handled


def _handle(
    conn: Connection,
    ctx: Any,
    ev: dict[str, Any],
    providers: ProviderSet,
    *,
    now: dt.datetime,
    cfg: NotificationsConfig,
    report: Report,
) -> str:
    kind, payload = ev["event_type"], ev["payload"] or {}
    if kind == "identity.reverification_required":
        row = conn.execute(
            text("SELECT person_id FROM memberships WHERE id = :m"),
            {"m": payload.get("membership_id")},
        ).first()
        if row is None:
            return "membership_unknown"
        n = devices.revoke_all_for_person(conn, ctx, row[0], reason="phone_number_changed")
        report.add("tokens_revoked", n)
        return "tokens_revoked" if n else "no_tokens"
    request_id = uuid.UUID(str(payload.get("request_id") or ev["aggregate_id"]))
    request = approvals.fetch_request(conn, request_id)
    if request is None:
        return "request_unknown"
    if kind == "ApprovalRequested":
        if request["state"] != "pending":
            return "already_closed"
        created = engine.start_cascade(conn, ctx, request)
        if created is None:
            return "duplicate"
        report.add("cascades_started")
        return "cascade_started"
    # ApprovalDecided / ApprovalEscalated: the request left "pending"
    cascades = conn.execute(
        text("SELECT id, request_id, unit_id, attempt_no, started_at, expires_at, plan FROM notification_cascades WHERE request_id = :r AND state = 'active'"),
        {"r": request_id},
    ).mappings().all()  # fmt: skip
    if request["state"] == "pending":
        return "still_pending"  # a stale or out-of-order event: the committed state is the truth
    for cascade in cascades:
        engine.close_for_request_state(
            conn, ctx, dict(cascade), request, providers, now=now, report=report
        )
    if not cascades:
        engine.invalidate_request(conn, ctx, request_id, request, providers, now=now, report=report)
    return "closed"


def process_society(
    db: Database,
    society_id: uuid.UUID,
    providers: ProviderSet,
    *,
    events: list[ProviderEvent] | None = None,
    now: dt.datetime | None = None,
    cfg: NotificationsConfig | None = None,
) -> tuple[Report, set[str]]:
    """One tick for one society. ``events`` are the provider reports drained by the caller (applied here to the notifications that belong
    to this society); the second result is the set of event ids that did. Raises nothing for a provider fault."""
    cfg = cfg or NotificationsConfig()
    moment = now or utc_now()
    report = Report()
    decisions: list[PendingDecision] = []
    matched: set[str] = set()
    ctx = system_ctx(society_id)
    with db.worker_tx(ctx) as conn:
        if not _lock(conn, society_id):
            report.add("skipped_locked")
            return report, matched
        ingest_events(conn, society_id, providers, now=moment, cfg=cfg, report=report)
        if events:
            decisions, matched = engine.apply_provider_events(
                conn, ctx, events, now=moment, report=report
            )
        engine.dispatch_pending_calls(conn, ctx, providers, now=moment, cfg=cfg, report=report)
        for cascade in engine.active_cascades(conn, cfg.max_cascades_per_tick):
            try:
                with conn.begin_nested():
                    engine.advance_cascade(
                        conn, ctx, cascade, providers, now=moment, cfg=cfg, report=report
                    )
            except Exception as exc:
                log.warning(
                    "cascade step failed", extra={"exc_type": type(exc).__name__}, exc_info=True
                )
                report.add("cascade_errors")
    for pending in decisions:
        engine.execute_decision(db, pending, now=moment, report=report)
    if decisions:
        # the decision committed above emitted ApprovalDecided: close the cascade and withdraw the other devices in the same tick
        with db.worker_tx(ctx) as conn:
            if _lock(conn, society_id):
                ingest_events(conn, society_id, providers, now=moment, cfg=cfg, report=report)
    return report, matched


def drain_provider_events(providers: ProviderSet, now: dt.datetime) -> list[ProviderEvent]:
    """Collect what every provider reported since the last drain. A provider that fails to answer is logged and skipped."""
    drained: list[ProviderEvent] = []
    for provider in providers.all():
        try:
            drained.extend(provider.drain_events(now=now))
        except Exception as exc:
            log.warning("provider drain failed", extra={"exc_type": type(exc).__name__})
    return drained


def run_tick(
    db: Database,
    providers: ProviderSet,
    *,
    societies: list[uuid.UUID],
    clock: Clock = utc_now,
    cfg: NotificationsConfig | None = None,
) -> dict[uuid.UUID, Report]:
    """The job body: drain what the providers reported, then give every society one tick. Provider reports that belong to no society are
    counted (``unmatched_provider_events``) and dropped: a callback for a message we never recorded is not evidence of anything."""
    cfg = cfg or NotificationsConfig()
    now = clock()
    drained = drain_provider_events(providers, now)
    out: dict[uuid.UUID, Report] = {}
    seen: set[str] = set()
    for society_id in societies:
        report, matched = process_society(
            db, society_id, providers, events=drained, now=now, cfg=cfg
        )
        seen |= matched
        out[society_id] = report
    leftover = {e.event_id for e in drained} - seen
    if leftover and out:
        next(iter(out.values())).add("unmatched_provider_events", len(leftover))
    return out


__all__ = [
    "Clock",
    "drain_provider_events",
    "ingest_events",
    "pending_events",
    "process_society",
    "run_tick",
]
