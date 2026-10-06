"""Shift jobs as plain functions: escalate unacknowledged handovers, expire overrides. Idempotent; the clock is injected.

REQ: SHIFT-01 (a missing next guard ESCALATES, it never locks the kiosk), Appendix C (an override expires at shift end), INV-08 (nothing here
touches a gate, a device, a visit or any decision path: escalation is a state and an event, nothing more), INV-01 (one transaction per society),
PRD 13 (job logic = plain functions; Dramatiq actors on a caller-supplied broker, ``StubBroker`` in tests).
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import dramatiq
from sqlalchemy import Connection, text

from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import Database, RequestContext
from .config import DEFAULT_CONFIG, ShiftsConfig

log = logging.getLogger("dwaar_api.shifts.jobs")


@dataclass
class SweepResult:
    societies: int = 0
    escalated: int = 0
    overrides_revoked: int = 0
    failed: dict[uuid.UUID, str] = field(default_factory=dict)


def escalate_unacknowledged(
    conn: Connection,
    ctx: RequestContext,
    *,
    now: dt.datetime | None = None,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
) -> int:
    """Pending handovers older than the deadline become ``escalated`` (reason ``no_incoming_guard`` or ``acknowledgement_overdue``).
    Each is escalated once (the UPDATE is conditional on ``state = 'pending'``); a second run finds nothing."""
    moment = now or utc_now()
    due = conn.execute(
        text(
            "SELECT id, gate_id, version, incoming_shift_id, jsonb_array_length(open_items) AS n FROM shift_handovers"
            " WHERE state = 'pending' AND created_at <= :cut ORDER BY created_at, id FOR UPDATE SKIP LOCKED"
        ),
        {"cut": moment - dt.timedelta(minutes=cfg.escalate_after_minutes)},
    ).mappings().all()  # fmt: skip
    escalated = 0
    for row in due:
        reason = (
            "no_incoming_guard" if row["incoming_shift_id"] is None else "acknowledgement_overdue"
        )

        def apply(c: Connection, *, _row: Any = row, _reason: str = reason) -> MutationResult:
            done = c.execute(
                text(
                    "UPDATE shift_handovers SET state = 'escalated', escalated_at = clock_timestamp(), escalation_reason = :r,"
                    " version = version + 1 WHERE id = :id AND state = 'pending' RETURNING id"
                ),
                {"id": _row["id"], "r": _reason},
            ).first()
            if done is None:  # pragma: no cover (rows are locked above)
                raise _Skip
            return MutationResult(
                _row["id"], int(_row["version"]) + 1, before={"state": "pending"}, after={"state": "escalated", "reason": _reason},
                event_payload={
                    "handover_id": _row["id"], "gate_id": _row["gate_id"], "reason": _reason, "open_item_count": int(_row["n"]),
                },
            )  # fmt: skip

        try:
            mutation(
                conn, ctx, operation="handover.escalate", object_type="shift_handover", event_type="HandoverEscalated",
                apply=apply,
            )  # fmt: skip
        except _Skip:
            continue
        escalated += 1
    return escalated


class _Skip(Exception):
    pass


def expire_overrides(
    conn: Connection, ctx: RequestContext, *, now: dt.datetime | None = None
) -> int:
    """Revoke overrides past ``valid_until`` or whose shift has ended (belt and braces: ending a shift already revokes them)."""
    moment = now or utc_now()
    rows = conn.execute(
        text(
            "UPDATE shift_overrides o SET revoked_at = clock_timestamp(), revoke_reason = CASE WHEN s.state = 'ended' THEN 'shift_ended'"
            " ELSE 'expired' END, version = o.version + 1 FROM shifts s WHERE s.society_id = o.society_id AND s.id = o.shift_id"
            " AND o.revoked_at IS NULL AND (o.valid_until <= :now OR s.state = 'ended') RETURNING o.id"
        ),
        {"now": moment},
    ).all()
    return len(rows)


def run_sweep(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
) -> SweepResult:  # fmt: skip
    result = SweepResult()
    if societies is None:
        with db.worker_tx() as conn:
            societies = [
                uuid.UUID(str(r[0]))
                for r in conn.execute(text("SELECT dwaar_active_society_ids()"))
            ]
    for society_id in societies:
        result.societies += 1
        ctx = RequestContext(society_id, None, "system", uuid7())
        try:
            with db.worker_tx(ctx) as conn:
                result.escalated += escalate_unacknowledged(conn, ctx, now=now, cfg=cfg)
                result.overrides_revoked += expire_overrides(conn, ctx, now=now)
        except Exception as exc:
            log.warning("shift sweep failed", extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
    return result


def build_shift_actors(
    broker: dramatiq.Broker,
    db: Database,
    *,
    queue: str = "dwaar",
    clock: Callable[[], dt.datetime] = utc_now,
    results: dict[str, Any] | None = None,
) -> Any:
    @dramatiq.actor(broker=broker, queue_name=queue, actor_name="shifts_sweep", max_retries=3)
    def shifts_sweep() -> None:
        outcome = run_sweep(db, now=clock())
        if results is not None:
            results["shifts_sweep"] = outcome

    return shifts_sweep
