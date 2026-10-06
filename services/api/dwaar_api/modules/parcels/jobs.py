"""Parcel jobs as plain functions (PAR-05 reminders) and their Dramatiq actors on a caller-supplied broker.

REQ: PAR-05 (reminders at 24 h and 48 h of custody; a custody report reconciling the physical count), PRD 13 (job logic = plain functions,
``StubBroker`` in tests), INV-01 (one transaction per society, with the RLS context of THAT society), INV-07 (a reminder is a fact about
time in custody, it says nothing about the resident having been told: the notifications slice delivers it).

IDEMPOTENT: ``parcel_reminders`` is unique per (parcel, kind) and the audit/outbox rows are written only by the run that inserts the row, so
running the job twice, or two runs at once, produces exactly one reminder (and one event) per parcel and age. The clock is injected (``now``).
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
from .config import DEFAULT_CONFIG, ParcelsConfig
from .service import IN_CUSTODY

log = logging.getLogger("dwaar_api.parcels.jobs")


class _AlreadyReminded(Exception):
    """Raised inside ``mutation`` so its savepoint rolls the (empty) audit/outbox rows back."""


@dataclass
class ReminderResult:
    societies: int = 0
    reminders: dict[str, int] = field(default_factory=dict)
    failed: dict[uuid.UUID, str] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.reminders.values())


def send_due_reminders(
    conn: Connection,
    ctx: RequestContext,
    *,
    now: dt.datetime | None = None,
    cfg: ParcelsConfig = DEFAULT_CONFIG,
) -> dict[str, int]:
    """One society (``ctx`` is its RLS context): create the reminders that are due and not yet created. Returns kind -> number created."""
    moment = now or utc_now()
    created: dict[str, int] = {}
    assert ctx.society_id is not None  # noqa: S101
    for kind, age in cfg.reminder_ages:
        rows = conn.execute(
            text(
                "SELECT p.id, p.unit_id, p.received_at FROM parcels p WHERE p.state = ANY(:s) AND p.received_at <= :cut"
                " AND NOT EXISTS (SELECT 1 FROM parcel_reminders r WHERE r.parcel_id = p.id AND r.kind = :k)"
                " ORDER BY p.received_at, p.id"
            ),
            {"s": list(IN_CUSTODY), "cut": moment - age, "k": kind},
        ).all()
        for parcel_id, unit_id, received_at in rows:
            reminder_id = uuid7()

            def apply(
                c: Connection, *, _id: uuid.UUID = reminder_id, _p: uuid.UUID = parcel_id,
                _u: uuid.UUID = unit_id, _kind: str = kind, _due: dt.datetime = received_at + age, _age: dt.timedelta = age,
            ) -> MutationResult:  # fmt: skip
                inserted = c.execute(
                    text(
                        "INSERT INTO parcel_reminders (id, society_id, parcel_id, kind, due_at) VALUES (:id, :s, :p, :k, :due)"
                        " ON CONFLICT (society_id, parcel_id, kind) DO NOTHING RETURNING id"
                    ),
                    {"id": _id, "s": ctx.society_id, "p": _p, "k": _kind, "due": _due},
                ).first()
                if inserted is None:
                    raise _AlreadyReminded
                return MutationResult(
                    _id, 1, after={"parcel_id": _p, "kind": _kind},
                    event_payload={
                        "reminder_id": _id, "parcel_id": _p, "unit_id": _u, "kind": _kind,
                        "hours_in_custody": int(_age.total_seconds() // 3600),
                    },
                )  # fmt: skip

            try:
                mutation(
                    conn, ctx, operation="parcel.reminder", object_type="parcel_reminder",
                    event_type="ParcelReminderDue", apply=apply,
                )  # fmt: skip
            except _AlreadyReminded:
                continue
            created[kind] = created.get(kind, 0) + 1
    return created


def _society_ids(db: Database) -> list[uuid.UUID]:
    with db.worker_tx() as conn:
        return [
            uuid.UUID(str(r[0])) for r in conn.execute(text("SELECT dwaar_active_society_ids()"))
        ]


def run_reminders(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None,
    cfg: ParcelsConfig = DEFAULT_CONFIG,
) -> ReminderResult:  # fmt: skip
    """Every active society, each in its own worker transaction. A failure in one society never stops the others."""
    result = ReminderResult()
    for society_id in societies if societies is not None else _society_ids(db):
        result.societies += 1
        ctx = RequestContext(society_id, None, "system", uuid7())
        try:
            with db.worker_tx(ctx) as conn:
                made = send_due_reminders(conn, ctx, now=now, cfg=cfg)
            for kind, n in made.items():
                result.reminders[kind] = result.reminders.get(kind, 0) + n
        except Exception as exc:
            log.warning("parcel reminders failed", extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
    return result


def build_parcel_actors(
    broker: dramatiq.Broker,
    db: Database,
    *,
    queue: str = "dwaar",
    clock: Callable[[], dt.datetime] = utc_now,
    results: dict[str, Any] | None = None,
) -> Any:
    """Register the reminder actor on ``broker`` (``StubBroker`` in tests, Redis in production). The message carries no business data."""

    @dramatiq.actor(broker=broker, queue_name=queue, actor_name="parcels_reminders", max_retries=3)
    def parcels_reminders() -> None:
        outcome = run_reminders(db, now=clock())
        if results is not None:
            results["parcels_reminders"] = outcome

    return parcels_reminders
