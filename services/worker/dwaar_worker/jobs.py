"""Worker jobs as plain, testable functions (the Dramatiq actors in ``actors.py`` only call these).

REQ: EDGE-04 / PRD 13 (the edge policy publisher: on change, and a periodic refresh so a snapshot never ages out), GATE-02 / GATE-05 /
GATE-11 (expiry of requests and authorisations, overstay exceptions, expiry of passes), OPS-01 / OPS-04 (helpdesk SLA breaches and feedback-window
closure), COM-01 / COM-06 (scheduled notices go live, polls close), PAR-05 (parcel reminders at 24 h and 48 h), SHIFT-01 / Appendix C (a handover nobody
acknowledged escalates, overrides expire), PRD 12.4 (every mutation commits with its audit
and outbox row; the worker role may insert outbox rows since migration 0010), INV-01 (one transaction per society with the RLS context of
THAT society: a job never sees two societies at once), INV-03 (an expiry never allows anything).

Every job is IDEMPOTENT: running it twice in a row changes nothing the second time (content-hash deduplicated snapshots; conditional
updates and unique keys in the sweeps), and safe under concurrency (advisory locks / ``FOR UPDATE SKIP LOCKED`` inside the domain code).
A failure in one society is recorded in the result and does not stop the others.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import text

from dwaar_api.core.db import Database, RequestContext
from dwaar_api.modules.community import notices as community_notices
from dwaar_api.modules.community import polls as community_polls
from dwaar_api.modules.edge.config import EdgeConfig
from dwaar_api.modules.edge.snapshot import PublishResult, publish_policy
from dwaar_api.modules.helpdesk import service as helpdesk_service
from dwaar_api.modules.parcels import jobs as parcel_jobs
from dwaar_api.modules.shifts import jobs as shift_jobs
from dwaar_api.modules.visits import policy as gate_policy
from dwaar_api.modules.visits import visits as visits_service
from dwaar_common.ids import uuid7

log = logging.getLogger("dwaar_worker.jobs")


@dataclass
class JobResult:
    """What one job run did. ``failed`` maps a society to the exception CLASS name (never a message: it may carry data)."""

    societies: int = 0
    changed: int = 0
    failed: dict[uuid.UUID, str] = field(default_factory=dict)
    detail: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, n: int) -> None:
        self.detail[key] = self.detail.get(key, 0) + n


def active_society_ids(db: Database) -> list[uuid.UUID]:
    """Every active society (the reviewed ``dwaar_active_society_ids()`` function: ids only, the worker role has no cross-society read)."""
    with db.worker_tx() as conn:
        return [
            uuid.UUID(str(r[0])) for r in conn.execute(text("SELECT dwaar_active_society_ids()"))
        ]


def _ctx(society_id: uuid.UUID) -> RequestContext:
    return RequestContext(society_id, None, "system", uuid7())


def publish_policies(
    db: Database,
    edge_cfg: EdgeConfig,
    *,
    now: dt.datetime | None = None,
    force: bool = False,
    societies: list[uuid.UUID] | None = None,
) -> JobResult:
    """The edge policy publisher: one idempotent ``publish_policy`` per society. A second run with nothing changed writes nothing."""
    result = JobResult()
    for society_id in societies if societies is not None else active_society_ids(db):
        result.societies += 1
        try:
            ctx = _ctx(society_id)
            with db.worker_tx(ctx) as conn:
                published: PublishResult = publish_policy(conn, ctx, edge_cfg, now=now, force=force)
            if published.changed:
                result.changed += 1
                result.add(f"published_{published.reason}", 1)
        except Exception as exc:
            log.warning("policy publish failed", extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
    return result


def sweep_visits(
    db: Database,
    *,
    now: dt.datetime | None = None,
    societies: list[uuid.UUID] | None = None,
    on_society: Callable[[uuid.UUID], None] | None = None,
) -> JobResult:
    """The visits expiry and overstay sweep of every society: pending requests past their expiry, authorisations past their window,
    overstays (one exception per visit), passes past their last window. Nothing is allowed by a timeout (INV-03)."""
    result = JobResult()
    for society_id in societies if societies is not None else active_society_ids(db):
        result.societies += 1
        try:
            ctx = _ctx(society_id)
            with db.worker_tx(ctx) as conn:
                policy = gate_policy.load_policy(conn)
                swept = visits_service.sweep(conn, ctx, policy, now=now)
            result.add("requests_expired", swept.requests_expired)
            result.add("authorisations_expired", swept.authorisations_expired)
            result.add("overstays_opened", swept.overstays_opened)
            result.add("invitations_expired", swept.invitations_expired)
            if swept.total():
                result.changed += 1
            if on_society is not None:
                on_society(society_id)
        except Exception as exc:
            log.warning("visits sweep failed", extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
    return result


# ------------------------------------------------------------------------------------------ slice 4 sweeps
def _per_society(
    db: Database,
    societies: list[uuid.UUID] | None,
    work: Callable[[uuid.UUID, RequestContext], dict[str, int]],
    *,
    what: str,
) -> JobResult:
    """Run ``work`` once per active society, each in its own worker transaction with THAT society's RLS context (INV-01).

    ``work`` receives the society and the context, opens the transaction itself (``db.worker_tx(ctx)``) and returns counters; a failure is recorded
    by exception class name only and never stops the other societies."""
    result = JobResult()
    for society_id in societies if societies is not None else active_society_ids(db):
        result.societies += 1
        try:
            counters = work(society_id, _ctx(society_id))
        except Exception as exc:
            log.warning("%s failed", what, extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
            continue
        if any(counters.values()):
            result.changed += 1
        for key, n in counters.items():
            result.add(key, n)
    return result


def sweep_helpdesk(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None
) -> JobResult:
    """OPS-01 / OPS-04: record SLA breaches that happened and close resolved tickets whose feedback window elapsed (``helpdesk.service.sweep_society``).
    Idempotent: breaches are unique per (ticket, clock) and a closed ticket is not closed again."""

    def work(_society: uuid.UUID, ctx: RequestContext) -> dict[str, int]:
        with db.worker_tx(ctx) as conn:
            return helpdesk_service.sweep_society(conn, ctx, now)

    return _per_society(db, societies, work, what="helpdesk sweep")


def publish_due_notices(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None
) -> JobResult:
    """COM-01: scheduled notice revisions whose time has come go live (the approval and translation gates are re-checked at that moment)."""

    def work(_society: uuid.UUID, ctx: RequestContext) -> dict[str, int]:
        with db.worker_tx(ctx) as conn:
            return {"notices_published": community_notices.publish_due(conn, ctx, now)}

    return _per_society(db, societies, work, what="notice publisher")


def close_due_polls(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None
) -> JobResult:
    """COM-06: open opinion polls whose closing time passed are closed (non-binding; the system is the actor)."""

    def work(_society: uuid.UUID, ctx: RequestContext) -> dict[str, int]:
        with db.worker_tx(ctx) as conn:
            return {"polls_closed": community_polls.close_due(conn, ctx, now)}

    return _per_society(db, societies, work, what="poll closer")


def send_parcel_reminders(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None
) -> JobResult:
    """PAR-05: the 24 h and 48 h custody reminders (one per parcel and age: a unique row decides, re-runs write nothing).

    The custody REPORT is not a job: it records a guard's physical count against the system's, and a job has no physical count (a report invented by a
    timer would be a fabricated reconciliation)."""
    outcome = parcel_jobs.run_reminders(db, now=now, societies=societies)
    result = JobResult(societies=outcome.societies, failed=dict(outcome.failed))
    for kind, n in outcome.reminders.items():
        result.add(f"reminders_{kind}", n)
    result.changed = 1 if outcome.total else 0
    return result


def sweep_shifts(
    db: Database, *, now: dt.datetime | None = None, societies: list[uuid.UUID] | None = None
) -> JobResult:
    """SHIFT-01 / Appendix C: escalate handovers nobody acknowledged (a state and an event, never a lock) and revoke overrides past their shift."""
    outcome = shift_jobs.run_sweep(db, now=now, societies=societies)
    result = JobResult(societies=outcome.societies, failed=dict(outcome.failed))
    result.add("handovers_escalated", outcome.escalated)
    result.add("overrides_revoked", outcome.overrides_revoked)
    result.changed = 1 if (outcome.escalated or outcome.overrides_revoked) else 0
    return result
