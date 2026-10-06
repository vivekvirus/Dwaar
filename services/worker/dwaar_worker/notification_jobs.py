"""Worker jobs of the notifications slice: the approval cascade tick (plain functions; the Dramatiq actor in ``actors.py`` only calls them).

REQ: NOTIF-03 / AT-40 (the cascade: t=0 / 10 / 20 / 35 / expiry, driven by the outbox events of the visits module), NOTIF-04 (a decision withdraws the
other devices: this tick runs every second, so the withdrawal is bounded by that cadence plus the job time), IAM-11 (the same tick revokes the push
tokens of a person whose number changed), CALL-01, PRD 12.4, INV-01 (one transaction per society with that society's RLS context), INV-03 (nothing here
can allow entry).

IDEMPOTENT and restart-safe: every outbox event is handled once per society (a ledger), every send is deduplicated by a key written before the provider
is called, and a per-society advisory lock makes two workers take turns. The clock is injectable (``clock``): tests and the simulator drive virtual time.
A failure in one society is recorded (exception class name only) and does not stop the others.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable

from dwaar_api.core.db import Database
from dwaar_api.modules.notifications import runner
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.providers import ProviderSet
from dwaar_common.timeutil import utc_now

from .jobs import JobResult, active_society_ids

log = logging.getLogger("dwaar_worker.notification_jobs")

#: counters that mean something changed (everything else, such as a skipped lock, is bookkeeping)
_CHANGES = (
    "cascades_started", "created_push", "created_ivr_call", "created_sms", "created_whatsapp", "invalidated", "cascade_decided",
    "cascade_expired", "cascade_cancelled", "tokens_revoked", "events_handled", "call_sessions_expired",
)  # fmt: skip


def notification_tick(
    db: Database,
    providers: ProviderSet,
    *,
    cfg: NotificationsConfig | None = None,
    clock: Callable[[], dt.datetime] = utc_now,
    societies: list[uuid.UUID] | None = None,
) -> JobResult:
    """One tick for every active society: handle new outbox events, apply provider reports, advance the live cascades, hand over keypad decisions."""
    cfg = cfg or NotificationsConfig()
    result = JobResult()
    now = clock()
    drained = runner.drain_provider_events(providers, now)
    seen: set[str] = set()
    for society_id in societies if societies is not None else active_society_ids(db):
        result.societies += 1
        try:
            report, matched = runner.process_society(
                db, society_id, providers, events=drained, now=now, cfg=cfg
            )
        except Exception as exc:
            log.warning("notification tick failed", extra={"exc_type": type(exc).__name__})
            result.failed[society_id] = type(exc).__name__
            continue
        seen |= matched
        for key, n in report.counts.items():
            result.add(key, n)
        if any(report.get(k) for k in _CHANGES):
            result.changed += 1
    leftover = {e.event_id for e in drained} - seen
    if leftover:
        result.add("unmatched_provider_events", len(leftover))
    return result
