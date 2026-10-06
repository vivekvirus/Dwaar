"""AI: switch the per-society daily AI allowance ON for the synthetic societies (default is 0 = AI off).

REQ: ARCH-05 (per-society AI budgets), AI-SYS-06, BUILD_BRIEF 7 (simulators are labelled; the local provider is the deterministic SIMULATOR).

Only the budget is seeded, through the SAME service function the quotas route uses (audit and outbox rows included). No AI run, answer or
draft is invented: ``ai_runs`` stays empty until someone asks for something, because a fabricated 'result' would read like a measurement.
Idempotent: a society that already has an allowance at or above the seeded one is left alone.
"""

from __future__ import annotations

from ...modules.organisation import service
from ...modules.organisation.schemas import QuotasPut
from ..dataset import SOCIETIES
from ..runtime import SeedContext

NAME = "ai"
ORDER = 700
DAILY_ALLOWANCE = 200


def run(ctx: SeedContext) -> None:
    secretary_key = "{}.secretary"
    for spec in SOCIETIES:
        sid = ctx.society_id(spec.key)
        person = ctx.person(secretary_key.format(spec.key))
        with ctx.tx(f"ai:quota:{spec.key}", society=sid, person=person, role="secretary") as (
            conn,
            rctx,
        ):
            current = service.fetch_quotas(conn, sid)
            if current is None:
                continue
            if int(current["ai_requests_per_day"]) >= DAILY_ALLOWANCE:
                ctx.count("ai_quota_existing")
                continue
            service.put_quotas(conn, rctx, sid, QuotasPut(ai_requests_per_day=DAILY_ALLOWANCE))
            ctx.count("ai_quota_set")
