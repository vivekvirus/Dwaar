"""Edge policy: the first signed snapshot of each seeded society, published AFTER the staff and parcel steps so that it already carries them.

REQ: EDGE-04 (signed snapshot), AT-12 / STAFF-03 (the manifest lists one entry per staff engagement), ADR-0019, seed idempotency (a second run must
change nothing).

Why a step of its own: ``publish_policy`` writes a new snapshot whenever the manifest content changed. The gateway/standing-rule step (``s450_edge``) used
to publish at once; once the policy began to carry staff engagements (slice 4 integration), a re-run after the staff step found a CHANGED manifest and
published a second snapshot per society, so ``make seed`` was not idempotent. Publishing here, after every step whose data goes into the manifest, makes
the first snapshot complete and the second run a no-op. Default ON like ``s450_edge``; skipped when that step is switched off or found no gateway.
"""

from __future__ import annotations

from sqlalchemy import text

from ...modules.edge.config import EdgeConfig
from ...modules.edge.snapshot import publish_policy
from ..runtime import SeedContext
from . import s400_visits, s450_edge

NAME = "edge_policy"
ORDER = 485


def run(ctx: SeedContext) -> None:
    if not s450_edge.enabled():
        return
    cfg = EdgeConfig.from_environment(ctx.settings)
    for plan in s400_visits.PLANS:
        soc = ctx.society(plan.society)
        with ctx.tx(f"edge:gateway-read:{plan.society}", society=soc.id, role="seed") as (conn, _c):
            has_gateway = (
                conn.execute(text("SELECT 1 FROM devices WHERE kind = 'gateway' LIMIT 1")).first()
                is not None
            )
        if not has_gateway:
            continue
        with ctx.tx(f"edge:publish:{plan.society}", society=soc.id, role="system") as (conn, rctx):
            result = publish_policy(conn, rctx, cfg)
        if result.changed:
            ctx.count("policy_snapshots_created")
    ctx.say("  edge policy: first signed snapshot per society (staff engagements included)")
