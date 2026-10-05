"""Reference data: load the shipped legal and tax packs (INV-10: law is configuration).

REQ: GOV-01, INV-10, D-24. The pack loader stores a pack as UNAPPROVED unless the environment carries approval evidence for
its exact content hash (ADR-0007 #9), so the seeded Maharashtra pack stays unapproved and binding governance stays off.
"""

from __future__ import annotations

from ...modules.organisation.packs import load_packs
from ..runtime import SeedContext

NAME = "packs"
ORDER = 10


def run(ctx: SeedContext) -> None:
    engine = ctx.owner_engine()
    try:
        with engine.begin() as conn:
            report = load_packs(conn)
    finally:
        engine.dispose()
    ctx.say(f"  packs: {report}")
