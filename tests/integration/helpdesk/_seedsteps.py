"""Run the platform seed steps (<= 450) plus ONLY the named slice-4 steps, so a module's seed test does not depend on another
engineer's in-flight seed step. (The orchestrator's full-seed tests still run every step.)"""

from __future__ import annotations

from collections.abc import Collection

from dwaar_api import seed
from dwaar_api.seed.runtime import SeedContext

PLATFORM_MAX_ORDER = 450


def run_steps(env: dict[str, str], names: Collection[str]) -> dict[str, int]:
    ctx = SeedContext.create(env, say=lambda _line: None)
    try:
        for module in seed.discover_steps():
            if module.ORDER <= PLATFORM_MAX_ORDER or module.NAME in names:
                module.run(ctx)
    finally:
        ctx.close()
    return dict(ctx.counts)
