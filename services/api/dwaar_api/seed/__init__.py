"""Synthetic seed data for the local demonstrator (``python -m dwaar_api.seed``, ``make seed``).

REQ: PRD 8.3 "Seed dataset" (slice 1 part), PRD 4.3 slice 1 ("synthetic data"), BUILD_BRIEF 7 (invented identities,
reserved test numbers; demo logins only with ``DWAAR_ENV=local``).

* Refuses to run unless ``DWAAR_ENV`` is exactly ``local``.
* Goes through the real service functions with the real ``dwaar_app`` role and RLS context, so every row has its audit and
  outbox record. Only the legal/tax pack loader uses the owner role (global reference data, ADR-0010).
* Deterministic (fixed UUIDv7 time, ids derived from stable scope keys) and idempotent (a re-run finds everything and
  changes nothing).
* Structured as steps (``steps/sNNN_*.py``, discovered by name) so later slices add their data without touching shared files.

Demo logins exist only through the labelled local identity simulator: see README "Local demo".
"""

from __future__ import annotations

import importlib
import pkgutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import ModuleType

from . import steps as _steps_pkg
from .runtime import SeedContext, SeedRefused, out, require_local

__all__ = ["SeedRefused", "SeedResult", "discover_steps", "require_local", "run"]


@dataclass(frozen=True)
class SeedResult:
    counts: dict[str, int]
    seconds: float
    steps: tuple[str, ...]

    @property
    def created_anything(self) -> bool:
        return any(
            v
            and (
                k.endswith(
                    (
                        "_created",
                        "_issued",
                        "_enrolled",
                        "_verified",
                        "_ended",
                        "_opened",
                        "_rejected",
                    )
                )
            )
            for k, v in self.counts.items()
        )


def discover_steps() -> list[ModuleType]:
    found: list[ModuleType] = []
    for info in pkgutil.iter_modules(_steps_pkg.__path__):
        if not info.name.startswith("s") or not info.name[1:4].isdigit():
            continue
        module = importlib.import_module(f"{_steps_pkg.__name__}.{info.name}")
        found.append(module)
    orders = [m.ORDER for m in found]
    if len(set(orders)) != len(orders):
        raise RuntimeError("seed steps must have unique ORDER values")
    return sorted(found, key=lambda m: m.ORDER)


def run(environ: Mapping[str, str], *, say: Callable[[str], None] = out) -> SeedResult:
    """Run every step in order against the database named by ``environ`` (must say ``DWAAR_ENV=local``)."""
    require_local(environ)
    started = time.monotonic()
    ctx = SeedContext.create(environ, say=say)
    names: list[str] = []
    try:
        for module in discover_steps():
            say(f"[{module.ORDER:03d}] {module.NAME}")
            module.run(ctx)
            names.append(module.NAME)
    finally:
        ctx.close()
    return SeedResult(dict(ctx.counts), time.monotonic() - started, tuple(names))
