"""Cascade and offline configuration with approved bounds (D-13, D-15, NOTIF-03, INV-03).

Per-society overrides are allowed only within the bounds stored in the pack. A timeout never auto-allows.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from itertools import pairwise
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .errors import ConfigBoundsError
from .loader import load_typed
from .models import CascadeOfflinePack, CascadeStep, OfflineDefaults
from .paths import legal_packs_dir

_ALLOWED = {"step_at_seconds", "expiry_seconds", "offline"}
_OFFLINE_INT_KEYS = {
    "resident_credential_validity_hours",
    "guest_pass_max_hours",
    "clock_uncertainty_disable_auto_approvals_seconds",
    "policy_age_guard_assisted_verification_hours",
    "edge_event_buffer_hours",
    "terminal_standalone_min_hours",
}


class CascadeConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    steps: list[CascadeStep]
    expiry_seconds: int
    offline: OfflineDefaults
    auto_allow_on_timeout: Literal[False] = (
        False  # INV-03: this config cannot even represent auto-allow
    )


@cache
def default_cascade_pack() -> CascadeOfflinePack:
    return load_typed(legal_packs_dir() / "defaults" / "cascade-offline.yaml", CascadeOfflinePack)


def cascade_config(
    overrides: Mapping[str, Any] | None = None, *, pack: CascadeOfflinePack | None = None
) -> CascadeConfig:
    """Resolve defaults plus per-society overrides; raise ConfigBoundsError listing every violation.

    ``overrides`` keys: ``step_at_seconds`` ({step: seconds} for steps 2..N-1), ``expiry_seconds`` (the
    final expiry step) and ``offline`` ({field: value}).
    """
    pack = pack or default_cascade_pack()
    ov = dict(overrides or {})
    bad: list[str] = []
    for k in ov:
        if k not in _ALLOWED:
            bad.append(f"unknown override {k!r} (a timeout can never be configured to auto-allow)")
    bounds = pack.cascade.bounds
    steps = [s.model_copy() for s in pack.cascade.steps]
    last = steps[-1]
    at = {s.step: s.at_seconds for s in steps}

    step_overrides = ov.get("step_at_seconds", {})
    if not isinstance(step_overrides, Mapping):
        bad.append("step_at_seconds must be an object of {step: seconds}")
        step_overrides = {}
    offline_overrides = ov.get("offline", {})
    if not isinstance(offline_overrides, Mapping):
        bad.append("offline must be an object of {field: value}")
        offline_overrides = {}
    for raw_step, secs in step_overrides.items():
        try:
            n = int(raw_step)
        except (TypeError, ValueError):
            bad.append(f"step {raw_step!r} is not a step number")
            continue
        if n not in at or n == 1 or n == last.step:
            bad.append(
                f"step {n} is not overridable (step 1 is t=0; use expiry_seconds for the last step)"
            )
        elif isinstance(secs, bool) or not isinstance(secs, int):
            bad.append(f"step {n}: seconds must be an integer")
        else:
            at[n] = secs
    if "expiry_seconds" in ov:
        exp = ov["expiry_seconds"]
        if isinstance(exp, bool) or not isinstance(exp, int):
            bad.append("expiry_seconds must be an integer")
        else:
            at[last.step] = exp
    exp_b = bounds.expiry_seconds
    if not exp_b.min <= at[last.step] <= exp_b.max:
        bad.append(f"expiry_seconds {at[last.step]} outside {exp_b.min}-{exp_b.max}")
    ordered = sorted(at)
    for a, b in pairwise(ordered):
        if at[b] - at[a] < bounds.min_seconds_between_steps:
            bad.append(
                f"steps {a}->{b}: gap {at[b] - at[a]}s below minimum {bounds.min_seconds_between_steps}s"
            )

    offline = pack.offline.model_dump()
    ceilings = pack.offline_bounds
    for k, v in offline_overrides.items():
        if k not in _OFFLINE_INT_KEYS:
            bad.append(f"offline.{k} is not overridable")
        elif isinstance(v, bool) or not isinstance(v, int) or v < 1:
            bad.append(f"offline.{k} must be a positive integer")
        elif k in type(ceilings).model_fields and v > getattr(ceilings, k).max:
            bad.append(f"offline.{k} {v} above approved maximum {getattr(ceilings, k).max}")
        else:
            offline[k] = v
    # D-13: guest passes are capped at the pack maximum (shorter allowed); the standalone terminal minimum
    # may only be raised.
    if offline["guest_pass_max_hours"] > pack.offline.guest_pass_max_hours:
        bad.append(
            f"offline.guest_pass_max_hours above maximum {pack.offline.guest_pass_max_hours}"
        )
    if offline["terminal_standalone_min_hours"] < pack.offline.terminal_standalone_min_hours:
        bad.append(
            f"offline.terminal_standalone_min_hours below minimum {pack.offline.terminal_standalone_min_hours}"
        )
    if bad:
        raise ConfigBoundsError(bad)
    final = [s.model_copy(update={"at_seconds": at[s.step]}) for s in steps]
    return CascadeConfig(
        steps=final,
        expiry_seconds=at[last.step],
        offline=OfflineDefaults.model_validate(offline),
        auto_allow_on_timeout=False,
    )
