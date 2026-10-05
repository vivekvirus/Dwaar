"""Gate policy: approval expiry, permission validity, overstay thresholds, the revocation counter.

REQ: GATE-02 (a pending request expires after the society policy, default 90 seconds, configurable only within the approved
cascade pack bounds; INV-03: a timeout never allows), GATE-11 (overstay thresholds are configuration: delivery default
20 minutes, service 2 to 8 hours), GATE-01 (the monotonic, society-wide revocation counter), INV-10 (operational thresholds
are configuration, not code).

The defaults of the approval cascade come from ``dwaar_packs.cascade_config`` (``packages/legal-packs/defaults/cascade-offline.yaml``,
PRD Appendix C): ``dwaar_packs`` is imported lazily, like the organisation module's pack loader. A society overrides the
expiry through ``PUT /v1/societies/{id}/gate-policy``; the override is validated by ``cascade_config`` itself, so a value
outside the approved bounds is refused with the pack's own message.
"""

from __future__ import annotations

import importlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, PolicyViolation
from dwaar_common.ids import uuid7

#: GATE-11 defaults, in minutes. ``None`` = not time-boxed (a guest is bounded by the pass window, staff by the engagement).
DEFAULT_OVERSTAY_MINUTES: Final[dict[str, int]] = {
    "delivery": 20,
    "cab": 15,
    "service": 240,
    "vendor": 240,
}
#: Allowed range per kind (inclusive). Service is "2 to 8 hours per booking" (GATE-11).
OVERSTAY_BOUNDS: Final[dict[str, tuple[int, int]]] = {
    "delivery": (5, 180),
    "cab": (5, 120),
    "service": (120, 480),
    "vendor": (30, 480),
}
FALLBACK_EXPIRY_SECONDS: Final = (
    90  # used only if the pack cannot be loaded; the pack default is the same 90 (PRD 9.2)
)


@dataclass(frozen=True)
class GatePolicy:
    approval_expiry_seconds: int
    permission_validity_minutes: int
    override_validity_minutes: int
    overstay_overrides: Mapping[str, int] = field(default_factory=dict)
    revocation_version: int = 0
    version: int = 0  # 0 = defaults only, no row yet

    @property
    def overstay_minutes(self) -> dict[str, int]:
        merged = dict(DEFAULT_OVERSTAY_MINUTES)
        merged.update(self.overstay_overrides)
        return merged

    def overstay_threshold(self, kind: str, expected_minutes: int | None) -> int | None:
        """Minutes after entry at which a visit counts as overstaying, or ``None`` (not time-boxed)."""
        if kind not in DEFAULT_OVERSTAY_MINUTES:
            return None
        return expected_minutes if expected_minutes is not None else self.overstay_minutes[kind]

    def as_view(self) -> dict[str, Any]:
        return {
            "approval_expiry_seconds": self.approval_expiry_seconds,
            "permission_validity_minutes": self.permission_validity_minutes,
            "override_validity_minutes": self.override_validity_minutes,
            "overstay_minutes": self.overstay_minutes,
            "overstay_bounds": {
                k: {"min": lo, "max": hi} for k, (lo, hi) in OVERSTAY_BOUNDS.items()
            },
            "revocation_version": self.revocation_version,
            "auto_allow_on_timeout": False,  # INV-03: the policy cannot represent it
            "version": self.version,
        }


def _packs() -> Any:
    return importlib.import_module("dwaar_packs")


def pack_default_expiry() -> int:
    try:
        return int(_packs().cascade_config().expiry_seconds)
    except Exception:  # a broken pack must not take the gate down; the PRD default applies and the operator is told
        return FALLBACK_EXPIRY_SECONDS


def default_policy() -> GatePolicy:
    return GatePolicy(pack_default_expiry(), 30, 240)


def load_policy(conn: Connection) -> GatePolicy:
    """The caller's society policy (RLS scopes the row), or the defaults when none was ever saved."""
    row = (
        conn.execute(
            text(
                "SELECT approval_expiry_seconds, permission_validity_minutes, override_validity_minutes,"
                " overstay_minutes, revocation_version, version FROM gate_policies"
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        return default_policy()
    overrides = row["overstay_minutes"] or {}
    return GatePolicy(
        int(row["approval_expiry_seconds"]),
        int(row["permission_validity_minutes"]),
        int(row["override_validity_minutes"]),
        {str(k): int(v) for k, v in overrides.items()},
        int(row["revocation_version"]),
        int(row["version"]),
    )


def validate_expiry(seconds: int) -> None:
    """Raise 422 with the pack's own message when ``seconds`` is outside the approved cascade bounds (D-15)."""
    packs = _packs()
    try:
        packs.cascade_config({"expiry_seconds": seconds})
    except packs.ConfigBoundsError as exc:
        raise PolicyViolation(
            details={"reason": "outside_approved_bounds", "problems": list(exc.args[0])[:5]}
            if exc.args and isinstance(exc.args[0], list)
            else {"reason": "outside_approved_bounds"}
        ) from None


def validate_overstay(overrides: Mapping[str, int]) -> None:
    problems: list[tuple[str, str]] = []
    for kind, minutes in overrides.items():
        bounds = OVERSTAY_BOUNDS.get(kind)
        if bounds is None:
            problems.append((f"overstay_minutes.{kind}", "unknown_kind"))
        elif not bounds[0] <= minutes <= bounds[1]:
            problems.append(
                (f"overstay_minutes.{kind}", f"must_be_between_{bounds[0]}_and_{bounds[1]}")
            )
    if problems:
        raise InvalidSchema.for_fields(problems)


def check_expected_minutes(kind: str, expected_minutes: int | None) -> None:
    """A per-booking duration must respect the kind's bounds (service: 2 to 8 hours, GATE-11)."""
    if expected_minutes is None:
        return
    bounds = OVERSTAY_BOUNDS.get(kind)
    if bounds is None:
        raise InvalidSchema.for_fields([("expected_minutes", "not_time_boxed_kind")])
    if not bounds[0] <= expected_minutes <= bounds[1]:
        raise InvalidSchema.for_fields(
            [("expected_minutes", f"must_be_between_{bounds[0]}_and_{bounds[1]}")]
        )


def cascade_plan(expiry_seconds: int) -> dict[str, Any]:
    """The cascade the notification worker will walk for one request (stored on the request so a later policy change does
    not rewrite a pending request). ``auto_allow_on_timeout`` is False by construction (INV-03)."""
    try:
        config = _packs().cascade_config({"expiry_seconds": expiry_seconds})
        steps = [
            {
                "step": s.step,
                "at_seconds": s.at_seconds,
                "action": s.action,
                "guard_options": list(s.guard_options),
            }
            for s in config.steps
        ]
    except Exception:
        steps = [
            {
                "step": 1,
                "at_seconds": 0,
                "action": "push_to_household_approvers",
                "guard_options": [],
            }
        ]
    return {"expiry_seconds": expiry_seconds, "steps": steps, "auto_allow_on_timeout": False}


def next_revocation_version(
    conn: Connection, society_id: uuid.UUID, actor: uuid.UUID | None
) -> int:
    """Take the next value of the society's monotonic revocation counter (row-locked: strictly increasing)."""
    value = conn.execute(
        text(
            "INSERT INTO gate_policies (id, society_id, revocation_version, updated_by)"
            " VALUES (:id, :s, 1, :by)"
            " ON CONFLICT (society_id) DO UPDATE SET revocation_version = gate_policies.revocation_version + 1"
            " RETURNING revocation_version"
        ),
        {"id": uuid7(), "s": society_id, "by": actor},
    ).scalar_one()
    return int(value)


def json_text(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), separators=(",", ":"), sort_keys=True)
