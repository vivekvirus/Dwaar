"""Shifts module configuration: operational thresholds (not statutory).

REQ: SHIFT-01 (how long a handover may wait for the next guard before it escalates), Appendix C (supervisor override: until shift end or
earlier), SHIFT-02 (the open-items list is complete up to a per-kind cap, and says so when it is not).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ShiftsConfig:
    escalate_after_minutes: int = 15
    default_override_minutes: int = 240
    max_items_per_kind: int = 100
    policy_stale_hours: int = 72  # Appendix C: policy age that triggers guard-assisted verification


DEFAULT_CONFIG = ShiftsConfig()
