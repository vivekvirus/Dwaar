"""Parcels module configuration: operational thresholds (not statutory; INV-10 does not apply, but they stay out of the logic).

REQ: PAR-03 (pickup token lifetime), PAR-05 (reminder ages 24 h and 48 h).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass


@dataclass(frozen=True)
class ParcelsConfig:
    pickup_token_ttl: dt.timedelta = dt.timedelta(hours=24)
    reminder_ages: tuple[tuple[str, dt.timedelta], ...] = (
        ("h24", dt.timedelta(hours=24)),
        ("h48", dt.timedelta(hours=48)),
    )
    max_window: dt.timedelta = dt.timedelta(days=14)


DEFAULT_CONFIG = ParcelsConfig()
