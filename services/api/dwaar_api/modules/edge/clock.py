"""Server-side clock plausibility (EDGE-05, AT-08). Flags; never rewrites a timestamp.

REQ: EDGE-05 (clock uncertainty is recorded; automatic time-sensitive approvals are disabled above the limit), AT-08 (a device wall clock
moved backwards: time-sensitive decisions are disabled or reviewed), PRD 7.4 (clock uncertainty recorded).
"""

from __future__ import annotations

import datetime as dt
from typing import Final

FLAG_FUTURE: Final = "future"
FLAG_STALE: Final = "stale"
FLAG_UNCERTAIN: Final = "uncertain"


def assess(
    *,
    occurred_at: dt.datetime,
    received_at: dt.datetime,
    clock_uncertainty_ms: int,
    uncertainty_limit_ms: int,
    max_age_s: int,
    future_grace_ms: int,
) -> str | None:
    """The first flag that applies, or ``None``.

    ``uncertain`` wins: a device that says it does not know the time makes every other judgement of its timestamps moot.
    """
    if clock_uncertainty_ms > uncertainty_limit_ms:
        return FLAG_UNCERTAIN
    if occurred_at - received_at > dt.timedelta(
        milliseconds=clock_uncertainty_ms + future_grace_ms
    ):
        return FLAG_FUTURE
    if received_at - occurred_at > dt.timedelta(seconds=max_age_s):
        return FLAG_STALE
    return None
