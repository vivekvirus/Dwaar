"""Pure acknowledgement arithmetic: highest contiguous sequence and gaps, for ANY arrival order.

REQ: EDGE-03 (highest contiguous acknowledged sequence, gaps), PRD 7.4 (device id plus monotonic device sequence), PRD 9.3 recovery
("inspect sequence gaps"). The database implementation in ``sync.py`` must agree with this reference function (property-tested).

Device sequences start at 1. ``start`` is the cursor already acknowledged (0 when nothing is). A seq is *disposed* once the cloud holds
it durably: in the processed ledger or in quarantine.
"""

from __future__ import annotations

from collections.abc import Iterable


def compute(
    disposed: Iterable[int], *, start: int = 0, max_gaps: int | None = None
) -> tuple[int, list[tuple[int, int]]]:
    """``(highest_contiguous, gaps)`` where gaps are inclusive ``(from, to)`` ranges of missing seqs below the highest disposed seq."""
    above = sorted({s for s in disposed if s > start})
    highest = start
    for seq in above:
        if seq == highest + 1:
            highest = seq
        else:
            break
    gaps: list[tuple[int, int]] = []
    previous = start
    for seq in above:
        if seq - previous > 1:
            gaps.append((previous + 1, seq - 1))
        previous = seq
    if max_gaps is not None:
        gaps = gaps[:max_gaps]
    return highest, gaps
