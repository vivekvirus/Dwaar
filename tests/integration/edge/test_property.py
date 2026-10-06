"""Property tests: contiguous acknowledgement and gap computation are correct for ANY arrival order (hypothesis).

REQ: EDGE-03 (highest contiguous acknowledged sequence, gaps), PRD 7.4 (device id plus monotonic device sequence).
The pure function is checked against a brute-force oracle; the database implementation is checked against the pure function through the real endpoint.
"""

from __future__ import annotations

import itertools
import random
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dwaar_api.modules.edge.contiguity import compute
from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("EDGE-03")]

seqs = st.sets(st.integers(min_value=1, max_value=60), max_size=40)


def brute_force(disposed: set[int], start: int = 0) -> tuple[int, list[tuple[int, int]]]:
    highest = start
    while highest + 1 in disposed:
        highest += 1
    top = max(disposed | {start})
    missing = [n for n in range(start + 1, top + 1) if n not in disposed]
    gaps: list[tuple[int, int]] = []
    for n in missing:
        if gaps and gaps[-1][1] == n - 1:
            gaps[-1] = (gaps[-1][0], n)
        else:
            gaps.append((n, n))
    return highest, gaps


@given(seqs, st.integers(min_value=0, max_value=10))
def test_compute_matches_a_brute_force_oracle(disposed: set[int], start: int) -> None:
    assert compute(disposed, start=start) == brute_force(disposed, start)


@given(seqs, st.randoms(use_true_random=False))
def test_the_answer_does_not_depend_on_arrival_order_or_repetition(
    disposed: set[int], rnd: random.Random
) -> None:
    shuffled = list(disposed) * 2
    rnd.shuffle(shuffled)
    assert compute(shuffled) == compute(sorted(disposed))


@given(seqs)
def test_gaps_and_received_seqs_partition_the_range_and_the_cursor_is_maximal(
    disposed: set[int],
) -> None:
    highest, gaps = compute(disposed)
    top = max(disposed, default=0)
    missing = {n for lo, hi in gaps for n in range(lo, hi + 1)}
    assert missing == set(range(1, top + 1)) - disposed  # gaps list exactly the missing seqs
    assert not missing & disposed
    assert all(lo <= hi for lo, hi in gaps) and all(
        a[1] + 1 < b[0] for a, b in itertools.pairwise(gaps)
    )  # maximal runs
    assert set(range(1, highest + 1)) <= disposed  # everything up to the cursor is held
    assert highest + 1 not in disposed  # and the cursor cannot advance further
    if gaps:
        assert gaps[0][0] == highest + 1  # the first gap starts right after the cursor
    else:
        assert highest == top


@given(seqs, seqs)
def test_the_cursor_never_moves_backwards_as_more_arrives(first: set[int], more: set[int]) -> None:
    before, _ = compute(first)
    after, _ = compute(first | more, start=before)
    assert after >= before
    assert (
        after == compute(first | more)[0]
    )  # resuming from the stored cursor equals recomputing from scratch


def test_gap_list_can_be_capped() -> None:
    highest, gaps = compute(range(2, 1000, 2), max_gaps=7)
    assert highest == 0 and len(gaps) == 7 and gaps[0] == (1, 1)


@settings(
    max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    disposed=st.sets(st.integers(min_value=1, max_value=25), min_size=1, max_size=18),
    chunk=st.integers(min_value=1, max_value=7),
    rnd=st.randoms(use_true_random=False),
    quarantine=st.sets(st.integers(min_value=1, max_value=25), max_size=3),
)
def test_the_endpoint_agrees_with_the_reference_for_any_arrival_order_and_batching(
    ew: EdgeWorld, disposed: set[int], chunk: int, rnd: random.Random, quarantine: set[int]
) -> None:
    dev = ew.edge_device()
    order = list(disposed)
    rnd.shuffle(order)
    sent: set[int] = set()
    last: dict[str, object] = {}
    for i in range(0, len(order), chunk):
        batch = []
        for n in order[i : i + chunk]:
            ev = dev.event("DeviceHealth", uuid.uuid4(), seq=n)
            if n in quarantine:
                ev["signature"] = "ed25519:" + "A" * 86  # quarantined events are still DISPOSED
            batch.append(ev)
            sent.add(n)
        r = dev.sync(batch)
        assert r.status_code == 200, r.text
        last = r.json()
        highest, gaps = compute(sent)
        assert last["highest_contiguous_seq"] == highest
        assert last["gaps"] == [list(g) for g in gaps]
    # the whole thing again, in another order: nothing changes
    again = list(disposed)
    rnd.shuffle(again)
    r = dev.sync([dev.event("DeviceHealth", uuid.uuid4(), seq=n) for n in again[:5]])
    highest, gaps = compute(sent)
    assert r.json()["highest_contiguous_seq"] == highest
    assert ew.count("edge_events", "device_id = %s", (dev.device_id,)) + ew.count(
        "edge_quarantine", "device_id = %s AND seq IS NOT NULL", (dev.device_id,)
    ) >= len(disposed)
