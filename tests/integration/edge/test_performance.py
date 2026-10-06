"""500-event batch performance sanity (NFR-09/NFR-10 shaped). Numbers are RECORDED, not certified.

REQ: EDGE-03, NFR-10 (sync recovery: the shape of the test; the 60,000-events-in-10-minutes target needs the 5 Mbps field set-up and is NOT
claimed), NFR-08 (ordinary API server time).

What is measured: wall time of ``POST /v1/edge/sync/batches`` through the real ASGI stack and a real PostgreSQL on this machine (one
process, in-process test client, empty database, no network, no other load). It says what THIS code does here; it is not an SLO, not a
capacity statement and not a substitute for the field measurement. The numbers go to the test output (``pytest -s``) and the file named
by ``DWAAR_PERF_REPORT`` when set.
"""

from __future__ import annotations

import json
import os
import statistics
import time
import uuid
from typing import Any

import pytest

from tests.integration.edge._support import EdgeClient, EdgeWorld

pytestmark = [pytest.mark.req("EDGE-03", "NFR-10"), pytest.mark.slow]

# A very loose bound: a regression guard (a quadratic loop, a missing index), not a claim. The measured numbers are far below it.
LOOSE_BOUND_S = 60.0
RESULTS: dict[str, Any] = {}


def _visits(ew: EdgeWorld, n: int) -> list[uuid.UUID]:
    """n authorised visits inserted directly (the approval flow itself is tested elsewhere; this only needs rows to move)."""
    ids = [uuid.uuid4() for _ in range(n)]
    ew.sql(
        "INSERT INTO visits (id, society_id, kind, state, visitor_alias, gate_id, authorisation_source, authorised_at, authorised_until,"
        " created_by) SELECT i, %s, 'guest', 'authorised', 'Perf Visitor', %s, 'household_approval', now(), now() + interval '2 hours', %s"
        " FROM unnest(%s::uuid[]) AS i",
        (ew.soc.id, ew.gate_id, ew.guard.id, ids),
    )
    return ids


def _timed(dev: EdgeClient, events: list[dict[str, Any]]) -> tuple[float, int, dict[str, Any]]:
    body = json.dumps({"device_id": str(dev.device_id), "events": events}).encode()
    started = time.perf_counter()
    r = dev.sync_raw(body)
    elapsed = time.perf_counter() - started
    assert r.status_code == 200, r.text
    return elapsed, len(body), r.json()


def _record(name: str, elapsed: float, size: int, events: int) -> None:
    RESULTS[name] = {
        "events": events,
        "seconds": round(elapsed, 3),
        "events_per_second": round(events / elapsed, 1),
        "bytes": size,
    }
    print(
        f"[edge-perf] {name}: {events} events in {elapsed:.2f}s = {events / elapsed:.0f} events/s, body {size / 1024:.0f} KiB"
    )  # noqa: T201


def test_500_entries_for_authorised_visits(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    visits = _visits(ew, 500)
    elapsed, size, body = _timed(dev, [dev.entry(v) for v in visits])
    _record("entries_for_authorised_visits_500", elapsed, size, 500)
    assert size <= 1_048_576 and elapsed < LOOSE_BOUND_S
    assert {o["status"] for o in body["outcomes"]} == {"accepted"} and body[
        "highest_contiguous_seq"
    ] == 500
    assert (
        ew.count("visits", "state = 'inside'") == 500
        and ew.count("audit_log", "operation = 'edge.entry_observed'") == 500
    )


def test_500_events_that_are_only_recorded(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    elapsed, size, body = _timed(
        dev,
        [
            dev.event("DeviceHealth", uuid.uuid4(), payload={"disk_pct": 41, "temp_c": 52})
            for _ in range(500)
        ],
    )
    _record("recorded_only_500", elapsed, size, 500)
    assert elapsed < LOOSE_BOUND_S and body["highest_contiguous_seq"] == 500


def test_500_entries_that_are_flagged_for_review_is_the_heaviest_path(ew: EdgeWorld) -> None:
    """Every event writes an observation, a ledger row, an exception, audit and outbox rows: the slowest realistic path."""
    dev = ew.edge_device()
    elapsed, size, body = _timed(
        dev, [dev.entry(uuid.uuid4(), payload={"decision_source": "ivr"}) for _ in range(500)]
    )
    _record("unauthorised_entries_500", elapsed, size, 500)
    assert elapsed < LOOSE_BOUND_S
    assert {o["status"] for o in body["outcomes"]} == {"rejected_transition"} and ew.count(
        "exceptions"
    ) == 500


def test_resending_a_full_batch_is_cheap_and_four_batches_in_a_row(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    batches = [[dev.event("DeviceHealth", uuid.uuid4()) for _ in range(500)] for _ in range(4)]
    times = [_timed(dev, b)[0] for b in batches]
    _record("recorded_only_4x500_mean_batch", statistics.mean(times), 0, 500)
    resend, _, body = _timed(dev, batches[0])
    _record("resend_of_acknowledged_batch_500", resend, 0, 500)
    assert {o["status"] for o in body["outcomes"]} == {"duplicate"}
    assert resend < LOOSE_BOUND_S and body["highest_contiguous_seq"] == 2000
    # a naive extrapolation, labelled as such: the NFR-10 target (60,000 events within 10 minutes) is 100 events per second
    RESULTS["extrapolation_note"] = (
        "60,000 events = 120 batches of 500; NOT a measurement of NFR-10 (no 5 Mbps uplink, no field device)"
    )


def test_zz_write_the_report() -> None:
    path = os.environ.get("DWAAR_PERF_REPORT")
    if path and RESULTS:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"note": "local synthetic measurement, not a certification", "results": RESULTS},
                fh,
                indent=2,
            )
