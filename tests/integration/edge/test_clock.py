"""Clock handling on the server side (EDGE-05, AT-08): record the uncertainty, flag the implausible, never rewrite a timestamp.

REQ: EDGE-05, AT-08, PRD 7.4 (clock uncertainty recorded), EDGE-07 (exception queue).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from dwaar_api.modules.edge import clock
from tests.integration.edge._support import EdgeClient, EdgeWorld, now

pytestmark = [pytest.mark.req("EDGE-05")]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device()


# ------------------------------------------------------------------------------------------ pure rules
def _assess(occurred: timedelta, uncertainty: int = 0) -> str | None:
    received = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
    return clock.assess(
        occurred_at=received + occurred, received_at=received, clock_uncertainty_ms=uncertainty,
        uncertainty_limit_ms=60_000, max_age_s=72 * 3600, future_grace_ms=5_000,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("occurred", "uncertainty", "flag"),
    [
        (timedelta(seconds=-5), 0, None),
        (timedelta(hours=-71), 0, None),
        (timedelta(hours=-72), 0, None),
        (timedelta(hours=-72, seconds=-1), 0, "stale"),
        (timedelta(seconds=4), 0, None),
        (timedelta(seconds=6), 0, "future"),
        (timedelta(seconds=30), 25_000, None),  # inside stated uncertainty plus the grace
        (timedelta(seconds=31), 25_000, "future"),
        (timedelta(hours=-80), 61_000, "uncertain"),  # uncertain wins
        (timedelta(0), 60_000, None),
        (timedelta(0), 60_001, "uncertain"),
    ],
)
def test_plausibility_rules(occurred: timedelta, uncertainty: int, flag: str | None) -> None:
    assert _assess(occurred, uncertainty) == flag


# ------------------------------------------------------------------------------------------ over the wire
def test_future_event_is_flagged_and_its_timestamp_is_stored_exactly_as_sent(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    stated = now() + timedelta(hours=3)
    ev = dev.entry(visit, occurred_at=stated, clock_uncertainty_ms=120)
    out = dev.sync([ev]).json()["outcomes"][0]
    assert out["clock_flag"] == "future" and out["exception_id"]
    stored = ew.rows("SELECT occurred_at, clock_uncertainty_ms FROM access_events")[0]
    assert stored[0] == datetime.fromisoformat(
        ev["occurred_at"].replace("Z", "+00:00")
    )  # never "fixed"
    assert stored[1] == 120
    ledger = ew.rows("SELECT clock_flag, occurred_at, clock_uncertainty_ms FROM edge_events")[0]
    assert ledger[0] == "future" and ledger[1] == stored[0]
    assert len(ew.exceptions("clock_implausible")) == 1


def test_stale_event_older_than_the_policy_age_limit_is_flagged(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ev = dev.event("DeviceHealth", uuid.uuid4(), occurred_at=now() - timedelta(hours=80))
    out = dev.sync([ev]).json()["outcomes"][0]
    assert out["status"] == "accepted" and out["clock_flag"] == "stale"
    assert ew.rows("SELECT clock_flag FROM edge_events")[0][0] == "stale"
    assert len(ew.exceptions("clock_implausible")) == 1


def test_a_72_hour_buffer_is_not_flagged(ew: EdgeWorld, dev: EdgeClient) -> None:
    ev = dev.event(
        "DeviceHealth", uuid.uuid4(), occurred_at=now() - timedelta(hours=71, minutes=50)
    )
    assert "clock_flag" not in dev.sync([ev]).json()["outcomes"][0]
    assert ew.exceptions("clock_implausible") == []


def test_uncertain_clock_entry_is_recorded_but_the_authorisation_is_not_applied(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    """AT-08: a device clock that is not trusted must not turn a permission into an entry automatically: a human reviews it."""
    visit = ew.authorised_visit()
    out = dev.sync([dev.entry(visit, clock_uncertainty_ms=90_000)]).json()["outcomes"][0]
    assert out["status"] == "rejected_transition" and out["reason"] == "clock_uncertain_review"
    assert out["access_event_recorded"] is True and out["clock_flag"] == "uncertain"
    assert ew.visit_state(visit) == "authorised" and ew.count("access_events") == 1
    assert ew.rows("SELECT clock_uncertainty_ms FROM access_events")[0][0] == 90_000
    flagged = ew.exceptions("clock_implausible")
    assert len(flagged) == 1 and flagged[0][2] == visit


def test_exit_with_an_uncertain_clock_still_applies_essential_egress(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    assert dev.sync([dev.entry(visit)]).json()["outcomes"][0]["status"] == "accepted"
    out = dev.sync([dev.exit(visit, clock_uncertainty_ms=300_000)]).json()["outcomes"][0]
    assert out["status"] == "accepted" and out["clock_flag"] == "uncertain"
    assert ew.visit_state(visit) == "exited"


def test_a_bad_clock_does_not_flood_the_exception_queue(ew: EdgeWorld, dev: EdgeClient) -> None:
    events = [
        dev.event("DeviceHealth", uuid.uuid4(), clock_uncertainty_ms=500_000) for _ in range(25)
    ]
    r = dev.sync(events).json()
    assert [o["status"] for o in r["outcomes"]] == ["accepted"] * 25
    assert all(o["clock_flag"] == "uncertain" for o in r["outcomes"])
    assert len(ew.exceptions("clock_implausible")) == 1  # one open exception per device and flag
    assert ew.count("edge_events", "clock_flag = 'uncertain'") == 25


def test_clock_going_backwards_is_visible_not_repaired(ew: EdgeWorld, dev: EdgeClient) -> None:
    """AT-08 server view: after a restart with a wall clock moved back a day, the device reports a large uncertainty and old timestamps."""
    first = dev.event("DeviceHealth", uuid.uuid4(), occurred_at=now() - timedelta(seconds=10))
    back = dev.event(
        "DeviceHealth",
        uuid.uuid4(),
        occurred_at=now() - timedelta(days=1),
        clock_uncertainty_ms=86_400_000,
    )
    r = dev.sync([first, back]).json()
    assert [o.get("clock_flag") for o in r["outcomes"]] == [None, "uncertain"]
    rows = ew.rows("SELECT seq, occurred_at, clock_uncertainty_ms FROM edge_events ORDER BY seq")
    assert (
        rows[1][1] < rows[0][1] and rows[1][2] == 86_400_000
    )  # the backwards timestamp is kept exactly as stated
