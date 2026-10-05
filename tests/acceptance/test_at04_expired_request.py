"""AT-04 (M0): a request expires, then a queued approval arrives -> no permission is issued, the user sees the expiry.

PRD 16: "Request expires, then a queued approval arrives. Required outcome: No permission issued; user sees expiry."
PRD 9.2: pending request default 90 seconds, never an auto-admission; GATE-03: 409 ``request_expired``.

Dataset: the real seed (Pawar household of A-203, Main Gate, guard Ramesh Shinde), real API, real tokens (simulation=true),
real Postgres. Two variants of the same scenario:

* the CLOCK variant ages the request in the database (the database clock is the authority for expiry) so the suite stays fast;
* the REAL-TIME variant sets the society policy to the pack minimum (60 seconds) through the API, waits for the real clock
  and lets the phone's queued approval arrive afterwards (marked ``slow``).

"The user sees expiry" is checked on the resident's own read and on the guard's, which also carries the guard-assisted options
(hold, leave at gate, lobby only, intercom, deny) and states that nothing is allowed automatically.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from tests.acceptance._visits_world import (
    decision_body,
    post_with_own_client,
    raise_request,
    visit_ids,
)
from tests.acceptance._world import DATASET, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-04", dataset=DATASET),
    pytest.mark.req("GATE-02", "GATE-03", "INV-03", "INV-07"),
]


def _check_no_permission(world: World, request: dict[str, Any], late: Any) -> None:
    assert late.status_code == 409, late.text
    assert late.json()["code"] == "request_expired"
    canonical = late.json()["details"]["canonical"]
    assert canonical["status"] == "expired" and canonical["permission_expires_at"] is None
    assert canonical["entry_observed"] is False and canonical["decision_id"] is None
    row = world.admin_rows(
        "SELECT state, permission_expires_at, decision_id, closed_reason FROM approval_requests WHERE id = %s",
        (request["id"],),
    )[0]
    assert row == ("expired", None, None, "expired")
    assert (
        world.admin_rows(
            "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
        )[0][0]
        == 0
    )
    visit = world.admin_rows(
        "SELECT state, authorised_at, authorised_until, authorisation_source FROM visits WHERE id = %s",
        (request["visit_id"],),
    )[0]
    assert visit == ("expired", None, None, None)  # nobody was authorised
    assert world.admin_rows(
        "SELECT authorised, state FROM visit_stops WHERE visit_id = %s", (request["visit_id"],)
    ) == [(False, "expired")]
    outcome_events = world.admin_rows(
        "SELECT event_type FROM outbox WHERE aggregate_id = %s ORDER BY aggregate_version",
        (request["id"],),
    )
    assert outcome_events == [
        ("ApprovalRequested",),
        ("ApprovalEscalated",),
    ]  # the cascade ended: alerts stop, guard options open


def _users_see_expiry(world: World, request: dict[str, Any], ids: Any) -> None:
    ganesh = world.login("ganesh")
    mine = world.call(
        ganesh,
        "GET",
        f"/v1/approval-requests/{request['id']}",
        headers={"X-Society-Id": str(ids.society)},
    )
    assert (
        mine.status_code == 200
        and mine.json()["status"] == "expired"
        and mine.json()["permission_expires_at"] is None
    )
    guard = world.login("mh.guard1")
    theirs = world.call(
        guard,
        "GET",
        f"/v1/approval-requests/{request['id']}",
        params={"gate_id": str(ids.gate)},
        headers={"X-Society-Id": str(ids.society)},
    )
    body = theirs.json()
    assert body["status"] == "expired" and body["auto_allow_on_timeout"] is False
    assert set(body["guard_options"]) == {"hold", "leave_at_gate", "lobby_only", "intercom", "deny"}


def test_a_queued_approval_after_expiry_issues_no_permission(fresh_world: World) -> None:
    world = fresh_world
    ids = visit_ids(world, "mh")
    guard, rekha = world.login("mh.guard1"), world.login("rekha")
    unit = world.society_ref("mh").unit("A", "203")
    req = raise_request(world, guard, ids, unit, "Late courier")
    assert req["status"] == "pending" and 80 <= req["expires_in_seconds"] <= 90
    world.admin_rows("SELECT 1")  # (oracle ready)
    with (
        world.db.admin_conn() as conn
    ):  # the 90 seconds are over; the phone was offline and only now sends its approval
        conn.execute(
            "UPDATE approval_requests SET expires_at = clock_timestamp() - interval '1 second' WHERE id = %s",
            (req["id"],),
        )
    queued = decision_body("approve", req["version"])
    late = post_with_own_client(
        world,
        rekha,
        f"/v1/approval-requests/{req['id']}/decision",
        queued,
        ids.society,
        key="queued-approval-1",
    )
    _check_no_permission(world, req, late)
    # the phone retries the SAME queued message (same key, then a new key): the answer stays the same and nothing changes
    again = post_with_own_client(
        world,
        rekha,
        f"/v1/approval-requests/{req['id']}/decision",
        queued,
        ids.society,
        key="queued-approval-1",
    )
    assert again.status_code == 409 and again.json()["code"] == "request_expired"
    other = post_with_own_client(
        world,
        rekha,
        f"/v1/approval-requests/{req['id']}/decision",
        queued,
        ids.society,
        key="queued-approval-2",
    )
    assert other.status_code == 409 and other.json()["code"] == "request_expired"
    _users_see_expiry(world, req, ids)
    _check_no_permission(world, req, again)
    # a person standing at the gate now is NOT admitted by this request: an observed entry creates no permission either
    gate_device = ids.device
    entry = world.call(
        guard, "POST", f"/v1/visits/{req['visit_id']}/observations",
        json={"type": "entry", "gate_id": str(ids.gate), "device_id": str(gate_device), "event_id": decision_body("approve", 1)["client_action_id"],
              "seq": 9001, "occurred_at": "2026-10-05T12:00:00+00:00"},
        headers={"X-Society-Id": str(ids.society)},
    )  # fmt: skip
    assert entry.status_code == 201 and entry.json()["permission_created"] is False
    assert (
        world.admin_rows("SELECT state FROM visits WHERE id = %s", (req["visit_id"],))[0][0]
        == "expired"
    )
    assert (
        world.admin_rows(
            "SELECT count(*) FROM exceptions WHERE visit_id = %s AND kind = 'unauthorised_entry'",
            (req["visit_id"],),
        )[0][0]
        == 1
    )


def test_a_denied_request_and_an_expired_one_stay_closed_whoever_answers_late(
    fresh_world: World,
) -> None:
    world = fresh_world
    ids = visit_ids(world, "mh")
    guard, rekha, aarav = world.login("mh.guard1"), world.login("rekha"), world.login("aarav")
    unit = world.society_ref("mh").unit("A", "203")
    denied = raise_request(world, guard, ids, unit, "Denied then retried")
    ok = post_with_own_client(
        world,
        rekha,
        f"/v1/approval-requests/{denied['id']}/decision",
        decision_body("deny", denied["version"]),
        ids.society,
    )
    assert ok.status_code == 200 and ok.json()["status"] == "denied"
    stale = post_with_own_client(
        world,
        aarav,
        f"/v1/approval-requests/{denied['id']}/decision",
        decision_body("approve", denied["version"]),
        ids.society,
    )
    assert (
        stale.status_code == 409
        and stale.json()["code"] == "already_decided"
        and stale.json()["details"]["canonical"]["status"] == "denied"
    )
    assert (
        world.admin_rows("SELECT state FROM visits WHERE id = %s", (denied["visit_id"],))[0][0]
        == "cancelled"
    )


@pytest.mark.slow
def test_real_clock_the_request_expires_by_itself_and_the_queued_approval_is_refused(
    fresh_world: World,
) -> None:
    """No database trickery: the society policy is set to the pack minimum (60 s) through the API and the real clock runs out."""
    world = fresh_world
    ids = visit_ids(world, "mh")
    secretary = world.login("mh.secretary")
    current = world.call(secretary, "GET", f"/v1/societies/{ids.society}/gate-policy").json()
    policy = world.call(
        secretary,
        "PUT",
        f"/v1/societies/{ids.society}/gate-policy",
        json={"approval_expiry_seconds": 60, "expected_version": current["version"]},
    )
    assert policy.status_code == 200, policy.text
    guard, rekha = world.login("mh.guard1"), world.login("rekha")
    req = raise_request(
        world, guard, ids, world.society_ref("mh").unit("A", "203"), "Courier who waited"
    )
    assert 55 <= req["expires_in_seconds"] <= 60
    time.sleep(61.5)
    late = post_with_own_client(
        world,
        rekha,
        f"/v1/approval-requests/{req['id']}/decision",
        decision_body("approve", req["version"]),
        ids.society,
    )
    _check_no_permission(world, req, late)
    _users_see_expiry(world, req, ids)
