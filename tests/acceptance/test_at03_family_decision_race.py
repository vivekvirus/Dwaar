"""AT-03 (M0): a guest is pending and two family members decide at the same time -> ONE canonical decision, the other device
receives the result, the alerts stop.

PRD 16: "Pending guest; two family decisions race. Required outcome: One canonical decision; other device receives result;
alerts stop."  PRD 4.3 slice 2: visitor request, decision and observation across resident and guard apps, real persistence.

Dataset: the real seed. The Pawar household of A-203 (Ganesh, owner-occupier, and his two family members Rekha and Aarav, to whom
the seed delegated household approval) at Sahyadri Residency; Ramesh Shinde is the day-shift guard at the Main Gate with an active,
supervisor-approved terminal.

What is real: the HTTP API, real tokens from the local simulator (``simulation=true``), real Postgres with RLS, real concurrent
transactions (every racing phone is a thread with its own client and its own database transaction). What is not: the phones
and the notification worker (slice 4): "alerts stop" is proven at the contract the worker consumes, the ``ApprovalDecided`` /
``ApprovalEscalated`` outbox events (exactly one outcome event per request, so a worker deduplicating on the request stops).
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

import pytest

from tests.acceptance._visits_world import (
    VisitIds,
    decision_body,
    post_with_own_client,
    race,
    raise_request,
    visit_ids,
)
from tests.acceptance._world import DATASET, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-03", dataset=DATASET),
    pytest.mark.req("GATE-02", "GATE-03", "INV-07", "INV-03"),
]


def _decision_url(request_id: Any) -> str:
    return f"/v1/approval-requests/{request_id}/decision"


def _state(world: World, request_id: Any) -> tuple[str, int]:
    row = world.admin_rows(
        "SELECT state, version FROM approval_requests WHERE id = %s", (request_id,)
    )[0]
    return str(row[0]), int(row[1])


def _scene(world: World) -> tuple[VisitIds, Any, uuid.UUID]:
    ids = visit_ids(world, "mh")
    guard = world.login("mh.guard1")
    unit = world.society_ref("mh").unit("A", "203")
    return ids, guard, unit


def test_the_seed_delegated_household_approval_to_the_family(world: World) -> None:
    """Precondition of the scenario, from the seed: Rekha and Aarav are family members of A-203 who may decide."""
    rows = world.admin_rows(
        "SELECT p.display_name, m.kind, m.is_primary_approver FROM memberships m JOIN iam.persons p ON p.id = m.person_id"
        " WHERE m.unit_id = %s AND m.verification = 'verified' ORDER BY p.display_name",
        (world.society_ref("mh").unit("A", "203"),),
    )
    assert rows == [
        ("Aarav Pawar", "family", True),
        ("Ganesh Pawar", "owner", False),
        ("Rekha Pawar", "family", True),
    ]


def test_two_family_decisions_race_and_exactly_one_is_canonical(fresh_world: World) -> None:
    world = fresh_world
    ids, guard, unit = _scene(world)
    rekha, aarav, ganesh = world.login("rekha"), world.login("aarav"), world.login("ganesh")
    seen_by_guard = raise_request(world, guard, ids, unit, "Cousin Meena")
    request_id, version = seen_by_guard["id"], seen_by_guard["version"]
    assert seen_by_guard["status"] == "pending" and seen_by_guard["entry_observed"] is False
    outcomes: list[Counter[int]] = []
    for round_ in range(6):  # six independent races: the guarantee is not luck
        if round_:
            fresh = raise_request(world, guard, ids, unit, f"Cousin Meena {round_}")
            request_id, version = fresh["id"], fresh["version"]

        def phone(who: Any, decision: str, rid: Any = request_id, ver: int = version) -> Any:
            return post_with_own_client(
                world, who, _decision_url(rid), decision_body(decision, ver), ids.society
            )

        results = race([lambda: phone(rekha, "approve"), lambda: phone(aarav, "deny")])
        codes = sorted(r.status_code for r in results)
        assert codes == [200, 409], [r.text for r in results]
        winner = next(r for r in results if r.status_code == 200)
        loser = next(r for r in results if r.status_code == 409)
        # ONE canonical decision ...
        state, final_version = _state(world, request_id)
        assert (
            state == winner.json()["status"]
            and final_version == winner.json()["version"] == version + 1
        )
        valid = world.admin_rows(
            "SELECT decision, decided_by FROM approval_decisions WHERE request_id = %s AND valid",
            (request_id,),
        )
        assert len(valid) == 1
        # ... and the OTHER device receives that result in the very answer it gets
        assert loser.json()["code"] == "already_decided"
        assert loser.json()["details"]["canonical"] == winner.json()
        assert loser.json()["details"]["decided_by_role"] == "family"
        # the household's third member (the owner) opening the screen later sees the same canonical state
        late = post_with_own_client(
            world, ganesh, _decision_url(request_id), decision_body("approve", version), ids.society
        )
        assert late.status_code == 409 and late.json()["details"]["canonical"] == winner.json()
        seen = world.call(
            ganesh,
            "GET",
            f"/v1/approval-requests/{request_id}",
            headers={"X-Society-Id": str(ids.society)},
        )
        assert (
            seen.json()["status"] == winner.json()["status"]
            and seen.json()["decision"]["by_role"] == "family"
        )
        # alerts stop: exactly ONE outcome event for the request, the notification worker's cue to cancel the cascade
        events = world.admin_rows(
            "SELECT event_type, aggregate_version FROM outbox WHERE aggregate_id = %s ORDER BY aggregate_version",
            (request_id,),
        )
        assert events == [("ApprovalRequested", 1), ("ApprovalDecided", 2)]
        outcomes.append(Counter({winner.json()["version"]: 1}))
    assert len(outcomes) == 6


def test_the_guard_sees_the_canonical_outcome_and_approval_is_not_entry(fresh_world: World) -> None:
    world = fresh_world
    ids, guard, unit = _scene(world)
    rekha = world.login("rekha")
    req = raise_request(world, guard, ids, unit, "Neighbour's friend")
    ok = post_with_own_client(
        world,
        rekha,
        _decision_url(req["id"]),
        decision_body("approve", req["version"]),
        ids.society,
    )
    assert (
        ok.status_code == 200
        and ok.json()["status"] == "approved"
        and ok.json()["entry_observed"] is False
    )
    on_guard = world.call(
        guard,
        "GET",
        f"/v1/approval-requests/{req['id']}",
        params={"gate_id": str(ids.gate)},
        headers={"X-Society-Id": str(ids.society)},
    )
    assert on_guard.status_code == 200
    body = on_guard.json()
    assert (
        body["status"] == "approved"
        and body["entry_observed"] is False
        and body["permission_expires_at"]
    )
    assert (
        body["decision"]["by_role"] == "family"
    )  # the guard learns the kind of household member, not who
    assert "Rekha" not in on_guard.text and str(rekha.person_id) not in on_guard.text
    visit = world.admin_rows(
        "SELECT state, entered_at FROM visits WHERE id = %s", (req["visit_id"],)
    )[0]
    assert visit == ("authorised", None)  # permission is not physical entry (INV-07)
    assert (
        world.admin_rows(
            "SELECT count(*) FROM access_events WHERE visit_id = %s", (req["visit_id"],)
        )[0][0]
        == 0
    )


def test_a_decision_from_outside_the_household_is_not_part_of_the_race(fresh_world: World) -> None:
    """Another household's members, and a family member without the delegation, cannot win or even take part."""
    world = fresh_world
    ids, guard, unit = _scene(world)
    req = raise_request(world, guard, ids, unit, "Visitor for the Pawars")
    neighbour = world.login("neha")  # A-101
    mohini = world.login("mohini")  # household join to A-203 still pending: not a member yet
    for who in (neighbour, mohini):
        r = post_with_own_client(
            world,
            who,
            _decision_url(req["id"]),
            decision_body("approve", req["version"]),
            ids.society,
        )
        assert r.status_code == 404, (who.key, r.text)
    assert _state(world, req["id"]) == ("pending", 1)
    assert (
        world.admin_rows(
            "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (req["id"],)
        )[0][0]
        == 0
    )
