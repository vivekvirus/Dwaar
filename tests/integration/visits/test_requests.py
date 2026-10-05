"""Unannounced visitor: the approval REQUEST (GATE-02), its policy, destination helpers, masking and multi-stop visits (GATE-04).

REQ: GATE-02, GATE-04, GATE-13, INV-03, INV-07.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from tests.integration.visits._support import VW

pytestmark = [pytest.mark.req("GATE-02")]

PHONE = "+919999900777"


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def test_request_is_pending_and_admits_nobody(gate: VW) -> None:
    h = gate.household("A-101")
    body = gate.request_body(h.unit, visitor_phone=PHONE)
    r = gate.call(gate.guard, "POST", "/v1/approval-requests", json=body)
    assert r.status_code == 201, r.text
    req = r.json()
    assert req["status"] == "pending" and req["version"] == 1
    assert req["entry_observed"] is False and req["permission_expires_at"] is None
    assert req["auto_allow_on_timeout"] is False  # INV-03
    assert 80 <= req["expires_in_seconds"] <= 90  # the pack default (PRD 9.2: 90 seconds)
    assert req["visitor"]["alias"] == "Test Visitor" and req["unit_label"] == "A-101"
    state = gate.rows(
        "SELECT state, consent_recorded, notice_version, notice_language FROM visits"
    )[0]
    assert state == ("requested", True, "visitor-notice-v1", "en")
    stops = gate.rows("SELECT authorised, state, seq FROM visit_stops")
    assert stops == [(False, "pending", 1)]
    # PRD 12.4: the mutation, its audit row and its outbox event
    events = gate.outbox("ApprovalRequested", req["id"])
    assert len(events) == 1 and events[0]["version"] == 1
    assert (
        events[0]["payload"]["unit_id"] == str(h.unit)
        and events[0]["payload"]["expiry_seconds"] == 90
    )
    audit = gate.audit("approval.request")
    assert len(audit) == 1 and audit[0][1] == gate.guard.id and audit[0][2] == "guard"


def test_visitor_notice_and_consent_are_required(gate: VW) -> None:
    h = gate.household("A-101")
    refused = gate.request_body(h.unit, notice=gate.notice(consent=False))
    r = gate.call(gate.guard, "POST", "/v1/approval-requests", json=refused)
    assert r.status_code == 422 and r.json()["details"]["reason"] == "visitor_consent_required"
    r = gate.call(
        gate.guard,
        "POST",
        "/v1/approval-requests",
        json=gate.request_body(h.unit, destination_confirmed=False),
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "destination_not_confirmed"
    assert (
        gate.rows("SELECT count(*) FROM visits")[0][0] == 0
        and gate.rows("SELECT count(*) FROM approval_requests")[0][0] == 0
    )


def test_a_unit_nobody_can_answer_for_gets_no_request(gate: VW) -> None:
    empty = gate.unit("A-103")
    r = gate.call(gate.guard, "POST", "/v1/approval-requests", json=gate.request_body(empty))
    assert r.status_code == 422 and r.json()["details"]["reason"] == "no_household_approver"
    # a household that only has a NON-RESIDENT owner and an undelegated family member cannot answer either
    unit = gate.unit("B-201")
    gate.resident(unit, "owner", lives=False)
    gate.resident(unit, "family")
    r = gate.call(gate.guard, "POST", "/v1/approval-requests", json=gate.request_body(unit))
    assert r.status_code == 422 and r.json()["details"]["reason"] == "no_household_approver"


def test_only_the_gate_staff_raise_requests_and_only_in_their_society(gate: VW) -> None:
    h = gate.household("A-101", tenant=True)
    body = gate.request_body(h.unit)
    for who in (h.owner, h.tenant, h.family, gate.secretary):
        r = gate.call(who, "POST", "/v1/approval-requests", json=body)
        assert r.status_code == 403, (who.phone, r.text)
    stranger = gate.person()
    assert gate.call(stranger, "POST", "/v1/approval-requests", json=body).status_code == 404
    assert (
        gate.call(
            gate.guard, "POST", "/v1/approval-requests", json=body, society=uuid.uuid4()
        ).status_code
        == 404
    )
    unknown_unit = gate.request_body(uuid.uuid4())
    assert (
        gate.call(gate.guard, "POST", "/v1/approval-requests", json=unknown_unit).status_code == 404
    )
    other = gate.request_body(h.unit, gate_id=str(uuid.uuid4()))
    r = gate.call(gate.guard, "POST", "/v1/approval-requests", json=other)
    assert r.status_code == 400 and r.json()["code"] == "invalid_schema"
    smuggle = gate.call(
        gate.guard, "POST", "/v1/approval-requests", json={**body, "society_id": str(uuid.uuid4())}
    )
    assert smuggle.status_code == 400  # a society in a body is never read


def test_creation_needs_an_idempotency_key_and_replays_it(gate: VW) -> None:
    h = gate.household("A-101")
    body = gate.request_body(h.unit)
    missing = gate.client.post(
        "/v1/approval-requests",
        json=body,
        headers={**gate.guard.headers, "X-Society-Id": str(gate.soc.id)},
    )
    assert missing.status_code == 400 and missing.json()["code"] == "invalid_schema"
    first = gate.call(gate.guard, "POST", "/v1/approval-requests", json=body, key="create-key-0001")
    again = gate.call(gate.guard, "POST", "/v1/approval-requests", json=body, key="create-key-0001")
    assert first.status_code == again.status_code == 201
    assert (
        again.headers["Idempotent-Replayed"] == "true" and first.json()["id"] == again.json()["id"]
    )
    assert gate.rows("SELECT count(*) FROM approval_requests")[0][0] == 1
    changed = gate.call(
        gate.guard,
        "POST",
        "/v1/approval-requests",
        json={**body, "visitor_alias": "Someone Else"},
        key="create-key-0001",
    )
    assert changed.status_code == 409 and changed.json()["code"] == "duplicate_payload_mismatch"


def test_expiry_comes_from_the_society_policy_within_the_pack_bounds(gate: VW) -> None:
    h = gate.household("A-101")
    policy = gate.call(gate.secretary, "GET", gate.s("gate-policy")).json()
    assert policy["approval_expiry_seconds"] == 90 and policy["auto_allow_on_timeout"] is False
    too_short = gate.call(
        gate.secretary, "PUT", gate.s("gate-policy"), json={"approval_expiry_seconds": 30}
    )
    assert (
        too_short.status_code == 422
        and too_short.json()["details"]["reason"] == "outside_approved_bounds"
    )
    too_long = gate.call(
        gate.secretary, "PUT", gate.s("gate-policy"), json={"approval_expiry_seconds": 600}
    )
    assert too_long.status_code == 422
    stale = gate.call(
        gate.secretary,
        "PUT",
        gate.s("gate-policy"),
        json={"approval_expiry_seconds": 120, "expected_version": 5},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    ok = gate.call(
        gate.secretary, "PUT", gate.s("gate-policy"), json={"approval_expiry_seconds": 120}
    )
    assert (
        ok.status_code == 200
        and ok.json()["approval_expiry_seconds"] == 120
        and ok.json()["version"] == 1
    )
    req = gate.raise_request(h.unit)
    assert 110 <= req["expires_in_seconds"] <= 120
    cascade = gate.rows("SELECT cascade FROM approval_requests")[0][0]
    assert cascade["auto_allow_on_timeout"] is False and cascade["expiry_seconds"] == 120
    assert cascade["steps"][-1]["action"] == "expire_with_guard_assisted_options"
    for who in (gate.guard, h.owner):  # only the secretary configures
        assert gate.call(
            who, "PUT", gate.s("gate-policy"), json={"approval_expiry_seconds": 100}
        ).status_code in (403, 404)


def test_destination_hint_is_a_masked_surname_and_nothing_else(gate: VW) -> None:
    h = gate.household("A-101")
    gate.sql("UPDATE iam.persons SET display_name = 'Rekha Pawar' WHERE id = %s", (h.owner.id,))
    r = gate.call(gate.guard, "GET", gate.s(f"units/{h.unit}/destination-hint"))
    assert r.status_code == 200, r.text
    hint = r.json()
    assert (
        hint["surname_hint"] == "P****"
        and hint["unit_label"] == "A-101"
        and hint["can_request"] is True
    )
    raw = json.dumps(hint)
    assert "Rekha" not in raw and "Pawar" not in raw and str(h.owner.id) not in raw
    assert (
        gate.call(gate.guard, "GET", gate.s(f"units/{gate.unit('A-103')}/destination-hint")).json()[
            "can_request"
        ]
        is False
    )
    assert gate.call(h.owner, "GET", gate.s(f"units/{h.unit}/destination-hint")).status_code in (
        403,
        404,
    )
    assert (
        gate.call(gate.guard, "GET", gate.s(f"units/{uuid.uuid4()}/destination-hint")).status_code
        == 404
    )


def test_recent_destinations_are_distinct_and_newest_first(gate: VW) -> None:
    a, b = gate.household("A-101"), gate.household("A-102")
    gate.raise_request(a.unit)
    gate.raise_request(b.unit)
    gate.raise_request(a.unit)
    items = gate.call(
        gate.guard, "GET", gate.s(f"gates/{gate.gate_id}/recent-destinations")
    ).json()["items"]
    assert [i["unit_label"] for i in items] == ["A-101", "A-102"]


def test_guard_views_are_masked_and_scoped_to_the_current_gate(gate: VW) -> None:
    h = gate.household("A-101")
    gate.sql("UPDATE iam.persons SET display_name = 'Rekha Pawar' WHERE id = %s", (h.owner.id,))
    req = gate.raise_request(h.unit, visitor_phone=PHONE)
    other_gate = gate.make_gate("Back gate", "pedestrian")
    seen = gate.call(
        gate.guard,
        "GET",
        f"/v1/approval-requests/{req['id']}",
        params={"gate_id": str(gate.gate_id)},
    )
    assert seen.status_code == 200
    wrong_gate = gate.call(
        gate.guard, "GET", f"/v1/approval-requests/{req['id']}", params={"gate_id": str(other_gate)}
    )
    assert wrong_gate.status_code == 404  # another gate's request is not the current gate's
    assert (
        gate.call(gate.guard, "GET", f"/v1/approval-requests/{req['id']}").status_code == 400
    )  # gate required
    listing = gate.call(
        gate.guard, "GET", gate.s("approval-requests"), params={"gate_id": str(gate.gate_id)}
    )
    assert [i["id"] for i in listing.json()["items"]] == [req["id"]]
    assert (
        gate.call(
            gate.guard, "GET", gate.s("approval-requests"), params={"gate_id": str(other_gate)}
        ).json()["items"]
        == []
    )
    assert gate.call(gate.guard, "GET", gate.s("approval-requests")).status_code == 400
    blob = seen.text + listing.text
    for secret in (str(h.owner.id), "Rekha", "Pawar", "9999900777", PHONE):
        assert secret not in blob  # GATE-13: no resident identity, no number


def test_household_sees_only_its_own_requests_and_pages_them(gate: VW) -> None:
    a, b = gate.household("A-101"), gate.household("A-102")
    first = gate.raise_request(a.unit)
    second = gate.raise_request(a.unit, visitor_alias="Second")
    theirs = gate.raise_request(b.unit)
    mine = gate.call(a.owner, "GET", gate.s("approval-requests"), params={"limit": 1})
    assert mine.status_code == 200 and len(mine.json()["items"]) == 1 and mine.json()["next_cursor"]
    rest = gate.call(
        a.owner,
        "GET",
        gate.s("approval-requests"),
        params={"limit": 1, "cursor": mine.json()["next_cursor"]},
    )
    ids = {mine.json()["items"][0]["id"], rest.json()["items"][0]["id"]}
    assert ids == {first["id"], second["id"]} and theirs["id"] not in ids
    assert (
        gate.call(
            a.owner, "GET", gate.s("approval-requests"), params={"unit_id": str(b.unit)}
        ).status_code
        == 404
    )
    assert gate.call(a.owner, "GET", f"/v1/approval-requests/{theirs['id']}").status_code == 404
    assert gate.call(b.owner, "GET", f"/v1/approval-requests/{theirs['id']}").status_code == 200
    tampered = gate.call(
        a.owner,
        "GET",
        gate.s("approval-requests"),
        params={"limit": 1, "cursor": "x" + mine.json()["next_cursor"]},
    )
    assert tampered.status_code == 400
    assert (
        gate.call(a.owner, "GET", gate.s("approval-requests"), params={"colour": "red"}).status_code
        == 400
    )


# ------------------------------------------------------------------------------------------ multi-destination (GATE-04)
@pytest.mark.req("GATE-04")
def test_a_second_stop_is_a_new_request_and_approving_one_stop_authorises_only_that_stop(
    gate: VW,
) -> None:
    a, b = gate.household("A-101"), gate.household("A-102")
    first = gate.raise_request(a.unit, kind="delivery")
    visit_id = first["visit_id"]
    visit = gate.call(
        gate.guard, "GET", f"/v1/visits/{visit_id}", params={"gate_id": str(gate.gate_id)}
    ).json()
    added = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{visit_id}/stops",
        json={
            "unit_id": str(b.unit),
            "destination_confirmed": True,
            "expected_version": visit["version"],
        },
    )
    assert added.status_code == 201, added.text
    second = added.json()
    assert (
        second["status"] == "pending"
        and second["id"] != first["id"]
        and second["visit_id"] == visit_id
    )
    assert len(gate.outbox("ApprovalRequested")) == 2  # a NEW request event for the new stop
    # approve the FIRST stop only
    assert gate.decide(a.owner, first).status_code == 200
    stops = gate.rows("SELECT unit_id, authorised, state, seq FROM visit_stops ORDER BY seq")
    assert stops == [(a.unit, True, "authorised", 1), (b.unit, False, "pending", 2)]
    state = gate.rows("SELECT state FROM visits")[0][0]
    assert state == "authorised"
    # the second household still has a pending request that nobody has answered
    assert (
        gate.rows("SELECT state FROM approval_requests WHERE id = %s", (second["id"],))[0][0]
        == "pending"
    )
    # each household sees only its own stop of the multi-destination visit
    mine = gate.call(a.owner, "GET", f"/v1/visits/{visit_id}").json()
    assert [s["unit_label"] for s in mine["stops"]] == ["A-101"]
    theirs = gate.call(b.owner, "GET", f"/v1/visits/{visit_id}").json()
    assert [s["unit_label"] for s in theirs["stops"]] == ["A-102"] and theirs["stops"][0][
        "authorised"
    ] is False
    # a denial of the second stop does not undo the first authorisation
    assert gate.decide(b.owner, second, "deny").status_code == 200
    assert gate.rows("SELECT state FROM visits")[0][0] == "authorised"
    assert gate.rows("SELECT authorised FROM visit_stops ORDER BY seq") == [(True,), (False,)]


@pytest.mark.req("GATE-04")
def test_stop_rules(gate: VW) -> None:
    a, b = gate.household("A-101"), gate.household("A-102")
    first = gate.raise_request(a.unit)
    visit = gate.call(
        gate.guard, "GET", f"/v1/visits/{first['visit_id']}", params={"gate_id": str(gate.gate_id)}
    ).json()

    def add(unit: uuid.UUID, version: int, **extra: Any) -> Any:
        return gate.call(
            gate.guard,
            "POST",
            f"/v1/visits/{first['visit_id']}/stops",
            json={
                "unit_id": str(unit),
                "destination_confirmed": True,
                "expected_version": version,
                **extra,
            },
        )

    assert add(a.unit, visit["version"]).json()["details"]["reason"] == "duplicate_stop"
    assert add(b.unit, visit["version"] + 5).status_code == 409  # stale visit version
    assert (
        add(gate.unit("A-103"), visit["version"]).json()["details"]["reason"]
        == "no_household_approver"
    )
    assert add(b.unit, visit["version"], destination_confirmed=False).status_code == 422
    for who in (a.owner, gate.secretary):
        assert (
            gate.call(
                who,
                "POST",
                f"/v1/visits/{first['visit_id']}/stops",
                json={
                    "unit_id": str(b.unit),
                    "destination_confirmed": True,
                    "expected_version": visit["version"],
                },
            ).status_code
            == 403
        )
    # a cancelled visit takes no more stops
    cancelled = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{first['visit_id']}/cancel",
        json={"expected_version": visit["version"], "reason": "Visitor left the gate"},
    )
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"
    assert add(b.unit, cancelled.json()["version"]).json()["details"]["reason"] == "visit_closed"
    # cancelling the visit cancelled its pending request too, and told the notification worker
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "cancelled"
    assert any(
        e["payload"]["status"] == "cancelled" for e in gate.outbox("ApprovalDecided", first["id"])
    )
