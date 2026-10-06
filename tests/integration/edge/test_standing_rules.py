"""Standing rules per household (GATE-14): who may set them, validation, publication to the edge, ending, isolation.

REQ: GATE-14, INV-03, INV-04, INV-01, PRD 12.4.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("GATE-14")]


def milk(unit: uuid.UUID, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "unit_id": str(unit), "rule_kind": "allow_window", "visit_kind": "vendor", "category": "milk",
        "start_local": "06:00", "end_local": "07:00",
    }  # fmt: skip
    body.update(extra)
    return body


def food(unit: uuid.UUID, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "unit_id": str(unit), "rule_kind": "leave_at_gate", "visit_kind": "delivery", "category": "food",
        "start_local": "22:00", "end_local": "06:00",
    }  # fmt: skip
    body.update(extra)
    return body


def create(ew: EdgeWorld, who: Any, body: dict[str, Any], **kw: Any) -> Any:
    return ew.call(who, "POST", ew.s("standing-rules"), json=body, **kw)


def test_the_two_rules_of_the_prd_are_stored_per_household_and_published(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    unit = ew.soc.units["A-101"]
    dev = ew.edge_device()
    a = create(ew, h.owner, milk(unit))
    b = create(ew, h.owner, food(unit))
    assert a.status_code == b.status_code == 201, (a.text, b.text)
    assert a.json()["params"] == {
        "visit_kind": "vendor", "action": "allow", "days": [1, 2, 3, 4, 5, 6, 7], "start_local": "06:00",
        "end_local": "07:00", "tz": "Asia/Kolkata", "category": "milk",
    }  # fmt: skip
    assert (
        b.json()["params"]["action"] == "leave_at_gate"
        and b.json()["params"]["start_local"] > b.json()["params"]["end_local"]
    )  # wraps midnight
    rules = dev.policy().json()["manifest"]["standing_rules"]
    assert {r["rule_kind"] for r in rules} == {"allow_window", "leave_at_gate"}
    assert all(r["unit_id"] == str(unit) and r["effective_to"] is None for r in rules)
    assert len(ew.audit("standing_rule.create")) == 2
    assert [o["payload"]["rule_kind"] for o in ew.outbox("StandingRuleCreated")] == [
        "allow_window",
        "leave_at_gate",
    ]


def test_only_members_who_may_decide_for_the_household_set_its_rules(ew: EdgeWorld) -> None:
    h = ew.household("A-101", tenant=True, family=True, nr_owner=True)
    unit = ew.soc.units["A-101"]
    assert create(ew, h.tenant, milk(unit)).status_code == 201
    assert (
        create(ew, h.family, milk(unit, category="paper")).status_code == 201
    )  # delegated family member
    undelegated = ew.resident(unit, "family")
    assert create(ew, undelegated, milk(unit, category="gas")).status_code == 403
    assert (
        create(ew, h.nr_owner, milk(unit, category="gas")).status_code == 403
    )  # INV-04: a non-resident owner is not the household
    assert create(ew, ew.guard, milk(unit)).status_code == 403
    assert create(ew, ew.secretary, milk(unit)).status_code == 403


def test_another_household_cannot_touch_the_unit_and_sees_nothing(ew: EdgeWorld) -> None:
    h1, h2 = ew.household("A-101", family=False), ew.household("A-102", family=False)
    u1, u2 = ew.soc.units["A-101"], ew.soc.units["A-102"]
    assert create(ew, h2.owner, milk(u1)).status_code == 404
    mine = create(ew, h1.owner, milk(u1)).json()
    listing = ew.call(h2.owner, "GET", ew.s("standing-rules"))
    assert listing.status_code == 200 and listing.json()["items"] == []
    assert (
        ew.call(h2.owner, "GET", ew.s("standing-rules"), params={"unit_id": str(u1)}).status_code
        == 404
    )
    assert ew.call(h2.owner, "DELETE", ew.s(f"standing-rules/{mine['id']}")).status_code == 404
    assert create(ew, h2.owner, milk(u2)).status_code == 201
    everything = ew.call(ew.secretary, "GET", ew.s("standing-rules")).json()["items"]
    assert len(everything) == 2  # society roles read every unit's


@pytest.mark.parametrize(
    "extra",
    [
        {"start_local": "6:00"}, {"end_local": "24:00"}, {"end_local": "06:00"}, {"days": []}, {"days": [0]}, {"days": [8]},
        {"category": None}, {"category": "Milk!"}, {"visit_kind": "alien"}, {"rule_kind": "deny"}, {"surprise": 1},
        {"effective_from": "2026-10-05", "effective_to": "2026-10-01"},
    ],
)  # fmt: skip
def test_invalid_rules_are_refused(ew: EdgeWorld, extra: dict[str, Any]) -> None:
    h = ew.household("A-101", family=False)
    r = create(ew, h.owner, milk(ew.soc.units["A-101"], **extra))
    assert r.status_code == 400 and r.json()["code"] == "invalid_schema", r.text
    assert ew.count("standing_rules") == 0


def test_a_household_has_a_bounded_number_of_rules(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    unit = ew.soc.units["A-101"]
    for i in range(20):
        assert create(ew, h.owner, milk(unit, category=f"vendor {i}")).status_code == 201
    r = create(ew, h.owner, milk(unit, category="one too many"))
    assert r.status_code == 422 and r.json()["details"]["reason"] == "too_many_standing_rules"


def test_a_retry_with_the_same_idempotency_key_creates_one_rule(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    body = milk(ew.soc.units["A-101"])
    key = f"rule-{uuid.uuid4()}"
    first = create(ew, h.owner, body, key=key)
    again = create(ew, h.owner, body, key=key)
    assert (
        first.status_code == again.status_code == 201 and first.json()["id"] == again.json()["id"]
    )
    assert ew.count("standing_rules") == 1
    assert create(ew, h.owner, {**body, "end_local": "08:00"}, key=key).status_code == 409


def test_ending_a_rule_removes_it_from_the_next_snapshot_and_is_idempotent(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    unit = ew.soc.units["A-101"]
    dev = ew.edge_device()
    rule = create(ew, h.owner, milk(unit)).json()
    first = dev.policy().json()
    assert len(first["manifest"]["standing_rules"]) == 1
    r = ew.call(h.owner, "DELETE", ew.s(f"standing-rules/{rule['id']}"))
    assert r.status_code == 200 and r.json()["state"] == "ended" and r.json()["version"] == 2
    again = ew.call(h.owner, "DELETE", ew.s(f"standing-rules/{rule['id']}"))
    assert again.status_code == 200 and again.json()["version"] == 2
    second = dev.policy(after=first["seq"]).json()
    assert second["manifest"]["standing_rules"] == [] and second["seq"] == first["seq"] + 1
    assert ew.call(h.owner, "GET", ew.s("standing-rules")).json()["items"] == []
    ended = ew.call(h.owner, "GET", ew.s("standing-rules"), params={"state": "ended"}).json()[
        "items"
    ]
    assert [e["id"] for e in ended] == [rule["id"]]
    assert len(ew.audit("standing_rule.end")) == 1


def test_a_rule_that_has_not_started_or_has_expired_is_not_published(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    unit = ew.soc.units["A-101"]
    dev = ew.edge_device()
    create(ew, h.owner, milk(unit, effective_from="2026-10-05", effective_to="2026-10-05"))
    ew.sql("UPDATE standing_rules SET effective_from = '2020-01-01', effective_to = '2020-01-02'")
    assert dev.policy().json()["manifest"]["standing_rules"] == []
    create(ew, h.owner, food(unit, effective_to="2099-01-01"))
    latest = dev.policy(after=0).json()["manifest"]["standing_rules"]
    assert len(latest) == 1 and latest[0]["effective_to"] == "2099-01-01"


def test_a_rule_names_a_category_and_a_window_never_a_person_or_a_number(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    body = milk(ew.soc.units["A-101"], visitor_phone="+919999900123")
    assert create(ew, h.owner, body).status_code == 400
    stored = create(ew, h.owner, milk(ew.soc.units["A-101"])).json()
    assert set(stored["params"]) == {
        "visit_kind",
        "action",
        "days",
        "start_local",
        "end_local",
        "tz",
        "category",
    }
