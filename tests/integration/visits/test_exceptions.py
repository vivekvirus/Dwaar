"""Gate exceptions: emergency and manual entry need the local authority and a reason; nothing is an invisible bypass (GATE-07).

REQ: GATE-07, GATE-11, INV-03, IAM-03.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.integration.identity._support import Person
from tests.integration.visits._support import VW

pytestmark = [pytest.mark.req("GATE-07")]

REASON = "Ambulance for a collapsed resident, lift lobby"


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def raise_(vw: VW, who: Person, kind: str, **extra: Any) -> Any:
    body: dict[str, Any] = {"kind": kind, "reason": REASON}
    body.update(extra)
    return vw.call(who, "POST", vw.s("exceptions"), json=body)


def test_a_plain_guard_cannot_authorise_a_manual_or_an_emergency_entry(gate: VW) -> None:
    for kind in ("manual_entry", "emergency_entry"):
        r = raise_(
            gate, gate.guard, kind, visitor_alias="Ambulance crew", gate_id=str(gate.gate_id)
        )
        assert r.status_code == 403 and r.json()["code"] == "not_authorised", kind
    assert (
        gate.rows("SELECT count(*) FROM visits")[0][0] == 0
        and gate.rows("SELECT count(*) FROM exceptions")[0][0] == 0
    )
    h = gate.household("A-101")
    for who in (h.owner, gate.secretary):
        assert raise_(gate, who, "manual_entry", visitor_alias="X").status_code == 403
    assert raise_(gate, gate.person(), "other").status_code == 404


def test_the_supervisor_authorises_an_emergency_entry_with_a_reason_and_it_always_leaves_an_exception(
    gate: VW,
) -> None:
    h = gate.household("A-101")
    r = raise_(gate, gate.guard_sup, "emergency_entry", visitor_alias="Ambulance crew", visit_kind="service",
               unit_id=str(h.unit), gate_id=str(gate.gate_id), people_count=3)  # fmt: skip
    assert r.status_code == 201, r.text
    body = r.json()
    exc, visit = body["exception"], body["visit"]
    assert exc["kind"] == "emergency_entry" and exc["state"] == "open" and exc["reason"] == REASON
    assert exc["actor_id"] == str(gate.guard_sup.id) and exc["entry_happened"] is None
    assert visit["state"] == "authorised" and visit["authorisation_source"] == "supervisor_override"
    assert visit["authorised_until"] and visit["stops"][0]["authorised"] is True
    row = gate.rows("SELECT authorised_until - authorised_at FROM visits")[0][0]
    assert (
        239 * 60 <= row.total_seconds() <= 241 * 60
    )  # the policy's override validity (240 minutes): never open-ended
    audit = gate.audit("visit.emergency_entry")
    assert (
        len(audit) == 1
        and audit[0][1] == gate.guard_sup.id
        and audit[0][2] == "guard_sup"
        and audit[0][5] == REASON
    )
    assert gate.outbox("ExceptionOpened") and gate.outbox("VisitAuthorised")
    # the guard still has to OBSERVE the entry: authorisation is not entry
    assert visit["entry_observed"] is False
    assert (
        gate.observe(visit["id"], "entry", decision_source="supervisor_override").json()["visit"][
            "state"
        ]
        == "inside"
    )
    # an emergency vehicle needs no destination unit at all
    amb = raise_(
        gate,
        gate.guard_sup,
        "emergency_entry",
        visitor_alias="Fire engine",
        gate_id=str(gate.gate_id),
    )
    assert amb.status_code == 201 and amb.json()["visit"]["stops"] == []


def test_manual_entry_input_rules(gate: VW) -> None:
    assert raise_(gate, gate.guard_sup, "manual_entry").status_code == 400  # an alias is needed
    short = gate.call(
        gate.guard_sup,
        "POST",
        gate.s("exceptions"),
        json={"kind": "manual_entry", "reason": "no", "visitor_alias": "A"},
    )
    assert short.status_code == 400
    assert (
        raise_(
            gate, gate.guard_sup, "manual_entry", visitor_alias="A", unit_id=str(uuid.uuid4())
        ).status_code
        == 404
    )
    assert (
        raise_(
            gate, gate.guard_sup, "manual_entry", visitor_alias="A", gate_id=str(uuid.uuid4())
        ).status_code
        == 400
    )
    assert (
        raise_(gate, gate.guard_sup, "overstay").status_code == 400
    )  # detections are made by the system, not raised
    pol = gate.call(
        gate.secretary, "PUT", gate.s("gate-policy"), json={"override_validity_minutes": 60}
    )
    assert pol.status_code == 200
    ok = raise_(
        gate,
        gate.guard_sup,
        "manual_entry",
        visitor_alias="Late courier",
        gate_id=str(gate.gate_id),
    )
    assert ok.status_code == 201
    seconds = gate.rows("SELECT extract(epoch FROM authorised_until - authorised_at) FROM visits")[
        0
    ][0]
    assert float(seconds) <= 60 * 60 + 1


def test_a_guard_can_raise_an_ordinary_exception_with_a_reason(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    r = raise_(
        gate,
        gate.guard,
        "other",
        visit_id=req["visit_id"],
        reason="Visitor refused to show any identification",
        evidence_ref="note:gate-register-17",
    )
    assert r.status_code == 201, r.text
    exc = r.json()["exception"]
    assert (
        exc["kind"] == "other"
        and exc["actor_id"] == str(gate.guard.id)
        and exc["evidence_ref"] == "note:gate-register-17"
    )
    assert r.json()["visit"] is None
    assert raise_(gate, gate.guard, "other", visit_id=str(uuid.uuid4())).status_code == 404
    short = gate.call(
        gate.guard, "POST", gate.s("exceptions"), json={"kind": "other", "reason": "x"}
    )
    assert short.status_code == 400


def test_state_machine_open_review_resolved_or_escalated(gate: VW) -> None:
    exc = raise_(
        gate, gate.guard, "other", reason="Unlogged vehicle entered behind a resident car"
    ).json()["exception"]

    def go(who: Person, action: str, version: int, note: str | None = None) -> Any:
        return gate.call(
            who,
            "POST",
            f"/v1/exceptions/{exc['id']}/transition",
            json={"action": action, "expected_version": version, "note": note},
        )

    assert (
        go(gate.guard, "start_review", 1).status_code == 403
    )  # a guard does not review exceptions
    skip = go(gate.guard_sup, "resolve", 1, "Everything is fine now")
    assert skip.status_code == 422 and skip.json()["details"]["reason"] == "review_first"
    reviewing = go(gate.guard_sup, "start_review", 1)
    assert (
        reviewing.status_code == 200
        and reviewing.json()["state"] == "supervisor_review"
        and reviewing.json()["reviewed_by"] == str(gate.guard_sup.id)
    )
    assert go(gate.guard_sup, "start_review", 1).status_code == 409  # already in review / stale
    assert go(gate.guard_sup, "resolve", 2).status_code == 400  # a resolution note is mandatory
    escalated = go(gate.guard_sup, "escalate", 2, "Needs the committee")
    assert escalated.status_code == 200 and escalated.json()["state"] == "escalated"
    assert gate.outbox("ExceptionEscalated")
    assert (
        go(gate.guard_sup, "resolve", 3, "Closing it myself now").status_code == 403
    )  # an escalated one is the secretary's
    done = go(gate.secretary, "resolve", 3, "Vehicle identified as a resident's relative")
    assert (
        done.status_code == 200
        and done.json()["state"] == "resolved"
        and done.json()["resolved_by"] == str(gate.secretary.id)
    )
    assert go(gate.secretary, "escalate", 4).status_code == 409  # resolved is final
    assert gate.rows("SELECT count(*) FROM audit_log WHERE object_id = %s", (exc["id"],))[0][0] == 4
    listed = gate.call(
        gate.secretary, "GET", gate.s("exceptions"), params={"state": "resolved"}
    ).json()["items"]
    assert [e["id"] for e in listed] == [exc["id"]]
    assert gate.call(gate.guard, "GET", gate.s("exceptions")).status_code == 403
    assert (
        gate.call(gate.guard_sup, "GET", gate.s("exceptions"), params={"kind": "other"}).status_code
        == 200
    )


def test_the_supervisor_who_authorised_an_entry_cannot_close_its_exception(gate: VW) -> None:
    created = raise_(
        gate, gate.guard_sup, "manual_entry", visitor_alias="Plumber", gate_id=str(gate.gate_id)
    ).json()["exception"]
    url = f"/v1/exceptions/{created['id']}/transition"
    assert (
        gate.call(
            gate.guard_sup, "POST", url, json={"action": "start_review", "expected_version": 1}
        ).status_code
        == 200
    )
    mine = gate.call(
        gate.guard_sup,
        "POST",
        url,
        json={"action": "resolve", "expected_version": 2, "note": "Fine, I allowed it"},
    )
    assert mine.status_code == 422 and mine.json()["details"]["reason"] == "maker_checker"
    other = gate.call(
        gate.secretary,
        "POST",
        url,
        json={"action": "resolve", "expected_version": 2, "note": "Reviewed with the supervisor"},
    )
    assert other.status_code == 200 and other.json()["state"] == "resolved"
    assert gate.rows("SELECT state FROM exceptions")[0][0] == "resolved"
