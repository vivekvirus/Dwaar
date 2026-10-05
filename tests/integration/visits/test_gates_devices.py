"""Gates, lanes, device enrolment with supervisor approval (SOC-05 subset) and the gate policy API.

REQ: SOC-05, GATE-11, INV-01, IAM-03.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.integration.visits._support import VW, new_key

pytestmark = [pytest.mark.req("SOC-05")]


def enrol(vw: VW, who: Any = None, **extra: Any) -> Any:
    body: dict[str, Any] = {"kind": "terminal", "name": "Guard terminal", "public_key": new_key()}
    body.update(extra)
    return vw.call(who or vw.guard, "POST", vw.s("devices"), json=body)


def test_gates_and_lanes_are_configured_by_the_secretary(vw: VW) -> None:
    r = vw.call(
        vw.secretary,
        "POST",
        vw.s("gates"),
        json={"name": "Main Gate", "kind": "vehicle"},
        key="gate-key-0001",
    )
    assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["version"] == 1
    again = vw.call(
        vw.secretary,
        "POST",
        vw.s("gates"),
        json={"name": "Main Gate", "kind": "vehicle"},
        key="gate-key-0001",
    )
    assert again.headers["Idempotent-Replayed"] == "true" and again.json()["id"] == r.json()["id"]
    gate = r.json()["id"]
    dup = vw.call(
        vw.secretary, "POST", vw.s("gates"), json={"name": " main gate ", "kind": "mixed"}
    )
    assert dup.status_code == 422 and dup.json()["details"]["reason"] == "already_exists"
    lane = vw.call(
        vw.secretary,
        "POST",
        vw.s(f"gates/{gate}/lanes"),
        json={"label": "Entry lane", "direction": "in"},
    )
    assert lane.status_code == 201 and lane.json()["gate_id"] == gate
    assert (
        vw.call(
            vw.secretary,
            "POST",
            vw.s(f"gates/{gate}/lanes"),
            json={"label": "entry LANE", "direction": "out"},
        ).status_code
        == 422
    )
    assert (
        vw.call(
            vw.secretary,
            "POST",
            vw.s(f"gates/{uuid.uuid4()}/lanes"),
            json={"label": "x", "direction": "in"},
        ).status_code
        == 404
    )
    for who in (vw.guard, vw.guard_sup):
        listed = vw.call(who, "GET", vw.s("gates")).json()["items"]
        assert [g["name"] for g in listed] == ["Main Gate"]
        assert [
            lane_["label"]
            for lane_ in vw.call(who, "GET", vw.s(f"gates/{gate}/lanes")).json()["items"]
        ] == ["Entry lane"]
    h = vw.household("A-101")
    for who in (vw.guard, vw.guard_sup, h.owner):
        assert (
            vw.call(who, "POST", vw.s("gates"), json={"name": "Rogue", "kind": "mixed"}).status_code
            == 403
        )
    assert vw.call(h.owner, "GET", vw.s("gates")).status_code == 403
    assert vw.call(vw.person(), "GET", vw.s("gates")).status_code == 404
    assert len(vw.outbox("GateCreated")) == 1 and len(vw.audit("gate.create")) == 1
    assert (
        vw.call(
            vw.secretary,
            "POST",
            vw.s("gates"),
            json={"name": "X", "kind": "mixed", "society_id": str(vw.soc.id)},
        ).status_code
        == 400
    )


def test_another_societys_gate_id_is_just_unknown(vw: VW) -> None:
    other = vw.idh.society("Elsewhere", units=("Z-1",))
    foreign_secretary = vw.person()
    vw.idh.seed_grant(other.id, foreign_secretary.id, "secretary")
    vw.idh.elevate_session(foreign_secretary)
    theirs = vw.call(
        foreign_secretary,
        "POST",
        f"/v1/societies/{other.id}/gates",
        json={"name": "Theirs", "kind": "mixed"},
    ).json()["id"]
    assert vw.call(vw.secretary, "GET", vw.s(f"gates/{theirs}/lanes")).status_code == 404
    assert (
        vw.call(
            vw.secretary,
            "POST",
            vw.s(f"gates/{theirs}/lanes"),
            json={"label": "L", "direction": "in"},
        ).status_code
        == 404
    )
    r = enrol(vw, gate_id=theirs)
    assert r.status_code == 400 and r.json()["details"]["fields"][0]["issue"] == "unknown_gate"
    assert [g["name"] for g in vw.call(vw.secretary, "GET", vw.s("gates")).json()["items"]] == []


def test_device_enrolment_is_a_request_that_a_different_person_approves(vw: VW) -> None:
    gate = vw.make_gate()
    r = enrol(vw, gate_id=str(gate), firmware="1.2.3", capabilities={"nfc": True})
    assert r.status_code == 201, r.text
    dev = r.json()
    assert (
        dev["state"] == "pending_approval"
        and dev["key_id"].startswith("ed-")
        and dev["requested_by"] == str(vw.guard.id)
    )
    assert "public_key" not in dev and dev["capabilities"] == {"nfc": True}
    # not usable, not decidable by its requester, not by someone without the role
    for who, status in ((vw.guard, 403), (vw.person(), 404)):
        d = vw.call(
            who,
            "POST",
            vw.s(f"devices/{dev['id']}/decision"),
            json={"decision": "approve", "expected_version": 1},
        )
        assert d.status_code == status
    # the supervisor is also its own requester here: maker != checker (service and database)
    own = enrol(vw, vw.guard_sup, name="Supervisor handheld").json()
    refused = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{own['id']}/decision"),
        json={"decision": "approve", "expected_version": 1},
    )
    assert refused.status_code == 422 and refused.json()["details"]["reason"] == "maker_checker"
    assert (
        vw.call(
            vw.secretary,
            "POST",
            vw.s(f"devices/{own['id']}/decision"),
            json={"decision": "approve", "expected_version": 1},
        ).status_code
        == 200
    )
    # the supervisor approves the guard's request
    stale = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "approve", "expected_version": 4},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    ok = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "approve", "expected_version": 1},
        key="dev-key-00001",
    )
    assert (
        ok.status_code == 200
        and ok.json()["state"] == "active"
        and ok.json()["decided_by"] == str(vw.guard_sup.id)
    )
    replay = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "approve", "expected_version": 1},
        key="dev-key-00001",
    )
    assert replay.headers["Idempotent-Replayed"] == "true"
    again = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "approve", "expected_version": 1},
    )
    assert again.status_code == 409  # already decided: a second approval is not a second activation
    assert (
        len(vw.outbox("DeviceEnrolmentRequested")) == 2 and len(vw.outbox("DeviceActivated")) == 2
    )
    assert len(vw.audit("device.approve")) == 2 and vw.audit("device.approve")[0][1] in (
        vw.guard_sup.id,
        vw.secretary.id,
    )
    listed = vw.call(vw.guard_sup, "GET", vw.s("devices"), params={"state": "active"}).json()[
        "items"
    ]
    assert {d["id"] for d in listed} == {dev["id"], own["id"]}
    assert (
        vw.call(vw.guard, "GET", vw.s("devices")).status_code == 403
    )  # PRD 5.1: device status belongs to the supervisor
    assert (
        vw.call(vw.guard_sup, "GET", vw.s("devices"), params={"state": "bogus"}).status_code == 400
    )


def test_reject_needs_a_reason_and_revoke_closes_the_device(vw: VW) -> None:
    dev = enrol(vw).json()
    no_reason = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "reject", "expected_version": 1},
    )
    assert no_reason.status_code == 400
    rejected = vw.call(
        vw.guard_sup, "POST", vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "reject", "expected_version": 1, "reason": "Unknown installer, serial mismatch"},
    )  # fmt: skip
    assert rejected.status_code == 200 and rejected.json()["state"] == "rejected"
    assert (
        vw.call(
            vw.guard_sup,
            "POST",
            vw.s(f"devices/{dev['id']}/revoke"),
            json={"expected_version": 2, "reason": "Not active at all"},
        ).status_code
        == 409
    )
    active = vw.make_device()
    d = vw.call(vw.guard_sup, "GET", vw.s(f"devices/{active}")).json()
    revoked = vw.call(
        vw.guard_sup,
        "POST",
        vw.s(f"devices/{active}/revoke"),
        json={"expected_version": d["version"], "reason": "Terminal reported lost"},
    )
    assert (
        revoked.status_code == 200
        and revoked.json()["state"] == "revoked"
        and revoked.json()["revoked_at"]
    )
    assert len(vw.outbox("DeviceRevoked")) == 1


def test_enrolment_input_is_validated_and_a_key_enrols_once_per_society(vw: VW) -> None:
    for bad in (
        {"public_key": "short"},
        {"public_key": "A" * 43 + "="},
        {"kind": "toaster"},
        {"name": ""},
        {"capabilities": {"x": 1.5}},
    ):
        assert enrol(vw, **bad).status_code == 400, bad
    key = new_key()
    assert enrol(vw, public_key=key).status_code == 201
    dup = enrol(vw, public_key=key)
    assert dup.status_code == 422 and dup.json()["details"]["reason"] == "already_enrolled"
    # a 43-character string that is not a valid Ed25519 point encoding is still 32 bytes: the format is what is checked here
    h = vw.household("A-101")
    assert enrol(vw, h.owner).status_code == 403
    assert enrol(vw, vw.secretary).status_code == 403


def test_supervisor_without_a_step_up_cannot_decide(vw: VW) -> None:
    """IAM-03: the supervisor is an elevated role; a session without a fresh step-up is refused (403), as everywhere."""
    dev = enrol(vw).json()
    fresh = vw.person()
    vw.idh.seed_grant(vw.soc.id, fresh.id, "guard_sup")  # no elevate_session
    r = vw.call(
        fresh,
        "POST",
        vw.s(f"devices/{dev['id']}/decision"),
        json={"decision": "approve", "expected_version": 1},
    )
    assert r.status_code == 403


def test_gate_policy_is_readable_by_the_gate_and_writable_by_the_secretary_only(vw: VW) -> None:
    for who in (vw.guard, vw.guard_sup, vw.secretary):
        r = vw.call(who, "GET", vw.s("gate-policy"))
        assert (
            r.status_code == 200
            and r.json()["version"] == 0
            and r.json()["permission_validity_minutes"] == 30
        )
        assert r.json()["overstay_minutes"] == {
            "delivery": 20,
            "cab": 15,
            "service": 240,
            "vendor": 240,
        }
    put = vw.call(
        vw.secretary,
        "PUT",
        vw.s("gate-policy"),
        json={"permission_validity_minutes": 45, "override_validity_minutes": 120},
    )
    assert (
        put.status_code == 200
        and put.json()["permission_validity_minutes"] == 45
        and put.json()["version"] == 1
    )
    for who in (vw.guard, vw.guard_sup):
        assert (
            vw.call(
                who, "PUT", vw.s("gate-policy"), json={"permission_validity_minutes": 5}
            ).status_code
            == 403
        )
    h = vw.household("A-101")
    assert vw.call(h.owner, "GET", vw.s("gate-policy")).status_code == 403
    assert (
        vw.call(
            vw.secretary,
            "PUT",
            vw.s("gate-policy"),
            json={"permission_validity_minutes": 0, "expected_version": 1},
        ).status_code
        == 400
    )
    assert len(vw.audit("gate_policy.put")) == 1
    # the permission validity of a NEW approval follows the policy
    vw.setup_gate()
    req = vw.raise_request(h.unit)
    done = vw.decide(h.owner, req).json()
    seconds = vw.rows(
        "SELECT extract(epoch FROM permission_expires_at - closed_at) FROM approval_requests"
    )[0][0]
    assert 44 * 60 <= float(seconds) <= 45 * 60 + 1 and done["status"] == "approved"
