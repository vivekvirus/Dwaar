"""Edge-local movements: the gateway mints its own movement ids (residents, passes, standing rules, overrides), so an observation whose
``entity_id`` is not a cloud visit is recorded and judged by its payload.

REQ: EDGE-07 (physical observations are never discarded; invalid ones are flagged), GATE-06 (resident credentials are validated locally),
GATE-07 (an override always leaves an exception), GATE-05 (exit matched to its entry), INV-03, INV-07.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from tests.integration.edge._support import EdgeClient, EdgeWorld, now
from tests.integration.edge.test_policy import make_invitation

pytestmark = [pytest.mark.req("EDGE-07", "GATE-06", "GATE-07")]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device()


def test_a_resident_entry_decided_by_the_cached_policy_is_recorded_and_flags_nothing(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    movement = uuid.uuid4()
    out = dev.sync(
        [
            dev.entry(
                movement,
                payload={
                    "decision_source": "cached_policy",
                    "credential_kind": "resident_app",
                    "reason_code": "allow_resident",
                },
            )
        ]
    )
    body = out.json()["outcomes"][0]
    assert (
        body["status"] == "accepted"
        and body["outcome"] == "edge_entry_recorded"
        and body["access_event_recorded"] is True
    )
    assert "exception_id" not in body and ew.count("exceptions") == 0
    row = ew.rows("SELECT visit_id, credential_kind, decision_source FROM access_events")[0]
    assert row == (
        None,
        "resident_app",
        "cached_policy",
    )  # an observation, not a visit and not a permission
    assert ew.count("visits") == 0
    assert ew.rows("SELECT projected FROM edge_events")[0][0] is False


def test_the_exit_of_a_movement_the_gateway_minted_matches_its_entry(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    movement = uuid.uuid4()
    dev.sync([dev.entry(movement, payload={"credential_kind": "resident_app"})])
    out = dev.sync(
        [
            dev.exit(
                movement,
                payload={
                    "exit_basis": "scanned",
                    "credential_kind": "qr",
                    "decision_source": "cached_policy",
                },
            )
        ]
    ).json()["outcomes"][0]
    assert (
        out["status"] == "accepted"
        and out["outcome"] == "edge_movement_exit"
        and "exception_id" not in out
    )
    assert ew.count("exceptions") == 0 and ew.count("access_events") == 2
    # an exit that matches nothing is still recorded, and says so
    lone = dev.sync([dev.exit(uuid.uuid4())]).json()["outcomes"][0]
    assert lone["status"] == "rejected_transition" and lone["access_event_recorded"] is True
    assert len(ew.exceptions("exit_without_entry")) == 1 and ew.count("access_events") == 3


def test_a_guest_pass_entry_is_checked_against_the_passes_the_cloud_knows(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    h = ew.household("A-101", family=False)
    good = make_invitation(ew, ew.soc.units["A-101"], h.owner)
    ok = dev.sync(
        [dev.entry(uuid.uuid4(), payload={"credential_kind": "qr", "invitation_id": good["id"]})]
    ).json()["outcomes"][0]
    assert ok["status"] == "accepted" and ew.count("exceptions") == 0
    unknown = dev.sync(
        [
            dev.entry(
                uuid.uuid4(), payload={"credential_kind": "qr", "invitation_id": str(uuid.uuid4())}
            )
        ]
    ).json()["outcomes"][0]
    assert (
        unknown["status"] == "rejected_transition"
        and unknown["reason"] == "entry_unknown_invitation"
    )
    assert ew.count("access_events") == 2 and len(ew.exceptions("unauthorised_entry")) == 1


def test_a_pass_revoked_before_the_entry_is_flagged_but_one_revoked_after_is_not(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    h = ew.household("A-101", family=False)
    early = make_invitation(ew, ew.soc.units["A-101"], h.owner, purpose="Early")
    late = make_invitation(ew, ew.soc.units["A-101"], h.owner, purpose="Late")
    before = now()
    assert ew.call(h.owner, "DELETE", f"/v1/invitations/{early['id']}").status_code == 200
    stale = dev.entry(
        uuid.uuid4(),
        occurred_at=now() + timedelta(seconds=1),
        payload={"invitation_id": early["id"], "credential_kind": "qr"},
    )
    out = dev.sync([stale]).json()["outcomes"][0]
    assert (
        out["status"] == "rejected_transition"
        and out["reason"] == "entry_after_revocation"
        and out["access_event_recorded"] is True
    )
    # the entry happened BEFORE the revocation (the gateway was offline): nothing to flag
    assert ew.call(h.owner, "DELETE", f"/v1/invitations/{late['id']}").status_code == 200
    earlier = dev.entry(
        uuid.uuid4(),
        occurred_at=before,
        payload={"invitation_id": late["id"], "credential_kind": "qr"},
    )
    assert dev.sync([earlier]).json()["outcomes"][0]["status"] == "accepted"


def test_a_supervisor_override_always_leaves_a_manual_entry_exception(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ev = dev.entry(
        uuid.uuid4(),
        payload={
            "decision_source": "supervisor_override",
            "credential_kind": "guard_assisted",
            "override_id": "ovr-1",
            "review": True,
        },
    )
    out = dev.sync([ev]).json()["outcomes"][0]
    assert (
        out["status"] == "accepted"
        and out["reason"] == "override_entry_recorded"
        and out["exception_id"]
    )
    exc = ew.exceptions("manual_entry")
    assert len(exc) == 1 and exc[0][1] == "open" and exc[0][2] is None
    assert ew.rows("SELECT decision_source FROM access_events")[0][0] == "supervisor_override"


def test_a_conflict_the_gateway_flagged_is_surfaced_to_the_supervisor(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ev = dev.entry(
        uuid.uuid4(),
        payload={"credential_kind": "qr", "conflict": "single_use_pass_reused", "review": True},
    )
    out = dev.sync([dev.entry(uuid.uuid4()), ev]).json()["outcomes"]
    assert out[0]["status"] == "accepted" and "exception_id" not in out[0]
    assert out[1]["status"] == "accepted" and out[1]["exception_id"]
    assert len(ew.exceptions("other")) == 1


def test_guard_assisted_admissions_are_recorded_without_flooding_the_queue(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    out = dev.sync(
        [
            dev.entry(
                uuid.uuid4(),
                payload={
                    "decision_source": "guard_assisted",
                    "credential_kind": "guard_assisted",
                    "review": True,
                },
            )
            for _ in range(5)
        ]
    )
    assert [o["status"] for o in out.json()["outcomes"]] == ["accepted"] * 5
    assert ew.count("exceptions") == 0 and ew.count("access_events") == 5


def test_a_cloud_visit_id_still_takes_the_visit_path_even_with_a_cached_policy_source(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    ew.age_authorisation(visit, minutes=600)
    out = dev.sync([dev.entry(visit, payload={"decision_source": "cached_policy"})]).json()[
        "outcomes"
    ][0]
    assert out["status"] == "rejected_transition" and out["reason"] == "entry_without_authorisation"
    assert ew.visit_state(visit) == "authorised"
