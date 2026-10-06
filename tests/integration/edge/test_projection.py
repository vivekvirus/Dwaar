"""Pass entries observed by an edge gateway are PROJECTED onto the cloud: a visit that is inside, one more use of the pass (ADR-0019).

REQ: EDGE-07 (a physical observation is recorded, never discarded; no matching authorisation raises a supervisor exception, a legitimate
entry raises none), GATE-05 (exit matched to its entry), GATE-07, INV-07 (the projection records facts: it creates no permission), INV-03.
Also here: the gateway's trust anchors (``/v1/edge/keys`` pass keys) and the age rule for events uploaded after a long outage (NFR-09).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest

from dwaar_api.modules.edge.sync import edge_visit_id
from dwaar_common.signing import public_key_from_b64, verify_bytes
from tests.integration.edge._support import EdgeClient, EdgeWorld, now
from tests.integration.edge.test_policy import make_invitation

pytestmark = [pytest.mark.req("EDGE-07", "GATE-05", "INV-07")]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device(bind_gate=False, name="Society gateway")


@pytest.fixture
def host(ew: EdgeWorld) -> Any:
    return ew.household("A-101", tenant=False, family=False)


def pass_entry(
    dev: EdgeClient, ew: EdgeWorld, movement: uuid.UUID, invitation: str, **extra: Any
) -> dict[str, Any]:
    payload = {
        "gate_id": str(ew.gate_id), "decision_source": "cached_policy", "credential_kind": "qr",
        "invitation_id": invitation, "reason_code": "guest_pass_valid", **extra.pop("payload", {}),
    }  # fmt: skip
    return dev.entry(movement, payload=payload, **extra)


def only(r: Any) -> dict[str, Any]:
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()["outcomes"][0]
    return out


def test_an_accepted_pass_entry_becomes_a_visit_inside_one_use_of_the_pass_and_a_visible_history(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=2)
    movement = uuid.uuid4()
    out = only(dev.sync([pass_entry(dev, ew, movement, inv["id"])]))
    assert (
        out["status"] == "accepted"
        and out["outcome"] == "edge_entry_recorded"
        and "exception_id" not in out
    )
    vid = edge_visit_id(ew.soc.id, movement)
    row = ew.rows(
        "SELECT state, authorisation_source, invitation_id, gate_id, kind, authorised_until = entered_at, confidence_inside FROM visits"
    )
    assert row == [
        ("inside", "invitation", uuid.UUID(inv["id"]), ew.gate_id, "guest", True, "observed")
    ]
    assert ew.rows("SELECT id FROM visits") == [(vid,)]
    assert ew.rows("SELECT unit_id, authorised, state FROM visit_stops") == [
        (ew.soc.units["A-101"], True, "authorised")
    ]
    assert ew.rows("SELECT uses, state FROM invitations") == [
        (1, "active")
    ]  # two permitted, one used
    assert ew.rows("SELECT visit_id FROM access_events") == [(vid,)] and ew.rows(
        "SELECT projected FROM edge_events"
    ) == [(True,)]
    assert (
        ew.count("exceptions") == 0
        and ew.count("audit_log", "operation = 'edge.pass_entry_projected'") == 1
    )
    event = ew.outbox("VisitEntered", vid)
    assert (
        len(event) == 1
        and event[0]["payload"]["invitation_id"] == inv["id"]
        and event[0]["payload"]["seq"] == 1
    )
    hist = ew.call(host.owner, "GET", ew.s(f"units/{ew.soc.units['A-101']}/visits"))
    assert hist.status_code == 200 and [v["state"] for v in hist.json()["items"]] == ["inside"]
    # the permission was consumed by the entry itself: nothing here authorises a second entry (INV-07)
    second = only(dev.sync([pass_entry(dev, ew, uuid.uuid4(), inv["id"])]))
    assert second["status"] == "accepted" and ew.rows("SELECT uses, state FROM invitations") == [
        (2, "consumed")
    ]


def test_resending_the_entry_counts_the_use_once_and_the_exit_closes_the_visit(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=1)
    movement = uuid.uuid4()
    entry = pass_entry(dev, ew, movement, inv["id"])
    dev.sync([entry])
    assert only(dev.sync([entry]))["status"] == "duplicate"  # a lost response: the gateway resends
    assert ew.rows("SELECT uses FROM invitations") == [(1,)] and ew.count("visits") == 1
    exit_ = dev.exit(
        movement,
        payload={
            "gate_id": str(ew.gate_id),
            "exit_basis": "observed",
            "decision_source": "guard_assisted",
        },
    )
    out = only(dev.sync([exit_]))
    assert out["status"] == "accepted" and out["outcome"] == "exited" and "exception_id" not in out
    assert ew.rows(
        "SELECT state, exit_basis, exited_at IS NOT NULL, confidence_inside FROM visits"
    ) == [("exited", "observed", True, "none")]
    assert ew.rows("SELECT visit_id IS NOT NULL FROM access_events ORDER BY seq") == [
        (True,),
        (True,),
    ]


def test_an_exit_that_arrives_before_its_entry_leaves_a_review_and_the_late_entry_becomes_an_exited_visit(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner)
    movement = uuid.uuid4()
    entry = pass_entry(
        dev, ew, movement, inv["id"], seq=1, occurred_at=now() - timedelta(minutes=30)
    )
    exit_ = dev.exit(
        movement,
        seq=2,
        occurred_at=now() - timedelta(minutes=10),
        payload={"gate_id": str(ew.gate_id), "exit_basis": "observed"},
    )
    first = only(dev.sync([exit_]))  # arrival order is not observation order
    assert (
        first["status"] == "rejected_transition"
        and first["reason"] == "exit_without_entry"
        and first["exception_id"]
    )
    late = only(dev.sync([entry]))
    assert late["status"] == "accepted"
    assert ew.rows("SELECT state, exit_basis FROM visits") == [
        ("exited", "observed")
    ]  # nobody is left 'inside' forever
    assert ew.rows("SELECT highest_contiguous_seq FROM edge_device_state") == [(2,)]


def test_a_pass_the_cloud_counted_out_still_leaves_the_visit_and_one_supervisor_exception(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=1)
    ew.sql(
        "UPDATE invitations SET uses = 1, state = 'consumed' WHERE id = %s", (inv["id"],)
    )  # redeemed online meanwhile
    out = only(dev.sync([pass_entry(dev, ew, uuid.uuid4(), inv["id"])]))
    assert (
        out["status"] == "accepted"
        and out["outcome"] == "edge_entry_pass_overused"
        and out["exception_id"]
    )
    assert ew.rows("SELECT state FROM visits") == [("inside",)] and ew.rows(
        "SELECT uses FROM invitations"
    ) == [(1,)]
    ex = ew.exceptions("unauthorised_entry")
    assert (
        len(ex) == 1 and "more often than allowed" in ex[0][4] and ex[0][2] is not None
    )  # linked to the visit


def test_an_override_with_a_known_pass_projects_it_as_a_supervisor_override_and_keeps_the_manual_entry_exception(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=1)
    out = only(
        dev.sync(
            [
                pass_entry(
                    dev,
                    ew,
                    uuid.uuid4(),
                    inv["id"],
                    payload={
                        "decision_source": "supervisor_override",
                        "credential_kind": "guard_assisted",
                    },
                )
            ]
        )
    )
    assert out["status"] == "accepted" and out["outcome"] == "override_entry_recorded"
    assert ew.rows("SELECT authorisation_source FROM visits") == [("supervisor_override",)]
    assert [r[0] for r in ew.exceptions()] == ["manual_entry"]


def test_a_pass_revoked_before_the_entry_is_recorded_but_not_projected_and_one_revoked_after_is(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    early = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=2)
    late = make_invitation(ew, ew.soc.units["A-101"], host.owner, max_uses=2)
    for inv in (early, late):
        assert ew.call(host.owner, "DELETE", f"/v1/invitations/{inv['id']}").status_code == 200
    ew.sql(
        "UPDATE invitations SET revoked_at = %s WHERE id = %s",
        (now() - timedelta(hours=2), early["id"]),
    )  # revoked two hours ago
    ew.sql(
        "UPDATE invitations SET revoked_at = %s WHERE id = %s",
        (now() + timedelta(hours=1), late["id"]),
    )  # revoked AFTER the entry below
    a = only(dev.sync([pass_entry(dev, ew, uuid.uuid4(), early["id"], seq=1)]))
    b = only(dev.sync([pass_entry(dev, ew, uuid.uuid4(), late["id"], seq=2)]))
    assert (
        a["status"] == "rejected_transition"
        and a["reason"] == "entry_after_revocation"
        and a["access_event_recorded"] is True
    )
    assert b["status"] == "accepted"
    assert ew.rows("SELECT invitation_id FROM visits") == [
        (uuid.UUID(late["id"]),)
    ]  # the observation of `early` is NOT a visit
    assert ew.rows("SELECT uses FROM invitations ORDER BY id") == [
        (0,),
        (0,),
    ]  # a revoked pass is never counted further
    assert ew.count("access_events") == 2  # but both observations are recorded (never discarded)
    assert [r[0] for r in ew.exceptions()] == ["unauthorised_entry"]


def test_residents_and_unknown_passes_never_become_visits(ew: EdgeWorld, dev: EdgeClient) -> None:
    resident = only(
        dev.sync(
            [
                dev.entry(
                    uuid.uuid4(),
                    payload={
                        "gate_id": str(ew.gate_id),
                        "decision_source": "cached_policy",
                        "credential_kind": "resident_app",
                    },
                    seq=1,
                )
            ]
        )
    )
    unknown = only(dev.sync([pass_entry(dev, ew, uuid.uuid4(), str(uuid.uuid4()), seq=2)]))
    assert resident["status"] == "accepted" and unknown["reason"] == "entry_unknown_invitation"
    assert ew.count("visits") == 0 and ew.count("access_events") == 2


def test_the_derived_visit_id_is_deterministic_per_society_and_not_the_movement_id() -> None:
    soc, other, movement = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    assert edge_visit_id(soc, movement) == edge_visit_id(soc, movement) != movement
    assert edge_visit_id(soc, movement) != edge_visit_id(other, movement)


# ------------------------------------------------------------------------------------------ trust anchors and outage age
def test_the_keys_endpoint_publishes_the_pass_verification_key_a_gateway_pins(
    ew: EdgeWorld, dev: EdgeClient, host: Any
) -> None:
    inv = make_invitation(ew, ew.soc.units["A-101"], host.owner)
    keys = dev.request("GET", "/v1/edge/keys").json()
    assert [k["status"] for k in keys["pass_keys"]] == ["active"] and keys["keys"][0][
        "status"
    ] == "active"
    pass_key = public_key_from_b64(keys["pass_keys"][0]["public_key"])
    body_part, signature = inv["qr"].split(".", 1)
    from dwaar_common.signing import b64url_decode

    assert verify_bytes(
        pass_key, b64url_decode(body_part), signature
    )  # the published key verifies the real QR
    assert (
        keys["pass_keys"][0]["public_key"] != keys["keys"][0]["public_key"]
    )  # a different key purpose: never the policy issuer


def test_events_older_than_the_policy_age_limit_are_not_a_clock_problem_when_an_outage_explains_them(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    dev.sync(
        [dev.event("DeviceHealth", uuid.uuid4(), seq=1)]
    )  # a batch arrives: last_sync_at = now
    ew.sql(
        "UPDATE edge_device_state SET last_sync_at = now() - interval '100 hours'"
    )  # ... and was 100 hours ago
    buffered = dev.event(
        "DeviceHealth", uuid.uuid4(), seq=2, occurred_at=now() - timedelta(hours=96)
    )
    absurd = dev.event(
        "DeviceHealth", uuid.uuid4(), seq=3, occurred_at=now() - timedelta(hours=400)
    )
    out = dev.sync([buffered, absurd]).json()["outcomes"]
    assert (
        "clock_flag" not in out[0]
    )  # 96 h old, 100 h of silence: that is what a 100 h outage looks like
    assert out[1]["clock_flag"] == "stale"  # older than the silence itself: a wrong clock
