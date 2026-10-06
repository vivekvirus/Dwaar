"""NOTIF-02 states and truthful display, receipts, deep links, lock-screen actions, invalidation of stale actions, AT-11 fallbacks.

REQ: NOTIF-02 (provider acceptance is never delivery to a person), NOTIF-04 (decision accepted -> remaining ringing cancelled and stale actions
invalidated within 2 s on every device; measured here in the simulator), NOTIF-05 (immutable request id; deep link fetches CURRENT state;
lock-screen actions re-check membership; a late action shows expiry), AT-11 (phone force-stopped / permission denied -> no false delivery claim,
configured call or intercom fallback), INV-03, INV-07.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import pytest

from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-02", "NOTIF-04", "NOTIF-05")]


def _two(nw: NW) -> tuple[Any, Any]:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.register_device(family, "family-phone", model="SM-A546E", manufacturer="Samsung")
    return owner, family


def _board(nw: NW, request: dict[str, Any]) -> dict[str, Any]:
    r = nw.call(
        nw.guard,
        "GET",
        nw.s(f"approval-requests/{request['id']}/notification-status"),
        params={"gate_id": str(nw.gate_id)},
    )
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def _my(nw: NW, who: Any, request: dict[str, Any]) -> dict[str, Any]:
    rows = nw.rows(
        "SELECT id FROM notifications WHERE request_id = %s AND recipient_person_id = %s ORDER BY created_at",
        (request["id"], who.id),
    )
    assert rows, "no notification for this person"
    return {"id": str(rows[0][0])}


# ------------------------------------------------------------------------------------------------------------ NOTIF-02
def test_provider_acceptance_is_not_delivery_to_a_person(nw: NW) -> None:
    owner, _family = _two(nw)
    nw.sim_device("owner-phone").force_stopped = True  # AT-11: the phone was force-stopped
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(5))
    board = _board(nw, request)
    push = board["notifications"][0]
    assert (
        push["state"] == "provider_accepted"
        and push["provider_accepted"] is True
        and push["person_reached"] is False
    )
    assert board["summary"] == {"person_reached": False, "provider_accepted_only": 1, "failed": 0}
    text = json.dumps(board)
    assert "delivered" not in text.lower()  # no word of delivery anywhere
    mine = nw.call(owner, "GET", nw.s("notifications")).json()["items"][0]
    assert mine["state"] == "provider_accepted" and mine["person_reached"] is False
    assert "delivered" not in json.dumps(mine).lower()


def test_states_advance_only_on_evidence_and_never_go_backwards(nw: NW) -> None:
    owner, _family = _two(nw)
    nw.sim_device("owner-phone").force_stopped = True
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = _my(nw, owner, request)["id"]
    path = nw.s(f"notifications/{nid}/receipt")
    r = nw.call(
        owner, "POST", path, json={"event": "displayed"}
    )  # the app reports display first (out of order)
    assert r.status_code == 200, r.text
    n = r.json()["notification"]
    assert (
        n["state"] == "displayed" and n["app_received_at"] is not None
    )  # a display implies receipt
    r = nw.call(owner, "POST", path, json={"event": "app_received"})  # the receipt arrives late
    assert r.json()["notification"]["state"] == "displayed"  # not moved back
    again = nw.call(owner, "POST", path, json={"event": "displayed"}).json()["notification"]
    assert again["displayed_at"] == n["displayed_at"]  # the first report of a fact wins
    rows = nw.rows(
        "SELECT count(*) FROM notification_attempts WHERE notification_id = %s AND source = 'device'",
        (nid,),
    )
    assert rows == [(2,)]  # each device fact recorded once


def test_a_receipt_from_anyone_but_the_recipient_is_not_found(nw: NW) -> None:
    owner, family = _two(nw)
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = _my(nw, owner, request)["id"]
    assert (
        nw.call(
            family, "POST", nw.s(f"notifications/{nid}/receipt"), json={"event": "app_received"}
        ).status_code
        == 404
    )
    assert (
        nw.call(
            family,
            "POST",
            nw.s(f"notifications/{uuid.uuid4()}/receipt"),
            json={"event": "app_received"},
        ).status_code
        == 404
    )
    assert (
        nw.call(
            nw.guard, "POST", nw.s(f"notifications/{nid}/receipt"), json={"event": "app_received"}
        ).status_code
        == 403
    )


def test_a_receipt_after_expiry_stamps_the_time_but_does_not_revive(nw: NW) -> None:
    owner, _family = _two(nw)
    nw.sim_device("owner-phone").force_stopped = True
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.shift_request(request["id"], 100)
    nw.tick(t0 + secs(90))
    nid = _my(nw, owner, request)["id"]
    r = nw.call(
        owner, "POST", nw.s(f"notifications/{nid}/receipt"), json={"event": "displayed"}
    ).json()
    assert (
        r["notification"]["state"] == "expired"
        and r["actionable"] is False
        and r["request_status"] == "expired"
    )
    assert r["notification"]["displayed_at"] is not None


# ------------------------------------------------------------------------------------------------------------ NOTIF-05
def test_the_deep_link_fetches_the_current_state_not_the_state_at_send_time(nw: NW) -> None:
    owner, family = _two(nw)
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = _my(nw, owner, request)["id"]
    first = nw.call(owner, "GET", nw.s(f"notifications/{nid}")).json()
    assert first["request"]["status"] == "pending" and first["actionable"] is True
    assert (
        first["notification"]["app_received_at"] is not None
    )  # the authenticated fetch is the app's receipt
    assert first["request"]["id"] == request["id"]  # the immutable request id
    d = nw.decide(family, request)
    assert d.status_code == 200
    second = nw.call(owner, "GET", nw.s(f"notifications/{nid}")).json()
    assert second["request"]["status"] == "approved" and second["actionable"] is False
    assert second["request"]["decision"]["by_role"] in ("family", "owner_occ", "tenant")


def test_a_late_action_after_expiry_shows_the_expiry(nw: NW) -> None:
    owner, _family = _two(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nid = _my(nw, owner, request)["id"]
    nw.shift_request(request["id"], 100)
    r = nw.call(
        owner,
        "POST",
        nw.s(f"notifications/{nid}/action"),
        json={"action": "approve", "client_action_id": str(uuid.uuid4())},
    )
    assert r.status_code == 409 and r.json()["code"] == "request_expired"
    assert (
        r.json()["details"]["canonical"]["status"] == "expired"
        and r.json()["details"]["canonical"]["permission_expires_at"] is None
    )
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(0,)]
    seen = nw.call(owner, "GET", nw.s(f"notifications/{nid}")).json()
    assert seen["request"]["status"] == "expired" and seen["actionable"] is False


def test_the_lock_screen_action_decides_through_the_visits_service(nw: NW) -> None:
    owner, _family = _two(nw)
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = _my(nw, owner, request)["id"]
    r = nw.call(
        owner,
        "POST",
        nw.s(f"notifications/{nid}/action"),
        json={"action": "approve", "client_action_id": str(uuid.uuid4())},
    )
    assert r.status_code == 200, r.text
    assert (
        r.json()["decision"]["status"] == "approved"
        and r.json()["decision"]["entry_observed"] is False
    )
    assert r.json()["notification"]["state"] == "actioned"
    assert nw.rows(
        "SELECT channel, decision, decided_by FROM approval_decisions WHERE request_id = %s",
        (request["id"],),
    ) == [("app", "approve", owner.id)]
    assert nw.rows("SELECT count(*) FROM audit_log WHERE operation = 'approval.decide'") == [(1,)]


def test_a_member_who_left_cannot_act_from_an_old_notification(nw: NW) -> None:
    owner, family = _two(nw)
    nw.sim_device(
        "owner-phone"
    ).force_stopped = True  # no acknowledgement: the alternate is notified at t = 10 s
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10):
        nw.tick(t0 + secs(at))
    nid = _my(nw, family, request)["id"]
    nw.sql(
        "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
        (family.id,),
    )
    r = nw.call(
        family,
        "POST",
        nw.s(f"notifications/{nid}/action"),
        json={"action": "approve", "client_action_id": str(uuid.uuid4())},
    )
    assert r.status_code in (403, 404)  # membership re-checked: standing gone
    assert nw.call(family, "GET", nw.s(f"notifications/{nid}")).status_code in (403, 404)
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]


def test_someone_elses_notification_cannot_be_acted_on(nw: NW) -> None:
    owner, family = _two(nw)
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = _my(nw, owner, request)["id"]
    r = nw.call(
        family,
        "POST",
        nw.s(f"notifications/{nid}/action"),
        json={"action": "approve", "client_action_id": str(uuid.uuid4())},
    )
    assert r.status_code == 404
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]


# ------------------------------------------------------------------------------------------------------------ NOTIF-04
def test_a_decision_invalidates_stale_actions_on_every_device_within_two_seconds(nw: NW) -> None:
    owner, family = _two(nw)
    r = nw.set_settings(
        owner,
        nw.unit("A-101"),
        primary_person_id=owner.id,
        approver_person_ids=[owner.id, family.id],
    )
    assert r.status_code == 200, r.text
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    for who in (owner, family):
        assert (
            nw.nrows(request["id"], f"recipient_person_id = '{who.id}'")[0]["state"]
            == "provider_accepted"
        )
    family_nid = _my(nw, family, request)["id"]
    owner_nid = _my(nw, owner, request)["id"]
    started = time.monotonic()
    d = nw.call(
        owner,
        "POST",
        nw.s(f"notifications/{owner_nid}/action"),
        json={"action": "deny", "client_action_id": str(uuid.uuid4())},
    )
    assert d.status_code == 200, d.text
    # the other device's action is refused AT ONCE: the decision is the committed state, no job has to run for that
    stale = nw.call(
        family,
        "POST",
        nw.s(f"notifications/{family_nid}/action"),
        json={"action": "approve", "client_action_id": str(uuid.uuid4())},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "already_decided"
    assert stale.json()["details"]["canonical"]["status"] == "denied"
    # and the worker withdraws what is still open
    nw.tick()
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, (
        elapsed
    )  # SIMULATION, one process: decision to withdrawn on both devices (NOTIF-04 target: 2 s)
    states = {
        r["recipient_person_id"]: (r["state"], r["closed_reason"]) for r in nw.nrows(request["id"])
    }
    assert states[owner.id][0] == "actioned" and states[family.id] == ("expired", "request_decided")
    assert nw.sims.push.cancelled  # the provider was told to withdraw the other device's push
    lat = nw.rows(
        "SELECT extract(epoch FROM (n.invalidated_at - d.decided_at)) FROM notifications n JOIN approval_decisions d ON d.request_id = n.request_id"
        " WHERE n.recipient_person_id = %s AND n.request_id = %s", (family.id, request["id"]))[0][0]  # fmt: skip
    assert float(lat) < 2.0, (
        lat
    )  # invalidated_at (job clock) minus the database-stamped decision time


def test_cancelling_ringing_hangs_the_call_up(nw: NW) -> None:
    owner, family = _two(nw)
    nw.sims.ivr.script(
        f"person:{owner.id}", outcome="answered", dtmf=None, duration_s=60, answer_delay_s=5
    )
    nw.sim_device("owner-phone").force_stopped = True
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(20))  # the masked call is ringing
    assert nw.sims.ivr.cancelled == []
    d = nw.decide(family, request)  # somebody else answers on the app
    assert d.status_code == 200
    nw.tick(t0 + secs(22))
    assert len(nw.sims.ivr.cancelled) == 1  # hung up
    nw.tick(t0 + secs(23))  # the provider reports the call ended by cancellation
    row = nw.rows(
        "SELECT state, dial_outcome FROM proxy_call_sessions WHERE request_id = %s",
        (request["id"],),
    )[0]
    assert row == ("completed", "cancelled")


# ------------------------------------------------------------------------------------------------------------ AT-11 building blocks
def test_notification_permission_denied_makes_no_delivery_claim_and_offers_the_fallback(
    nw: NW,
) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone", permission="denied")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    rows = nw.nrows(request["id"])
    assert (
        rows[0]["failure_reason"] == "notification_permission_denied"
        and rows[0]["provider_ref"] is None
    )
    assert (
        rows[0]["state"] == "created" and nw.sims.push.sent == []
    )  # the OS would drop it: we do not even send
    board = _board(nw, request)
    assert (
        board["fallback"]["offered"] == ["masked_call", "intercom"]
        and board["fallback"]["reason"] == "app_unreachable"
    )
    assert board["summary"]["person_reached"] is False
    nw.set_settings(owner, nw.unit("A-101"), fallback_mode="intercom")
    assert _board(nw, request)["fallback"]["offered"] == [
        "intercom"
    ]  # the household's configured fallback


def test_a_force_stopped_phone_is_never_reported_as_reached(nw: NW) -> None:
    owner, family = _two(nw)
    nw.sim_device("owner-phone").force_stopped = True
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    assert _board(nw, request)["fallback"]["offered"] == []  # too early to say
    nw.shift_request(
        request["id"], 10
    )  # ten real seconds have passed (the board reads the database clock)
    nw.tick(t0 + secs(10))
    board = _board(nw, request)
    assert (
        board["fallback"]["offered"] == ["masked_call", "intercom"]
        and board["fallback"]["reason"] == "no_app_acknowledgement"
    )
    assert board["summary"]["person_reached"] is False
    nw.tick(t0 + secs(20))
    assert any(
        r["channel"] == "ivr_call" for r in nw.nrows(request["id"])
    )  # the configured call is placed


def test_a_phone_without_any_registered_device_is_recorded_as_such(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    assert nw.nrows(request["id"])[0]["failure_reason"] == "no_active_device"
    assert _board(nw, request)["fallback"]["offered"] == ["masked_call", "intercom"]
