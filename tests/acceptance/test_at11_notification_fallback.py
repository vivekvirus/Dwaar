"""AT-11 (M1): phone force-stopped or notification permission denied -> no false delivery claim; configured call or intercom fallback.

PRD 16: "Phone force-stopped or notification permission denied. Required outcome: No false delivery claim; configured call or intercom fallback."
PRD 9.4 NOTIF-02 (provider acceptance is never displayed as delivery to a person), NOTIF-06, CALL-01.

Dataset: the real seed (A-203, Ganesh the primary approver with a SIMULATED registered phone, Rekha the alternate), the real API and worker tick, simulators
labelled ``simulation = true``. SIMULATION: how a force-stopped phone or a denied permission BEHAVES is scripted on the simulator (the provider accepts and
nothing ever comes back; a denied permission is known from the device's own report). No real Android or iOS device, and no real push behaviour, took part.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from tests.acceptance._notify_world import Scene, scene
from tests.acceptance._world import DATASET, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-11", dataset=DATASET),
    pytest.mark.req("NOTIF-02", "NOTIF-06", "CALL-01", "INV-07"),
]


def _secs(n: float) -> dt.timedelta:
    return dt.timedelta(seconds=n)


def _no_delivery_claim(sc: Scene, rid: str) -> None:
    board = sc.board(sc.guard, rid)
    assert board["summary"]["person_reached"] is False
    assert all(n["person_reached"] is False for n in board["notifications"])
    assert "delivered" not in json.dumps(board).lower()
    mine = sc.world.call(sc.ganesh, "GET", sc.s("notifications")).json()["items"]
    assert mine and all(n["person_reached"] is False for n in mine if n["request_id"] == rid)
    assert "delivered" not in json.dumps(mine).lower()


def test_at11_a_force_stopped_phone_is_never_reported_as_reached_and_the_configured_call_follows(
    fresh_world: World,
) -> None:
    sc = scene(fresh_world)
    sc.phone("ganesh").force_stopped = True
    sc.phone(
        "rekha"
    ).force_stopped = True  # the alternate adult's phone is stopped too: nobody's app can report
    request = sc.raise_request("AT-11 force stopped")
    rid, t0 = request["id"], sc.created_at(request["id"])
    sc.tick(t0)
    first = sc.rows(rid)[0]
    assert (
        first["state"] == "provider_accepted" and first["app_received_at"] is None
    )  # accepted by the provider, NOT received by the app
    sc.age(rid, 12)  # twelve seconds on the database clock
    sc.tick(t0 + _secs(12))
    board = sc.board(sc.guard, rid)
    assert board["fallback"]["reason"] == "no_app_acknowledgement" and board["fallback"][
        "offered"
    ] == ["masked_call", "intercom"]
    assert board["summary"]["provider_accepted_only"] >= 1
    _no_delivery_claim(sc, rid)
    sc.tick(t0 + _secs(20))
    assert [r["channel"] for r in sc.rows(rid)].count(
        "ivr_call"
    ) == 1  # the household's configured call is placed
    assert sc.world.admin_rows("SELECT state FROM approval_requests WHERE id = %s", (rid,)) == [
        ("pending",)
    ]  # silence never allows
    _no_delivery_claim(sc, rid)


def test_at11_a_denied_permission_is_known_so_nothing_is_sent_and_the_fallback_is_offered_at_once(
    fresh_world: World,
) -> None:
    sc = scene(fresh_world)
    token = sc.world.admin_rows(
        "SELECT token_hash FROM device_push_tokens WHERE device_label = 'Seeded simulated phone' LIMIT 1"
    )
    assert token  # the seeded simulated phone
    from dwaar_api.seed.steps.s590_notifications import _token

    refreshed = sc.world.call(
        sc.ganesh,
        "POST",
        sc.s("push-tokens"),
        json={"platform": "fcm", "token": _token("ganesh"), "notification_permission": "denied"},
    )
    assert refreshed.status_code == 201 and refreshed.json()["notification_permission"] == "denied"
    request = sc.raise_request("AT-11 permission denied")
    rid, t0 = request["id"], sc.created_at(request["id"])
    sc.tick(t0)
    row = sc.rows(rid)[0]
    assert (
        row["failure_reason"] == "notification_permission_denied"
        and row["provider_ref"] is None
        and row["state"] == "created"
    )
    assert sc.sims.push.sent == []  # the OS would have dropped it: no provider call, no claim
    board = sc.board(sc.guard, rid)
    assert board["fallback"]["reason"] == "app_unreachable" and board["fallback"]["offered"] == [
        "masked_call",
        "intercom",
    ]
    _no_delivery_claim(sc, rid)


def test_at11_a_household_that_configured_the_intercom_is_offered_the_intercom_and_no_call(
    fresh_world: World,
) -> None:
    sc = scene(fresh_world)
    sc.phone("ganesh").force_stopped = True
    sc.phone("rekha").force_stopped = True
    current = sc.world.call(sc.ganesh, "GET", sc.s(f"units/{sc.unit}/notification-settings")).json()
    saved = sc.world.call(sc.ganesh, "PUT", sc.s(f"units/{sc.unit}/notification-settings"), json={
        "primary_person_id": current["primary_person_id"], "approver_person_ids": current["approver_person_ids"],
        "alternate_person_id": current["alternate_person_id"], "fallback_mode": "intercom", "expected_version": current["version"]})  # fmt: skip
    assert saved.status_code == 200, saved.text
    request = sc.raise_request("AT-11 intercom household")
    rid, t0 = request["id"], sc.created_at(request["id"])
    sc.tick(t0)
    sc.age(rid, 12)
    for at in (12, 20, 40):
        sc.tick(t0 + _secs(at))
    board = sc.board(sc.guard, rid)
    assert (
        board["fallback"]["offered"] == ["intercom"]
        and board["fallback"]["text_key"] == "fallback.intercom"
    )
    assert "ivr_call" not in [r["channel"] for r in sc.rows(rid)] and sc.sims.ivr.sent == []
    _no_delivery_claim(sc, rid)


def test_at11_the_diagnostic_never_promises_delivery_even_when_nothing_is_wrong(
    fresh_world: World,
) -> None:
    sc = scene(fresh_world)
    r = sc.world.call(sc.ganesh, "POST", sc.s("device-diagnostics"), json={
        "manufacturer": "Xiaomi", "notification_permission": "granted", "battery_optimisation": "unrestricted", "focus_mode_blocks": "no", "test_push": "received"})  # fmt: skip
    assert r.status_code == 201
    assert r.json()["verdict"] == "no_problem_found" and r.json()["delivery_guaranteed"] is False
    guide = sc.world.call(
        sc.ganesh, "GET", sc.s("device-diagnostics/guidance"), params={"manufacturer": "Xiaomi"}
    ).json()
    assert (
        guide["rules"]["battery_exemption_guarantees_delivery"] is False
        and guide["rules"]["fake_incoming_call_ui"] is False
    )
