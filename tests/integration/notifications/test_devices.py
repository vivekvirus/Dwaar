"""Push-token registry, IAM-11 revocation, the on-device diagnostic and its manufacturer guidance, preferences and household settings.

REQ: IAM-11 (a number change revokes push tokens), NOTIF-06 (diagnostic; Xiaomi/HyperOS, Oppo/ColorOS, Vivo/Funtouch, Samsung, iOS Focus; no battery
exemption guarantee, no fake incoming-call UI), NOTIF-07 (telemetry by model and OS), NOTIF-09 (identity opt-in is the resident's own), NOTIF-03
(alternate adult configuration), D-21 (FCM / APNs simulated).
"""

from __future__ import annotations

import json
import uuid

import pytest

from dwaar_api.modules.notifications import catalog
from tests.integration.identity._support import phone
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("IAM-11", "NOTIF-06", "NOTIF-07")]


def test_the_token_is_registered_as_a_hash_and_never_echoed(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    body = nw.register_device(owner, "phone-a")
    assert body["token_ref"].startswith("tk_") and body["notification_permission"] == "granted"
    blob = json.dumps(body) + json.dumps(
        nw.rows("SELECT * FROM audit_log WHERE operation LIKE 'notification.token%%'"), default=str
    )
    blob += json.dumps(
        nw.rows("SELECT payload FROM outbox WHERE event_type LIKE 'notification.token%%'"),
        default=str,
    )
    assert (
        nw.tokens["phone-a"] not in blob
    )  # neither the response, nor audit, nor events carry the token
    stored = nw.rows("SELECT token_hash, token_ref FROM device_push_tokens")[0]
    assert nw.tokens["phone-a"] not in "".join(stored) and len(stored[0]) == 64


def test_registering_twice_refreshes_and_a_reassigned_token_leaves_the_old_owner(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    first = nw.register_device(owner, "phone-a")
    token = nw.tokens["phone-a"]
    r = nw.call(
        owner,
        "POST",
        nw.s("push-tokens"),
        json={"platform": "fcm", "token": token, "notification_permission": "granted"},
    )
    assert r.status_code == 201 and r.json()["id"] == first["id"]  # a refresh, not a second device
    r = nw.call(
        family,
        "POST",
        nw.s("push-tokens"),
        json={"platform": "fcm", "token": token, "notification_permission": "granted"},
    )
    assert r.status_code == 201 and r.json()["id"] != first["id"]  # the phone changed hands
    mine = nw.call(owner, "GET", nw.s("push-tokens")).json()["items"]
    assert mine == []  # the old owner no longer has it
    assert nw.rows(
        "SELECT revoked_reason FROM device_push_tokens WHERE id = %s", (first["id"],)
    ) == [("reassigned_to_another_person",)]


def test_a_person_can_only_revoke_their_own_device(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    dev = nw.register_device(owner, "phone-a")
    assert nw.call(family, "DELETE", nw.s(f"push-tokens/{dev['id']}")).status_code == 404
    assert nw.call(family, "DELETE", nw.s(f"push-tokens/{uuid.uuid4()}")).status_code == 404
    r = nw.call(owner, "DELETE", nw.s(f"push-tokens/{dev['id']}"))
    assert r.status_code == 200 and r.json()["revoked_reason"] == "revoked_by_owner"


def test_a_revoked_device_is_not_pushed_to(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    dev = nw.register_device(owner, "phone-a")
    nw.call(owner, "DELETE", nw.s(f"push-tokens/{dev['id']}"))
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    assert (
        nw.sims.push.sent == []
        and nw.nrows(request["id"])[0]["failure_reason"] == "no_active_device"
    )


def test_there_is_a_limit_to_active_devices_per_person(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    for i in range(6):
        nw.register_device(owner, f"d{i}")
    r = nw.call(
        owner,
        "POST",
        nw.s("push-tokens"),
        json={"platform": "apns", "token": "x" * 40, "notification_permission": "granted"},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "too_many_devices"


# ------------------------------------------------------------------------------------------------------------ IAM-11
def test_a_number_change_revokes_push_tokens_and_the_old_phone_is_not_notified(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "old-phone")
    request = nw.raise_request(nw.unit("A-101"))
    new_number = phone(4444)
    c = nw.client
    assert (
        c.post(
            "/v1/auth/phone/change/request", json={"phone": new_number}, headers=owner.headers
        ).status_code
        == 202
    )
    code = nw.idh.otp(new_number, c)
    ok = c.post(
        "/v1/auth/phone/change/confirm",
        json={"phone": new_number, "code": code},
        headers=owner.headers,
    )
    assert ok.status_code == 200, ok.text
    # the membership went back to review in the same transaction: even BEFORE the worker runs, the old phone is not notified
    nw.tick(nw.created_at(request["id"]))
    first = nw.nrows(request["id"])
    assert all(
        r["recipient_person_id"] != owner.id or r["failure_reason"] == "recipient_not_authorised"
        for r in first
    )
    assert nw.sims.push.sent == []
    # and the worker revokes the registry entry
    assert nw.rows(
        "SELECT revoked_reason FROM device_push_tokens WHERE person_id = %s", (owner.id,)
    ) == [("phone_number_changed",)]
    assert nw.audit("notification.token.revoke")


# ------------------------------------------------------------------------------------------------------------ diagnostic (NOTIF-06)
@pytest.mark.parametrize(("maker", "family"), [("Xiaomi", "xiaomi"), ("Redmi", "xiaomi"), ("OPPO", "oppo"), ("realme", "oppo"), ("vivo", "vivo"),
                                         ("samsung", "samsung"), ("Apple", "apple"), ("Nokia", "other"), ("", "other")])  # fmt: skip
def test_guidance_exists_for_every_named_manufacturer(maker: str, family: str) -> None:
    g = catalog.guidance_for(maker)
    assert (
        g["manufacturer"] == family
        and g["steps"]
        and g["rules"]["battery_exemption_guarantees_delivery"] is False
    )
    assert g["rules"]["fake_incoming_call_ui"] is False


def test_the_guidance_route_never_claims_a_guarantee_and_names_the_oem_families(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    r = nw.call(owner, "GET", nw.s("device-diagnostics/guidance"))
    assert r.status_code == 200
    body = r.json()
    assert {g["manufacturer"] for g in body["guidance"]} == {
        "xiaomi",
        "oppo",
        "vivo",
        "samsung",
        "apple",
        "other",
    }
    assert {g["os_family"] for g in body["guidance"]} >= {
        "HyperOS / MIUI",
        "ColorOS",
        "Funtouch OS",
        "One UI",
        "iOS",
    }
    assert body["rules"] == {
        "battery_exemption_guarantees_delivery": False,
        "fake_incoming_call_ui": False,
        "disclaimer_key": "diag.disclaimer.no_guarantee",
    }
    one = nw.call(
        owner, "GET", nw.s("device-diagnostics/guidance"), params={"manufacturer": "Samsung"}
    ).json()
    assert [g["manufacturer"] for g in one["guidance"]] == ["samsung"]
    assert "guarantee" not in json.dumps(body).replace("guarantees_delivery", "").replace(
        "no_guarantee", ""
    )  # keys only, no promise in prose


def test_a_diagnostic_with_problems_returns_the_steps_for_that_manufacturer_and_no_guarantee(
    nw: NW,
) -> None:
    owner, _ = nw.household2("A-101")
    dev = nw.register_device(owner, "phone-a")
    r = nw.call(
        owner,
        "POST",
        nw.s("device-diagnostics"),
        json={
            "token_id": dev["id"],
            "manufacturer": "Xiaomi",
            "device_model": "Redmi Note 12",
            "os_name": "HyperOS",
            "os_version": "1.0",
            "notification_permission": "denied",
            "battery_optimisation": "optimised",
            "focus_mode_blocks": "unknown",
            "test_push": "not_received",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["verdict"] == "needs_attention" and body["delivery_guaranteed"] is False
    ids = {s["id"] for s in body["problem_steps"]}
    assert "notification_permission" in ids and "test_push" in ids
    # the permission the device reported is now on the token: the cascade will not push to a phone that cannot show it
    assert nw.rows(
        "SELECT notification_permission, manufacturer FROM device_push_tokens WHERE id = %s",
        (dev["id"],),
    ) == [("denied", "xiaomi")]


def test_even_a_clean_diagnostic_never_says_delivery_is_guaranteed(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    r = nw.call(
        owner,
        "POST",
        nw.s("device-diagnostics"),
        json={
            "manufacturer": "Samsung",
            "notification_permission": "granted",
            "battery_optimisation": "unrestricted",
            "focus_mode_blocks": "no",
            "test_push": "received",
        },
    )
    body = r.json()
    assert body["verdict"] == "no_problem_found" and body["delivery_guaranteed"] is False
    assert (
        body["verdict_text_key"] == "diag.verdict.no_problem_found"
        and body["disclaimer_key"] == "diag.disclaimer.no_guarantee"
    )


def test_the_diagnostic_of_someone_elses_device_is_not_found(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    dev = nw.register_device(owner, "phone-a")
    r = nw.call(
        family,
        "POST",
        nw.s("device-diagnostics"),
        json={"token_id": dev["id"], "manufacturer": "Oppo", "notification_permission": "granted"},
    )
    assert r.status_code == 404


# ------------------------------------------------------------------------------------------------------------ preferences and settings
def test_the_identity_opt_in_is_the_residents_own_and_defaults_off(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    mine = nw.call(owner, "GET", nw.s("notification-preferences/me")).json()
    assert (
        mine["show_identity_on_lockscreen"] is False
        and mine["whatsapp_opt_in"] is False
        and mine["sms_opt_in"] is False
    )
    r = nw.call(
        owner,
        "PUT",
        nw.s("notification-preferences/me"),
        json={
            "show_identity_on_lockscreen": True,
            "whatsapp_opt_in": True,
            "sms_opt_in": False,
            "language": "hi",
        },
    )
    assert (
        r.status_code == 200
        and r.json()["show_identity_on_lockscreen"] is True
        and r.json()["language"] == "hi"
    )
    assert (
        nw.call(family, "GET", nw.s("notification-preferences/me")).json()[
            "show_identity_on_lockscreen"
        ]
        is False
    )  # not shared
    assert nw.audit("notification.preferences.put")
    for who in (nw.guard, nw.secretary):
        assert nw.call(who, "GET", nw.s("notification-preferences/me")).status_code == 403


def test_unit_settings_accept_only_current_adult_approvers_of_the_unit(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    outsider = nw.resident(nw.unit("A-102"), "owner")
    unit = nw.unit("A-101")
    ok = nw.set_settings(
        owner,
        unit,
        primary_person_id=owner.id,
        approver_person_ids=[owner.id],
        alternate_person_id=family.id,
        fallback_mode="intercom",
    )
    assert ok.status_code == 200, ok.text
    assert (
        ok.json()["alternate_person_id"] == str(family.id)
        and ok.json()["fallback_mode"] == "intercom"
        and ok.json()["version"] == 1
    )
    bad = nw.set_settings(owner, unit, alternate_person_id=outsider.id)
    assert bad.status_code == 400 and "must_be_an_approver_of_this_unit" in json.dumps(bad.json())
    same = nw.set_settings(owner, unit, primary_person_id=owner.id, alternate_person_id=owner.id)
    assert same.status_code == 400
    stale = nw.set_settings(owner, unit, alternate_person_id=family.id, expected_version=7)
    assert stale.status_code == 409
    upd = nw.set_settings(
        owner, unit, alternate_person_id=None, fallback_mode="call", expected_version=1
    )
    assert upd.status_code == 200 and upd.json()["version"] == 2
    got = nw.call(owner, "GET", nw.s(f"units/{unit}/notification-settings")).json()
    assert got["fallback_mode"] == "call" and got["effective"]["defaults_in_use"] is False
    assert (
        nw.call(outsider, "GET", nw.s(f"units/{unit}/notification-settings")).status_code == 404
    )  # not their unit
    assert (
        nw.call(nw.secretary, "GET", nw.s(f"units/{unit}/notification-settings")).status_code == 200
    )
    assert nw.call(nw.guard, "GET", nw.s(f"units/{unit}/notification-settings")).status_code == 403


def test_a_family_member_without_the_delegation_cannot_be_named(nw: NW) -> None:
    owner, _family = nw.household2("A-101")
    plain = nw.resident(nw.unit("A-101"), "family", delegated=False)
    r = nw.set_settings(owner, nw.unit("A-101"), alternate_person_id=plain.id)
    assert r.status_code == 400  # a push that offered an action the decision would refuse
    assert (
        nw.call(
            plain,
            "PUT",
            nw.s(f"units/{nw.unit('A-101')}/notification-settings"),
            json={"fallback_mode": "call"},
        ).status_code
        == 403
    )


def test_telemetry_by_model_and_os_comes_from_the_device_reports(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(
        owner,
        "phone-a",
        model="Redmi Note 12",
        manufacturer="Xiaomi",
        os_name="HyperOS",
        os_version="1.0",
    )
    from dwaar_api.modules.notifications.providers import DeviceTelemetry

    nw.sim_device("phone-a").telemetry = DeviceTelemetry(
        "Redmi Note 12", "xiaomi", "HyperOS", "1.0"
    )
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(2))
    row = nw.nrows(request["id"])[0]
    assert row["state"] == "displayed"
    assert nw.rows(
        "SELECT phone_model, os_name, os_version FROM notifications WHERE request_id = %s",
        (request["id"],),
    ) == [("Redmi Note 12", "HyperOS", "1.0")]
