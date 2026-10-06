"""NOTIF-09 lock-screen text, GATE-13 / CALL-01 masking: no visitor identity and unit unless opted in; no raw phone number anywhere.

REQ: NOTIF-09, GATE-13, CALL-01, OBS-01 (no phones in logs), INV-01.
"""

from __future__ import annotations

import json
import logging
import re

import pytest

from dwaar_api.modules.notifications import categories as cat
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-09", "CALL-01")]
PHONE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")


def test_the_lock_screen_omits_visitor_and_unit_unless_the_resident_opted_in(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    request = nw.raise_request(nw.unit("A-101"), visitor_alias="Zubin Contractor")
    nw.tick(nw.created_at(request["id"]))
    msg = nw.sims.push.sent[0]
    shown = f"{msg.title} {msg.text}"
    assert "Zubin" not in shown and "101" not in shown and "Contractor" not in shown
    assert json.dumps(msg.payload).count("Zubin") == 0 and "101" not in json.dumps(msg.payload)
    assert set(msg.payload) == {
        "notification_id",
        "request_id",
        "expires_at",
        "category",
        "priority",
        "channel_id",
    }  # ids and time only
    assert nw.rows(
        "SELECT lockscreen_identity FROM notifications WHERE request_id = %s", (request["id"],)
    ) == [(False,)]
    assert msg.title == cat.copy("approval.request.lockscreen.title") and msg.text == cat.copy(
        "approval.request.lockscreen.body"
    )


def test_after_the_opt_in_the_lock_screen_names_the_visitor_and_the_unit(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    r = nw.call(
        owner,
        "PUT",
        nw.s("notification-preferences/me"),
        json={
            "show_identity_on_lockscreen": True,
            "whatsapp_opt_in": False,
            "sms_opt_in": False,
            "language": "en",
        },
    )
    assert r.status_code == 200
    request = nw.raise_request(nw.unit("A-101"), visitor_alias="Zubin Contractor")
    nw.tick(nw.created_at(request["id"]))
    msg = nw.sims.push.sent[0]
    assert "Zubin Contractor" in msg.text and "101" in msg.text
    assert (
        json.dumps(msg.payload).count("Zubin") == 0
    )  # the data payload stays identity-free: the app fetches the request itself
    assert nw.rows(
        "SELECT lockscreen_identity FROM notifications WHERE request_id = %s", (request["id"],)
    ) == [(True,)]
    seen = nw.call(owner, "GET", nw.s("notifications")).json()["items"][0]
    assert seen["lockscreen_identity"] is True


def test_the_copy_follows_the_residents_language(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.call(
        owner,
        "PUT",
        nw.s("notification-preferences/me"),
        json={
            "show_identity_on_lockscreen": False,
            "whatsapp_opt_in": False,
            "sms_opt_in": False,
            "language": "mr",
        },
    )
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    msg = nw.sims.push.sent[0]
    assert msg.language == "mr" and msg.title == cat.copy(
        "approval.request.lockscreen.title", "mr"
    ) != cat.copy("approval.request.lockscreen.title", "en")


def test_a_sms_or_whatsapp_text_carries_no_identity_either(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sims.push.default_device.force_stopped = True
    nw.call(
        family,
        "PUT",
        nw.s("notification-preferences/me"),
        json={
            "show_identity_on_lockscreen": True,
            "whatsapp_opt_in": True,
            "sms_opt_in": False,
            "language": "en",
        },
    )
    nw.call(
        nw.secretary,
        "POST",
        nw.s("notification-templates"),
        json={
            "template_key": "approval.link",
            "category": "security_approval",
            "channel": "whatsapp",
            "language": "en",
            "body_key": "approval.link.whatsapp",
            "whitelisted_url": "https://links.dwaar.example/r",
        },
    )
    request = nw.raise_request(nw.unit("A-101"), visitor_alias="Zubin Contractor")
    t0 = nw.created_at(request["id"])
    for at in (0, 35):
        nw.tick(t0 + secs(at))
    wa = nw.sims.whatsapp.sent[0]
    assert (
        "Zubin" not in wa.text and "101" not in wa.text and wa.link is not None
    )  # a link has no identity even for an opted-in lock screen


def test_no_raw_phone_number_appears_in_any_response_row_or_log(
    nw: NW, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.sims.ivr.script(f"person:{owner.id}", outcome="answered", dtmf="3")
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 26, 40):
        nw.tick(t0 + secs(at))
    nw.call(
        nw.guard,
        "POST",
        nw.s(f"approval-requests/{request['id']}/proxy-calls"),
        json={"target": "alternate", "gate_id": str(nw.gate_id)},
    )
    nw.tick(t0 + secs(45))
    gp = {"gate_id": str(nw.gate_id)}
    responses = [
        nw.call(
            nw.guard,
            "GET",
            nw.s(f"approval-requests/{request['id']}/notification-status"),
            params=gp,
        ),
        nw.call(owner, "GET", nw.s("notifications")),
        nw.call(owner, "GET", nw.s(f"units/{nw.unit('A-101')}/notification-settings")),
        nw.call(nw.secretary, "GET", nw.s("notification-metrics")),
        nw.call(nw.secretary, "GET", nw.s("device-health")),
        nw.call(nw.secretary, "GET", nw.s("notification-providers")),
        nw.call(owner, "GET", nw.s("push-tokens")),
    ]
    blob = "".join(r.text for r in responses)
    people = [p.phone for p in (owner, family, nw.guard, nw.secretary, nw.guard_sup)]
    for number in people:
        assert number not in blob and number[-10:] not in blob
    assert PHONE.search(blob) is None
    for sql in (
        "SELECT diff_masked FROM audit_log",
        "SELECT payload FROM outbox",
        "SELECT detail FROM notification_attempts",
        "SELECT masked_label, contact_ref FROM proxy_call_sessions",
        "SELECT * FROM notifications",
    ):
        dump = json.dumps(nw.rows(sql), default=str)
        for number in people:
            assert number[-10:] not in dump, sql
    logs = " ".join(
        r.getMessage() + json.dumps(getattr(r, "__dict__", {}), default=str)
        for r in caplog.records
        if r.name.startswith("dwaar_api.notifications")
    )
    assert PHONE.search(logs) is None
    for sent in nw.sims.ivr.sent + nw.sims.push.sent:
        assert (
            PHONE.search(json.dumps([sent.contact_ref, sent.text, sent.title, sent.payload]))
            is None
        )


def test_mask_helpers() -> None:
    assert cat.mask_phone_like(
        "call +91 98765 43210 now"
    ) == "call [phone] now" and cat.contains_phone_like("9876543210")
    assert not cat.contains_phone_like("request 12345")
