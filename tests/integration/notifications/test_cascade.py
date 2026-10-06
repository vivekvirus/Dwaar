"""The approval cascade end to end on the real database with an injectable clock and the labelled provider simulators.

REQ: NOTIF-03 (t=0 push to the selected approvers; t=10 s alternate without app acknowledgement; t=20 s masked IVR to the primary; t=35 s
WhatsApp / SMS link to opted-in recipients; t=90 s expire with guard-assisted options; one primary and one alternate call per attempt unless a
supervisor starts a new attempt), NOTIF-04, INV-03 (no auto-allow), D-15, OBS-02.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-03", "D-15", "INV-03")]


def _roles(rows: list[dict]) -> list[tuple[str, str, int]]:  # type: ignore[type-arg]
    return [(r["channel"], r["recipient_role"], r["cascade_step"]) for r in rows]


def _setup(nw: NW, *, ack: bool = False) -> tuple:  # type: ignore[type-arg]
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.register_device(family, "family-phone", model="SM-A546E", manufacturer="Samsung")
    if not ack:
        nw.sim_device(
            "owner-phone"
        ).force_stopped = True  # the provider accepts, the phone never reports
    return owner, family


# REQ: NOTIF-03
def test_the_cascade_follows_the_pack_timings_on_the_injected_clock(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    assert _roles(nw.nrows(request["id"])) == [("push", "primary", 1)]
    nw.tick(t0 + secs(9.5))
    assert len(nw.nrows(request["id"])) == 1  # not yet
    nw.tick(t0 + secs(10))
    assert _roles(nw.nrows(request["id"])) == [("push", "primary", 1), ("push", "alternate", 2)]
    nw.tick(t0 + secs(19.5))
    assert len(nw.nrows(request["id"])) == 2
    nw.tick(t0 + secs(20))
    rows = nw.nrows(request["id"])
    assert _roles(rows)[-1] == ("ivr_call", "primary", 3)
    assert rows[-1]["state"] == "provider_accepted"  # a call placed is not a call answered
    nw.tick(t0 + secs(89))
    assert [r["channel"] for r in nw.nrows(request["id"])] == [
        "push",
        "push",
        "ivr_call",
    ]  # no opt-in: no link


def test_the_link_step_goes_only_to_opted_in_recipients_with_a_registered_template(nw: NW) -> None:
    owner, family = _setup(nw)
    # family opts in to SMS; the template is registered with DLT ids and a whitelisted link (CALL-02)
    assert (
        nw.call(
            family,
            "PUT",
            nw.s("notification-preferences/me"),
            json={
                "show_identity_on_lockscreen": False,
                "whatsapp_opt_in": False,
                "sms_opt_in": True,
                "language": "en",
            },
        ).status_code
        == 200
    )
    made = nw.call(
        nw.secretary,
        "POST",
        nw.s("notification-templates"),
        json={
            "template_key": "approval.link",
            "category": "security_approval",
            "channel": "sms",
            "language": "en",
            "body_key": "approval.link.sms",
            "dlt_header": "DWAARX",
            "dlt_template_id": "1107160000000000001",
            "whitelisted_url": "https://links.dwaar.example/r",
        },
    )
    assert made.status_code == 201, made.text
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 34, 35):
        nw.tick(t0 + secs(at))
    rows = nw.nrows(request["id"])
    assert _roles(rows)[-1] == ("sms", "opted_in", 4)
    assert rows[-1]["state"] == "provider_accepted" and rows[-1]["failure_reason"] is None
    sent = nw.sims.sms.sent[-1]
    assert sent.link is not None and sent.link.startswith("https://links.dwaar.example/r/")
    assert (
        sent.dlt_header == "DWAARX" and "person:" in sent.contact_ref
    )  # an opaque reference, not a number
    nw.tick(t0 + secs(36))
    assert sum(1 for r in nw.nrows(request["id"]) if r["channel"] == "sms") == 1  # once


def test_without_registered_dlt_ids_the_sms_is_a_placeholder_and_never_sent(nw: NW) -> None:
    owner, family = _setup(nw)
    nw.call(
        family,
        "PUT",
        nw.s("notification-preferences/me"),
        json={
            "show_identity_on_lockscreen": False,
            "whatsapp_opt_in": False,
            "sms_opt_in": True,
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
            "channel": "sms",
            "language": "en",
            "body_key": "approval.link.sms",
            "whitelisted_url": "https://links.dwaar.example/r",
        },
    )  # no DLT ids
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 35):
        nw.tick(t0 + secs(at))
    sms = [r for r in nw.nrows(request["id"]) if r["channel"] == "sms"]
    assert (
        len(sms) == 1
        and sms[0]["failure_reason"] == "dlt_template_not_registered"
        and sms[0]["provider_ref"] is None
    )
    assert nw.sims.sms.sent == []  # nothing reached the gateway


def test_an_acknowledging_app_stops_the_alternate_but_not_the_call(nw: NW) -> None:
    owner, family = _setup(nw, ack=True)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(2))  # the simulated phone reports receipt and display
    first = nw.nrows(request["id"])[0]
    assert first["state"] == "displayed" and first["app_received_at"] is not None
    nw.tick(t0 + secs(10))
    assert [r["recipient_role"] for r in nw.nrows(request["id"])] == [
        "primary"
    ]  # acknowledged: no alternate
    nw.tick(t0 + secs(20))
    assert _roles(nw.nrows(request["id"]))[-1] == (
        "ivr_call",
        "primary",
        3,
    )  # "still pending" is the condition of step 3


def test_a_household_that_prefers_the_intercom_gets_no_automated_call(nw: NW) -> None:
    owner, family = _setup(nw)
    r = nw.set_settings(owner, nw.unit("A-101"), fallback_mode="intercom")
    assert r.status_code == 200, r.text
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 40):
        nw.tick(t0 + secs(at))
    assert "ivr_call" not in [r["channel"] for r in nw.nrows(request["id"])]
    assert nw.sims.ivr.sent == []


# REQ: NOTIF-03, AT-40
def test_expiry_shows_the_guard_options_and_never_allows(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20):
        nw.tick(t0 + secs(at))
    nw.shift_request(
        request["id"], 91
    )  # the 90 seconds are over (the database clock decides expiry)
    report = nw.tick(t0 + secs(90))
    assert report.get("cascade_expired") == 1
    assert nw.rows(
        "SELECT state, permission_expires_at FROM approval_requests WHERE id = %s", (request["id"],)
    ) == [("expired", None)]
    assert nw.rows("SELECT state FROM visits WHERE id = %s", (request["visit_id"],)) == [
        ("expired",)
    ]
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(0,)]
    states = {r["state"] for r in nw.nrows(request["id"])}
    assert states == {"expired"}  # every notification is withdrawn
    assert {r["closed_reason"] for r in nw.nrows(request["id"])} == {"request_expired"}
    status = nw.call(
        nw.guard,
        "GET",
        nw.s(f"approval-requests/{request['id']}/notification-status"),
        params={"gate_id": str(nw.gate_id)},
    )
    body = status.json()
    assert body["request_status"] == "expired" and body["auto_allow_on_timeout"] is False
    assert set(body["guard_options"]) == {"hold", "leave_at_gate", "lobby_only", "intercom", "deny"}
    assert body["cascade"]["state"] == "expired"
    # nothing more is ever sent after expiry
    before = nw.sims.total_sent()
    nw.tick(t0 + secs(120))
    nw.tick(t0 + secs(300))
    assert nw.sims.total_sent() == before


def test_a_decision_cancels_the_rest_of_the_cascade(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    d = nw.decide(owner, request)
    assert d.status_code == 200, d.text
    nw.tick(t0 + secs(5))
    assert nw.rows(
        "SELECT state FROM notification_cascades WHERE request_id = %s", (request["id"],)
    ) == [("decided",)]
    for at in (10, 20, 35):
        nw.tick(t0 + secs(at))
    assert _roles(nw.nrows(request["id"])) == [
        ("push", "primary", 1)
    ]  # no alternate, no call, no link
    assert nw.sims.ivr.sent == []
    # the decider's own notification is actioned; no stale notification stays open
    only = nw.nrows(request["id"])[0]
    assert only["state"] == "actioned" and only["action"] == "approve"


# REQ: NOTIF-03, CALL-01
def test_a_second_call_to_the_primary_needs_a_supervisor_attempt(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 21, 25, 30):
        nw.tick(t0 + secs(at))
    assert sum(1 for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call") == 1
    # a guard cannot place another call to the primary in this attempt
    path = nw.s(f"approval-requests/{request['id']}/proxy-calls")
    r = nw.call(nw.guard, "POST", path, json={"target": "primary", "gate_id": str(nw.gate_id)})
    assert r.status_code == 422 and r.json()["details"]["reason"] == "call_limit_reached"
    # nor can a guard start an attempt; the supervisor can
    attempts = nw.s(f"approval-requests/{request['id']}/cascade-attempts")
    assert (
        nw.call(nw.guard, "POST", attempts, json={"reason": "owner did not pick up"}).status_code
        == 403
    )
    r = nw.call(nw.guard_sup, "POST", attempts, json={"reason": "owner did not pick up"})
    assert r.status_code == 201, r.text
    assert r.json()["cascade"]["attempt_no"] == 2
    assert nw.rows("SELECT attempt_no, state FROM notification_cascades WHERE request_id = %s ORDER BY attempt_no", (request["id"],)) == [
        (1, "superseded"), (2, "active")]  # fmt: skip
    started = nw.rows(
        "SELECT started_at FROM notification_cascades WHERE request_id = %s AND attempt_no = 2",
        (request["id"],),
    )[0][0]
    for at in (0, 10, 20):
        nw.tick(started + secs(at))
    calls = [r for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call"]
    assert [c["attempt_no"] for c in calls] == [1, 2]  # one per attempt
    nw.tick(started + secs(25))
    assert len([r for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call"]) == 2
    assert nw.rows(
        "SELECT count(*) FROM audit_log WHERE operation = 'notification.cascade.start' AND reason LIKE %s",
        ("%did not pick up%",),
    ) == [(1,)]


def test_the_database_itself_refuses_a_second_call_to_a_role_in_one_attempt(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 20):
        nw.tick(t0 + secs(at))
    call = [r for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call"][0]
    import psycopg

    with pytest.raises(psycopg.errors.UniqueViolation):
        nw.sql(
            "INSERT INTO notifications (society_id, cascade_id, request_id, attempt_no, category, channel, cascade_step, recipient_role,"
            " recipient_person_id, dedupe_key) SELECT society_id, cascade_id, request_id, attempt_no, category, channel, cascade_step,"
            " recipient_role, recipient_person_id, 'forged-second-call' FROM notifications WHERE id = %s",
            (call["id"],),
        )


# REQ: NOTIF-03 (restarts and duplicates)
def test_ticks_are_idempotent_and_a_replayed_outbox_event_changes_nothing(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0 + secs(20))
    snapshot = nw.nrows(request["id"])
    sent = nw.sims.total_sent()
    for _ in range(3):
        nw.tick(t0 + secs(20))  # a restarted or duplicated worker
    assert nw.nrows(request["id"]) == snapshot and nw.sims.total_sent() == sent
    # the ledger is wiped (a replayed delivery of the same events): no second cascade, no second notification
    nw.sql("ALTER TABLE notification_processed_events DISABLE TRIGGER ALL")
    nw.sql("DELETE FROM notification_processed_events")
    nw.tick(t0 + secs(20))
    assert nw.rows(
        "SELECT count(*) FROM notification_cascades WHERE request_id = %s", (request["id"],)
    ) == [(1,)]
    assert nw.nrows(request["id"]) == snapshot and nw.sims.total_sent() == sent


def test_a_recipient_who_left_the_household_is_not_notified(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.sql(
        "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
        (family.id,),
    )  # the alternate adult moved out
    nw.tick(t0 + secs(10))
    alt = [r for r in nw.nrows(request["id"]) if r["recipient_role"] == "alternate"]
    assert alt == [] or alt[0]["failure_reason"] == "recipient_not_authorised"
    assert len(nw.sims.push.sent) == 1


def test_the_request_expiry_is_never_extended_and_calls_never_follow_a_decision(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0 + secs(1))
    assert abs(nw.expires_at(request["id"]) - (t0 + secs(90))) < secs(
        0.01
    )  # the notification layer never moved it
    nw.decide(family, request)
    before = nw.sims.ivr.sent[:]
    nw.tick(t0 + secs(25))
    assert nw.sims.ivr.sent == before == []


def test_every_notification_is_created_inside_the_request_lifetime(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in range(0, 95, 5):
        nw.tick(t0 + secs(at))
    rows = nw.rows("SELECT created_at FROM notifications WHERE request_id = %s", (request["id"],))
    assert all(t0 <= r[0] < t0 + dt.timedelta(seconds=90) for r in rows)


# REQ: PRD 12.4
def test_every_dispatch_and_withdrawal_leaves_an_audit_row_and_an_outbox_event(nw: NW) -> None:
    owner, family = _setup(nw)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20):
        nw.tick(t0 + secs(at))
    nw.decide(owner, request)
    nw.tick(t0 + secs(25))
    dispatches = nw.rows("SELECT payload FROM outbox WHERE event_type = 'notification.dispatched' ORDER BY occurred_at")
    assert [p[0]["channel"] for p in dispatches] == ["push", "push", "ivr_call"]
    assert all(p[0]["outcome"] == "provider_accepted" for p in dispatches)
    assert nw.rows("SELECT count(*) FROM audit_log WHERE operation = 'notification.dispatch'") == [(3,)]
    withdrawn = nw.rows("SELECT payload FROM outbox WHERE event_type = 'notification.withdrawn'")
    assert len(withdrawn) == 1 and withdrawn[0][0]["status"] == "approved" and withdrawn[0][0]["withdrawn"] >= 1
    assert nw.rows("SELECT count(*) FROM audit_log WHERE operation = 'notification.withdraw'") == [(1,)]
    for op in ("notification.cascade.start", "notification.cascade.close"):
        assert nw.rows("SELECT count(*) FROM audit_log WHERE operation = %s", (op,)) == [(1,)]
    # no audit row or event of this slice carries a person's name, a number or a message text
    blob = str(nw.rows("SELECT diff_masked FROM audit_log WHERE operation LIKE 'notification.%%'")) + str(
        nw.rows("SELECT payload FROM outbox WHERE event_type LIKE 'notification.%%'")
    )
    assert "Test Visitor" not in blob and "+91" not in blob and "Open Dwaar" not in blob
