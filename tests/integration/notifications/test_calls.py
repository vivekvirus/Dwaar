"""IVR keypad decisions and proxy calls: DTMF 1 allow / 2 deny / 3 talk to the guard, dial outcome and duration, TTL, no recording, outage fallback.

REQ: NOTIF-03 (masked IVR to the primary, DTMF; spoken yes/no is M2 and is NOT built), CALL-01 (TTL-bound sessions, role-authorised contact resolution,
dial outcome and duration logged, no audio, provider outage exposes intercom or office), NOTIF-02, INV-03 (a keypad decision goes through the visits
service: a late key after expiry issues no permission), GATE-13 (no number anywhere).
"""

from __future__ import annotations

import json
import re
from typing import Any

import psycopg
import pytest

from dwaar_api.modules.notifications import engine
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-03", "CALL-01", "INV-03")]


def _world(nw: NW, dtmf: str | None, **script: Any) -> tuple[Any, Any, dict[str, Any], Any]:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.sims.ivr.script(f"person:{owner.id}", outcome="answered", dtmf=dtmf, **script)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(20))  # the masked call is placed
    return owner, family, request, t0


def _session(nw: NW, request: dict[str, Any]) -> tuple[Any, ...]:
    return nw.rows(
        "SELECT state, dial_outcome, dtmf_digit, duration_seconds, recording_enabled FROM proxy_call_sessions WHERE request_id = %s",
        (request["id"],),
    )[0]


def test_dtmf_1_allows_through_the_visits_service(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "1")
    assert (
        nw.sims.ivr.sent[0].payload["speech_input"] is False
    )  # NOTIF-08 (spoken) is M2: keypad only
    nw.tick(t0 + secs(26))  # answered (+4 s) and the key (+6 s) are reported
    row = nw.rows(
        "SELECT state, permission_expires_at IS NOT NULL FROM approval_requests WHERE id = %s",
        (request["id"],),
    )[0]
    assert row == ("approved", True)
    d = nw.rows(
        "SELECT channel, decision, valid, decided_by FROM approval_decisions WHERE request_id = %s",
        (request["id"],),
    )
    assert d == [
        ("ivr", "approve", True, owner.id)
    ]  # the household member's own decision, by keypad
    call = [r for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call"][0]
    assert call["state"] == "actioned" and call["action"] == "approve"
    nw.tick(t0 + secs(33))  # the call ends
    assert _session(nw, request) == (
        "completed",
        "answered",
        "1",
        8,
        False,
    )  # outcome and duration logged, never audio
    assert nw.rows(
        "SELECT state FROM notification_cascades WHERE request_id = %s", (request["id"],)
    ) == [("decided",)]
    assert nw.rows("SELECT state FROM visits WHERE id = %s", (request["visit_id"],)) == [
        ("authorised",)
    ]


def test_dtmf_2_denies(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "2")
    nw.tick(t0 + secs(26))
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("denied",)
    ]
    assert nw.rows(
        "SELECT channel, decision FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [("ivr", "deny")]


def test_dtmf_3_hands_over_to_the_guard_and_decides_nothing(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "3")
    nw.tick(t0 + secs(26))
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(0,)]
    board = nw.call(
        nw.guard,
        "GET",
        nw.s(f"approval-requests/{request['id']}/notification-status"),
        params={"gate_id": str(nw.gate_id)},
    ).json()
    assert board["talk_to_guard_requested"] is True and board["request_status"] == "pending"


def test_an_unknown_key_is_ignored(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "7")
    nw.tick(t0 + secs(26))
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]


def test_a_key_after_expiry_issues_no_permission(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "1")
    nw.shift_request(request["id"], 100)  # the request is long over when the key arrives
    nw.tick(t0 + secs(26))
    assert nw.rows(
        "SELECT state, permission_expires_at FROM approval_requests WHERE id = %s", (request["id"],)
    ) == [("expired", None)]
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(0,)]
    refused = nw.rows(
        "SELECT a.event FROM notification_attempts a JOIN notifications n ON n.id = a.notification_id WHERE n.request_id = %s"
        " AND a.event LIKE 'keypad_decision%%'",
        (request["id"],),
    )
    assert refused == [("keypad_decision_request_expired",)]


def test_a_key_from_someone_who_left_the_household_decides_nothing(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "1")
    nw.sql(
        "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
        (owner.id,),
    )
    nw.tick(t0 + secs(26))
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(0,)]


def test_reordered_and_duplicated_provider_callbacks_apply_once(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.sims.ivr.script(f"person:{owner.id}", outcome="answered", dtmf="1")
    nw.sims.ivr.reorder = True  # the end of the call is reported BEFORE the key and the answer
    nw.sims.ivr.duplicate = True  # and every report arrives twice
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(20))
    nw.tick(t0 + secs(60))
    assert nw.rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (request["id"],)
    ) == [(1,)]
    assert _session(nw, request) == ("completed", "answered", "1", 8, False)
    kinds = [r[0] for r in nw.rows(
        "SELECT a.event FROM notification_attempts a JOIN notifications n ON n.id = a.notification_id WHERE n.request_id = %s"
        " AND a.source = 'provider' ORDER BY a.recorded_at, a.id", (request["id"],))]  # fmt: skip
    assert (
        kinds.count("dtmf") == 1 and kinds.count("completed") == 1 and kinds.count("answered") == 1
    )  # duplicates absorbed


def test_an_unanswered_call_is_logged_with_its_outcome_and_is_not_a_failed_call(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.sims.ivr.script(f"person:{owner.id}", outcome="no_answer", duration_s=25)
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    nw.tick(t0 + secs(20))
    nw.tick(t0 + secs(50))
    assert _session(nw, request) == ("completed", "no_answer", None, 0, False)
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]  # silence never allows


def test_the_ivr_payload_and_log_never_carry_a_phone_number(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, "1")
    nw.tick(t0 + secs(40))
    sent = nw.sims.ivr.sent[0]
    blob = json.dumps({"c": sent.contact_ref, "t": sent.text, "p": sent.payload})
    assert re.search(r"\d{10}", blob) is None and sent.contact_ref.startswith("person:")
    dump = json.dumps(nw.rows("SELECT detail FROM notification_attempts"), default=str)
    assert re.search(r"(?<!\d)[6-9]\d{9}(?!\d)", dump) is None


# ------------------------------------------------------------------------------------------------------------ provider outage (CALL-01)
def test_a_provider_outage_exposes_the_intercom_and_office_process(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.register_device(family, "family-phone")
    nw.sims.set_outage("provider_unavailable")
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 10, 20, 35):
        nw.tick(t0 + secs(at))
    rows = nw.nrows(request["id"])
    assert rows and all(
        r["failure_reason"] == "provider_unavailable" and r["provider_ref"] is None for r in rows
    )
    assert all(r["state"] == "created" for r in rows)  # nothing is claimed
    board = nw.call(
        nw.guard,
        "GET",
        nw.s(f"approval-requests/{request['id']}/notification-status"),
        params={"gate_id": str(nw.gate_id)},
    ).json()
    assert board["fallback"]["provider_outage"] is True and board["fallback"]["offered"] == [
        "intercom",
        "office",
    ]
    assert board["summary"]["person_reached"] is False and board["summary"]["failed"] == len(rows)
    assert nw.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("pending",)
    ]
    sessions = nw.rows(
        "SELECT state, dial_outcome FROM proxy_call_sessions WHERE request_id = %s",
        (request["id"],),
    )
    assert sessions == [("failed", "failed")]
    nw.sims.set_outage(None)


# ------------------------------------------------------------------------------------------------------------ guard proxy call (CALL-01)
def test_a_guard_proxy_call_is_masked_ttl_bound_and_not_recorded(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.sims.ivr.script(
        f"person:{owner.id}", outcome="answered", dtmf=None, duration_s=30, answer_delay_s=5
    )
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    path = nw.s(f"approval-requests/{request['id']}/proxy-calls")
    # the gate is required for a guard, and must be the request's
    assert nw.call(nw.guard, "POST", path, json={"target": "primary"}).status_code == 400
    assert (
        nw.call(
            nw.guard,
            "POST",
            path,
            json={"target": "primary", "gate_id": str(nw.make_gate("Other"))},
        ).status_code
        == 404
    )
    r = nw.call(nw.guard, "POST", path, json={"target": "primary", "gate_id": str(nw.gate_id)})
    assert r.status_code == 201, r.text
    body = r.json()
    assert (
        body["state"] == "created"
        and body["audio_recorded"] is False
        and body["no_number_shown"] is True
    )
    assert body["who"].startswith("Household of ") and str(owner.id) not in json.dumps(body)
    nw.tick(t0 + secs(2))
    nw.tick(t0 + secs(40))
    got = nw.call(
        nw.guard, "GET", nw.s(f"proxy-calls/{body['id']}"), params={"gate_id": str(nw.gate_id)}
    ).json()
    assert (
        got["state"] == "completed"
        and got["dial_outcome"] == "answered"
        and got["duration_seconds"] == 25
    )
    assert got["audio_recorded"] is False and "phone" not in json.dumps(got)
    # a second call to the same role in the same attempt is refused
    again = nw.call(nw.guard, "POST", path, json={"target": "primary", "gate_id": str(nw.gate_id)})
    assert again.status_code == 422 and again.json()["details"]["reason"] == "call_limit_reached"
    # the cascade's own IVR step does not call the primary again either (the slot is taken)
    nw.tick(t0 + secs(21))
    assert sum(1 for r in nw.nrows(request["id"]) if r["channel"] == "ivr_call") == 1


def test_recording_cannot_be_enabled(nw: NW) -> None:
    owner, family, request, t0 = _world(nw, None)
    with pytest.raises(psycopg.errors.CheckViolation):
        nw.sql(
            "UPDATE proxy_call_sessions SET recording_enabled = true WHERE request_id = %s",
            (request["id"],),
        )


def test_a_session_that_outlives_its_ttl_is_never_dialled(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    nw.tick(t0)
    path = nw.s(f"approval-requests/{request['id']}/proxy-calls")
    r = nw.call(nw.guard, "POST", path, json={"target": "primary", "gate_id": str(nw.gate_id)})
    assert r.status_code == 201
    nw.tick(t0 + secs(300))  # the worker was away longer than the 120 s TTL
    got = nw.call(
        nw.guard, "GET", nw.s(f"proxy-calls/{r.json()['id']}"), params={"gate_id": str(nw.gate_id)}
    ).json()
    assert got["state"] == "expired" and nw.sims.ivr.sent == []


def test_contact_resolution_is_role_authorised_and_chosen_by_the_server(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    unit = nw.unit("A-101")
    from dwaar_api.core.db import RequestContext

    with nw.database.app_tx(RequestContext(nw.soc.id, nw.guard.id, "guard", None)) as conn:  # type: ignore[union-attr]
        row = dict(
            conn.execute(
                __import__("sqlalchemy").text("SELECT * FROM approval_requests WHERE id = :i"),
                {"i": request["id"]},
            )
            .mappings()
            .one()
        )
        row["block_name"], row["unit_label"] = "A", "101"
        person, label = engine.resolve_contact(
            conn,
            requester_role="guard",
            purpose="guard_call",
            request=row,
            target="primary",
            cascade_unit=unit,
        )
        assert person == owner.id and "101" in label
        with pytest.raises(engine._Refused):  # noqa: SLF001
            engine.resolve_contact(
                conn,
                requester_role="owner_occ",
                purpose="guard_call",
                request=row,
                target="primary",
                cascade_unit=unit,
            )
        with pytest.raises(engine._Refused):  # noqa: SLF001
            engine.resolve_contact(
                conn,
                requester_role="guard",
                purpose="cascade_ivr",
                request=row,
                target="primary",
                cascade_unit=unit,
            )
        person2, _ = engine.resolve_contact(
            conn,
            requester_role="guard_sup",
            purpose="guard_call",
            request=row,
            target="alternate",
            cascade_unit=unit,
        )
        assert person2 == family.id


def test_residents_cannot_place_or_read_proxy_calls(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    path = nw.s(f"approval-requests/{request['id']}/proxy-calls")
    assert nw.call(owner, "POST", path, json={"target": "primary"}).status_code == 403
    assert nw.call(owner, "GET", nw.s(f"proxy-calls/{request['id']}")).status_code == 403
