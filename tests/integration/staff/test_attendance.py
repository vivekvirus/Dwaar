"""Attendance: an observation by code or card; corrections are appended with who, why and when (STAFF-02, STAFF-05, STAFF-01).

REQ: STAFF-02, STAFF-05, STAFF-01, INV-08.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest

from tests.integration.parcels._support import PW, iso, now, schedule_elsewhere, schedule_now

pytestmark = [pytest.mark.req("STAFF-02", "STAFF-05", "STAFF-01", "INV-08")]


def _setup(pw: PW, schedule=None):  # type: ignore[no-untyped-def]
    h = pw.household("A-101")
    staff = pw.register_staff()
    eng = pw.engage(h.owner, staff, h.unit, schedule=schedule or schedule_now())
    code = pw.issue_code(staff)
    return h, staff, eng, code


# REQ: STAFF-05
def test_check_in_by_code_records_an_observation_and_tells_the_guard_where_the_person_may_go(
    pw: PW,
) -> None:
    h, staff, eng, code = _setup(pw)
    r = pw.check_in(pw.guard, code)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["recorded"] is True and body["authorised_now"] is True and body["direction"] == "in"
    assert body["staff"]["display_name"] == "Sunita Devi" and [
        d["unit_label"] for d in body["authorised_destinations"]
    ] == ["A-101"]
    row = pw.rows(
        "SELECT staff_id, engagement_id, direction, credential_kind, recorded_by, authorised_now FROM attendance_events"
    )[0]
    assert row == (uuid.UUID(staff["id"]), uuid.UUID(eng["id"]), "in", "code", pw.guard.id, True)
    out = pw.check_in(pw.guard, code, "out")
    assert out.status_code == 201 and out.json()["direction"] == "out"
    assert pw.audit("staff.attendance_record") and len(pw.outbox("StaffAttendanceObserved")) == 2


def test_check_in_by_card_works_the_same_way(pw: PW) -> None:
    h, staff, eng, _ = _setup(pw)
    pw.issue_code(
        pw.call(pw.secretary, "GET", f"/v1/staff/{staff['id']}").json(),
        "card",
        card_uid="04A1B2C3D4",
    )
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "card", "value": "04a1b2c3d4"},
            "direction": "in",
            "client_event_id": str(uuid.uuid4()),
        },
    )
    assert r.status_code == 201 and r.json()["authorised_now"] is True
    assert pw.rows("SELECT credential_kind FROM attendance_events")[0][0] == "card"
    cols = pw.rows("SELECT credential_card_hash, credential_code_hash FROM staff")[0]
    assert "04A1B2C3D4" not in str(cols) and len(cols[0]) == 64, "only keyed hashes are stored"


def test_a_code_that_matches_nobody_is_a_404_and_a_code_of_another_society_does_not_work(
    pw: PW,
) -> None:
    h, staff, eng, code = _setup(pw)
    wrong = pw.check_in(pw.guard, "ZZZZZZZZ")
    assert wrong.status_code == 404 and wrong.json()["code"] == "not_found"
    foreign = pw.call_b(
        pw.other.guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "code", "value": code},
            "direction": "in",
            "client_event_id": str(uuid.uuid4()),
        },
    )
    assert foreign.status_code == 404
    assert {k: v for k, v in foreign.json().items() if k != "request_id"} == {
        k: v for k, v in wrong.json().items() if k != "request_id"
    }
    assert pw.rows("SELECT count(*) FROM attendance_events")[0][0] == 0


# REQ: STAFF-02
def test_attendance_is_an_observation_it_neither_grants_nor_removes_permission(pw: PW) -> None:
    h, staff, eng, code = _setup(pw, schedule_elsewhere())
    before = pw.rows("SELECT version, ended_at, schedule::text FROM staff_engagements")
    r = pw.check_in(pw.guard, code)
    assert r.status_code == 201
    body = r.json()
    assert (
        body["authorised_now"] is False
        and "staff" not in body
        and "authorised_destinations" not in body
    ), "outside the hours the guard learns nothing"
    assert pw.rows("SELECT engagement_id, authorised_now FROM attendance_events") == [
        (None, False)
    ], "recorded, not linked, not authorised"
    assert pw.rows("SELECT version, ended_at, schedule::text FROM staff_engagements") == before, (
        "the engagement is unchanged"
    )
    pw.check_in(pw.guard, code, "out")
    assert pw.rows("SELECT version, ended_at FROM staff_engagements")[0][1] is None
    assert "grant" in body["note"] or "observation" in body["note"]


def test_with_several_households_the_guard_names_the_destination(pw: PW) -> None:
    a, b = pw.household("A-101"), pw.household("A-102")
    staff = pw.register_staff()
    pw.engage(a.owner, staff, a.unit, schedule=schedule_now())
    eb = pw.engage(b.owner, staff, b.unit, schedule=schedule_now())
    code = pw.issue_code(staff)
    ambiguous = pw.check_in(pw.guard, code).json()
    assert (
        ambiguous["ambiguous_destination"] is True
        and len(ambiguous["authorised_destinations"]) == 2
    )
    named = pw.check_in(pw.guard, code, unit_id=str(b.unit)).json()
    assert named["authorised_now"] is True
    assert pw.rows("SELECT engagement_id FROM attendance_events ORDER BY recorded_at DESC LIMIT 1")[
        0
    ][0] == uuid.UUID(eb["id"])


def test_a_replayed_check_in_is_one_event(pw: PW) -> None:
    h, staff, eng, code = _setup(pw)
    cid = str(uuid.uuid4())
    body = {
        "credential": {"kind": "code", "value": code},
        "direction": "in",
        "client_event_id": cid,
    }
    first = pw.call(pw.guard, "POST", "/v1/attendance", json=body)
    again = pw.call(
        pw.guard, "POST", "/v1/attendance", json=body
    )  # a retry with a NEW idempotency key
    assert first.status_code == again.status_code == 201 and again.json()["replayed"] is True
    assert first.json()["id"] == again.json()["id"]
    assert pw.rows("SELECT count(*) FROM attendance_events")[0][0] == 1
    other = pw.issue_code(pw.register_staff("Another"), "code")
    clash = pw.call(
        pw.guard,
        "POST",
        "/v1/attendance",
        json={**body, "credential": {"kind": "code", "value": other}},
    )
    assert (
        clash.status_code == 422 and clash.json()["details"]["reason"] == "client_event_id_in_use"
    )


def test_device_and_sequence_numbers_are_unique_per_device(pw: PW) -> None:
    h, staff, eng, code = _setup(pw)
    assert pw.check_in(pw.guard, code, device_id=str(pw.vw.device_id), seq=1).status_code == 201
    dup = pw.check_in(pw.guard, code, device_id=str(pw.vw.device_id), seq=1)
    assert dup.status_code in (409, 422), dup.text
    assert pw.check_in(pw.guard, code, device_id=str(pw.vw.device_id)).status_code == 400, (
        "device and seq go together"
    )


# REQ: STAFF-02
def test_a_correction_is_appended_with_who_why_and_when_and_the_original_is_never_edited(
    pw: PW,
) -> None:
    h, staff, eng, code = _setup(pw)
    ev = pw.check_in(pw.guard, code).json()
    original = pw.rows(
        "SELECT direction, occurred_at, recorded_by FROM attendance_events WHERE id = %s",
        (ev["id"],),
    )[0]
    fixed_time = now() - timedelta(hours=1)
    c1 = pw.call(
        h.owner,
        "POST",
        f"/v1/attendance/{ev['id']}/corrections",
        json={
            "kind": "amend_time",
            "new_occurred_at": iso(fixed_time),
            "reason": "She arrived an hour earlier",
        },
    )
    assert c1.status_code == 201, c1.text
    c2 = pw.call(
        pw.guard_sup,
        "POST",
        f"/v1/attendance/{ev['id']}/corrections",
        json={
            "kind": "amend_direction",
            "new_direction": "out",
            "reason": "Tablet recorded the wrong button",
        },
    )
    assert c2.status_code == 201
    assert (
        pw.rows(
            "SELECT direction, occurred_at, recorded_by FROM attendance_events WHERE id = %s",
            (ev["id"],),
        )[0]
        == original
    )
    rows = pw.rows(
        "SELECT kind, reason, corrected_by, corrector_role, at IS NOT NULL FROM attendance_corrections ORDER BY at"
    )
    assert rows == [
        ("amend_time", "She arrived an hour earlier", h.owner.id, "owner_occ", True),
        ("amend_direction", "Tablet recorded the wrong button", pw.guard_sup.id, "guard_sup", True),
    ]
    listed = pw.call(h.owner, "GET", "/v1/attendance").json()["items"][0]
    assert listed["direction"] == "in", "the observation as recorded"
    assert listed["effective"]["direction"] == "out" and listed["effective"]["voided"] is False
    assert [c["corrector_role"] for c in listed["corrections"]] == ["owner_occ", "guard_sup"]
    assert pw.audit("staff.attendance_correct") and len(pw.outbox("StaffAttendanceCorrected")) == 2
    void = pw.call(
        pw.secretary,
        "POST",
        f"/v1/attendance/{ev['id']}/corrections",
        json={"kind": "void", "reason": "Duplicate of another entry"},
    )
    assert void.status_code == 201 and void.json()["effective"]["voided"] is True
    assert (
        pw.call(
            pw.secretary,
            "POST",
            f"/v1/attendance/{ev['id']}/corrections",
            json={"kind": "void", "reason": "Voiding twice"},
        ).status_code
        == 422
    )


def test_the_database_makes_attendance_and_corrections_append_only(pw: PW) -> None:
    h, staff, eng, code = _setup(pw)
    ev = pw.check_in(pw.guard, code).json()
    pw.call(
        h.owner,
        "POST",
        f"/v1/attendance/{ev['id']}/corrections",
        json={"kind": "void", "reason": "Entered by mistake"},
    )
    for sql in (
        "UPDATE attendance_events SET direction = 'out'",
        "DELETE FROM attendance_events",
        "UPDATE attendance_corrections SET reason = 'edited'",
        "DELETE FROM attendance_corrections",
    ):
        with pytest.raises(psycopg.DatabaseError), pw.idh.db.app_conn(society_id=pw.soc.id) as conn:
            conn.execute(sql)  # type: ignore[call-overload]
        with pytest.raises(psycopg.DatabaseError), pw.idh.db.admin_conn() as conn:
            conn.execute(sql)  # type: ignore[call-overload]


def test_correction_shapes_and_who_may_correct(pw: PW) -> None:
    h, staff, eng, code = _setup(pw)
    other = pw.household("A-102")
    ev = pw.check_in(pw.guard, code).json()
    for bad in (
        {"kind": "void", "new_direction": "out", "reason": "Voids carry no value"},
        {"kind": "amend_time", "reason": "Missing the new time"},
        {
            "kind": "amend_direction",
            "new_occurred_at": iso(now()),
            "reason": "Wrong field for the kind",
        },
        {"kind": "void", "reason": "no"},
    ):
        assert (
            pw.call(h.owner, "POST", f"/v1/attendance/{ev['id']}/corrections", json=bad).status_code
            == 400
        ), bad
    ok = {"kind": "void", "reason": "A proper reason here"}
    assert (
        pw.call(other.owner, "POST", f"/v1/attendance/{ev['id']}/corrections", json=ok).status_code
        == 404
    ), "another household cannot correct it"
    assert (
        pw.call(pw.guard, "POST", f"/v1/attendance/{ev['id']}/corrections", json=ok).status_code
        == 403
    ), "a guard records, it does not correct"
    assert (
        pw.call(h.owner, "POST", f"/v1/attendance/{uuid.uuid4()}/corrections", json=ok).status_code
        == 404
    )


def test_an_unlinked_observation_can_only_be_corrected_by_society_roles(pw: PW) -> None:
    h, staff, eng, code = _setup(pw, schedule_elsewhere())
    ev = pw.check_in(pw.guard, code).json()
    ok = {"kind": "void", "reason": "Tested outside the hours"}
    assert (
        pw.call(h.owner, "POST", f"/v1/attendance/{ev['id']}/corrections", json=ok).status_code
        == 404
    )
    assert (
        pw.call(pw.guard_sup, "POST", f"/v1/attendance/{ev['id']}/corrections", json=ok).status_code
        == 201
    )


def test_attendance_reads_are_scoped_bounded_and_paginated(pw: PW) -> None:
    a, b = pw.household("A-101"), pw.household("A-102")
    sa, sb = pw.register_staff("Cook A"), pw.register_staff("Cook B")
    pw.engage(a.owner, sa, a.unit, schedule=schedule_now())
    pw.engage(b.owner, sb, b.unit, schedule=schedule_now())
    ca, cb = pw.issue_code(sa), pw.issue_code(sb)
    for _ in range(3):
        pw.check_in(pw.guard, ca)
    pw.check_in(pw.guard, cb)
    assert len(pw.call(a.owner, "GET", "/v1/attendance").json()["items"]) == 3
    assert len(pw.call(b.owner, "GET", "/v1/attendance").json()["items"]) == 1
    assert len(pw.call(pw.secretary, "GET", "/v1/attendance").json()["items"]) == 4
    page = pw.call(pw.secretary, "GET", "/v1/attendance", params={"limit": 3}).json()
    assert len(page["items"]) == 3 and page["next_cursor"]
    assert (
        pw.call(a.owner, "GET", "/v1/attendance", params={"unit_id": str(b.unit)}).status_code
        == 404
    )
    assert (
        pw.call(
            pw.secretary,
            "GET",
            "/v1/attendance",
            params={"from": iso(now() - timedelta(days=400)), "to": iso(now())},
        ).status_code
        == 400
    )
    assert pw.call(pw.guard, "GET", "/v1/attendance").status_code == 403, (
        "a guard records attendance; the history is for society roles and the household"
    )
    assert pw.call_b(pw.other.secretary, "GET", "/v1/attendance").json()["items"] == []


def test_a_withdrawn_consent_stops_attendance_capture(pw: PW) -> None:
    h = pw.household("A-101")
    c = pw.consent()
    staff = pw.register_staff(consent=c)
    pw.engage(h.owner, staff, h.unit, schedule=schedule_now())
    code = pw.issue_code(staff)
    assert pw.check_in(pw.guard, code).status_code == 201
    pw.call(
        pw.secretary,
        "POST",
        f"/v1/staff-consents/{c['id']}/withdraw",
        json={"expected_version": 1, "reason": "Staff member withdrew consent"},
    )
    blocked = pw.check_in(pw.guard, code)
    assert blocked.status_code == 422 and blocked.json()["details"]["reason"] == "consent_withdrawn"
    assert pw.rows("SELECT count(*) FROM attendance_events")[0][0] == 1


def test_staff_entry_is_never_tied_to_dues_or_anything_but_the_engagement(pw: PW) -> None:
    """INV-08: nothing in the attendance path reads billing or dues; an authorised person is authorised regardless of the household's account."""
    h, staff, eng, code = _setup(pw)
    tables = {
        r[0]
        for r in pw.rows(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        )
    }
    import inspect

    from dwaar_api.modules.staff import attendance, authorisation

    source = inspect.getsource(attendance) + inspect.getsource(authorisation)
    assert not [t for t in tables if t in ("invoices", "journals", "receipts") and t in source]
    assert pw.check_in(pw.guard, code).json()["authorised_now"] is True
