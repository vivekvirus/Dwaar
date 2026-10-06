"""Staff consent BEFORE capture, ID masking, police verification as a status, no blacklist (STAFF-04, PRIV-03, PRIV-04, STAFF-01).

REQ: STAFF-04, PRIV-03, PRIV-04, STAFF-01.
"""

from __future__ import annotations

import logging
import uuid

import pytest

from dwaar_api.modules.staff import service as staff_service
from dwaar_api.modules.staff.schemas import ConsentCapture
from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("STAFF-04", "PRIV-03", "PRIV-04", "STAFF-01")]
AADHAAR = "234567891234"  # an invented, syntactically plausible 12-digit number (never a real one)


def _register(pw: PW, consent_id: str, **extra):  # type: ignore[no-untyped-def]
    pw.vw._n += 1  # noqa: SLF001
    body = {
        "consent_id": consent_id,
        "display_name": "Lata Bai",
        "phone": f"+9199999{70000 + pw.vw._n:05d}",
        "staff_type": "cook",
    }  # noqa: SLF001
    body.update(extra)
    return pw.call(pw.secretary, "POST", "/v1/staff", json=body)


# REQ: STAFF-04
def test_nothing_is_captured_before_a_consent_receipt_exists(pw: PW) -> None:
    no_consent = pw.call(
        pw.secretary,
        "POST",
        "/v1/staff",
        json={"display_name": "Lata", "phone": "+919999970001", "staff_type": "cook"},
    )
    assert no_consent.status_code == 400 and no_consent.json()["code"] == "invalid_schema"
    unknown = _register(pw, str(uuid.uuid4()))
    assert unknown.status_code == 404
    assert pw.rows("SELECT count(*) FROM staff")[0][0] == 0
    assert pw.rows("SELECT count(*) FROM iam.persons WHERE display_name = 'Lata Bai'")[0][0] == 0, (
        "not even a person row was created"
    )


def test_the_consent_receipt_carries_language_notice_purposes_and_the_staff_members_own_action(
    pw: PW,
) -> None:
    c = pw.consent(language="mr", notice_version="staff-notice-v3")
    assert (
        c["language"] == "mr"
        and c["notice_version"] == "staff-notice-v3"
        and c["channel"] == "assisted_tablet"
    )
    assert (
        c["staff_action_recorded"] is True
        and c["notice_read_aloud"] is True
        and c["simulation"] is False
    )
    assert set(c["purposes"]) >= {"engagement_record", "attendance"}
    assert pw.audit("staff.consent_capture") and pw.outbox("StaffConsentCaptured", c["id"])
    row = pw.rows("SELECT captured_by FROM staff_consents WHERE id = %s", (c["id"],))[0]
    assert row[0] == pw.secretary.id, "who assisted is recorded"
    assert not any(k in c for k in ("phone", "name", "display_name")), (
        "the receipt holds no personal data"
    )


def test_a_guard_tap_is_not_consent_the_staff_members_action_must_be_recorded(pw: PW) -> None:
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/staff-consents",
        json={
            "language": "hi",
            "notice_version": "v1",
            "purposes": ["engagement_record"],
            "staff_action_recorded": False,
        },
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "staff_action_required"
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/staff-consents",
        json={
            "language": "hi",
            "notice_version": "v1",
            "purposes": ["attendance"],
            "staff_action_recorded": True,
        },
    )
    assert r.status_code == 400, "the record itself needs its purpose"
    assert pw.rows("SELECT count(*) FROM staff_consents")[0][0] == 0
    ok = pw.call(
        pw.guard,
        "POST",
        "/v1/staff-consents",
        json={
            "language": "hi",
            "notice_version": "v1",
            "purposes": ["engagement_record"],
            "staff_action_recorded": True,
        },
    )
    assert ok.status_code == 201, "a guard on the assisted tablet may capture it"


def test_ivr_assist_is_m2_the_api_refuses_the_channel_and_only_the_simulator_hook_records_it(
    pw: PW,
) -> None:
    r = pw.call(
        pw.secretary,
        "POST",
        "/v1/staff-consents",
        json={
            "language": "hi",
            "notice_version": "v1",
            "purposes": ["engagement_record"],
            "staff_action_recorded": True,
            "channel": "ivr_assisted",
        },
    )
    assert r.status_code == 400
    with pw.idh.database.app_tx(
        __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, pw.secretary.id, "secretary", uuid.uuid4()
        )
    ) as conn:
        ctx = __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, pw.secretary.id, "secretary", uuid.uuid4()
        )
        sim = staff_service.simulate_ivr_consent(
            conn,
            ctx,
            ConsentCapture(
                language="hi",
                notice_version="v1",
                purposes=["engagement_record"],
                staff_action_recorded=True,
            ),
        )
    assert sim["channel"] == "ivr_assisted" and sim["simulation"] is True
    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation), pw.idh.db.owner_conn() as conn2:
        conn2.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
        conn2.execute(  # type: ignore[call-overload]
            "INSERT INTO staff_consents (society_id, language, notice_version, channel, purposes, staff_action_recorded, captured_by)"
            " VALUES (%s, 'hi', 'v1', 'ivr_assisted', ARRAY['engagement_record'], true, %s)",
            (pw.soc.id, pw.secretary.id),
        )


def test_capture_is_limited_to_the_purposes_consented_to(pw: PW) -> None:
    narrow = pw.consent(purposes=("engagement_record",))
    for extra, purpose in (
        ({"id_document": {"kind": "aadhaar", "number": AADHAAR}}, "id_capture"),
        ({"photo_ref": "photo://x"}, "photo"),
        ({"police_verification_status": "verified"}, "police_verification_status"),
    ):
        r = _register(pw, narrow["id"], **extra)
        assert r.status_code == 422 and r.json()["details"] == {
            "reason": "consent_scope_missing",
            "purpose": purpose,
        }, extra
    assert pw.rows("SELECT count(*) FROM staff")[0][0] == 0
    ok = _register(pw, narrow["id"])
    assert ok.status_code == 201
    staff = ok.json()
    for body, purpose in (
        ({"id_document": {"kind": "aadhaar", "number": AADHAAR}}, "id_capture"),
        ({"photo_ref": "photo://x"}, "photo"),
    ):
        r = pw.call(
            pw.secretary,
            "PATCH",
            f"/v1/staff/{staff['id']}",
            json={"expected_version": staff["version"], **body},
        )
        assert r.status_code == 422 and r.json()["details"]["purpose"] == purpose
    cred = pw.call(
        pw.secretary,
        "POST",
        f"/v1/staff/{staff['id']}/credentials",
        json={"kind": "code", "expected_version": staff["version"]},
    )
    assert cred.status_code == 422 and cred.json()["details"]["purpose"] == "attendance"


def test_a_withdrawn_consent_blocks_every_further_capture(pw: PW) -> None:
    c = pw.consent()
    staff = _register(pw, c["id"]).json()
    w = pw.call(
        pw.secretary,
        "POST",
        f"/v1/staff-consents/{c['id']}/withdraw",
        json={"expected_version": c["version"], "reason": "Staff member asked to withdraw"},
    )
    assert w.status_code == 200 and w.json()["withdrawn_at"] is not None
    for path, body in (
        (f"/v1/staff/{staff['id']}", {"expected_version": 1, "photo_ref": "photo://x"}),
    ):
        r = pw.call(pw.secretary, "PATCH", path, json=body)
        assert r.status_code == 422 and r.json()["details"]["reason"] == "consent_withdrawn"
    fresh = _register(pw, c["id"])
    assert fresh.status_code == 422 and fresh.json()["details"]["reason"] == "consent_withdrawn"
    eng = pw.call(
        pw.secretary,
        "POST",
        "/v1/staff-engagements",
        json={
            "staff_id": staff["id"],
            "unit_id": str(pw.household("A-101").unit),
            "duty": "cook",
            "schedule": {"days": ["mon"], "from": "07:00", "to": "09:00"},
        },
    )
    assert eng.status_code == 422 and eng.json()["details"]["reason"] == "consent_withdrawn"
    again = pw.call(
        pw.secretary,
        "POST",
        f"/v1/staff-consents/{c['id']}/withdraw",
        json={"expected_version": 1, "reason": "A second withdrawal"},
    )
    assert again.status_code == 200, "naturally idempotent"


def test_one_consent_receipt_covers_one_person_only(pw: PW) -> None:
    c = pw.consent()
    assert _register(pw, c["id"]).status_code == 201
    second = _register(pw, c["id"])
    assert (
        second.status_code == 422 and second.json()["details"]["reason"] == "consent_already_used"
    )


def test_the_same_number_cannot_be_registered_twice_in_one_society(pw: PW) -> None:
    c1, c2 = pw.consent(), pw.consent()
    assert _register(pw, c1["id"], phone="+919999980123").status_code == 201
    dup = _register(pw, c2["id"], phone="+91 99999 80123")
    assert dup.status_code == 422 and dup.json()["details"]["reason"] == "already_registered"


# REQ: PRIV-04
def test_an_aadhaar_number_is_masked_to_the_last_four_and_the_full_number_is_stored_nowhere(
    pw: PW, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    c = pw.consent()
    r = _register(pw, c["id"], id_document={"kind": "aadhaar", "number": "2345 6789 1234"})
    assert r.status_code == 201, r.text
    assert r.json()["id_document"] == {"kind": "aadhaar", "masked": "XXXX XXXX 1234"}
    staff = r.json()
    upd = pw.call(
        pw.secretary,
        "PATCH",
        f"/v1/staff/{staff['id']}",
        json={
            "expected_version": staff["version"],
            "id_document": {"kind": "aadhaar", "number": "XXXX XXXX 9876"},
        },
    )
    assert upd.status_code == 200 and upd.json()["id_document"]["masked"] == "XXXX XXXX 9876", (
        "an already masked value is accepted as it is"
    )
    dumps = [
        pw.rows("SELECT string_agg(s::text, ' ') FROM staff s")[0][0],
        pw.rows("SELECT string_agg(diff_masked::text, ' ') FROM audit_log")[0][0],
        pw.rows("SELECT string_agg(payload::text, ' ') FROM outbox")[0][0],
        pw.rows("SELECT string_agg(response_body::text, ' ') FROM idempotency_keys")[0][0],
        r.text, upd.text, caplog.text,
    ]  # fmt: skip
    for dump in dumps:
        for needle in ("234567891234", "2345 6789 1234", "2345-6789-1234", "567891234"):
            assert needle not in (dump or ""), needle
    assert pw.rows("SELECT id_doc_masked FROM staff")[0][0] == "XXXX XXXX 9876"


@pytest.mark.parametrize("number", ["12345", "1234567890123", "ABCDEFGHIJKL", "2345 6789", ""])
def test_a_malformed_aadhaar_is_a_400_and_nothing_is_stored(pw: PW, number: str) -> None:
    c = pw.consent()
    r = _register(pw, c["id"], id_document={"kind": "aadhaar", "number": number})
    assert r.status_code == 400
    assert pw.rows("SELECT count(*) FROM staff")[0][0] == 0


def test_other_id_kinds_are_masked_the_same_way_and_the_database_refuses_an_unmasked_value(
    pw: PW,
) -> None:
    assert staff_service.mask_id_number("driving_licence", "MH12 2019 0001234") == "XXXX 1234"
    assert staff_service.mask_id_number("aadhaar", "XXXX-XXXX-5555") == "XXXX XXXX 5555"
    import psycopg

    c = pw.consent()
    staff = _register(pw, c["id"]).json()
    with pytest.raises(psycopg.errors.CheckViolation), pw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
        conn.execute(
            "UPDATE staff SET id_doc_kind = 'aadhaar', id_doc_masked = '234567891234' WHERE id = %s",
            (staff["id"],),
        )  # type: ignore[call-overload]


# REQ: PRIV-04
def test_police_verification_is_recorded_as_a_status_only(pw: PW) -> None:
    c = pw.consent()
    staff = _register(pw, c["id"], police_verification_status="requested").json()
    assert staff["police_verification_status"] == "requested"
    upd = pw.call(
        pw.secretary,
        "PATCH",
        f"/v1/staff/{staff['id']}",
        json={"expected_version": staff["version"], "police_verification_status": "verified"},
    )
    assert upd.status_code == 200 and upd.json()["police_verification_status"] == "verified"
    cols = {
        r[0]
        for r in pw.rows(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'staff'"
        )
    }
    assert not {
        c_
        for c_ in cols
        if any(w in c_ for w in ("certificate", "document_ref", "police_record", "fir", "criminal"))
    }
    bad = pw.call(
        pw.secretary,
        "PATCH",
        f"/v1/staff/{staff['id']}",
        json={
            "expected_version": upd.json()["version"],
            "police_verification_status": "clear_no_record",
        },
    )
    assert bad.status_code == 400
    smuggled = pw.call(
        pw.secretary,
        "PATCH",
        f"/v1/staff/{staff['id']}",
        json={"expected_version": upd.json()["version"], "police_certificate": "scan.pdf"},
    )
    assert smuggled.status_code == 400


# REQ: STAFF-04
def test_there_is_no_global_blacklist_anywhere(pw: PW) -> None:
    tables = (
        "staff",
        "staff_consents",
        "staff_engagements",
        "attendance_events",
        "payroll_adjustments",
    )
    cols = pw.rows(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_name = ANY(%s)",
        (list(tables),),
    )
    assert not [
        c
        for c in cols
        if any(
            w in c[1]
            for w in ("blacklist", "blocklist", "banned", "reputation", "do_not_hire", "flag")
        )
    ], cols
    paths = pw.route_paths()
    assert not [
        p for p in paths if any(w in p for w in ("blacklist", "blocklist", "banned", "reputation"))
    ]
    # every staff row belongs to ONE society (RLS) and ends with an engagement; nothing is shared across societies
    c = pw.consent()
    staff = _register(pw, c["id"], phone="+919999980321").json()
    assert pw.call_b(pw.other.secretary, "GET", f"/v1/staff/{staff['id']}").status_code == 404
    assert pw.call_b(pw.other.secretary, "GET", "/v1/staff").json()["items"] == []


def test_the_register_is_for_society_roles_and_residents_cannot_register_or_read_it(pw: PW) -> None:
    h = pw.household("A-101")
    c = pw.consent()
    assert (
        pw.call(
            h.owner,
            "POST",
            "/v1/staff-consents",
            json={
                "language": "hi",
                "notice_version": "v1",
                "purposes": ["engagement_record"],
                "staff_action_recorded": True,
            },
        ).status_code
        == 403
    )
    r = pw.vw.call(
        h.owner,
        "POST",
        "/v1/staff",
        json={
            "consent_id": c["id"],
            "display_name": "X",
            "phone": "+919999980999",
            "staff_type": "cook",
        },
    )
    assert r.status_code == 403
    listed = pw.call(h.owner, "GET", "/v1/staff")
    assert listed.status_code == 200 and listed.json()["items"] == [], (
        "no engagement, nothing visible"
    )
    staff = _register(pw, c["id"]).json()
    assert pw.call(h.owner, "GET", f"/v1/staff/{staff['id']}").status_code == 404
    full = pw.call(pw.secretary, "GET", f"/v1/staff/{staff['id']}")
    assert (
        full.status_code == 200 and full.json()["id_document"] is None and "consent" in full.json()
    )
