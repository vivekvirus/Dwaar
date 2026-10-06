"""Engagements: separate per household, valid hours, guards see only authorised destinations, ending one never touches another (STAFF-01, STAFF-03, AT-12).

REQ: STAFF-01, STAFF-03, INV-08.
"""

from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo

import pytest

from dwaar_api.modules.staff import authorisation
from tests.integration.parcels._support import PW, schedule_elsewhere, schedule_now

pytestmark = [pytest.mark.req("STAFF-01", "STAFF-03", "INV-08")]
IST = ZoneInfo("Asia/Kolkata")


def _end(pw: PW, who, engagement, reason: str = "Moved out of the city"):  # type: ignore[no-untyped-def]
    return pw.call(
        who,
        "POST",
        f"/v1/staff-engagements/{engagement['id']}/end",
        json={"expected_version": engagement["version"], "reason": reason},
    )


# REQ: STAFF-01
def test_one_person_has_a_separate_engagement_with_its_own_hours_per_household(pw: PW) -> None:
    a, b, c = pw.household("A-101"), pw.household("A-102"), pw.household("A-103")
    staff = pw.register_staff()
    ea = pw.engage(
        a.owner,
        staff,
        a.unit,
        duty="cook",
        schedule={"days": ["mon", "tue"], "from": "07:00", "to": "09:00"},
    )
    eb = pw.engage(
        b.owner,
        staff,
        b.unit,
        duty="cleaning",
        schedule={"days": ["wed"], "from": "10:00", "to": "12:00"},
    )
    ec = pw.engage(c.owner, staff, c.unit)
    assert len({ea["id"], eb["id"], ec["id"]}) == 3
    assert {ea["staff_id"], eb["staff_id"], ec["staff_id"]} == {staff["id"]}, "one staff person"
    assert ea["schedule"]["days"] == ["mon", "tue"] and eb["duty"] == "cleaning"
    assert pw.rows(
        "SELECT count(*) FROM staff_engagements WHERE staff_id = %s", (staff["id"],)
    ) == [(3,)]
    assert pw.audit("staff.engagement_create") and len(pw.outbox("StaffEngagementCreated")) == 3


def test_a_household_engages_only_for_its_own_unit_and_a_stranger_cannot_engage_for_another(
    pw: PW,
) -> None:
    a, b = pw.household("A-101"), pw.household("A-102")
    staff = pw.register_staff()
    r = pw.call(
        a.owner,
        "POST",
        "/v1/staff-engagements",
        json={
            "staff_ref": staff["staff_ref"],
            "unit_id": str(b.unit),
            "duty": "cook",
            "schedule": schedule_now(),
        },
    )
    assert r.status_code == 404
    unknown_ref = pw.call(
        a.owner,
        "POST",
        "/v1/staff-engagements",
        json={
            "staff_ref": "AAAAAAAAAA",
            "unit_id": str(a.unit),
            "duty": "cook",
            "schedule": schedule_now(),
        },
    )
    assert unknown_ref.status_code == 404
    assert (
        pw.call(
            a.family,
            "POST",
            "/v1/staff-engagements",
            json={
                "staff_ref": staff["staff_ref"],
                "unit_id": str(a.unit),
                "duty": "cook",
                "schedule": schedule_now(),
            },
        ).status_code
        == 403
    )
    assert pw.rows("SELECT count(*) FROM staff_engagements")[0][0] == 0
    # a society role may engage for any unit (for example on the household's request)
    assert (
        pw.call(
            pw.secretary,
            "POST",
            "/v1/staff-engagements",
            json={
                "staff_ref": staff["staff_ref"],
                "unit_id": str(b.unit),
                "duty": "cook",
                "schedule": schedule_now(),
            },
        ).status_code
        == 201
    )


def test_two_live_overlapping_engagements_in_one_household_are_refused_by_the_database(
    pw: PW,
) -> None:
    a = pw.household("A-101")
    staff = pw.register_staff()
    first = pw.engage(a.owner, staff, a.unit)
    clash = pw.call(
        a.owner,
        "POST",
        "/v1/staff-engagements",
        json={
            "staff_id": staff["id"],
            "unit_id": str(a.unit),
            "duty": "again",
            "schedule": schedule_now(),
        },
    )
    assert clash.status_code in (409, 422), clash.text
    assert _end(pw, a.owner, first).status_code == 200
    assert (
        pw.call(
            a.owner,
            "POST",
            "/v1/staff-engagements",
            json={
                "staff_id": staff["id"],
                "unit_id": str(a.unit),
                "duty": "again",
                "schedule": schedule_now(),
            },
        ).status_code
        == 201
    )


@pytest.mark.parametrize(
    "schedule",
    [
        {"days": [], "from": "07:00", "to": "09:00"},
        {"days": ["mon", "mon"], "from": "07:00", "to": "09:00"},
        {"days": ["funday"], "from": "07:00", "to": "09:00"},
        {"days": ["mon"], "from": "09:00", "to": "07:00"},
        {"days": ["mon"], "from": "7am", "to": "9am"},
        {"days": ["mon"], "from": "07:00"},
    ],
)
def test_invalid_hours_are_a_400(pw: PW, schedule: dict[str, object]) -> None:
    a = pw.household("A-101")
    staff = pw.register_staff()
    r = pw.call(
        a.owner,
        "POST",
        "/v1/staff-engagements",
        json={
            "staff_ref": staff["staff_ref"],
            "unit_id": str(a.unit),
            "duty": "cook",
            "schedule": schedule,
        },
    )
    assert r.status_code == 400


# REQ: STAFF-01
def test_valid_hours_and_dates_decide_what_is_authorised_now() -> None:
    row = {
        "ended_at": None, "effective_from": dt.date(2026, 10, 1), "effective_to": dt.date(2026, 10, 31),
        "schedule": {"days": ["mon", "wed"], "from": "07:00", "to": "11:00"},
    }  # fmt: skip
    monday_8 = dt.datetime(2026, 10, 5, 8, 0, tzinfo=IST)
    assert authorisation.authorised_now(row, monday_8)
    assert not authorisation.authorised_now(row, dt.datetime(2026, 10, 5, 11, 0, tzinfo=IST)), (
        "the end of the window is exclusive"
    )
    assert not authorisation.authorised_now(row, dt.datetime(2026, 10, 6, 8, 0, tzinfo=IST)), (
        "Tuesday is not a working day"
    )
    assert not authorisation.authorised_now(row, dt.datetime(2026, 11, 2, 8, 0, tzinfo=IST)), (
        "after the effective dates"
    )
    assert not authorisation.authorised_now(row, dt.datetime(2026, 9, 28, 8, 0, tzinfo=IST)), (
        "before the effective dates"
    )
    assert authorisation.authorised_now(row, monday_8.astimezone(dt.UTC)), (
        "evaluated in Asia/Kolkata whatever the zone given"
    )
    ended = {**row, "ended_at": dt.datetime(2026, 10, 5, 7, 30, tzinfo=IST)}
    assert not authorisation.authorised_now(ended, monday_8)
    assert authorisation.authorised_now(ended, dt.datetime(2026, 10, 5, 7, 0, tzinfo=IST)), (
        "before it ended it was authorised"
    )


# REQ: STAFF-01
def test_a_guard_sees_only_staff_authorised_now_and_only_the_destination(pw: PW) -> None:
    a, b, c = pw.household("A-101"), pw.household("A-102"), pw.household("A-103")
    inside = pw.register_staff("Inside Hours")
    outside = pw.register_staff("Outside Hours")
    nowhere = pw.register_staff("No Engagement")
    pw.engage(a.owner, inside, a.unit, schedule=schedule_now())
    pw.engage(
        b.owner, inside, b.unit, schedule=schedule_elsewhere()
    )  # a second household whose hours are not now
    pw.engage(c.owner, outside, c.unit, schedule=schedule_elsewhere())
    listed = pw.call(pw.guard, "GET", "/v1/staff").json()["items"]
    assert [s["display_name"] for s in listed] == ["Inside Hours"]
    only = listed[0]
    assert [d["unit_label"] for d in only["authorised_destinations"]] == ["A-101"], (
        "B's arrangement is not shown"
    )
    assert set(only) == {"id", "display_name", "staff_type", "photo_ref", "authorised_destinations"}
    assert set(only["authorised_destinations"][0]) == {
        "engagement_id",
        "unit_id",
        "block_name",
        "unit_label",
        "days",
        "from",
        "to",
    }
    assert pw.call(pw.guard, "GET", f"/v1/staff/{inside['id']}").status_code == 200
    for hidden in (outside, nowhere):
        assert pw.call(pw.guard, "GET", f"/v1/staff/{hidden['id']}").status_code == 404, (
            "outside their hours: unknown to the guard"
        )
    engagements = pw.call(pw.guard, "GET", "/v1/staff-engagements").json()["items"]
    assert [e["unit_label"] for e in engagements] == ["A-101"]
    assert not {"duty", "ended_at", "staff_name", "end_reason"} & set(engagements[0])
    full = pw.call(pw.secretary, "GET", "/v1/staff").json()["items"]
    assert {s["display_name"] for s in full} == {"Inside Hours", "Outside Hours", "No Engagement"}


def test_a_household_sees_only_its_own_staff_and_its_own_engagements(pw: PW) -> None:
    a, b, stranger = pw.household("A-101"), pw.household("A-102"), pw.household("A-103")
    shared = pw.register_staff("Shared Cook")
    only_b = pw.register_staff("Only B")
    ea = pw.engage(a.owner, shared, a.unit)
    eb = pw.engage(b.owner, shared, b.unit, duty="b-duty")
    pw.engage(b.owner, only_b, b.unit)
    mine = pw.call(a.owner, "GET", "/v1/staff").json()["items"]
    assert [s["display_name"] for s in mine] == ["Shared Cook"]
    assert not {"id_document", "police_verification_status", "check_in", "consent"} & set(
        mine[0]
    ), "household view carries no ID, status or credentials"
    engs = pw.call(a.owner, "GET", "/v1/staff-engagements").json()["items"]
    assert [e["id"] for e in engs] == [ea["id"]], "the other employer's engagement is invisible"
    assert pw.call(a.owner, "GET", f"/v1/staff/{only_b['id']}").status_code == 404
    assert (
        pw.call(
            a.owner, "GET", "/v1/staff-engagements", params={"unit_id": str(b.unit)}
        ).status_code
        == 404
    )
    assert pw.call(stranger.owner, "GET", "/v1/staff").json()["items"] == []
    assert pw.call(stranger.owner, "GET", f"/v1/staff/{shared['id']}").status_code == 404
    assert (
        pw.call(
            a.owner,
            "PATCH",
            f"/v1/staff-engagements/{eb['id']}",
            json={"expected_version": 1, "duty": "x"},
        ).status_code
        == 404
    )
    assert _end(pw, a.owner, eb).status_code == 404
    assert (
        pw.call(a.owner, "GET", f"/v1/staff/{shared['id']}").json()["staff_ref"]
        == shared["staff_ref"]
    )


# REQ: STAFF-03
def test_ending_one_engagement_does_not_revoke_the_other_employers_engagements(pw: PW) -> None:
    a, b, c = pw.household("A-101"), pw.household("A-102"), pw.household("A-103")
    staff = pw.register_staff()
    ea, eb, ec = (pw.engage(h.owner, staff, h.unit) for h in (a, b, c))
    ended = _end(pw, b.owner, eb)
    assert (
        ended.status_code == 200
        and ended.json()["ended_at"] is not None
        and ended.json()["authorised_now"] is False
    )
    live = {
        str(r[0])
        for r in pw.rows(
            "SELECT id FROM staff_engagements WHERE staff_id = %s AND ended_at IS NULL",
            (staff["id"],),
        )
    }
    assert live == {ea["id"], ec["id"]}
    for who, eng in ((a.owner, ea), (c.owner, ec)):
        mine = pw.call(who, "GET", "/v1/staff-engagements").json()["items"]
        assert (
            [e["id"] for e in mine] == [eng["id"]]
            and mine[0]["ended_at"] is None
            and mine[0]["version"] == eng["version"]
        )
    event = pw.outbox("StaffEngagementEnded", eb["id"])[0]["payload"]
    assert event["remaining_live_engagements"] == 2 and event["engagement_id"] == eb["id"]
    again = _end(pw, b.owner, eb)
    assert again.status_code == 200 and len(pw.outbox("StaffEngagementEnded")) == 1, (
        "ending twice is idempotent"
    )
    assert pw.call(b.owner, "GET", f"/v1/staff-engagements/{eb['id']}").status_code == 405, (
        "there is no per-id read route"
    )


def test_ending_requires_a_version_a_reason_and_the_right_household(pw: PW) -> None:
    a, b = pw.household("A-101"), pw.household("A-102")
    staff = pw.register_staff()
    ea = pw.engage(a.owner, staff, a.unit)
    assert (
        pw.call(
            a.owner,
            "POST",
            f"/v1/staff-engagements/{ea['id']}/end",
            json={"expected_version": 9, "reason": "A fine reason"},
        ).status_code
        == 409
    )
    assert (
        pw.call(
            a.owner,
            "POST",
            f"/v1/staff-engagements/{ea['id']}/end",
            json={"expected_version": 1, "reason": "no"},
        ).status_code
        == 400
    )
    assert (
        pw.call(
            b.owner,
            "POST",
            f"/v1/staff-engagements/{ea['id']}/end",
            json={"expected_version": 1, "reason": "A fine reason"},
        ).status_code
        == 404
    )
    assert (
        pw.call(
            a.family,
            "POST",
            f"/v1/staff-engagements/{ea['id']}/end",
            json={"expected_version": 1, "reason": "A fine reason"},
        ).status_code
        == 403
    )


def test_an_engagement_can_be_changed_until_it_ends(pw: PW) -> None:
    a = pw.household("A-101")
    staff = pw.register_staff()
    ea = pw.engage(a.owner, staff, a.unit)
    upd = pw.call(
        a.owner,
        "PATCH",
        f"/v1/staff-engagements/{ea['id']}",
        json={
            "expected_version": ea["version"],
            "schedule": schedule_elsewhere(),
            "duty": "evening cook",
        },
    )
    assert (
        upd.status_code == 200
        and upd.json()["duty"] == "evening cook"
        and upd.json()["authorised_now"] is False
    )
    assert (
        pw.call(
            a.owner,
            "PATCH",
            f"/v1/staff-engagements/{ea['id']}",
            json={"expected_version": ea["version"], "duty": "stale"},
        ).status_code
        == 409
    )
    assert _end(pw, a.owner, upd.json()).status_code == 200
    late = pw.call(
        a.owner,
        "PATCH",
        f"/v1/staff-engagements/{ea['id']}",
        json={"expected_version": 3, "duty": "after the end"},
    )
    assert late.status_code == 422 and late.json()["details"]["reason"] == "engagement_ended"


# REQ: STAFF-03, AT-12
def test_the_edge_policy_input_reflects_the_remaining_engagements(pw: PW) -> None:
    a, b, c = pw.household("A-101"), pw.household("A-102"), pw.household("A-103")
    staff = pw.register_staff()
    ea, eb, ec = (pw.engage(h.owner, staff, h.unit) for h in (a, b, c))

    def snapshot() -> dict[str, object]:
        with pw.idh.database.app_tx(
            __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
                pw.soc.id, None, "system", None
            )
        ) as conn:
            return authorisation.edge_staff_input(conn)

    before = snapshot()
    assert {e["engagement_id"] for e in before["entries"]} == {ea["id"], eb["id"], ec["id"]}  # type: ignore[attr-defined]
    assert all(
        e["staff_ref"] == staff["staff_ref"] and "display_name" not in e for e in before["entries"]
    )  # type: ignore[attr-defined]
    _end(pw, b.owner, eb)
    after = snapshot()
    assert {e["engagement_id"] for e in after["entries"]} == {ea["id"], ec["id"]}  # type: ignore[attr-defined]
    assert [e["engagement_id"] for e in after["ended"]] == [eb["id"]]  # type: ignore[attr-defined]
    assert after["digest"] != before["digest"]
    again = snapshot()
    assert again["entries"] == after["entries"] and again["digest"] == after["digest"], (
        "deterministic"
    )
