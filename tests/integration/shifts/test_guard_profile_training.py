"""Guard language per guard (UX-08) and practice-mode training completion per guard per scenario type (UX-09).

REQ: UX-08, UX-09, INV-11.
"""

from __future__ import annotations

import pytest

from dwaar_api.modules.shifts.schemas import SCENARIO_TYPES
from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("UX-08", "UX-09", "INV-11")]


def test_a_guard_chooses_their_own_language_per_guard_not_per_site(pw: PW) -> None:
    g2 = pw.vw.person()
    pw.idh.seed_grant(pw.soc.id, g2.id, "guard")
    assert pw.call(pw.guard, "GET", f"/v1/guards/{pw.guard.id}/profile").json()["language"] is None
    r = pw.call(pw.guard, "PUT", f"/v1/guards/{pw.guard.id}/profile", json={"language": "hi"})
    assert r.status_code == 200 and r.json()["language"] == "hi" and r.json()["version"] == 1
    assert (
        pw.call(g2, "PUT", f"/v1/guards/{g2.id}/profile", json={"language": "mr"}).json()[
            "language"
        ]
        == "mr"
    )
    assert (
        pw.call(pw.guard, "GET", f"/v1/guards/{pw.guard.id}/profile").json()["language"] == "hi"
    ), "another guard's choice does not change mine"
    upd = pw.call(
        pw.guard,
        "PUT",
        f"/v1/guards/{pw.guard.id}/profile",
        json={"language": "en", "expected_version": 1},
    )
    assert upd.status_code == 200 and upd.json()["version"] == 2
    stale = pw.call(
        pw.guard,
        "PUT",
        f"/v1/guards/{pw.guard.id}/profile",
        json={"language": "mr", "expected_version": 1},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    assert pw.audit("guard.profile_set") and pw.outbox("GuardProfileChanged")


def test_kannada_is_m2_and_is_refused_now(pw: PW) -> None:
    r = pw.call(pw.guard, "PUT", f"/v1/guards/{pw.guard.id}/profile", json={"language": "kn"})
    assert (
        r.status_code == 422 and r.json()["details"]["reason"] == "language_not_available_until_m2"
    )
    assert (
        pw.call(
            pw.guard, "PUT", f"/v1/guards/{pw.guard.id}/profile", json={"language": "ta"}
        ).status_code
        == 400
    )
    assert pw.rows("SELECT count(*) FROM guard_profiles")[0][0] == 0


def test_a_guard_cannot_change_another_guards_profile_but_a_supervisor_or_secretary_can(
    pw: PW,
) -> None:
    g2 = pw.vw.person()
    pw.idh.seed_grant(pw.soc.id, g2.id, "guard")
    assert (
        pw.call(pw.guard, "PUT", f"/v1/guards/{g2.id}/profile", json={"language": "hi"}).status_code
        == 404
    )
    assert (
        pw.call(
            pw.guard_sup, "PUT", f"/v1/guards/{g2.id}/profile", json={"language": "hi"}
        ).status_code
        == 200
    )
    assert (
        pw.call(
            pw.secretary,
            "PUT",
            f"/v1/guards/{g2.id}/profile",
            json={"language": "mr", "expected_version": 1},
        ).status_code
        == 200
    )
    assert pw.call(pw.guard, "GET", f"/v1/guards/{g2.id}/profile").status_code == 404


def test_a_profile_exists_only_for_a_person_who_holds_a_guard_role(pw: PW) -> None:
    h = pw.household("A-101")
    r = pw.call(pw.secretary, "PUT", f"/v1/guards/{h.owner.id}/profile", json={"language": "hi"})
    assert r.status_code == 404
    assert pw.call(pw.secretary, "GET", f"/v1/guards/{h.owner.id}/training").status_code == 404
    assert (
        pw.call(
            h.owner, "PUT", f"/v1/guards/{h.owner.id}/profile", json={"language": "hi"}
        ).status_code
        == 403
    )


# REQ: UX-09
def test_training_completion_is_recorded_per_guard_per_scenario_type_in_practice_mode(
    pw: PW,
) -> None:
    fresh = pw.call(pw.guard, "GET", f"/v1/guards/{pw.guard.id}/training").json()
    assert (
        fresh["completed"] == []
        and fresh["missing"] == list(SCENARIO_TYPES)
        and fresh["practice_mode"] is True
    )
    pw.call(pw.guard, "PUT", f"/v1/guards/{pw.guard.id}/profile", json={"language": "mr"})
    for scenario in ("guest_entry", "parcel_pickup"):
        r = pw.call(
            pw.guard, "POST", f"/v1/guards/{pw.guard.id}/training", json={"scenario_type": scenario}
        )
        assert r.status_code == 201, r.text
    again = pw.call(
        pw.guard,
        "POST",
        f"/v1/guards/{pw.guard.id}/training",
        json={"scenario_type": "guest_entry"},
    )
    assert again.status_code == 201
    status = pw.call(pw.guard, "GET", f"/v1/guards/{pw.guard.id}/training").json()
    assert [c["scenario_type"] for c in status["completed"]] == ["guest_entry", "parcel_pickup"]
    assert all(c["language"] == "mr" for c in status["completed"])
    assert (
        "guest_entry" not in status["missing"] and len(status["missing"]) == len(SCENARIO_TYPES) - 2
    )
    assert pw.rows("SELECT count(*) FROM guard_training_completions WHERE practice_mode")[0][0] == 3
    assert pw.rows("SELECT count(*) FROM guard_training_completions")[0][0] == 3, (
        "append-only: the repeat is a second row"
    )
    bad = pw.call(
        pw.guard,
        "POST",
        f"/v1/guards/{pw.guard.id}/training",
        json={"scenario_type": "real_gate_entry"},
    )
    assert bad.status_code == 400


def test_training_touches_no_gate_data_and_a_guard_records_only_their_own(pw: PW) -> None:
    g2 = pw.vw.person()
    pw.idh.seed_grant(pw.soc.id, g2.id, "guard")
    before = [
        pw.rows(f"SELECT count(*) FROM {t}")[0][0]
        for t in ("visits", "approval_requests", "parcels", "access_events")
    ]
    assert (
        pw.call(
            pw.guard, "POST", f"/v1/guards/{g2.id}/training", json={"scenario_type": "guest_entry"}
        ).status_code
        == 404
    )
    assert (
        pw.call(
            pw.guard_sup,
            "POST",
            f"/v1/guards/{g2.id}/training",
            json={"scenario_type": "guest_entry"},
        ).status_code
        == 201
    )
    assert [
        pw.rows(f"SELECT count(*) FROM {t}")[0][0]
        for t in ("visits", "approval_requests", "parcels", "access_events")
    ] == before
    import psycopg

    with pytest.raises(psycopg.DatabaseError), pw.idh.db.app_conn(society_id=pw.soc.id) as conn:
        conn.execute("UPDATE guard_training_completions SET scenario_type = 'guest_entry'")  # type: ignore[call-overload]
    with pytest.raises(psycopg.errors.CheckViolation), pw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
        conn.execute(  # type: ignore[call-overload]
            "INSERT INTO guard_training_completions (society_id, person_id, scenario_type, language, practice_mode, recorded_by)"
            " VALUES (%s, %s, 'guest_entry', 'en', false, %s)",
            (pw.soc.id, g2.id, g2.id),
        )
