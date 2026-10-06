"""The shifts, staff and parcels parts of the synthetic seed (steps/s470_parcels.py, s480_staff.py, s490_shifts.py): shape, honesty, idempotency.

REQ: SHIFT-01, UX-08, UX-09, STAFF-01, STAFF-04, PRIV-04, PAR-02, PAR-03, PAR-04, PAR-05, AT-12, PRD 8.3.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api import seed
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = [
    pytest.mark.req(
        "SHIFT-01",
        "UX-08",
        "UX-09",
        "STAFF-01",
        "STAFF-04",
        "PRIV-04",
        "PAR-02",
        "PAR-03",
        "PAR-04",
        "PAR-05",
    )
]


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    for handle in _clone(pg_server, template_db):
        w = build_world(handle)
        try:
            yield w
        finally:
            w.database.dispose()


def _one(w: World, sql: str, *params: Any) -> Any:
    return w.admin_rows(sql, params)[0][0]


# REQ: SHIFT-01
def test_six_guard_shifts_appear_in_the_seed(seeded: World) -> None:
    rows = seeded.admin_rows(
        "SELECT s.state, st.state, sh.state FROM shifts sh JOIN gates g ON g.id = sh.gate_id JOIN societies st ON st.id = sh.society_id JOIN societies s ON s.id = st.id ORDER BY 2, sh.planned_start"
    )
    assert len(rows) == 6
    assert [r[2] for r in rows if r[1] == "Maharashtra"] == [
        "ended",
        "ended",
        "active",
        "scheduled",
    ]
    assert [r[2] for r in rows if r[1] == "Karnataka"] == ["ended", "active"]
    assert _one(seeded, "SELECT count(*) FROM shift_checklists WHERE kind = 'start'") == 5
    assert _one(seeded, "SELECT count(*) FROM shift_checklists WHERE kind = 'end'") == 3


def test_handovers_show_a_signed_one_an_escalated_one_signed_by_the_supervisor_and_an_unsigned_escalated_one(
    seeded: World,
) -> None:
    rows = seeded.admin_rows(
        "SELECT st.state, h.state, h.escalation_reason, h.incoming_guard IS NOT NULL, h.supervisor_ack_at IS NOT NULL, h.outgoing_ack_at IS NOT NULL, h.incoming_ack_at IS NOT NULL FROM shift_handovers h JOIN societies st ON st.id = h.society_id JOIN shifts s ON s.id = h.outgoing_shift_id ORDER BY st.state, s.planned_start"
    )
    assert rows == [
        ("Karnataka", "escalated", "no_incoming_guard", False, False, False, False),
        ("Maharashtra", "acknowledged", None, True, False, True, True),
        (
            "Maharashtra",
            "acknowledged",
            "no_incoming_guard",
            False,
            True,
            False,
            False,
        ),  # escalated first, then signed by the supervisor
    ]
    assert _one(seeded, "SELECT count(*) FROM outbox WHERE event_type = 'HandoverEscalated'") == 2


def test_guard_languages_and_training_are_seeded_and_kannada_is_not_offered_before_m2(
    seeded: World,
) -> None:
    langs = seeded.admin_rows(
        "SELECT p.display_name, g.language FROM guard_profiles g JOIN iam.persons p ON p.id = g.person_id ORDER BY 1"
    )
    assert {r[1] for r in langs} <= {"en", "hi", "mr"} and len(langs) == 5
    assert _one(seeded, "SELECT count(*) FROM guard_training_completions WHERE practice_mode") == 10


# REQ: STAFF-01, AT-12
def test_the_cook_has_three_separate_engagements_and_consent_came_first(seeded: World) -> None:
    rows = seeded.admin_rows(
        "SELECT s.display_name, count(e.id) FROM staff s LEFT JOIN staff_engagements e ON e.staff_id = s.id GROUP BY s.display_name ORDER BY 1"
    )
    assert rows == [("Lakshmi Naik", 1), ("Raju Pardeshi", 1), ("Sunita Kamble", 3)]
    assert (
        _one(
            seeded,
            "SELECT count(*) FROM staff s JOIN staff_consents c ON c.id = s.consent_id WHERE c.given_at <= s.created_at AND c.staff_action_recorded",
        )
        == 3
    )


def test_the_seeded_staff_hold_masked_ids_and_statuses_only(seeded: World) -> None:
    rows = seeded.admin_rows(
        "SELECT display_name, id_doc_kind, id_doc_masked, police_verification_status FROM staff ORDER BY 1"
    )
    assert rows == [
        ("Lakshmi Naik", None, None, "not_recorded"),
        ("Raju Pardeshi", "other", "XXXX 4567", "requested"),
        ("Sunita Kamble", "aadhaar", "XXXX XXXX 0123", "verified"),
    ]
    dump = str(seeded.admin_rows("SELECT string_agg(s::text, ' ') FROM staff s")) + str(
        seeded.admin_rows("SELECT string_agg(diff_masked::text, ' ') FROM audit_log")
    )
    assert "2345 6789 0123" not in dump and "234567890123" not in dump


# REQ: PAR-02, PAR-03, PAR-04, PAR-05
def test_the_parcels_seed_covers_the_states_and_keeps_courier_claims_apart(seeded: World) -> None:
    states = seeded.admin_rows("SELECT state, count(*) FROM parcels GROUP BY state ORDER BY 1")
    assert dict(states) == {
        "collected": 1,
        "expected": 1,
        "pickup_pending": 1,
        "received_at_gate": 1,
        "returned": 1,
        "stored": 2,
    }
    assert _one(seeded, "SELECT count(*) FROM courier_observations WHERE external") == 1
    assert _one(seeded, "SELECT state FROM parcels WHERE brand = 'Zomart'") == "expected", (
        "a courier's delivered claim never moved it"
    )
    assert _one(seeded, "SELECT count(*) FROM parcel_custody_reports") == 2
    # every parcel in custody has exactly one current custodian and a complete chain
    assert (
        _one(
            seeded,
            "SELECT count(*) FROM parcels p WHERE p.state <> 'expected' AND p.custodian IS DISTINCT FROM (SELECT to_party FROM custody_transfers t WHERE t.parcel_id = p.id ORDER BY seq DESC LIMIT 1)",
        )
        == 0
    )
    assert (
        _one(seeded, "SELECT count(*) FROM parcel_pickup_attempts WHERE outcome = 'granted'") == 1
    )


def test_every_new_row_has_its_audit_and_outbox_record(seeded: World) -> None:
    for op in (
        "parcel.receive",
        "parcel.store",
        "parcel.collect",
        "staff.register",
        "staff.consent_capture",
        "staff.engagement_create",
        "shift.schedule",
        "shift.start",
        "shift.end",
        "handover.acknowledge",
    ):
        assert _one(seeded, "SELECT count(*) FROM audit_log WHERE operation = %s", op) > 0, op
    assert (
        _one(seeded, "SELECT count(*) FROM audit_log WHERE operation = 'staff.engagement_create'")
        == 5
    )


def test_the_seeded_cook_can_be_checked_in_through_the_real_api(seeded: World) -> None:
    guard = seeded.login("mh.guard1")
    mh = seeded.society_ref("mh").id
    r = seeded.call(
        guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "code", "value": "SUNITA01"},
            "direction": "in",
            "client_event_id": "00000000-0000-4000-8000-0000000000f1",
        },
        headers={"X-Society-Id": str(mh)},
    )
    assert r.status_code == 201 and r.json()["recorded"] is True
    wrong = seeded.call(
        guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "code", "value": "SUNITA99"},
            "direction": "in",
            "client_event_id": "00000000-0000-4000-8000-0000000000f2",
        },
        headers={"X-Society-Id": str(mh)},
    )
    assert wrong.status_code == 404


def test_a_second_run_changes_nothing(pg_server: PgServer, template_db: str) -> None:
    for handle in _clone(pg_server, template_db):
        w = build_world(handle)
        try:
            probes = (
                "SELECT (SELECT count(*) FROM parcels), (SELECT count(*) FROM custody_transfers), (SELECT count(*) FROM staff), (SELECT count(*) FROM staff_engagements),"
                " (SELECT count(*) FROM attendance_events), (SELECT count(*) FROM shifts), (SELECT count(*) FROM shift_handovers), (SELECT count(*) FROM guard_profiles),"
                " (SELECT count(*) FROM guard_training_completions), (SELECT count(*) FROM audit_log), (SELECT count(*) FROM outbox), (SELECT count(*) FROM iam.persons)"
            )
            before = w.admin_rows(probes)
            again = seed.run(seed_environment(w.db), say=lambda _l: None)
            assert w.admin_rows(probes) == before
            created = {
                k: v
                for k, v in again.counts.items()
                if v
                and k
                in (
                    "parcels_created",
                    "staff_created",
                    "shifts_created",
                    "engagements_created",
                    "attendance_created",
                    "guard_profiles_created",
                    "training_completions_created",
                    "courier_claims_created",
                    "custody_reports_created",
                    "staff_consents_created",
                )
            }
            assert created == {}, created
        finally:
            w.database.dispose()
