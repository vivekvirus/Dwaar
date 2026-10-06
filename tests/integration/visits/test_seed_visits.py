"""The visits part of the synthetic seed (steps/s400_visits.py): shape, honesty, determinism, idempotency.

REQ: GATE-01, GATE-02, GATE-08, GATE-11, SOC-05, PRD 8.3, BUILD_BRIEF 7.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api import seed
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = [pytest.mark.req("GATE-01", "GATE-02", "GATE-08", "GATE-11", "SOC-05")]


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


def test_gates_lanes_and_devices(seeded: World) -> None:
    w = seeded
    gates = w.admin_rows(
        "SELECT s.state, g.name, g.kind FROM gates g JOIN societies s ON s.id = g.society_id ORDER BY 1, 2"
    )
    assert gates == [
        ("Karnataka", "Tower Gate", "mixed"),
        ("Maharashtra", "Main Gate", "mixed"),
        ("Maharashtra", "Pedestrian Gate", "pedestrian"),
    ]
    assert _one(w, "SELECT count(*) FROM lanes") == 4
    devices = w.admin_rows("SELECT name, state, simulation FROM devices ORDER BY name")
    assert devices == [
        # slice 3 (edge seed default ON, ADR-0019): one society gateway per society, enrolled and approved through the same audited paths
        ("Main gate edge gateway", "active", True),
        ("Main gate terminal", "active", True),
        (
            "Pedestrian gate handheld",
            "pending_approval",
            True,
        ),  # left pending on purpose: the supervisor's queue is not empty
        ("Tower gate edge gateway", "active", True),
        ("Tower gate terminal", "active", True),
    ]
    # requested by a guard, decided by somebody else (maker != checker)
    assert w.admin_rows("SELECT count(*) FROM devices WHERE decided_by = requested_by")[0][0] == 0
    # 3 terminals/handhelds of the visits seed + 2 gateways of the edge seed = 5 requests; 2 + 2 = 4 approvals (the handheld stays pending)
    assert _one(w, "SELECT count(*) FROM audit_log WHERE operation = 'device.enrol_request'") == 5
    assert _one(w, "SELECT count(*) FROM audit_log WHERE operation = 'device.approve'") == 4


def test_passes_are_explicit_windows_one_revoked_one_phone_free(seeded: World) -> None:
    w = seeded
    rows = w.admin_rows(
        "SELECT purpose, state, max_uses, revoked_version, visitor_contact_token IS NULL, code_hash IS NULL FROM invitations ORDER BY purpose"
    )
    by_purpose = {r[0]: r[1:] for r in rows}
    assert len(rows) == 5
    assert by_purpose["Plumber visit (plan changed)"] == ("revoked", 1, 1, True, False)
    assert (
        by_purpose["Friend visiting (no phone)"][0] == "active"
        and by_purpose["Friend visiting (no phone)"][3] is True
    )  # phone-free
    assert by_purpose["Daily milk delivery"] == (
        "active",
        7,
        0,
        True,
        True,
    )  # recurring: explicit windows, no code at all
    assert (
        _one(
            w,
            "SELECT count(*) FROM invitation_windows w JOIN invitations i ON i.id = w.invitation_id WHERE i.purpose = 'Daily milk delivery'",
        )
        == 7
    )
    assert (
        _one(w, "SELECT max(window_end - window_start) FROM invitation_windows").total_seconds()
        <= 7 * 86400
    )
    assert (
        _one(
            w,
            "SELECT revocation_version FROM gate_policies WHERE society_id = (SELECT id FROM societies WHERE state = 'Maharashtra')",
        )
        == 1
    )


def test_requests_visits_and_the_overstay(seeded: World) -> None:
    w = seeded
    visits = {
        r[0]: r[1:]
        for r in w.admin_rows(
            "SELECT visitor_alias, kind, state, exit_basis, exited_at IS NOT NULL, confidence_inside, closed_reason FROM visits"
        )
    }
    assert visits["Vikas (cousin)"] == ("guest", "exited", "scanned", True, "none", None)
    assert visits["Grocery Basket delivery"] == ("delivery", "inside", None, False, "stale", None)
    assert visits["Unknown sales visitor"] == ("guest", "cancelled", None, False, "none", "denied")
    assert visits["Courier parcel"][0] == "delivery" and visits["Courier parcel"][1] in (
        "requested",
        "expired",
    )
    assert len(visits) == 4
    exceptions = w.admin_rows(
        "SELECT e.kind, e.state, e.raised_by_system, v.visitor_alias FROM exceptions e JOIN visits v ON v.id = e.visit_id"
    )
    assert exceptions == [("overstay", "open", True, "Grocery Basket delivery")]
    # approval requests: two approved, one denied, one that was pending (and is expired by the policy once somebody looks)
    states = sorted(r[0] for r in w.admin_rows("SELECT state FROM approval_requests"))
    assert (
        states.count("approved") == 2
        and states.count("denied") == 1
        and states.count("pending") + states.count("expired") == 1
    )
    # entry and exit are observed facts of their own, from the approved terminal
    events = w.admin_rows(
        "SELECT e.event_type, v.visitor_alias FROM access_events e JOIN visits v ON v.id = e.visit_id ORDER BY e.seq"
    )
    assert events == [
        ("EntryObserved", "Vikas (cousin)"),
        ("ExitObserved", "Vikas (cousin)"),
        ("EntryObserved", "Grocery Basket delivery"),
    ]
    # everything went through the audited paths
    for op, n in (
        ("approval.request", 4),
        ("approval.decide", 3),
        ("visit.entry_observed", 2),
        ("visit.exit_observed", 1),
        ("invitation.create", 5),
    ):
        assert _one(w, "SELECT count(*) FROM audit_log WHERE operation = %s", op) == n, op
    assert (
        _one(w, "SELECT count(*) FROM audit_log WHERE operation = 'visit.seed_timeline_shift'") == 1
    )  # the one synthetic shift is on record


def test_family_delegation_is_recorded_and_the_household_can_decide(seeded: World) -> None:
    w = seeded
    rows = w.admin_rows(
        "SELECT p.display_name, m.is_primary_approver FROM memberships m JOIN iam.persons p ON p.id = m.person_id"
        " WHERE m.kind = 'family' AND m.verification = 'verified' ORDER BY 1"
    )
    assert rows == [("Aarav Pawar", True), ("Rekha Pawar", True)]
    assert (
        _one(w, "SELECT count(*) FROM audit_log WHERE operation = 'membership.delegate_approver'")
        == 2
    )


def test_no_visitor_number_in_the_seeded_data(seeded: World) -> None:
    """The seed enters visitors by alias only; no number of any kind reaches the visit tables, audit rows or events."""
    for table in ("visits", "invitations", "approval_requests", "audit_log", "outbox"):
        text = "".join(str(r) for r in seeded.admin_rows(f"SELECT t::text FROM {table} t"))  # noqa: S608
        assert "99999" not in text, table  # the fictional range +91 99999 0nnnn
    columns = seeded.admin_rows(
        "SELECT column_name FROM information_schema.columns WHERE table_name IN ('visits', 'invitations')"
        " AND column_name ILIKE '%%phone%%'"
    )
    assert columns == []


def test_second_run_changes_nothing_in_the_visit_tables(seeded: World) -> None:
    w = seeded
    tables = ("gates", "lanes", "devices", "invitations", "invitation_windows", "visits", "visit_stops", "approval_requests",
              "approval_decisions", "access_events", "exceptions", "gate_policies", "audit_log", "outbox")  # fmt: skip
    sql = "SELECT " + ", ".join(f"(SELECT count(*) FROM {t})" for t in tables)  # noqa: S608
    before = w.admin_rows(sql)
    again = seed.run(seed_environment(w.db), say=lambda _l: None)
    assert w.admin_rows(sql) == before
    assert not {
        k: v
        for k, v in again.counts.items()
        if v and k.endswith(("_created", "_issued", "_enrolled", "_opened", "_ended"))
    }


def test_ids_are_deterministic_across_databases(
    pg_server: PgServer, template_db: str, seeded: World
) -> None:
    def snapshot(w: World) -> dict[str, list[tuple[Any, ...]]]:
        return {
            "gates": w.admin_rows("SELECT id, name FROM gates ORDER BY name"),
            "lanes": w.admin_rows(
                "SELECT id, label FROM lanes ORDER BY society_id, gate_id, label"
            ),
            "devices": w.admin_rows("SELECT id, name, key_id FROM devices ORDER BY name"),
            "invitations": w.admin_rows("SELECT id, purpose FROM invitations ORDER BY purpose"),
            "visits": w.admin_rows("SELECT id, visitor_alias FROM visits ORDER BY visitor_alias"),
            "requests": w.admin_rows(
                "SELECT r.id, v.visitor_alias FROM approval_requests r JOIN visits v ON v.id = r.visit_id ORDER BY 2"
            ),
            "events": w.admin_rows("SELECT event_id, seq FROM access_events ORDER BY seq"),
        }

    first = snapshot(seeded)
    for handle in _clone(pg_server, template_db):
        other = build_world(handle)
        try:
            second = snapshot(other)
        finally:
            other.database.dispose()
    assert first == second
    assert len(first["gates"]) == 3 and len(first["visits"]) == 4
