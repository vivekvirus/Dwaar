"""The helpdesk part of the synthetic seed (steps/s530_helpdesk.py): shape, honesty, idempotency, audit and outbox.

REQ: OPS-01, OPS-02, OPS-04, OPS-09, UX-07, PRD 8.3, BUILD_BRIEF 7.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment
from tests.integration.helpdesk._seedsteps import run_steps

pytestmark = [pytest.mark.req("OPS-01", "OPS-02", "OPS-04", "OPS-09", "UX-07")]


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    for handle in _clone(pg_server, template_db):
        w = build_world(handle, run_seed=False)
        run_steps(seed_environment(handle), {"helpdesk"})
        try:
            yield w
        finally:
            w.database.dispose()


def rows(w: World, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    return w.admin_rows(sql, params)


def test_procedures_exist_for_both_societies_and_are_invented_text(seeded: World) -> None:
    got = rows(
        seeded,
        "SELECT s.state, count(*) FROM emergency_procedures p JOIN societies s ON s.id = p.society_id GROUP BY 1 ORDER BY 1",
    )
    assert got == [("Karnataka", 5), ("Maharashtra", 5)]
    phones = rows(
        seeded, "SELECT c->>'phone' FROM emergency_procedures p, jsonb_array_elements(p.contacts) c"
    )
    assert phones and all(
        p[0].startswith("+9199999") for p in phones
    )  # the reserved fictional range
    assert (
        rows(seeded, "SELECT count(*) FROM helpdesk_settings WHERE sla_source = 'pilot_default'")[
            0
        ][0]
        == 1
    )  # MH only: created with its first ticket


def test_tickets_cover_the_states_and_the_hazard_route(seeded: World) -> None:
    got = {
        r[0]: r[1:]
        for r in rows(
            seeded,
            "SELECT title, state, priority, routing, closed_basis, hazard_kind FROM tickets WHERE category <> 'support_privacy'",
        )
    }
    assert got["Kitchen tap leaking"] == ("closed", "normal", "staff", "resident_confirmed", None)
    assert got["Ceiling seepage in the bedroom"][0] == "assigned"
    lift = got["Lift B is sparking near the door"]
    assert lift == ("assigned", "emergency", "qualified_contractor", None, "lift")
    assert (
        rows(seeded, "SELECT count(*) FROM outbox WHERE event_type = 'TicketEmergencyAlert'")[0][0]
        == 1
    )
    # the second stairwell report was PROPOSED as a duplicate of the first (same society-wide scope), never merged by itself
    link = rows(
        seeded,
        "SELECT l.state, l.method FROM ticket_links l JOIN tickets a ON a.id = l.ticket_id JOIN tickets b ON b.id = l.linked_ticket_id WHERE a.title = b.title",
    )
    assert link == [("proposed", "trigram")]
    assert rows(seeded, "SELECT count(*) FROM tickets WHERE state = 'draft'")[0][0] == 0


def test_ux07_disputed_tenant_has_a_support_issue(seeded: World) -> None:
    got = rows(
        seeded,
        "SELECT t.category, t.scope, t.raised_channel FROM tickets t JOIN memberships m ON m.person_id = t.raised_by WHERE m.verification = 'disputed' AND t.category = 'support_privacy'",
    )
    assert got == [("support_privacy", "private", "support")]


def test_every_ticket_has_its_audit_and_outbox_rows_and_no_text_leaks(seeded: World) -> None:
    n = rows(seeded, "SELECT count(*) FROM tickets")[0][0]
    assert (
        rows(seeded, "SELECT count(*) FROM audit_log WHERE operation = 'ticket.submit_new'")[0][0]
        == n
    )
    assert (
        rows(seeded, "SELECT count(*) FROM outbox WHERE event_type = 'TicketSubmitted'")[0][0] == n
    )
    blob = str(rows(seeded, "SELECT payload FROM outbox WHERE aggregate_type = 'ticket'")) + str(
        rows(seeded, "SELECT diff_masked FROM audit_log WHERE object_type = 'ticket'")
    )
    assert "seepage" not in blob.lower() and "washer" not in blob.lower()


def test_second_run_changes_nothing(seeded: World) -> None:
    tables = ("tickets", "ticket_events", "ticket_priority_history", "ticket_sla_log", "ticket_sla_breaches", "ticket_links",
              "helpdesk_settings", "emergency_procedures", "audit_log", "outbox")  # fmt: skip
    sql = "SELECT " + ", ".join(f"(SELECT count(*) FROM {t})" for t in tables)  # noqa: S608
    before = seeded.admin_rows(sql)
    again = run_steps(seed_environment(seeded.db), {"helpdesk"})
    assert seeded.admin_rows(sql) == before
    assert not {
        k: v
        for k, v in again.items()
        if v and k in {"tickets_created", "procedures_created", "support_requests_created"}
    }
