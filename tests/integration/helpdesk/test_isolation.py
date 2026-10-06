"""INV-01 / AT-01 for every helpdesk route: another society's id answers EXACTLY like a random id (404 not_found, same body),
nothing of the foreign society leaks, and nothing in it changes."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest

from tests.integration.helpdesk._flow import raise_ticket, tid

pytestmark = pytest.mark.req("OPS-02", "INV-01")


@dataclass
class Case:
    actor: str
    method: str
    path: str
    body: dict[str, Any] | None = None


def cases(foreign_ticket: str, own_ticket: str) -> list[Case]:
    """``{x}`` is replaced by the id under test (foreign or random); ``own_ticket`` is a ticket of the caller's society."""
    t = "{x}"
    return [
        Case("sec", "GET", f"/v1/tickets/{t}"),
        Case("res", "GET", f"/v1/tickets/{t}"),
        Case("sec", "GET", f"/v1/tickets/{t}/sla"),
        Case("res", "POST", f"/v1/tickets/{t}/submit", {}),
        Case("sec", "POST", f"/v1/tickets/{t}/acknowledge", {}),
        Case("sec", "POST", f"/v1/tickets/{t}/triage", {}),
        Case("sec", "POST", f"/v1/tickets/{t}/assign", {"contractor_name": "Acme Repairs"}),
        Case("sec", "POST", f"/v1/tickets/{t}/transition", {"to": "in_progress"}),
        Case(
            "sec",
            "POST",
            f"/v1/tickets/{t}/priority",
            {"priority": "urgent", "reason": "isolation probe"},
        ),
        Case("res", "POST", f"/v1/tickets/{t}/respond", {}),
        Case("res", "POST", f"/v1/tickets/{t}/confirm", {}),
        Case("sec", "POST", f"/v1/tickets/{t}/confirm", {}),
        Case("res", "POST", f"/v1/tickets/{t}/reopen", {"reason": "isolation probe"}),
        Case("res", "POST", f"/v1/tickets/{t}/cancel", {"reason": "isolation probe"}),
        Case(
            "sec",
            "POST",
            f"/v1/tickets/{t}/merge",
            {"into_ticket_id": own_ticket, "reason": "isolation probe"},
        ),
        Case(
            "sec",
            "POST",
            f"/v1/tickets/{own_ticket}/merge",
            {"into_ticket_id": t, "reason": "isolation probe"},
        ),
        Case("sec", "POST", f"/v1/tickets/{own_ticket}/assign", {"assignee_id": t}),
        Case(
            "sec",
            "POST",
            f"/v1/tickets/{own_ticket}/priority",
            {"priority": "urgent", "reason": "isolation probe", "approver_id": t},
        ),
        Case(
            "sec",
            "POST",
            "/v1/tickets",
            {"scope": "private", "unit_id": t, "category": "plumbing", "title": "Isolation probe"},
        ),
        Case(
            "res",
            "POST",
            "/v1/tickets",
            {"scope": "private", "unit_id": t, "category": "plumbing", "title": "Isolation probe"},
        ),
        Case(
            "sec",
            "POST",
            "/v1/tickets",
            {"scope": "block", "block_id": t, "category": "plumbing", "title": "Isolation probe"},
        ),
        Case(
            "res",
            "POST",
            "/v1/tickets",
            {"scope": "block", "block_id": t, "category": "plumbing", "title": "Isolation probe"},
        ),
        Case("sec", "GET", "/v1/tickets?unit_id={x}"),
        Case("res", "GET", "/v1/tickets?unit_id={x}"),
    ]


def run(hw, who, case: Case, x: str) -> Any:
    path = case.path.replace("{x}", x)
    body = (
        None if case.body is None else {k: (x if v == "{x}" else v) for k, v in case.body.items()}
    )
    return hw.call(who, case.method, path, json=body)


def normal(r: Any) -> tuple[int, Any]:
    body = r.json()
    return r.status_code, {k: v for k, v in body.items() if k != "request_id"} if isinstance(
        body, dict
    ) else body


def test_every_ticket_route_answers_a_foreign_id_like_a_random_one(hw) -> None:
    foreign = hw.second_society()
    sec_b = hw.staff("secretary", soc=foreign)
    res_b = hw.resident(foreign.units["Z-101"], "owner", soc=foreign)
    r = hw.call(
        res_b,
        "POST",
        "/v1/tickets",
        society=foreign.id,
        json={
            "scope": "private",
            "unit_id": str(foreign.units["Z-101"]),
            "category": "plumbing",
            "title": "Foreign household secret leak",
            "description": "Foreign private description 77777",
        },
    )
    assert r.status_code == 201, r.text
    b_ticket = r.json()["ticket"]["id"]
    foreign_block = hw.rows("SELECT id FROM blocks WHERE society_id = %s", (foreign.id,))[0][0]
    foreign_unit = foreign.units["Z-102"]
    version_before = hw.rows("SELECT version, state FROM tickets WHERE id = %s", (b_ticket,))[0]

    people = {"sec": hw.staff("secretary"), "res": hw.resident(hw.unit("A-101"), "owner")}
    own = tid(
        raise_ticket(
            hw,
            people["res"],
            scope="private",
            unit_id=str(hw.unit("A-101")),
            category="plumbing",
            title="Our own leaking tap",
        )
    )
    probes: list[tuple[Case, str]] = []
    for case in cases(b_ticket, own):
        probes.append((case, b_ticket))
    for case in cases(str(foreign_unit), own):
        if "unit_id" in str(case.body) or "unit_id" in case.path:
            probes.append((case, str(foreign_unit)))
    for case in cases(str(foreign_block), own):
        if "block_id" in str(case.body):
            probes.append((case, str(foreign_block)))
    # a person of the foreign society as assignee / approver
    probes.append(
        (Case("sec", "POST", f"/v1/tickets/{own}/assign", {"assignee_id": "{x}"}), str(sec_b.id))
    )
    probes.append(
        (
            Case(
                "sec",
                "POST",
                f"/v1/tickets/{own}/priority",
                {"priority": "urgent", "reason": "isolation probe", "approver_id": "{x}"},
            ),
            str(sec_b.id),
        )
    )
    seen = 0
    for case, foreign_id in probes:
        who = people[case.actor]
        for _attempt in range(2):  # the same answer twice: a probe never changes state
            f = run(hw, who, case, foreign_id)
            rnd = run(hw, who, case, str(uuid.uuid4()))
            assert normal(f) == normal(rnd), (case, f.text, rnd.text)
            if (
                "?unit_id=" in case.path
            ):  # a list FILTER: an empty page, identical for foreign and random
                assert f.status_code == 200 and f.json()["items"] == []
            else:
                assert f.status_code in (400, 403, 404), (case, f.status_code)
            blob = f.text
            for leak in (
                b_ticket,
                "Foreign household",
                "77777",
                str(foreign.id),
                str(sec_b.id),
                str(foreign_block),
            ):
                assert leak not in blob, (case, leak)
        seen += 1
    assert seen >= 25
    assert (
        hw.rows("SELECT version, state FROM tickets WHERE id = %s", (b_ticket,))[0]
        == version_before
    )
    # and the foreign staff cannot reach OUR ticket either
    for verb in ("", "/sla"):
        assert (
            hw.call(sec_b, "GET", f"/v1/tickets/{own}{verb}", society=foreign.id).status_code == 404
        )
    assert (
        hw.call(sec_b, "POST", f"/v1/tickets/{own}/triage", json={}, society=foreign.id).status_code
        == 404
    )


PROC = {"headline": "Probe headline", "steps": "Probe steps for the isolation test"}
SETTINGS_BODY = {
    "working_days": [1, 2, 3, 4, 5], "opens_at": "09:00:00", "closes_at": "18:00:00",
    "sla": {"emergency": {"ack": {"mode": "clock", "minutes": 2}}},
}  # fmt: skip
#: (actor, method, path, body): every route that takes the society from ``X-Society-Id`` (or the path) and no object id. ``{foreign}`` is replaced by the
#: id of the other society (the same 404 as an unknown one is required); the table is what the test iterates over AND what AT-01's inventory reads.
NAMING_CALLS: tuple[tuple[str, str, str, dict[str, Any] | None], ...] = (
    ("sec", "GET", "/v1/tickets", None),
    ("res", "GET", "/v1/tickets", None),
    ("res", "POST", "/v1/tickets", {"scope": "society", "category": "other", "title": "Isolation probe"}),
    ("sec", "GET", "/v1/helpdesk/settings", None),
    ("sec", "PUT", "/v1/helpdesk/settings", SETTINGS_BODY),
    ("sec", "GET", "/v1/helpdesk/emergency-procedures", None),
    ("sec", "PUT", "/v1/helpdesk/emergency-procedures/lift", PROC),
    ("res", "GET", "/v1/helpdesk/emergency-procedures", None),
    ("res", "POST", "/v1/societies/{foreign}/support-requests", {"title": "Isolation probe"}),
    ("res", "GET", "/v1/societies/{foreign}/support-requests", None),
)  # fmt: skip


def probed_routes() -> list[tuple[str, str]]:
    """(method, path) of every helpdesk route REALLY probed with a foreign id or a foreign society: the ticket cases and ``NAMING_CALLS``. The AT-01
    route inventory resolves these against the live app: a route that is not here fails it."""
    return [
        (c.method, c.path.replace("{x}", "{id}").split("?")[0]) for c in cases("{id}", "{own}")
    ] + [(method, path) for _who, method, path, _body in NAMING_CALLS]


def test_naming_a_foreign_society_is_the_same_404_as_an_unknown_one(hw) -> None:
    foreign = hw.second_society()
    people = {"sec": hw.staff("secretary"), "res": hw.resident(hw.unit("A-101"), "owner")}
    for who_key, method, path, body in NAMING_CALLS:
        who = people[who_key]
        path = path.replace("{foreign}", str(foreign.id))
        a = hw.call(who, method, path, json=body, society=foreign.id)
        b = hw.call(
            who,
            method,
            path.replace(str(foreign.id), str(uuid.uuid4())),
            json=body,
            society=uuid.uuid4(),
        )
        assert normal(a) == normal(b) and a.status_code == 404, (method, path, a.text)
    assert hw.rows("SELECT count(*) FROM tickets WHERE society_id = %s", (foreign.id,))[0][0] == 0
    assert (
        hw.rows("SELECT count(*) FROM emergency_procedures WHERE society_id = %s", (foreign.id,))[
            0
        ][0]
        == 0
    )
    assert (
        hw.rows("SELECT count(*) FROM helpdesk_settings WHERE society_id = %s", (foreign.id,))[0][0]
        == 0
    )


def test_row_level_security_hides_foreign_rows_even_to_a_buggy_query(hw) -> None:
    foreign = hw.second_society()
    res_b = hw.resident(foreign.units["Z-101"], "owner", soc=foreign)
    r = hw.call(
        res_b,
        "POST",
        "/v1/tickets",
        society=foreign.id,
        json={
            "scope": "private",
            "unit_id": str(foreign.units["Z-101"]),
            "category": "plumbing",
            "title": "Foreign household leak",
        },
    )
    assert r.status_code == 201
    mine = hw.staff("secretary")
    raise_ticket(hw, mine, title="Our corridor light")
    for table in (
        "tickets",
        "ticket_events",
        "ticket_priority_history",
        "ticket_sla_log",
        "ticket_sla_breaches",
        "ticket_links",
        "helpdesk_settings",
        "emergency_procedures",
    ):
        with hw.idh.db.app_conn(hw.soc.id, mine.id, "secretary") as conn:
            rows = conn.execute(f"SELECT DISTINCT society_id FROM {table}").fetchall()  # type: ignore[call-overload]
            assert {x[0] for x in rows} <= {hw.soc.id}, table
        with hw.idh.db.app_conn() as conn:  # no context at all: zero rows, never all rows
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table  # type: ignore[call-overload,index]
