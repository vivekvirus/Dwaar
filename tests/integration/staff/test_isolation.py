"""Cross-society isolation of EVERY staff route (INV-01, AT-01 spirit): society A's ids used from society B answer EXACTLY like random ids.

REQ: INV-01, ARCH-01, STAFF-01, STAFF-04.

For each route the foreign id (a real object of A) and a made-up one are replayed by an authorised person of B. Both answers must be identical
(status, code, message, details; only ``request_id`` differs) and no identifier of A may appear. A positive control proves the ids are real for A.
The inventory test fails when a route is added without a case here.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

import pytest

from dwaar_api.core.authz import iter_api_routes
from dwaar_api.modules.staff import router
from tests.integration.parcels._support import PW, schedule_now

pytestmark = [pytest.mark.req("INV-01", "ARCH-01", "STAFF-01", "STAFF-04")]


@dataclass(frozen=True)
class Case:
    method: str
    template: str
    persona: str  # secretary | guard | resident
    body: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    must_404: bool = True
    compare: bool = True  # False for a pure create that takes no id at all (it can only create in the caller's own society)


V = {"expected_version": 1}
SCHED = {"days": ["mon"], "from": "07:00", "to": "09:00"}
CASES: tuple[Case, ...] = (
    Case(
        "POST",
        "/v1/staff-consents",
        "secretary",
        {
            "language": "hi",
            "notice_version": "v1",
            "purposes": ["engagement_record"],
            "staff_action_recorded": True,
        },
        must_404=False,
        compare=False,
    ),
    Case(
        "POST",
        "/v1/staff-consents/{consent}/withdraw",
        "secretary",
        {**V, "reason": "Probe from another society"},
    ),
    Case(
        "POST",
        "/v1/staff",
        "secretary",
        {
            "consent_id": "{consent}",
            "display_name": "Probe",
            "phone": "+919999980555",
            "staff_type": "cook",
        },
    ),
    Case("GET", "/v1/staff", "secretary", must_404=False),
    Case("GET", "/v1/staff", "guard", must_404=False),
    Case("GET", "/v1/staff/{staff}", "secretary"),
    Case("GET", "/v1/staff/{staff}", "guard"),
    Case("GET", "/v1/staff/{staff}", "resident"),
    Case("PATCH", "/v1/staff/{staff}", "secretary", {**V, "photo_ref": "photo://probe"}),
    Case("POST", "/v1/staff/{staff}/credentials", "secretary", {"kind": "code", **V}),
    Case(
        "POST",
        "/v1/staff-engagements",
        "resident",
        {"staff_ref": "{staff_ref}", "unit_id": "{unit}", "duty": "probe", "schedule": SCHED},
    ),
    Case(
        "POST",
        "/v1/staff-engagements",
        "secretary",
        {"staff_ref": "{staff_ref}", "unit_id": "{unit}", "duty": "probe", "schedule": SCHED},
    ),
    Case("GET", "/v1/staff-engagements", "resident", params={"unit_id": "{unit}"}),
    Case(
        "GET", "/v1/staff-engagements", "secretary", params={"staff_id": "{staff}"}, must_404=False
    ),
    Case("PATCH", "/v1/staff-engagements/{engagement}", "resident", {**V, "duty": "probe"}),
    Case(
        "POST",
        "/v1/staff-engagements/{engagement}/end",
        "resident",
        {**V, "reason": "Probe from another society"},
    ),
    Case(
        "POST",
        "/v1/attendance",
        "guard",
        {
            "credential": {"kind": "code", "value": "{code}"},
            "direction": "in",
            "client_event_id": "00000000-0000-4000-8000-0000000000aa",
        },
    ),
    Case("GET", "/v1/attendance", "secretary", params={"staff_id": "{staff}"}, must_404=False),
    Case("GET", "/v1/attendance", "resident", params={"unit_id": "{unit}"}),
    Case(
        "POST",
        "/v1/attendance/{attendance}/corrections",
        "secretary",
        {"kind": "void", "reason": "Probe from another society"},
    ),
    Case(
        "POST",
        "/v1/payroll-adjustments",
        "resident",
        {
            "engagement_id": "{engagement}",
            "kind": "bonus",
            "amount_paise": 100,
            "period": "2026-10",
            "reason": "Probe from society B",
        },
    ),
    Case(
        "GET",
        "/v1/payroll-adjustments",
        "resident",
        params={"engagement_id": "{engagement}"},
        must_404=False,
    ),
    Case(
        "POST",
        "/v1/payroll-adjustments/{adjustment}/decision",
        "resident",
        {"decision": "approve", **V},
    ),
)


def _fill(value: Any, ids: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format(**ids) if "{" in value else value
    if isinstance(value, dict):
        return {k: _fill(v, ids) for k, v in value.items()}
    return value


def _norm(response: Any) -> tuple[int, dict[str, Any]]:
    body = response.json()
    body.pop("request_id", None)
    return response.status_code, body


def _world(pw: PW) -> dict[str, str]:
    h = pw.household("A-101")
    staff = pw.register_staff()
    eng = pw.engage(h.owner, staff, h.unit, schedule=schedule_now())
    code = pw.issue_code(staff)
    event = pw.check_in(pw.guard, code).json()
    adj = pw.call(
        h.owner,
        "POST",
        "/v1/payroll-adjustments",
        json={
            "engagement_id": eng["id"],
            "kind": "bonus",
            "amount_paise": 5000,
            "period": "2026-10",
            "reason": "Bonus in society A",
        },
    ).json()
    return {
        "consent": staff["consent"]["id"], "staff": staff["id"], "staff_ref": staff["staff_ref"], "engagement": eng["id"],
        "attendance": event["id"], "adjustment": adj["id"], "unit": str(h.unit), "code": code,
    }  # fmt: skip


def _who(pw: PW, persona: str) -> Any:
    return {
        "secretary": pw.other.secretary,
        "guard": pw.other.guard,
        "resident": pw.other.resident,
    }[persona]


def _case_id(c: Case) -> str:
    return f"{c.method} {c.template} {c.persona}"


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_a_foreign_id_answers_exactly_like_a_random_id(pw: PW, case: Case) -> None:
    foreign = _world(pw)
    random_ids = {
        k: (
            str(uuid.uuid4())
            if k not in ("staff_ref", "code")
            else ("ABCDEFGHIJ" if k == "staff_ref" else "QWERTYUI")
        )
        for k in foreign
    }
    # B's own unit stands in for "unit" when the foreign one would only prove a different point (body routes below use A's unit on purpose)
    mine = pw.call_b(
        _who(pw, case.persona),
        case.method,
        _fill(case.template, foreign),
        json=_fill(case.body, foreign),
        params=_fill(case.params, foreign),
    )
    rand = pw.call_b(
        _who(pw, case.persona),
        case.method,
        _fill(case.template, random_ids),
        json=_fill(case.body, random_ids),
        params=_fill(case.params, random_ids),
    )
    if not case.compare:
        assert mine.status_code == rand.status_code == 201
        counts = pw.rows("SELECT society_id, count(*) FROM staff_consents GROUP BY society_id")
        assert dict(counts) == {pw.soc.id: 1, pw.other.soc.id: 2}, (
            "each consent was created in the caller's society only"
        )
        return
    assert _norm(mine) == _norm(rand), (mine.text, rand.text)
    leaked = [v for k, v in foreign.items() if k not in ("code",) and v in json.dumps(mine.json())]
    assert not leaked, leaked
    assert foreign["code"] not in json.dumps(mine.json())
    if case.must_404:
        assert mine.status_code in (404, 400, 403), mine.text
        assert mine.status_code != 200 and mine.status_code != 201


def test_positive_control_the_ids_are_real_for_society_a(pw: PW) -> None:
    ids = _world(pw)
    assert pw.call(pw.secretary, "GET", f"/v1/staff/{ids['staff']}").status_code == 200
    assert pw.call(pw.secretary, "GET", "/v1/attendance", params={"staff_id": ids["staff"]}).json()[
        "items"
    ]
    assert pw.call(pw.secretary, "GET", "/v1/staff-engagements").json()["items"]


def test_society_b_sees_nothing_of_a_and_a_nothing_of_b(pw: PW) -> None:
    ids = _world(pw)
    assert pw.call_b(pw.other.secretary, "GET", "/v1/staff").json()["items"] == []
    assert pw.call_b(pw.other.guard, "GET", "/v1/staff").json()["items"] == []
    assert pw.call_b(pw.other.secretary, "GET", "/v1/staff-engagements").json()["items"] == []
    assert pw.call_b(pw.other.resident, "GET", "/v1/payroll-adjustments").json()["items"] == []
    c = pw.call_b(
        pw.other.secretary,
        "POST",
        "/v1/staff-consents",
        json={
            "language": "kn",
            "notice_version": "v1",
            "purposes": ["engagement_record"],
            "staff_action_recorded": True,
        },
    )
    assert c.status_code == 201
    staff_b = pw.call_b(
        pw.other.secretary,
        "POST",
        "/v1/staff",
        json={
            "consent_id": c.json()["id"],
            "display_name": "B Cook",
            "phone": "+919999980556",
            "staff_type": "cook",
        },
    )
    assert staff_b.status_code == 201
    assert pw.call(pw.secretary, "GET", f"/v1/staff/{staff_b.json()['id']}").status_code == 404
    assert all(
        s["display_name"] != "B Cook"
        for s in pw.call(pw.secretary, "GET", "/v1/staff").json()["items"]
    )
    # A's consent receipt cannot register a person in B
    cross = pw.call_b(
        pw.other.secretary,
        "POST",
        "/v1/staff",
        json={
            "consent_id": ids["consent"],
            "display_name": "X",
            "phone": "+919999980557",
            "staff_type": "cook",
        },
    )
    assert cross.status_code == 404


def test_a_staff_credential_of_society_a_is_worthless_in_society_b_even_with_the_same_code_space(
    pw: PW,
) -> None:
    ids = _world(pw)
    r = pw.call_b(
        pw.other.guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "code", "value": ids["code"]},
            "direction": "in",
            "client_event_id": str(uuid.uuid4()),
        },
    )
    assert r.status_code == 404
    assert (
        pw.rows("SELECT count(*) FROM attendance_events WHERE society_id = %s", (pw.other.soc.id,))[
            0
        ][0]
        == 0
    )


def test_every_staff_route_has_an_isolation_case(pw: PW) -> None:
    def shape(path: str) -> str:
        return re.sub(r"\{\w+\}", "{x}", path)

    routes = {
        (m, shape(r.path))
        for r in iter_api_routes(router)
        for m in (r.methods or ())
        if m not in ("HEAD", "OPTIONS")
    }
    covered = {(c.method, shape(c.template)) for c in CASES}
    assert routes == covered, (routes - covered, covered - routes)
