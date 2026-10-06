"""Cross-society isolation of EVERY shifts route (INV-01, AT-01 spirit): society A's ids used from society B answer EXACTLY like random ids.

REQ: INV-01, ARCH-01, SHIFT-01, SHIFT-02, UX-08, UX-09.

For each route the foreign id (a real object of A) and a made-up one are replayed by an authorised person of B. Both answers must be identical
(status, code, message, details; only ``request_id`` differs) and no identifier of A may appear. A positive control proves the ids are real for A.
The inventory test fails when a route is added without a case here.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest

from dwaar_api.core.authz import iter_api_routes
from dwaar_api.modules.shifts import router
from tests.integration.parcels._support import PW, iso, now

pytestmark = [pytest.mark.req("INV-01", "ARCH-01", "SHIFT-01", "SHIFT-02", "UX-08", "UX-09")]


@dataclass(frozen=True)
class Case:
    method: str
    template: str
    persona: str  # secretary | guard | sup  (a person of society B)
    body: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    must_404: bool = True


START = {"checklist": {}}
END = {"checklist": {"parcels_counted": 0, "inside_records_reviewed": True}}
CASES: tuple[Case, ...] = (
    Case("PUT", "/v1/guards/{guard}/profile", "secretary", {"language": "hi"}),
    Case("GET", "/v1/guards/{guard}/profile", "secretary"),
    Case("POST", "/v1/guards/{guard}/training", "sup", {"scenario_type": "guest_entry"}),
    Case("GET", "/v1/guards/{guard}/training", "secretary"),
    Case(
        "POST",
        "/v1/shifts",
        "secretary",
        {
            "gate_id": "{gate}",
            "guard_id": "{guard}",
            "planned_start": "2030-01-01T10:00:00+00:00",
            "planned_end": "2030-01-01T18:00:00+00:00",
        },
    ),
    Case("GET", "/v1/shifts", "sup", must_404=False),
    Case("GET", "/v1/shifts", "sup", params={"gate_id": "{gate}"}, must_404=False),
    Case("GET", "/v1/shifts/current", "guard", must_404=False),
    Case("GET", "/v1/shifts/{shift}", "sup"),
    Case("POST", "/v1/shifts/{shift}/start", "sup", START),
    Case("POST", "/v1/shifts/{shift}/end", "sup", END),
    Case("POST", "/v1/shifts/{shift}/overrides", "sup", {"reason": "Probe from another society"}),
    Case("GET", "/v1/handovers", "sup", must_404=False),
    Case("GET", "/v1/handovers/{handover}", "sup"),
    Case("POST", "/v1/handovers/{handover}/acknowledge", "sup", {}),
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
    shift = pw.schedule(pw.guard)
    pw.call(pw.guard, "POST", f"/v1/shifts/{shift['id']}/start", json=START)
    ended = pw.call(pw.guard, "POST", f"/v1/shifts/{shift['id']}/end", json=END).json()
    live = pw.schedule(pw.guard, start=now() + timedelta(days=1))
    pw.call(pw.guard, "PUT", f"/v1/guards/{pw.guard.id}/profile", json={"language": "hi"})
    return {
        "guard": str(pw.guard.id),
        "gate": str(pw.gate_id),
        "shift": live["id"],
        "handover": ended["handover"]["id"],
        "ended_shift": shift["id"],
    }


def _who(pw: PW, persona: str) -> Any:
    return {"secretary": pw.other.secretary, "guard": pw.other.guard, "sup": pw.other.guard_sup}[
        persona
    ]


def _case_id(c: Case) -> str:
    return f"{c.method} {c.template} {c.persona}" + (" ?" + ",".join(c.params) if c.params else "")


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_a_foreign_id_answers_exactly_like_a_random_id(pw: PW, case: Case) -> None:
    foreign = _world(pw)
    random_ids = {k: str(uuid.uuid4()) for k in foreign}
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
    assert _norm(mine) == _norm(rand), (mine.text, rand.text)
    leaked = [v for v in foreign.values() if v in json.dumps(mine.json())]
    assert not leaked, leaked
    if case.must_404:
        assert mine.status_code in (400, 404), mine.text


def test_positive_control_the_ids_are_real_for_society_a(pw: PW) -> None:
    ids = _world(pw)
    assert pw.call(pw.guard_sup, "GET", f"/v1/shifts/{ids['shift']}").status_code == 200
    assert pw.call(pw.guard_sup, "GET", f"/v1/handovers/{ids['handover']}").status_code == 200
    assert pw.call(pw.guard_sup, "GET", f"/v1/guards/{ids['guard']}/profile").status_code == 200


def test_society_b_sees_nothing_of_a_and_a_nothing_of_b(pw: PW) -> None:
    ids = _world(pw)
    assert pw.call_b(pw.other.guard_sup, "GET", "/v1/shifts").json()["items"] == []
    assert pw.call_b(pw.other.guard_sup, "GET", "/v1/handovers").json()["items"] == []
    assert pw.call_b(pw.other.guard, "GET", "/v1/shifts/current").json() == {
        "shift": None,
        "context": None,
    }
    shift_b = pw.call_b(
        pw.other.guard_sup, "POST", "/v1/shifts",
        json={"gate_id": str(pw.other.gate_id), "guard_id": str(pw.other.guard.id), "planned_start": iso(now()), "planned_end": iso(now() + timedelta(hours=8))},
    )  # fmt: skip
    assert shift_b.status_code == 201, shift_b.text
    assert pw.call(pw.guard_sup, "GET", f"/v1/shifts/{shift_b.json()['id']}").status_code == 404
    assert all(
        s["id"] != shift_b.json()["id"]
        for s in pw.call(pw.guard_sup, "GET", "/v1/shifts").json()["items"]
    )
    # A's gate and A's guard cannot be used to schedule in B
    cross = pw.call_b(
        pw.other.guard_sup, "POST", "/v1/shifts",
        json={"gate_id": ids["gate"], "guard_id": str(pw.other.guard.id), "planned_start": iso(now() + timedelta(days=2)), "planned_end": iso(now() + timedelta(days=2, hours=8))},
    )  # fmt: skip
    assert cross.status_code == 400
    cross_guard = pw.call_b(
        pw.other.guard_sup, "POST", "/v1/shifts",
        json={"gate_id": str(pw.other.gate_id), "guard_id": ids["guard"], "planned_start": iso(now() + timedelta(days=2)), "planned_end": iso(now() + timedelta(days=2, hours=8))},
    )  # fmt: skip
    assert cross_guard.status_code == 404


def test_every_shifts_route_has_an_isolation_case(pw: PW) -> None:
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


def probed_routes() -> list[tuple[str, str]]:
    """(method, path template) of every route this file REALLY probes with a foreign id: the table the parametrized test iterates over. The AT-01
    route inventory (``tests/acceptance/test_at01_cross_society_isolation.py``) resolves these against the live app: a route that is not here fails it."""
    return [(c.method, c.template) for c in CASES]
