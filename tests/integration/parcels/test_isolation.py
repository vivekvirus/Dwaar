"""Cross-society isolation of EVERY parcels route (INV-01, AT-01 spirit): society A's ids used from society B answer EXACTLY like random ids.

REQ: INV-01, ARCH-01, PAR-02, PAR-03.

For each route the foreign id (a real object of A) and a made-up id are replayed by an authorised person of B. Both answers must be identical
(status, code, message, details; only ``request_id`` differs) and no identifier of A may appear in B's answers. A positive control proves that
the id IS real for A's own actor. The route inventory test fails when a route is added without a case here.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta  # noqa: I001
from typing import Any

import pytest

from dwaar_api.core.authz import iter_api_routes
from dwaar_api.modules.parcels import router
from tests.integration.parcels._support import PW, iso, now

pytestmark = [pytest.mark.req("INV-01", "ARCH-01", "PAR-02", "PAR-03")]


@dataclass(frozen=True)
class Case:
    method: str
    template: str
    persona: str  # guard | resident | secretary  (a person of society B)
    body: dict[str, Any] | None = None
    params: dict[str, Any] | None = None


V = {"expected_version": 1}
CASES: tuple[Case, ...] = (
    Case(
        "POST",
        "/v1/parcel-expectations",
        "resident",
        {
            "unit_id": "{unit}",
            "brand": "X",
            "expected_from": "2026-10-06T10:00:00+00:00",
            "expected_until": "2026-10-06T11:00:00+00:00",
        },
    ),
    Case("DELETE", "/v1/parcel-expectations/{parcel}", "resident"),
    Case("POST", "/v1/parcels", "guard", {"unit_id": "{unit}", "gate_id": "{gate}", "brand": "X"}),
    Case("GET", "/v1/parcels", "resident", params={"unit_id": "{unit}"}),
    Case("GET", "/v1/parcels", "guard"),
    Case("GET", "/v1/parcels/{parcel}", "guard"),
    Case("GET", "/v1/parcels/{parcel}", "resident"),
    Case("POST", "/v1/parcels/{parcel}/store", "guard", {"bin_code": "B-1", **V}),
    Case("PUT", "/v1/parcels/{parcel}/leave-at-gate-consent", "resident", {"granted": True, **V}),
    Case("POST", "/v1/parcels/{parcel}/pickup-token", "resident", V),
    Case(
        "POST",
        "/v1/parcels/{parcel}/collect",
        "guard",
        {"method": "token", "token": "t" * 30, "collector": {"kind": "recipient"}},
    ),
    Case(
        "POST",
        "/v1/parcels/{parcel}/resolve",
        "guard",
        {"outcome": "refused", "note": "probe by another society", **V},
    ),
    Case(
        "POST",
        "/v1/parcels/{parcel}/courier-claims",
        "guard",
        {"source": "courier_app", "claim": "delivered", "claimed_at": "2026-10-06T10:00:00+00:00"},
    ),
    Case("POST", "/v1/parcel-custody-reports", "guard", {"physical_count": 1, "gate_id": "{gate}"}),
    Case("GET", "/v1/parcel-custody-reports", "guard"),
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
    parcel = pw.stored_parcel(h.unit)
    pw.call(pw.guard, "POST", "/v1/parcel-custody-reports", json={"physical_count": 1})
    return {"unit": str(h.unit), "parcel": parcel["id"], "gate": str(pw.gate_id)}


def _who(pw: PW, persona: str) -> Any:
    return {
        "guard": pw.other.guard,
        "resident": pw.other.resident,
        "secretary": pw.other.secretary,
    }[persona]


def _case_id(c: Case) -> str:
    return f"{c.method} {c.template} {c.persona}"


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_a_foreign_id_answers_exactly_like_a_random_id(pw: PW, case: Case) -> None:
    foreign = _world(pw)
    random_ids = {k: str(uuid.uuid4()) for k in foreign}
    # the template may use an A unit/gate/parcel id: B must not be able to tell it from a made-up one
    mine = pw.call_b(
        _who(pw, case.persona), case.method, _fill(case.template, foreign),
        json=_fill(case.body, foreign), params=_fill(case.params, foreign),
    )  # fmt: skip
    rand = pw.call_b(
        _who(pw, case.persona), case.method, _fill(case.template, random_ids),
        json=_fill(case.body, random_ids), params=_fill(case.params, random_ids),
    )  # fmt: skip
    assert _norm(mine) == _norm(rand), (mine.text, rand.text)
    leaked = [v for v in foreign.values() if v in json.dumps(mine.json())]
    assert not leaked, leaked
    if "{parcel}" in case.template:
        assert mine.status_code == 404, mine.text


def test_a_positive_control_the_foreign_ids_are_real_for_society_a(pw: PW) -> None:
    ids = _world(pw)
    assert pw.call(pw.guard, "GET", f"/v1/parcels/{ids['parcel']}").status_code == 200
    assert (
        pw.call(pw.guard, "GET", "/v1/parcels", params={"unit_id": ids["unit"]}).status_code == 200
    )
    assert pw.call(pw.guard, "GET", "/v1/parcel-custody-reports").json()["items"]


def test_society_b_lists_show_nothing_of_a_and_a_shows_nothing_of_b(pw: PW) -> None:
    ids = _world(pw)
    for persona in ("guard", "resident"):
        listed = pw.call_b(_who(pw, persona), "GET", "/v1/parcels").json()
        assert listed["items"] == []
    assert pw.call_b(pw.other.guard, "GET", "/v1/parcel-custody-reports").json()["items"] == []
    b_parcel = pw.call_b(
        pw.other.guard,
        "POST",
        "/v1/parcels",
        json={"unit_id": str(pw.other.unit), "gate_id": str(pw.other.gate_id), "brand": "BOnly"},
    )
    assert b_parcel.status_code == 201
    assert pw.call(pw.guard, "GET", f"/v1/parcels/{b_parcel.json()['id']}").status_code == 404
    assert all(
        i["brand"] != "BOnly" for i in pw.call(pw.guard, "GET", "/v1/parcels").json()["items"]
    )
    assert ids


def test_a_person_of_b_naming_society_a_gets_the_same_404_as_for_an_unknown_society(pw: PW) -> None:
    mine = pw.vw.call(pw.other.guard, "GET", "/v1/parcels", society=pw.soc.id)
    rand = pw.vw.call(pw.other.guard, "GET", "/v1/parcels", society=uuid.uuid4())
    assert mine.status_code == 404 and _norm(mine) == _norm(rand)


def test_a_cursor_issued_in_one_society_is_useless_in_another(pw: PW) -> None:
    h = pw.household("A-101")
    for i in range(3):
        pw.receive(h.unit, f"B{i}")
    cursor = pw.call(pw.guard, "GET", "/v1/parcels", params={"limit": 1}).json()["next_cursor"]
    assert cursor
    foreign = pw.call_b(pw.other.guard, "GET", "/v1/parcels", params={"limit": 1, "cursor": cursor})
    assert foreign.status_code == 400 and foreign.json()["code"] == "invalid_schema"


def test_every_parcels_route_has_an_isolation_case(pw: PW) -> None:
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
    assert iso(now() + timedelta(days=1))


def probed_routes() -> list[tuple[str, str]]:
    """(method, path template) of every route this file REALLY probes with a foreign id: the table the parametrized test iterates over. The AT-01
    route inventory (``tests/acceptance/test_at01_cross_society_isolation.py``) resolves these against the live app: a route that is not here fails it."""
    return [(c.method, c.template) for c in CASES]
