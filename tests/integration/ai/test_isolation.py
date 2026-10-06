"""Cross-society, cross-role and cross-person isolation of EVERY new /v1/ai route (INV-01, ARCH-01, AT-01 style; PRD 12.2).

The AT-01 route inventory (tests/acceptance/test_at01_cross_society_isolation.py) goes red when new routes appear; this file is the real
cross-society coverage for them. ``test_route_inventory_of_the_ai_module`` fails when a route is added without a case here.

All routes take the society from ``X-Society-Id`` (validated against the caller's own grants), never from a body.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.routing import APIRoute

from dwaar_api.core.authz import iter_api_routes
from tests.integration.ai._support import AW, body_text

pytestmark = [pytest.mark.req("AI-SYS-02", "AI-SYS-04"), pytest.mark.at("AT-01")]

#: (method, path, permission, scope, auth) of every route this module adds
ROUTES = {
    ("GET", "/v1/ai/features"): "ai.use",
    ("POST", "/v1/ai/proposals"): "ai.use",
    ("GET", "/v1/ai/proposals"): "ai.use",
    ("GET", "/v1/ai/proposals/{proposal_id}"): "ai.use",
    ("POST", "/v1/ai/proposals/{proposal_id}/confirm"): "ai.use",
    ("POST", "/v1/ai/feedback"): "ai.use",
    ("GET", "/v1/ai/drafts"): "ai.use",
    ("GET", "/v1/ai/status"): "ai.status.read",
    ("PUT", "/v1/ai/controls"): "ai.controls.manage",
    ("GET", "/v1/ai/runs"): "ai.audit.read",
    ("GET", "/v1/ai/providers"): "ai.providers.read",
}


@pytest.fixture
def two(aw: AW) -> AW:
    aw.set_quota(100)
    aw.set_quota(100, aw.other)
    return aw


def test_route_inventory_of_the_ai_module(aw: AW) -> None:
    live = set()
    for route in iter_api_routes(aw.app):
        assert isinstance(route, APIRoute)
        if route.path.startswith("/v1/ai"):
            for m in route.methods or ():
                live.add((m, route.path))
    assert live == set(ROUTES), (
        f"new or removed /v1/ai routes: add an isolation case for {sorted(live ^ set(ROUTES))}"
    )
    registry = aw.app.state.permissions
    for (_, _), action in ROUTES.items():
        assert action in registry


def _proposal_of_a(aw: AW):  # type: ignore[no-untyped-def]
    owner = aw.person("owner1", unit="A-101", kind="owner")
    b = aw.draft(owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"})
    return owner, b


def test_a_member_of_one_society_gets_nothing_from_another_on_any_route(two: AW) -> None:
    owner, b = _proposal_of_a(two)
    pid, run_id = b["proposal"]["id"], b["run_id"]
    b_owner = two.vw.idh.login(971, client=two.vw.client)
    two.vw.idh.seed_membership(two.other.id, b_owner.id, two.other.units["A-101"], "owner")
    other = two.other.id
    cases = [
        ("GET", f"/v1/ai/proposals/{pid}", None),
        (
            "POST",
            f"/v1/ai/proposals/{pid}/confirm",
            {"payload_hash": b["proposal"]["payload_hash"]},
        ),
        ("POST", "/v1/ai/feedback", {"run_id": run_id, "outcome": "rejected"}),
    ]
    for method, path, body in cases:
        r = two.call(b_owner, method, path, json=body, society=other)
        assert r.status_code == 404, (path, r.text)
        assert r.json()["code"] == "not_found"
        for needle in (pid, run_id, b["proposal"]["payload_hash"], "hello neighbours"):
            assert needle not in body_text(r), (path, needle)
        # byte-identical in shape to a made-up id
        made_up = path.replace(pid, str(uuid.uuid4()))
        r2 = two.call(
            b_owner,
            method,
            made_up,
            json=({**body, "run_id": str(uuid.uuid4())} if body and "run_id" in body else body),
            society=other,
        )
        assert (
            r2.status_code == 404
            and set(r2.json()) == set(r.json())
            and r2.json()["code"] == r.json()["code"]
        )
    # list routes of B show nothing of A
    assert two.call(b_owner, "GET", "/v1/ai/proposals", society=other).json()["items"] == []
    assert two.call(b_owner, "GET", "/v1/ai/drafts", society=other).json()["items"] == []
    runs = two.call(two.other_secretary, "GET", "/v1/ai/runs", society=other).json()
    assert (
        runs["items"] == []
        and two.call(two.other_secretary, "GET", "/v1/ai/status", society=other).json()["budget"][
            "used_today"
        ]
        == 0
    )
    # naming A with B's token: no standing in A => 404 on every route
    for method, path, body in [
        ("GET", "/v1/ai/features", None),
        ("GET", "/v1/ai/proposals", None),
        (
            "POST",
            "/v1/ai/proposals",
            {"feature_id": "AI-R07", "inputs": {"text": "x", "target_language": "hi"}},
        ),
        ("GET", "/v1/ai/drafts", None),
        ("POST", "/v1/ai/feedback", {"run_id": run_id, "outcome": "rejected"}),
    ]:
        assert two.call(b_owner, method, path, json=body, society=two.soc.id).status_code == 404, (
            path
        )
    for method, path, body in [
        ("GET", "/v1/ai/status", None),
        ("GET", "/v1/ai/runs", None),
        ("GET", "/v1/ai/providers", None),
        ("PUT", "/v1/ai/controls", {"kill_switch": True}),
    ]:
        assert (
            two.call(two.other_secretary, method, path, json=body, society=two.soc.id).status_code
            == 404
        ), path  # a secretary of B is nobody in A
    assert two.rows("SELECT state FROM action_proposals") == [("proposed",)]
    assert (
        two.rows("SELECT count(*) FROM ai_society_controls")[0][0] == 0
    )  # B's secretary changed nothing in A
    assert owner is not None


def test_controls_and_budget_are_per_society(two: AW) -> None:
    owner, _ = _proposal_of_a(two)
    r = two.call(
        two.other_secretary,
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": True},
        society=two.other.id,
    )
    assert r.status_code == 200
    assert two.rows("SELECT society_id, kill_switch FROM ai_society_controls") == [
        (two.other.id, True)
    ]
    assert (
        two.ask(owner, "AI-R07", {"text": "still works in A", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    assert two.call(two.vw.secretary, "GET", "/v1/ai/status").json()["kill_switch"] is False
    assert (
        two.call(two.other_secretary, "GET", "/v1/ai/status", society=two.other.id).json()[
            "kill_switch"
        ]
        is True
    )


def test_roles_inside_one_society_resident_cannot_use_admin_routes_or_see_other_residents_things(
    two: AW,
) -> None:
    owner, b = _proposal_of_a(two)
    neighbour = two.person("owner2", unit="A-102", kind="owner")
    for method, path in [
        ("GET", "/v1/ai/status"),
        ("GET", "/v1/ai/runs"),
        ("GET", "/v1/ai/providers"),
        ("PUT", "/v1/ai/controls"),
    ]:
        assert (
            two.call(
                neighbour, method, path, json={"kill_switch": True} if method == "PUT" else None
            ).status_code
            == 403
        ), path
    assert two.call(neighbour, "GET", f"/v1/ai/proposals/{b['proposal']['id']}").status_code == 404
    runs = two.call(two.vw.secretary, "GET", "/v1/ai/runs").json()["items"]
    assert len(runs) == 1  # the secretary's audit view shows the run's FACTS, never the draft
    assert "hello neighbours" not in body_text(two.call(two.vw.secretary, "GET", "/v1/ai/runs"))
    assert owner is not None


def test_x_society_header_is_required_when_the_caller_has_several_societies_and_a_body_society_is_ignored(
    two: AW,
) -> None:
    both = two.vw.idh.login(972, client=two.vw.client)
    two.vw.idh.seed_membership(two.soc.id, both.id, two.unit("A-102"), "owner")
    two.vw.idh.seed_membership(two.other.id, both.id, two.other.units["A-102"], "owner")
    r = two.call(both, "GET", "/v1/ai/features", society=False)
    assert r.status_code == 400  # ambiguous: no selector
    r = two.call(
        both,
        "POST",
        "/v1/ai/proposals",
        json={
            "feature_id": "AI-R07",
            "inputs": {"text": "hi", "target_language": "hi", "society_id": str(two.soc.id)},
        },
        society=two.other.id,
    )
    assert r.status_code == 400  # not a field of the inputs schema
    ok = two.ask(
        both, "AI-R07", {"text": "hi there", "target_language": "hi"}, society=two.other.id
    )
    assert ok.status_code == 200
    assert two.rows("SELECT society_id FROM ai_runs") == [
        (two.other.id,)
    ]  # the society came from the validated header, nowhere else
