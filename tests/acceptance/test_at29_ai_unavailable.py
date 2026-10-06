"""AT-29 (M1): the AI provider is unavailable or the budget is exhausted -> forms, gate and billing work; no blocking spinner.

PRD 16: "AI provider unavailable or budget exhausted. Required outcome: Forms, gate and billing work; no blocking spinner."
PRD AI-SYS-06 (timeout 15 s or outage returns the ordinary form; exhausted budget disables optional assistance, never gate or billing; per-society
kill switch and per-feature rollback without an app update), NFR-13 (p95 <= 15 s; timeout returns the ordinary UI), INV-03.

Dataset: the real seed, real API, real sign-in through the labelled simulator. The failing / slow provider is the SIMULATOR with injected faults
(``simulation=true``). The gate scenario is the real approval flow (guard raises, household decides; ``entry_observed`` stays false).

HONEST SCOPE: there is no billing module yet (slice 5), so 'billing works' is covered structurally: no route outside /v1/ai depends on the AI runtime
(tests/integration/ai/test_failure_modes.py walks every route's dependencies), and the AI module is the ONLY thing that returns the ordinary-form
fallback. The billing scenario must be added to this file when the ledger slice lands (blocked on that slice, not on AI).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from dwaar_ai_gateway.providers import SimulatorProvider
from tests.acceptance._visits_world import decision_body, raise_request, visit_ids
from tests.acceptance._world import DATASET, World
from tests.integration.ai._support import install_runtime

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-29", dataset=DATASET),
    pytest.mark.req("AI-SYS-06", "NFR-13", "ARCH-05", "INV-03"),
]


def _quota(world: World, per_day: int) -> None:
    mh = world.society_ref("mh")
    r = world.call(
        world.login("mh.secretary"),
        "PUT",
        f"/v1/societies/{mh.id}/quotas",
        json={"ai_requests_per_day": per_day},
        headers={"X-Society-Id": str(mh.id)},
    )
    assert r.status_code == 200, r.text


def _ask(world: World, who: str, feature: str, inputs: dict, **kw):  # type: ignore[no-untyped-def,type-arg]
    mh = world.society_ref("mh")
    return world.call(
        world.login(who),
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": feature, "inputs": inputs, **kw},
        headers={"X-Society-Id": str(mh.id)},
    )


def _gate_decision_works(world: World, label: str = "Late courier") -> None:
    ids = visit_ids(world, "mh")
    guard, rekha = world.login("mh.guard1"), world.login("rekha")
    unit = world.society_ref("mh").unit("A", "203")
    req = raise_request(world, guard, ids, unit, label)
    assert req["status"] == "pending"
    decided = world.call(
        rekha,
        "POST",
        f"/v1/approval-requests/{req['id']}/decision",
        json={
            **decision_body("approve", req["version"]),
            "client_action_id": "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11",
        },
        headers={"X-Society-Id": str(ids.society)},
    )
    assert (
        decided.status_code == 200
        and decided.json()["status"] == "approved"
        and decided.json()["entry_observed"] is False
    )


def _forms_work(world: World) -> None:
    mh = world.society_ref("mh")
    sec = world.login("mh.secretary")
    assert world.call(sec, "GET", f"/v1/societies/{mh.id}").status_code == 200
    assert (
        world.call(sec, "GET", f"/v1/societies/{mh.id}/units", params={"limit": 5}).status_code
        == 200
    )
    assert world.call(world.login("ganesh"), "GET", "/v1/me").status_code == 200


def test_provider_outage_returns_the_ordinary_form_at_once_and_the_gate_and_forms_work(
    fresh_world: World,
) -> None:
    world = fresh_world
    _quota(world, 50)
    install_runtime(world.app, SimulatorProvider(fail_with="outage"))
    t0 = time.perf_counter()
    r = _ask(
        world,
        "ganesh",
        "AI-R07",
        {"text": "Water supply will be off tomorrow", "target_language": "hi"},
    )
    assert time.perf_counter() - t0 < 3.0  # a definite answer, not a spinner
    b = r.json()
    assert (
        r.status_code == 200
        and b["status"] == "unavailable"
        and b["reason"] == "provider_outage"
        and b["proposal"] is None
    )
    assert (
        b["fallback"]["kind"] == "ordinary_form"
        and b["fallback"]["blocks_user"] is False
        and b["fallback"]["upsell"] is False
    )
    _gate_decision_works(world)
    _forms_work(world)


def test_a_provider_that_hangs_is_cut_off_at_the_budget_and_never_delays_the_gate(
    fresh_world: World,
) -> None:
    world = fresh_world
    _quota(world, 50)
    install_runtime(world.app, SimulatorProvider(delay_seconds=4.0), timeout=0.5)

    def slow() -> tuple[float, dict]:  # type: ignore[type-arg]
        t0 = time.perf_counter()
        r = _ask(world, "ganesh", "AI-R07", {"text": "hello neighbours", "target_language": "mr"})
        return time.perf_counter() - t0, r.json()

    with ThreadPoolExecutor(1) as pool:
        fut = pool.submit(slow)
        time.sleep(0.05)
        t0 = time.perf_counter()
        _gate_decision_works(world, "Courier while AI hangs")
        gate_elapsed = time.perf_counter() - t0
        elapsed, body = fut.result()
    assert (
        gate_elapsed < 3.0
        and body["status"] == "unavailable"
        and body["reason"] == "provider_timeout"
        and 0.4 < elapsed < 3.0
    )


def test_an_exhausted_budget_disables_optional_assistance_only(fresh_world: World) -> None:
    world = fresh_world
    _quota(world, 1)
    install_runtime(world.app)
    assert (
        _ask(world, "ganesh", "AI-R07", {"text": "first notice", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    b = _ask(world, "ganesh", "AI-R07", {"text": "second notice", "target_language": "hi"}).json()
    assert (
        b["status"] == "unavailable"
        and b["reason"] == "budget_exhausted"
        and b["fallback"]["upsell"] is False
        and b["fallback"]["blocks_user"] is False
    )
    health = _ask(
        world, "ganesh", "AI-R06", {"manufacturer": "xiaomi", "battery_unrestricted": False}
    ).json()
    assert (
        health["status"] == "ok" and health["answer"]["guaranteed_delivery"] is False
    )  # the deterministic assistant costs nothing
    _gate_decision_works(world)
    _forms_work(world)
    st = world.call(
        world.login("mh.secretary"),
        "GET",
        "/v1/ai/status",
        headers={"X-Society-Id": str(world.society_ref("mh").id)},
    ).json()
    assert (
        st["budget"]["exhausted"] is True
        and st["budget"]["remaining"] == 0
        and st["upsell"] is False
        and st["declining_ai_reduces_service"] is False
    )


def test_the_society_kill_switch_works_without_an_app_update_and_only_for_that_society(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, ka = world.society_ref("mh"), world.society_ref("ka")
    _quota(world, 50)
    r = world.call(
        world.login("ka.secretary"),
        "PUT",
        f"/v1/societies/{ka.id}/quotas",
        json={"ai_requests_per_day": 50},
        headers={"X-Society-Id": str(ka.id)},
    )
    assert r.status_code == 200
    install_runtime(world.app)
    off = world.call(
        world.login("mh.secretary"),
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": True, "reason": "committee decision"},
        headers={"X-Society-Id": str(mh.id)},
    )
    assert off.status_code == 200 and "no app update" in off.json()["takes_effect"]
    assert (
        _ask(world, "ganesh", "AI-R07", {"text": "hello", "target_language": "hi"}).json()["reason"]
        == "kill_switch"
    )
    ka_user = world.call(
        world.login("farhan"),
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": "AI-R07", "inputs": {"text": "hello", "target_language": "hi"}},
        headers={"X-Society-Id": str(ka.id)},
    )
    assert ka_user.status_code == 200 and ka_user.json()["status"] == "ok"  # Society B keeps its AI
    _gate_decision_works(world)
    on = world.call(
        world.login("mh.secretary"),
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": False},
        headers={"X-Society-Id": str(mh.id)},
    )
    assert (
        on.status_code == 200
        and _ask(
            world, "ganesh", "AI-R07", {"text": "hello again", "target_language": "hi"}
        ).json()["status"]
        == "ok"
    )
