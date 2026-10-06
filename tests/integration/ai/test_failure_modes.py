"""Failure behaviour (AI-SYS-06, NFR-13, AT-29, ARCH-05): a failing, slow or exhausted AI never blocks forms, the gate or anything essential."""

from __future__ import annotations

import shutil
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml
from fastapi.routing import APIRoute

from dwaar_ai_gateway.paths import prompts_root
from dwaar_ai_gateway.prompts import PromptStore
from dwaar_ai_gateway.providers import SimulatorProvider
from dwaar_api.core.authz import iter_api_routes
from tests.integration.ai._support import AW

pytestmark = [pytest.mark.req("AI-SYS-06", "NFR-13", "ARCH-05"), pytest.mark.at("AT-29")]


@pytest.fixture
def enabled(aw: AW) -> AW:
    aw.set_quota(100)
    return aw


def gate_works(aw: AW) -> None:
    """The gate path end to end: a guard raises an approval request for a household, a resident decides it. No model anywhere."""
    if aw.vw.gate_id is None:
        aw.vw.setup_gate()
    unit_label = "B-201"
    try:
        hh = aw.vw.household(unit_label)
    except Exception:  # noqa: BLE001 - already created in this test
        raise
    request = aw.vw.raise_request(hh.unit)
    r = aw.vw.decide(hh.owner, request)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["entry_observed"] is False


def forms_work(aw: AW) -> None:
    """Ordinary forms and reads: the society configuration and quotas (the 'forms' of the administrator) and the caller's own profile."""
    assert aw.call(aw.vw.secretary, "GET", f"/v1/societies/{aw.soc.id}").status_code == 200
    assert aw.call(aw.vw.secretary, "GET", f"/v1/societies/{aw.soc.id}/units").status_code == 200
    assert aw.call(aw.vw.secretary, "GET", "/v1/me").status_code == 200


def test_provider_outage_gives_the_ordinary_path_quickly_and_the_gate_and_forms_keep_working(
    enabled: AW,
) -> None:
    enabled.install(SimulatorProvider(fail_with="outage"))
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    t0 = time.perf_counter()
    r = enabled.ask(owner, "AI-R07", {"text": "hello", "target_language": "hi"})
    assert time.perf_counter() - t0 < 2.0  # no blocking spinner: a definite, immediate answer
    b = r.json()
    assert (
        r.status_code == 200
        and b["status"] == "unavailable"
        and b["reason"] == "provider_outage"
        and b["proposal"] is None
        and b["answer"] is None
    )
    assert b["fallback"] == {
        "kind": "ordinary_form",
        "feature_id": "AI-R07",
        "reason": "provider_outage",
        "retry": "later",
        "message_key": "ai.fallback.ordinary_path",
        "blocks_user": False,
        "upsell": False,
    }
    run = enabled.runs()[0]
    assert (
        run["status"] == "unavailable"
        and run["outcome"] == "failed"
        and run["model_called"] is True
    )
    gate_works(enabled)
    forms_work(enabled)
    assert enabled.rows("SELECT count(*) FROM action_proposals")[0][0] == 0


def test_a_slow_model_is_cut_off_at_the_timeout_and_never_holds_up_the_gate(enabled: AW) -> None:
    enabled.install(SimulatorProvider(delay_seconds=3.0), timeout=0.4)
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    enabled.vw.setup_gate()
    hh = enabled.vw.household("B-201")
    request = enabled.vw.raise_request(hh.unit)

    def slow_ai() -> tuple[float, dict]:  # type: ignore[type-arg]
        t0 = time.perf_counter()
        r = enabled.ask(owner, "AI-R07", {"text": "hello", "target_language": "hi"})
        return time.perf_counter() - t0, r.json()

    with ThreadPoolExecutor(1) as pool:
        fut = pool.submit(slow_ai)
        time.sleep(0.05)
        t0 = time.perf_counter()
        decided = enabled.vw.decide(
            hh.owner, request
        )  # the gate decision while the AI call is still in flight
        gate_elapsed = time.perf_counter() - t0
        ai_elapsed, body = fut.result()
    assert decided.status_code == 200 and gate_elapsed < 1.5
    assert (
        body["status"] == "unavailable"
        and body["reason"] == "provider_timeout"
        and 0.3 < ai_elapsed < 2.0
    )  # cut at the budget, not after 3 s


def test_budget_exhaustion_disables_optional_assistance_only(aw: AW) -> None:
    aw.set_quota(2)
    owner = aw.person("owner1", unit="A-101", kind="owner")
    for i in range(2):
        assert (
            aw.ask(owner, "AI-R07", {"text": f"notice number {i}", "target_language": "hi"}).json()[
                "status"
            ]
            == "ok"
        )
    third = aw.ask(owner, "AI-R07", {"text": "notice number 3", "target_language": "hi"}).json()
    assert (
        third["status"] == "unavailable"
        and third["reason"] == "budget_exhausted"
        and third["fallback"]["upsell"] is False
        and third["fallback"]["blocks_user"] is False
    )
    assert third["proposal"] is None and [r["model_called"] for r in aw.runs()] == [
        True,
        True,
        False,
    ]  # the refusal made no model call and costs nothing
    # the deterministic assistant costs nothing and keeps answering; the gate and forms are untouched
    assert (
        aw.ask(owner, "AI-R06", {"manufacturer": "oppo", "autostart_enabled": False}).json()[
            "status"
        ]
        == "ok"
    )
    gate_works(aw)
    forms_work(aw)
    st = aw.call(aw.vw.secretary, "GET", "/v1/ai/status").json()
    assert (
        st["budget"]["exhausted"] is True
        and st["budget"]["used_today"] == 2
        and st["budget"]["remaining"] == 0
        and st["upsell"] is False
    )
    assert st["declining_ai_reduces_service"] is False
    # a bigger allowance takes effect at once
    aw.set_quota(10)
    assert (
        aw.ask(owner, "AI-R07", {"text": "notice number 4", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )


def test_per_feature_daily_limit(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    r = enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"features": {"AI-R07": {"daily_limit": 1}}},
    )
    assert r.status_code == 200
    assert (
        enabled.ask(owner, "AI-R07", {"text": "first one", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    assert (
        enabled.ask(owner, "AI-R07", {"text": "second one", "target_language": "hi"}).json()[
            "reason"
        ]
        == "budget_exhausted"
    )
    assert (
        enabled.ask(owner, "AI-R02", {"transcript": "water leaking in flat A-101 kitchen"}).json()[
            "status"
        ]
        == "ok"
    )  # another feature is unaffected
    enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"features": {"AI-R07": {"clear_daily_limit": True}}},
    )
    assert (
        enabled.ask(owner, "AI-R07", {"text": "third one", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )


def test_the_society_kill_switch_takes_effect_immediately_without_a_deploy_and_only_for_that_society(
    enabled: AW,
) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    enabled.set_quota(100, enabled.other)
    r = enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": True, "reason": "committee pause"},
    )
    assert r.status_code == 200 and "no app update or deploy" in r.json()["takes_effect"]
    b = enabled.ask(owner, "AI-R07", {"text": "hello", "target_language": "hi"}).json()
    assert (
        b["status"] == "unavailable"
        and b["reason"] == "kill_switch"
        and b["fallback"]["blocks_user"] is False
    )
    assert (
        enabled.ask(owner, "AI-R06", {"manufacturer": "oppo"}).json()["reason"] == "kill_switch"
    )  # even the free assistant: 'off' means off
    other_user = enabled.vw.idh.login(970, client=enabled.vw.client)
    enabled.vw.idh.seed_membership(
        enabled.other.id, other_user.id, enabled.other.units["A-101"], "owner"
    )
    ok = enabled.ask(
        other_user, "AI-R07", {"text": "hello", "target_language": "hi"}, society=enabled.other.id
    )
    assert ok.status_code == 200 and ok.json()["status"] == "ok"  # the other society is untouched
    gate_works(enabled)
    st = enabled.call(enabled.vw.secretary, "GET", "/v1/ai/status").json()
    assert st["kill_switch"] is True and st["kill_reason"] == "committee pause"
    enabled.call(enabled.vw.secretary, "PUT", "/v1/ai/controls", json={"kill_switch": False})
    assert (
        enabled.ask(owner, "AI-R07", {"text": "hello again", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    ops = [
        r[0]
        for r in enabled.rows(
            "SELECT operation FROM audit_log WHERE operation LIKE %s ORDER BY at",
            ("ai.controls.%",),
        )
    ]
    assert ops == ["ai.controls.kill_switch", "ai.controls.kill_switch"]
    assert (
        enabled.rows("SELECT count(*) FROM outbox WHERE event_type = 'AIControlsChanged'")[0][0]
        == 2
    )


def test_per_feature_rollback_disables_one_feature_and_pins_a_prompt_version_without_an_app_update(
    enabled: AW, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    sec = enabled.vw.secretary
    assert (
        enabled.call(
            sec, "PUT", "/v1/ai/controls", json={"features": {"AI-R07": {"state": "disabled"}}}
        ).status_code
        == 200
    )
    assert (
        enabled.ask(owner, "AI-R07", {"text": "hello", "target_language": "hi"}).json()["reason"]
        == "feature_disabled"
    )
    assert (
        enabled.ask(owner, "AI-R02", {"transcript": "water leaking in flat A-101 kitchen"}).json()[
            "status"
        ]
        == "ok"
    )  # others unaffected
    feats = {f["id"]: f for f in enabled.call(owner, "GET", "/v1/ai/features").json()["items"]}
    assert (
        feats["AI-R07"]["available"] is False
        and feats["AI-R07"]["unavailable_reason"] == "feature_disabled"
        and feats["AI-R02"]["available"] is True
    )
    enabled.call(sec, "PUT", "/v1/ai/controls", json={"features": {"AI-R07": {"state": "enabled"}}})
    # prompt rollback: v2 is the 100% canary; a pin to v1 rolls this society back immediately
    root = tmp_path / "prompts"
    shutil.copytree(prompts_root(), root, ignore=shutil.ignore_patterns("evals"))
    shutil.copytree(root / "translation" / "v1", root / "translation" / "v2")
    reg = yaml.safe_load((root / "registry.yaml").read_text())
    reg["features"]["AI-R07"].update({"canary": "v2", "canary_percent": 100})
    (root / "registry.yaml").write_text(yaml.safe_dump(reg))
    enabled.rt.gateway.prompts = PromptStore(root)
    assert (
        enabled.ask(owner, "AI-R07", {"text": "canary run", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    assert enabled.runs()[-1]["prompt_version"] == "translation/v2"
    bad = enabled.call(
        sec, "PUT", "/v1/ai/controls", json={"features": {"AI-R07": {"prompt_version_pin": "v9"}}}
    )
    assert bad.status_code == 400
    assert (
        enabled.call(
            sec,
            "PUT",
            "/v1/ai/controls",
            json={"features": {"AI-R07": {"prompt_version_pin": "v1"}}},
        ).status_code
        == 200
    )
    assert (
        enabled.ask(owner, "AI-R07", {"text": "after rollback", "target_language": "hi"}).json()[
            "status"
        ]
        == "ok"
    )
    assert enabled.runs()[-1]["prompt_version"] == "translation/v1"
    enabled.call(
        sec,
        "PUT",
        "/v1/ai/controls",
        json={"features": {"AI-R07": {"clear_prompt_version_pin": True}}},
    )
    enabled.ask(owner, "AI-R07", {"text": "unpinned", "target_language": "hi"})
    assert enabled.runs()[-1]["prompt_version"] == "translation/v2"


def test_only_the_secretary_manages_controls_and_excluded_switches_are_refused(enabled: AW) -> None:
    com = enabled.person("com", "committee")
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    for who in (com, owner, enabled.vw.guard):
        assert (
            enabled.call(who, "PUT", "/v1/ai/controls", json={"kill_switch": True}).status_code
            == 403
        )
    sec = enabled.vw.secretary
    for key in (
        "facial_recognition",
        "emotion_score",
        "auto_fine",
        "payment_execute",
        "lead_scoring",
        "AI-R07-gate_decision",
    ):
        r = enabled.call(
            sec, "PUT", "/v1/ai/controls", json={"features": {key: {"state": "enabled"}}}
        )
        assert (
            r.status_code == 422
            and r.json()["details"]["reason"] == "excluded_ai_cannot_be_enabled"
        ), key
    assert (
        enabled.call(
            sec, "PUT", "/v1/ai/controls", json={"features": {"AI-ZZ9": {"state": "enabled"}}}
        ).status_code
        == 404
    )
    for body in (
        {"facial_recognition": True},
        {"features": {"AI-R07": {"enabled_for_gate": True}}},
        {"gate_access": "auto"},
    ):
        assert (
            enabled.call(sec, "PUT", "/v1/ai/controls", json=body).status_code == 400
        )  # there is no such setting to turn on
    assert (
        enabled.rows("SELECT count(*) FROM ai_society_controls")[0][0] == 0
        and enabled.rows("SELECT count(*) FROM ai_feature_controls")[0][0] == 0
    )


def test_status_runs_and_providers_are_for_authorised_admins_and_state_the_truth(
    enabled: AW,
) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    enabled.draft(owner, "AI-R07", {"text": "hello", "target_language": "hi"})
    aud = enabled.person("aud", "auditor")
    sec = enabled.vw.secretary
    st = enabled.call(sec, "GET", "/v1/ai/status")
    assert st.status_code == 200
    s = st.json()
    assert (
        s["budget"]["used_today"] == 1
        and s["latency_ms"]["samples"] == 1
        and s["latency_ms"]["slo_p95_ms"] == 15000
        and s["latency_ms"]["simulated_samples"] == 1
    )
    assert {f["id"] for f in s["features"]} >= {"AI-R07", "AI-C05"} and next(
        f for f in s["features"] if f["id"] == "AI-C05"
    )["available"] is False
    assert enabled.call(aud, "GET", "/v1/ai/status").status_code == 200
    for who in (owner, enabled.vw.guard):
        assert enabled.call(who, "GET", "/v1/ai/status").status_code == 403
        assert enabled.call(who, "GET", "/v1/ai/runs").status_code == 403
        assert enabled.call(who, "GET", "/v1/ai/providers").status_code == 403
    runs = enabled.call(aud, "GET", "/v1/ai/runs").json()
    assert (
        len(runs["items"]) == 1
        and "payload" not in runs["items"][0]
        and "input" not in runs["items"][0]
    )
    assert runs["items"][0]["simulation"] is True and runs["items"][0]["feature_id"] == "AI-R07"
    assert (
        enabled.call(sec, "GET", "/v1/ai/runs", params={"feature_id": "AI-C01"}).json()["items"]
        == []
    )
    pr = enabled.call(sec, "GET", "/v1/ai/providers")
    assert pr.status_code == 200
    table = {p["name"]: p for p in pr.json()["providers"]}
    assert table["simulator"]["enabled"] is True and table["simulator"]["simulation"] is True
    assert table["anthropic"]["state"] == "not_configured" and table["anthropic"][
        "reason"
    ].startswith("not configured: DWAAR_AI_ANTHROPIC_API_KEY")
    assert {a["name"]: a for a in pr.json()["asr"]}["faster-whisper"]["state"] == "not_configured"
    assert (
        pr.json()["models"]["extraction"] == "claude-haiku-4-5-20251001"
        and pr.json()["models"]["drafting"] == "claude-sonnet-5-5"
    )
    assert (
        pr.json()["subprocessors"][0]["training_on_customer_data"] is False
        and pr.json()["gateway"]["anthropic_key_present"] is False
    )


def test_no_route_outside_v1_ai_depends_on_the_ai_runtime(aw: AW) -> None:
    """AI-SYS-01 / INV-03: gate, visits, organisation and identity routes cannot even import the model: no dependency on the AI runtime."""
    from dwaar_api.modules.ai.routes import runtime

    def walk(dep, found):  # type: ignore[no-untyped-def]
        if dep.call is runtime:
            found.append(True)
        for sub in dep.dependencies:
            walk(sub, found)

    offenders = []
    for route in iter_api_routes(aw.app):
        assert isinstance(route, APIRoute)
        found: list[bool] = []
        walk(route.dependant, found)
        if found and not route.path.startswith("/v1/ai"):
            offenders.append(route.path)
    assert offenders == []
