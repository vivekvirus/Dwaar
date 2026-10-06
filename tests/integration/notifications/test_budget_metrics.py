"""Budgets, budget metrics, device health by model and OS, and the provider registry.

REQ: PRD 9.4 budget metrics (notifications and calls per 1,000 arrivals, failed calls, fallback share; a high fallback rate is an operations problem,
not a cost passed to the society), PRD 18.1 (approval acknowledgement rate), NOTIF-07, OBS-02, D-21 (the registry shows 'not configured: <missing
dependency>' to authorised administrators only), NOTIF-01 (budget never blocks security or emergency), CALL-01.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from dwaar_api.core.db import RequestContext
from dwaar_api.modules.notifications import budget
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.providers import (
    DeviceTelemetry,
    providers_mode,
    registry_status,
)
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-07", "OBS-02", "CALL-02")]


def _window(nw: NW) -> dict[str, str]:
    now = dt.datetime.now(dt.UTC)
    return {
        "from": (now - dt.timedelta(days=1)).isoformat(),
        "to": (now + dt.timedelta(hours=1)).isoformat(),
    }


# ------------------------------------------------------------------------------------------------------------ budget
def test_the_budget_has_defaults_and_only_the_secretary_sets_it(nw: NW) -> None:
    got = nw.call(nw.secretary, "GET", nw.s("notification-budget")).json()
    assert got["caps"] == {"notification": 30000, "call": 3000, "sms": 3000} and got["version"] == 0
    assert got["policy"] == {
        "security_and_emergency_never_blocked": True,
        "cost_passed_to_society": False,
    }
    path = nw.s("notification-budget")
    body = {"monthly_notification_cap": 100, "monthly_call_cap": 10, "monthly_sms_cap": 5}
    assert nw.call(nw.guard_sup, "PUT", path, json=body).status_code == 403
    r = nw.call(nw.secretary, "PUT", path, json=body)
    assert r.status_code == 200 and r.json()["caps"]["call"] == 10 and r.json()["version"] == 1
    assert (
        nw.call(nw.secretary, "PUT", path, json={**body, "expected_version": 9}).status_code == 409
    )
    assert (
        nw.call(nw.secretary, "PUT", path, json={**body, "monthly_call_cap": -1}).status_code == 400
    )
    assert nw.audit("notification.budget.set")


def test_an_exhausted_budget_blocks_non_safety_sends_but_never_security_or_emergency(
    nw: NW,
) -> None:
    nw.call(
        nw.secretary,
        "PUT",
        nw.s("notification-budget"),
        json={"monthly_notification_cap": 2, "monthly_call_cap": 1, "monthly_sms_cap": 1},
    )
    now = dt.datetime.now(dt.UTC)
    ctx = RequestContext(nw.soc.id, None, "system", None)
    assert nw.database is not None
    with nw.database.worker_tx(ctx) as conn:
        decisions = [
            budget.authorise_send(
                conn, nw.soc.id, category="community_digest", channel="push", now=now
            )
            for _ in range(3)
        ]
        assert [d.allowed for d in decisions] == [True, True, False]  # the digest stops at the cap
        sec = [
            budget.authorise_send(
                conn, nw.soc.id, category="security_approval", channel="push", now=now
            )
            for _ in range(3)
        ]
        emg = budget.authorise_send(
            conn, nw.soc.id, category="emergency", channel="ivr_call", now=now
        )
        calls = [
            budget.authorise_send(conn, nw.soc.id, category="finance", channel="ivr_call", now=now)
            for _ in range(2)
        ]
    assert all(d.allowed for d in sec) and all(
        d.over_budget for d in sec
    )  # safety is never blocked, only counted
    assert emg.allowed and [c.allowed for c in calls] == [
        False,
        False,
    ]  # the emergency call took the one call slot; finance is refused
    shown = nw.call(nw.secretary, "GET", nw.s("notification-budget")).json()
    assert shown["blocked"] >= 1 and shown["over_budget"] >= 3


def test_an_exhausted_call_budget_still_places_the_security_call_and_flags_it(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.call(
        nw.secretary,
        "PUT",
        nw.s("notification-budget"),
        json={"monthly_notification_cap": 0, "monthly_call_cap": 0, "monthly_sms_cap": 0},
    )
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 20):
        nw.tick(t0 + secs(at))
    assert (
        len(nw.sims.push.sent) == 1 and len(nw.sims.ivr.sent) == 1
    )  # a resident is not left unreached because of a cost cap
    shown = nw.call(nw.secretary, "GET", nw.s("notification-budget")).json()
    assert (
        shown["over_budget"] == 2
        and shown["used"]["notification"] == 1
        and shown["used"]["call"] == 1
    )
    assert shown["policy"]["cost_passed_to_society"] is False


# ------------------------------------------------------------------------------------------------------------ metrics
def _three_requests(nw: NW) -> list[dict[str, Any]]:
    h1, h2, h3 = (nw.household(label, family=False) for label in ("A-101", "A-102", "A-103"))
    nw.register_device(
        h1.owner,
        "p1",
        model="Redmi Note 12",
        manufacturer="Xiaomi",
        os_name="HyperOS",
        os_version="1.0",
    )
    nw.sim_device("p1").telemetry = DeviceTelemetry("Redmi Note 12", "xiaomi", "HyperOS", "1.0")
    nw.register_device(
        h2.owner, "p2", model="SM-A546E", manufacturer="Samsung", os_name="Android", os_version="14"
    )
    nw.sim_device("p2").telemetry = DeviceTelemetry("SM-A546E", "samsung", "Android", "14")
    nw.sim_device("p2").force_stopped = True
    nw.register_device(h3.owner, "p3", permission="denied")
    out = []
    for label, owner in (("A-101", h1.owner), ("A-102", h2.owner), ("A-103", h3.owner)):
        req = nw.raise_request(nw.unit(label))
        t0 = nw.created_at(req["id"])
        for at in (0, 2):
            nw.tick(t0 + secs(at))
        if label == "A-101":
            assert (
                nw.decide(owner, req).status_code == 200
            )  # answered on the app within the first seconds: no fallback
        for at in (10, 20):
            nw.tick(t0 + secs(at))
        out.append(req)
    return out


def test_the_budget_metrics_are_counted_from_rows_with_their_definitions(nw: NW) -> None:
    _three_requests(nw)
    m = nw.call(nw.secretary, "GET", nw.s("notification-metrics"), params=_window(nw)).json()
    assert m["arrivals"] == 3 and m["requests_with_cascade"] == 3
    assert (
        m["notifications"]["by_channel"] == {"push": 2, "ivr_call": 2}
        and m["notifications"]["total"] == 2
    )
    assert m["calls"] == {"total": 2, "failed": 0, "unanswered": 0}
    assert m["notifications_per_1000_arrivals"] == pytest.approx(666.67, abs=0.01)
    assert m["calls_per_1000_arrivals"] == pytest.approx(666.67, abs=0.01)
    ack = m["approval_acknowledgement"]
    assert (
        ack["eligible_requests"] == 2
        and ack["acknowledged_before_fallback"] == 1
        and ack["rate"] == 0.5
    )
    assert ack["by_permission_cohort"] == {
        "granted": {"acknowledged": 1, "eligible": 2, "rate": 0.5}
    }
    assert ack["by_network_cohort"] == "not_observed"  # nothing invented
    fb = m["fallback"]
    assert (
        fb["requests_using_fallback"] == 2
        and fb["share"] == pytest.approx(0.6667, abs=0.0001)
        and fb["ops_attention"] is False
    )
    assert fb["cost_passed_to_society"] is False and "operations problem" in fb["note"]
    assert set(m["definitions"]) >= {
        "acknowledgement_rate",
        "fallback_share",
        "notifications_per_1000_arrivals",
        "failed_calls",
        "network_cohort",
    }
    assert m["simulation"] is True


def test_failed_calls_are_provider_failures_and_unanswered_calls_are_not(nw: NW) -> None:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.sim_device("owner-phone").force_stopped = True
    nw.sims.ivr.fail_next("provider_unavailable")
    request = nw.raise_request(nw.unit("A-101"))
    t0 = nw.created_at(request["id"])
    for at in (0, 20):
        nw.tick(t0 + secs(at))
    m = nw.call(nw.secretary, "GET", nw.s("notification-metrics"), params=_window(nw)).json()
    assert m["calls"]["failed"] == 1 and m["calls"]["unanswered"] == 0


def test_a_high_fallback_share_is_flagged_to_operations_not_charged(nw: NW) -> None:
    owners = [
        nw.household(label, family=False).owner
        for label in ("A-101", "A-102", "A-103", "B-201", "B-202")
    ]
    for i, owner in enumerate(owners):
        nw.register_device(owner, f"p{i}")
        nw.sim_device(f"p{i}").force_stopped = True
    for label in ("A-101", "A-102", "A-103", "B-201", "B-202"):
        req = nw.raise_request(nw.unit(label))
        t0 = nw.created_at(req["id"])
        for at in (0, 10, 20):
            nw.tick(t0 + secs(at))
    m = nw.call(nw.guard_sup, "GET", nw.s("notification-metrics"), params=_window(nw)).json()
    assert m["fallback"]["share"] == 1.0 and m["fallback"]["ops_attention"] is True
    assert m["approval_acknowledgement"]["rate"] == 0.0
    assert m["budget"]["policy"]["cost_passed_to_society"] is False


def test_device_health_groups_by_model_and_os(nw: NW) -> None:
    _three_requests(nw)
    h = nw.call(nw.secretary, "GET", nw.s("device-health"), params=_window(nw)).json()
    groups = {(g["phone_model"], g["os_name"], g["os_version"]): g for g in h["groups"]}
    redmi = groups[("Redmi Note 12", "HyperOS", "1.0")]
    samsung = groups[("SM-A546E", "Android", "14")]
    assert (
        redmi["acknowledgement_rate"] == 1.0
        and redmi["app_received"] == 1
        and redmi["fallback_share"] == 0.0
    )
    assert (
        samsung["acknowledgement_rate"] == 0.0
        and samsung["app_received"] == 0
        and samsung["fallback_share"] == 1.0
    )
    assert all(g["simulation"] is True for g in h["groups"])
    assert h["not_sent"] == {
        "notification_permission_denied": 1
    }  # the denied phone is counted, not hidden
    assert "person" not in json.dumps(h)


def test_metrics_need_an_operations_role_and_a_bounded_window(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    for path in ("notification-metrics", "device-health", "notification-budget"):
        assert nw.call(owner, "GET", nw.s(path)).status_code == 403
        assert nw.call(nw.guard, "GET", nw.s(path)).status_code == 403
    wide = {"from": "2020-01-01T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"}
    assert (
        nw.call(nw.secretary, "GET", nw.s("notification-metrics"), params=wide).status_code == 400
    )
    assert (
        nw.call(
            nw.secretary, "GET", nw.s("notification-metrics"), params={"colour": "red"}
        ).status_code
        == 400
    )


# ------------------------------------------------------------------------------------------------------------ provider registry
def test_the_registry_labels_simulators_for_administrators_only(nw: NW) -> None:
    r = nw.call(nw.secretary, "GET", nw.s("notification-providers"))
    assert r.status_code == 200
    body = r.json()
    assert {p["kind"] for p in body["providers"]} == {"push", "ivr_call", "sms", "whatsapp"}
    assert all(p["state"] == "simulator" and p["simulation"] is True for p in body["providers"])
    assert body["any_live_provider"] is False and body["outage_fallback"] == ["intercom", "office"]
    owner, _ = nw.household2("A-101")
    for who in (owner, nw.guard, nw.guard_sup):
        assert nw.call(who, "GET", nw.s("notification-providers")).status_code == 403
    assert (
        nw.call(
            nw.idh.login(950, client=nw.client), "GET", nw.s("notification-providers")
        ).status_code
        == 404
    )  # not a member at all


def test_without_a_provider_the_registry_names_the_specific_missing_dependency(nw: NW) -> None:
    nw.app.state.notifications_config = NotificationsConfig(providers_mode="none")
    body = nw.call(nw.secretary, "GET", nw.s("notification-providers")).json()
    by_kind = {p["kind"]: p for p in body["providers"]}
    assert all(
        p["state"] == "not_configured" and p["simulation"] is False for p in by_kind.values()
    )
    assert by_kind["sms"]["detail"].startswith("not configured: DLT principal-entity registration")
    assert by_kind["ivr_call"]["detail"].startswith(
        "not configured: Indian cloud-telephony account"
    )
    assert by_kind["push"]["detail"].startswith("not configured: FCM project credentials")
    assert by_kind["whatsapp"]["detail"].startswith(
        "not configured: WhatsApp Business API provider account"
    )
    assert body["simulation"] is False and body["any_live_provider"] is False


def test_simulators_are_honoured_only_where_the_environment_allows_them() -> None:
    assert (
        providers_mode({"DWAAR_NOTIFICATION_PROVIDERS": "simulator"}, simulation_allowed=True)
        == "simulator"
    )
    assert (
        providers_mode({"DWAAR_NOTIFICATION_PROVIDERS": "simulator"}, simulation_allowed=False)
        == "none"
    )
    assert providers_mode({}, simulation_allowed=False) == "none"
    assert (
        providers_mode({"DWAAR_NOTIFICATION_PROVIDERS": "twilio"}, simulation_allowed=True)
        == "none"
    )  # no vendor adapter exists
    assert all(s.state == "not_configured" for s in registry_status("none"))
