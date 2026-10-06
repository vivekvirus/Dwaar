"""The cloud's published manifest shape (docs/contracts/edge-sync.md): in|out lanes, invitation ``windows``, date-valued standing
rules with visit_kind/action/days/tz, masked aliases, 409 and 401 handling in the sync client."""

from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dwaar_common.timeutil import format_iso_utc
from dwaar_edge.decision import GuestPass, Outcome, StandingVisitor, decide
from dwaar_edge.sync import SyncClient, SyncConfig
from tests.integration.edge_gateway.fakecloud import FakeCloud
from tests.integration.edge_gateway.support import (
    START,
    ManualTime,
    World,
    standard_world_with_policy,
)

from .helpers import bundle, clock, req

pytestmark = pytest.mark.req("EDGE-04", "GATE-14")

W = World()
INV = uuid.uuid4()


def test_cloud_shaped_snapshot_is_accepted_and_applied(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        inv = w.invitation(
            INV,
            gate=None,
            start=t.wall_now,
            end=t.wall_now + timedelta(days=3),
            visitor_alias="T*** V***",
            windows=[
                {
                    "start": format_iso_utc(t.wall_now),
                    "end": format_iso_utc(t.wall_now + timedelta(hours=1)),
                },
                {
                    "start": format_iso_utc(t.wall_now + timedelta(days=1)),
                    "end": format_iso_utc(t.wall_now + timedelta(days=1, hours=1)),
                },
            ],
        )
        rule = {
            "unit_id": str(w.unit_1),
            "rule_kind": "leave_at_gate",
            "params": {
                "visit_kind": "delivery",
                "category": "food",
                "action": "leave_at_gate",
                "days": [1, 2, 3, 4, 5, 6, 7],
                "start_local": "22:00",
                "end_local": "06:00",
                "tz": "Asia/Kolkata",
            },
            "effective_from": "2026-01-01",
            "effective_to": None,
        }
        manifest = w.manifest(residents=[w.resident()], invitations=[inv], rules=[rule])
        out = gw.apply_policy(w.snapshot(seq=2, issued_at=t.wall_now, manifest=manifest))
        assert (
            out["applied_seq"] == 2
            and gw.policy
            and gw.policy.rules_by_unit[w.unit_1][0].effective_from is not None
        )
        assert (
            gw.policy.lanes[w.lane_a_in].direction == "in"
            and not gw.policy.lanes[w.lane_a_in].is_exit
        )
        assert gw.policy.lanes[w.lane_a_out].is_exit
    finally:
        gw.stop()


def test_recurring_pass_windows_not_just_outer_bounds() -> None:
    """A milk-vendor pass: 06:00-07:00 on two days. The outer bounds alone would admit it at 15:00."""
    day1 = START
    day2 = START + timedelta(days=1)
    windows = [
        {"start": format_iso_utc(day1), "end": format_iso_utc(day1 + timedelta(hours=1))},
        {"start": format_iso_utc(day2), "end": format_iso_utc(day2 + timedelta(hours=1))},
    ]
    inv = W.invitation(INV, gate=None, start=day1, end=day2 + timedelta(hours=1), windows=windows)
    b = bundle(
        W,
        W.manifest(invitations=[inv]),
        valid_for=timedelta(days=5),
        confirmed_at=START + timedelta(days=1, minutes=10),
    )
    g = GuestPass(INV, "nonce-abcdefgh")

    def at(when: datetime) -> Outcome:
        return decide(b, req(g, W.gate_a, W.lane_a_in), clock(when, unc=0)).outcome

    assert at(day1 + timedelta(minutes=10)) is Outcome.ALLOW
    assert (
        at(day1 + timedelta(hours=9)) is Outcome.NEEDS_GUARD
    )  # between the windows (the "15:00" case)
    assert at(day2 + timedelta(minutes=20)) is Outcome.ALLOW
    assert at(day2 + timedelta(hours=3)) is Outcome.NEEDS_GUARD


def test_standing_rule_cloud_params_days_dates_and_actions() -> None:
    mon_2230_ist = datetime(2026, 10, 5, 17, 0, tzinfo=UTC)  # Monday 22:30 IST
    assert mon_2230_ist.astimezone().isoweekday() in range(1, 8)

    def rule(action: str, **p: object) -> dict[str, object]:
        base = {
            "visit_kind": "delivery",
            "action": action,
            "days": [1, 2, 3, 4, 5, 6, 7],
            "start_local": "22:00",
            "end_local": "06:00",
            "tz": "Asia/Kolkata",
        }
        return {
            "unit_id": str(W.unit_1),
            "rule_kind": "leave_at_gate" if action == "leave_at_gate" else "allow_window",
            "params": {**base, **p},
            "effective_from": "2026-01-01",
            "effective_to": "2026-12-31",
        }

    def run(
        rules: list[dict[str, object]],
        at: datetime = mon_2230_ist,
        visit_kind: str = "delivery",
        category: str | None = None,
    ):  # type: ignore[no-untyped-def]
        b = bundle(W, W.manifest(rules=rules), issued_at=at - timedelta(minutes=1))
        return decide(
            b,
            req(StandingVisitor(W.unit_1, category, visit_kind), W.gate_a, W.lane_a_in),
            clock(at, unc=0),
        )

    d = run([rule("leave_at_gate")])
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "standing_rule_leave_at_gate"
    assert (
        run([rule("leave_at_gate")], visit_kind="service").reason_code == "no_local_entitlement"
    )  # another visit kind
    assert run([rule("deny")]).outcome is Outcome.DENY
    assert run([rule("hold")]).reason_code == "standing_rule_hold"
    allowed = run([rule("allow")])
    assert allowed.outcome is Outcome.ALLOW and allowed.evidence["guard_confirms_identity"] is True
    # weekday filter: only Tuesdays (2): a Monday evening does not match
    assert run([rule("allow", days=[2])]).outcome is Outcome.NEEDS_GUARD
    # a window that wraps midnight belongs to the day it started on: 01:00 Tuesday IST is still Monday's window
    tue_0100_ist = datetime(2026, 10, 5, 19, 30, tzinfo=UTC)
    assert run([rule("allow", days=[1])], at=tue_0100_ist).outcome is Outcome.ALLOW
    assert run([rule("allow", days=[2])], at=tue_0100_ist).outcome is Outcome.NEEDS_GUARD
    # effective dates are inclusive calendar days
    last_day = datetime(2026, 12, 31, 17, 0, tzinfo=UTC)
    assert run([rule("allow")], at=last_day).outcome is Outcome.ALLOW
    assert run([rule("allow")], at=last_day + timedelta(days=1)).outcome is Outcome.NEEDS_GUARD
    # malformed: no visit_kind/category, bad tz, bad action, bad time -> never grants
    for key, value in (
        ("visit_kind", None),
        ("tz", "Mars/Base"),
        ("action", "open_gate"),
        ("start_local", "10pm"),
    ):
        r = rule("allow")
        params = dict(r["params"])  # type: ignore[call-overload]
        if value is None:
            del params[key]
        else:
            params[key] = value
        r["params"] = params
        assert run([r]).outcome is Outcome.NEEDS_GUARD, key


def test_policy_409_cursor_ahead_of_cloud_keeps_serving_cached_policy(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        gw.apply_policy(w.snapshot(seq=7, issued_at=t.wall_now, manifest=w.manifest()))
        cloud = FakeCloud(w.society_id, t.wall)
        cloud.register_device(w.gateway_device, w.device_signer.public_key)
        cloud.publish_policy(
            w.snapshot(seq=3, issued_at=t.wall_now, manifest=w.manifest())
        )  # cloud is BEHIND the edge
        r = SyncClient(
            gw, cloud.transport(), SyncConfig(), sleep=lambda s: None, rng=random.Random(1)
        ).sync_once()
        assert r.policy == "cursor_ahead_of_cloud" and not r.failed
        assert gw.policy and gw.policy.seq == 7  # never rolled back
        assert gw.status()["sync"]["policy_cursor_ahead_of_cloud"] is True
    finally:
        gw.stop()


def test_a_device_clock_hours_off_still_syncs_and_recovers_trusted_time(tmp_path: Path) -> None:
    """The cloud refuses timestamps more than 120 s off. The client retries once with the server's own time, then the
    authenticated 2xx response synchronises the clock."""
    w = World()
    device_time = ManualTime(
        START + timedelta(hours=3)
    )  # the device believes it is 3 hours later than the cloud
    gw = w.gateway(tmp_path / "edge", device_time, trusted=False)
    cloud = FakeCloud(w.society_id, lambda: START)
    cloud.register_device(w.gateway_device, w.device_signer.public_key)
    try:
        with gw.store.transaction():
            gw.outbox.append(
                type="EntryObserved",
                entity_id=uuid.uuid4(),
                entity_version=1,
                payload={"g": "x"},
                occurred_at=START,
                clock_uncertainty_ms=0,
                policy_version=0,
            )
        assert not gw.clock_state().trusted
        res = SyncClient(
            gw, cloud.transport(), SyncConfig(), sleep=lambda s: None, rng=random.Random(1)
        ).sync_once()
        assert not res.failed and res.acked == 1
        st = gw.clock_state()
        assert (
            st.trusted and abs((st.now - START).total_seconds()) < 5
        )  # the cloud's time, not the device's
        assert cloud.auth_failures >= 1  # the first attempt was refused; the retry succeeded
    finally:
        gw.stop()
