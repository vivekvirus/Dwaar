"""AT-08 (M1) end to end: a device wall clock is moved backwards.

PRD 16: "Time-sensitive automatic decisions disabled or reviewed." EDGE-05; PRD 7.4 (offline ordering).

The SAME scenario against the FakeCloud and against the REAL API. The trusted time the gateway learns on sync is the HTTP ``Date`` of an
authenticated response; on the real leg the server's ``Date`` follows the virtual TRUE clock (monotonic), never the gateway's stepped wall
clock. SIMULATED. Not field evidence.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from tests.acceptance._edge_world import DATASET
from tests.acceptance._scene import Scene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at(
        "AT-08",
        dataset=DATASET
        + " | e2e: FakeCloud and the REAL API (uvicorn loopback, ephemeral PostgreSQL), virtual clock",
    ),
    pytest.mark.req("EDGE-05", "EDGE-07", "GATE-14", "INV-03"),
]


def wire_of(s: Scene, seq: int) -> dict:  # type: ignore[type-arg]
    row = s.gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (seq,))
    return json.loads(s.gw.store.cipher.open("outbox", "wire", seq, row["wire_enc"]))  # type: ignore[index,no-any-return]


@pytest.fixture
def started(scene: Scene) -> Scene:
    assert scene.sync().policy == "applied"
    scene.t.advance(300)
    return scene


def test_wall_clock_moved_backwards_disables_automatic_guest_and_standing_decisions_and_flags_review(
    started: Scene,
) -> None:
    s = started
    guard = s.actor(s.term_a)
    assert s.evaluate(guard, s.guest(s.pass_multi))["decision"]["outcome"] == "allow"
    s.t.advance(130)  # let the hold lapse
    assert s.evaluate(guard, s.standing())["decision"]["outcome"] == "allow"
    before_seq = s.gw.outbox.stats()["last_seq"]

    s.t.step_wall(-2 * 3600)  # <<< the fault: someone sets the device clock back two hours

    g = s.evaluate(guard, s.guest(s.pass_multi))
    assert (
        g["decision"]["outcome"] == "needs_supervisor"
        and g["decision"]["reason_code"] == "clock_jumped_backwards"
    )
    assert (
        g["decision"]["review_required"] is True and g["decision"]["auto_allow_on_timeout"] is False
    )
    assert g["reservation_id"] is None  # nothing consumed under an untrustworthy clock
    st = s.evaluate(guard, s.standing())["decision"]
    assert st["outcome"] == "needs_supervisor" and st["reason_code"] == "clock_jumped_backwards"

    r = s.evaluate(
        guard, s.resident()
    )  # the cached resident flow is NOT locked out, but flagged for review
    assert r["decision"]["outcome"] == "allow" and r["decision"]["review_required"] is True
    e = s.gw.record_entry(
        guard, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    assert wire_of(s, e["seq"])["payload"]["review"] is True

    types = [
        x["type"] for x in s.gw.store.all("SELECT type FROM outbox WHERE seq > ?", (before_seq,))
    ]
    assert types.count("ClockAnomalyDetected") == 1
    assert "clock_jumped_backwards" in [i["kind"] for i in s.gw.review_items()]
    status = s.gw.status()["clock"]
    assert status["jumped_backwards"] is True and status["guest_automatic_approval"] == "disabled"

    sup = s.actor(s.term_sup, "supervisor")
    out = s.gw.guard_decision(
        sup, pending_id=g["pending_id"], resolution="admit", note="host verified by phone"
    )
    assert out["decided_via"] == "supervisor"

    wires = [wire_of(s, n) for n in range(1, s.gw.outbox.stats()["last_seq"] + 1)]
    assert [x["seq"] for x in wires] == list(range(1, len(wires) + 1))
    times = [x["occurred_at"] for x in wires]
    assert times == sorted(times)  # observation times and sequence never go backwards

    # the evidence reaches the cloud with the uncertainty it was recorded with; nothing is rewritten
    assert s.sync().failed is None and s.gw.outbox.stats()["pending"] == 0
    assert len(s.cloud_anomalies()) == 1
    if (
        s.kind == "real"
    ):  # REAL-ONLY: the cloud keeps occurred_at exactly as stated and flags nothing about a resident entry
        ew = s.ew  # type: ignore[attr-defined]
        assert [
            r[0] for r in ew.rows("SELECT occurred_at FROM edge_events ORDER BY seq")
        ] == sorted(r[0] for r in ew.rows("SELECT occurred_at FROM edge_events"))
        assert ew.rows("SELECT count(*) FROM edge_quarantine") == [(0,)]


def test_a_trusted_resync_restores_automatic_decisions_and_events_reach_the_cloud(
    started: Scene,
) -> None:
    s = started
    guard = s.actor(s.term_a)
    s.t.step_wall(-3600)
    assert s.evaluate(guard, s.guest(s.pass_multi))["decision"]["outcome"] == "needs_supervisor"
    s.refresh_policy()  # reconnect: the cloud's authenticated time clears the latch; a fresh refresh resets the 2 h entitlement
    s.t.step_wall(3600)  # the operator fixes the clock; the latch alone would still hold
    res = s.sync()
    assert res.policy == "applied" and not res.failed
    assert s.evaluate(guard, s.guest(s.pass_multi))["decision"]["outcome"] == "allow"
    assert s.gw.status()["clock"]["jumped_backwards"] is False
    assert len(s.cloud_anomalies()) == 1


def test_uncertainty_above_60_seconds_disables_automatic_guest_approval(started: Scene) -> None:
    s = started
    guard = s.actor(s.term_a)
    s.gw.note_trusted_time(s.t.wall_now, 60_000)  # exactly the limit: still automatic
    assert s.evaluate(guard, s.guest(s.pass_multi))["decision"]["outcome"] == "allow"
    s.t.advance(130)
    s.gw.note_trusted_time(s.t.wall_now, 60_500)  # a poor sample, e.g. a very slow link
    d = s.evaluate(guard, s.guest(s.pass_multi))["decision"]
    assert d["outcome"] == "needs_supervisor" and d["reason_code"] == "clock_uncertainty_exceeded"
    r = s.evaluate(guard, s.resident())
    assert r["decision"]["outcome"] == "allow"  # residents are not locked out by uncertainty alone
    e = s.gw.record_entry(
        guard, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    assert wire_of(s, e["seq"])["clock_uncertainty_ms"] >= 60_500
    s.sync()
    if (
        s.kind == "real"
    ):  # REAL-ONLY: above the 60 s limit the cloud flags the device clock once; the resident entry stays accepted
        ew = s.ew  # type: ignore[attr-defined]
        assert ew.rows("SELECT status, clock_flag FROM edge_events ORDER BY seq DESC LIMIT 1") == [
            ("accepted", "uncertain")
        ]
        assert [r[0] for r in ew.exceptions()] == ["clock_implausible"]


def test_restart_after_a_backwards_step_cannot_extend_windows_and_guests_need_a_supervisor(
    started: Scene,
) -> None:
    s = started
    guard = s.actor(s.term_a)
    r = s.evaluate(guard, s.resident())
    e0 = s.gw.record_entry(
        guard, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    t_before = wire_of(s, e0["seq"])["occurred_at"]
    s.t.advance(1200)
    s.gw.record_exit(guard, gate_id=s.gate_a, lane_id=s.lane_a_out)  # persists the high-water mark
    s.t.step_wall(-5 * 3600)  # clock set back, then the gateway restarts (monotonic anchor lost)
    s.restart()
    guard = s.actor(s.term_a)
    clock = s.gw.clock_state()
    assert (
        not clock.trusted and clock.wall_jumped_backwards
    )  # detected through the persisted high-water mark
    assert clock.now >= s.t.wall_now + timedelta(hours=5) - timedelta(
        seconds=1
    )  # the estimate is never earlier than already observed
    d = s.evaluate(guard, s.guest(s.pass_multi))["decision"]
    assert d["outcome"] == "needs_supervisor" and d["reason_code"] == "clock_jumped_backwards"
    r2 = s.evaluate(guard, s.resident())
    e1 = s.gw.record_entry(
        guard, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=r2["evaluation_id"]
    )
    assert wire_of(s, e1["seq"])["occurred_at"] >= t_before  # nothing is back-dated
    assert wire_of(s, e1["seq"])["clock_uncertainty_ms"] == 86_400_000  # honestly unknown
