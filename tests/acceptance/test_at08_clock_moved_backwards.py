"""AT-08 (M1): a device wall clock is moved backwards.

PRD 16: "Time-sensitive automatic decisions disabled or reviewed." EDGE-05: clock uncertainty above 60 seconds disables
automatic time-sensitive guest approval; after a restart without trusted time, guest credentials need supervisor assistance.
PRD 7.4: offline ordering uses device id + monotonic device sequence, trusted sync time + monotonic elapsed time, clock
uncertainty recorded.

EDGE-LEVEL, injected clocks: the wall clock is stepped, the monotonic clock is not. FakeCloud supplies trusted time through
the HTTP Date header. Simulation, not field evidence.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from tests.acceptance._edge_world import DATASET, NONCE, RES, EdgeScene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-08", dataset=DATASET),
    pytest.mark.req("EDGE-05", "GATE-14", "INV-03"),
]

MILK = {
    "unit_id": "",
    "rule_kind": "allow_window",
    "params": {"category": "milk_vendor", "start_local": "00:00", "end_local": "23:59"},
    "effective_from": None,
    "effective_to": None,
}


def wire_of(s: EdgeScene, seq: int) -> dict:  # type: ignore[type-arg]
    row = s.gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (seq,))
    return json.loads(s.gw.store.cipher.open("outbox", "wire", seq, row["wire_enc"]))  # type: ignore[index,no-any-return]


@pytest.fixture
def scene(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = EdgeScene(tmp_path)
    MILK["unit_id"] = str(s.w.unit_1)
    s.publish(1, rules=[MILK])
    s.sync()
    s.t.advance(300)
    yield s
    s.close()


def guest(s: EdgeScene) -> dict:  # type: ignore[type-arg]
    return {"kind": "guest_pass", "invitation_id": str(s.inv_multi), "nonce": NONCE}


def test_wall_clock_moved_backwards_disables_automatic_guest_and_standing_decisions_and_flags_review(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    guard = s.actor(w.term_a)
    standing = {"kind": "standing", "unit_id": str(w.unit_1), "category": "milk_vendor"}

    # before the fault: both automatic paths work
    assert s.evaluate(guard, guest(s))["decision"]["outcome"] == "allow"
    s.t.advance(130)  # let the hold lapse
    assert s.evaluate(guard, standing)["decision"]["outcome"] == "allow"
    before_seq = s.gw.outbox.stats()["last_seq"]

    s.t.step_wall(-2 * 3600)  # <<< the fault: someone sets the device clock back two hours

    g = s.evaluate(guard, guest(s))
    assert (
        g["decision"]["outcome"] == "needs_supervisor"
        and g["decision"]["reason_code"] == "clock_jumped_backwards"
    )
    assert (
        g["decision"]["review_required"] is True and g["decision"]["auto_allow_on_timeout"] is False
    )
    assert g["reservation_id"] is None  # nothing consumed under an untrustworthy clock
    st = s.evaluate(guard, standing)["decision"]
    assert st["outcome"] == "needs_supervisor" and st["reason_code"] == "clock_jumped_backwards"

    # the cached resident flow is NOT locked out, but every such decision is flagged for review
    r = s.evaluate(guard, RES)
    assert r["decision"]["outcome"] == "allow" and r["decision"]["review_required"] is True
    e = s.gw.record_entry(
        guard, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    assert wire_of(s, e["seq"])["payload"]["review"] is True

    # the anomaly is recorded once as an event and a review item, status tells the truth
    types = [
        x["type"] for x in s.gw.store.all("SELECT type FROM outbox WHERE seq > ?", (before_seq,))
    ]
    assert types.count("ClockAnomalyDetected") == 1
    assert "clock_jumped_backwards" in [i["kind"] for i in s.gw.review_items()]
    status = s.gw.status()["clock"]
    assert status["jumped_backwards"] is True and status["guest_automatic_approval"] == "disabled"

    # the supervisor path remains available and recorded
    sup = s.actor(w.term_sup, "supervisor")
    out = s.gw.guard_decision(
        sup, pending_id=g["pending_id"], resolution="admit", note="host verified by phone"
    )
    assert out["decided_via"] == "supervisor"

    # offline ordering is unharmed: observation times and sequence never go backwards
    wires = [wire_of(s, n) for n in range(1, s.gw.outbox.stats()["last_seq"] + 1)]
    assert [x["seq"] for x in wires] == list(range(1, len(wires) + 1))
    times = [x["occurred_at"] for x in wires]
    assert times == sorted(
        times
    )  # the estimate comes from trusted time + monotonic elapsed, not the stepped wall clock


def test_a_trusted_resync_restores_automatic_decisions_and_events_reach_the_cloud(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    guard = s.actor(w.term_a)
    s.t.step_wall(-3600)
    assert s.evaluate(guard, guest(s))["decision"]["outcome"] == "needs_supervisor"
    # reconnect: the cloud's authenticated time clears the latch; a fresh policy refresh resets the 2 h entitlement
    s.publish(2, rules=[MILK])
    s.t.step_wall(3600)  # the operator fixes the clock; the latch alone would still hold
    res = s.sync()
    assert res.policy == "applied" and not res.failed
    assert s.evaluate(guard, guest(s))["decision"]["outcome"] == "allow"
    assert s.gw.status()["clock"]["jumped_backwards"] is False
    anomalies = [e for e in s.cloud.events.values() if e["type"] == "ClockAnomalyDetected"]
    assert len(anomalies) == 1 and anomalies[0]["payload"]["automatic_guest_approval"] == "disabled"


def test_uncertainty_above_60_seconds_disables_automatic_guest_approval(scene: EdgeScene) -> None:
    s, w = scene, scene.w
    guard = s.actor(w.term_a)
    s.gw.note_trusted_time(s.t.wall_now, 60_000)  # exactly the limit: still automatic
    assert s.evaluate(guard, guest(s))["decision"]["outcome"] == "allow"
    s.t.advance(130)
    s.gw.note_trusted_time(s.t.wall_now, 60_500)  # a poor sample, e.g. a very slow link
    d = s.evaluate(guard, guest(s))["decision"]
    assert d["outcome"] == "needs_supervisor" and d["reason_code"] == "clock_uncertainty_exceeded"
    r = s.evaluate(guard, RES)
    assert r["decision"]["outcome"] == "allow"  # residents are not locked out by uncertainty alone
    e = s.gw.record_entry(
        guard, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    assert wire_of(s, e["seq"])["clock_uncertainty_ms"] >= 60_500  # recorded on the event


def test_restart_after_a_backwards_step_cannot_extend_windows_and_guests_need_a_supervisor(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    guard = s.actor(w.term_a)
    r = s.evaluate(guard, RES)
    e0 = s.gw.record_entry(
        guard, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=r["evaluation_id"]
    )
    t_before = wire_of(s, e0["seq"])["occurred_at"]
    s.t.advance(1200)
    s.gw.record_exit(guard, gate_id=w.gate_a, lane_id=w.lane_a_out)  # persists the high-water mark
    s.t.step_wall(-5 * 3600)  # clock set back, then the gateway restarts (monotonic anchor lost)
    s.restart()
    guard = s.actor(w.term_a)
    clock = s.gw.clock_state()
    assert (
        not clock.trusted and clock.wall_jumped_backwards
    )  # detected through the persisted high-water mark
    assert clock.now >= s.t.wall_now + timedelta(hours=5) - timedelta(
        seconds=1
    )  # estimate never earlier than already observed
    d = s.evaluate(guard, guest(s))["decision"]
    assert d["outcome"] == "needs_supervisor" and d["reason_code"] == "clock_jumped_backwards"
    r2 = s.evaluate(guard, RES)
    e1 = s.gw.record_entry(
        guard, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=r2["evaluation_id"]
    )
    assert wire_of(s, e1["seq"])["occurred_at"] >= t_before  # nothing is back-dated
    assert wire_of(s, e1["seq"])["clock_uncertainty_ms"] == 86_400_000  # honestly unknown
