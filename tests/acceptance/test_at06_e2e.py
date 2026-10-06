"""AT-06 (M1) end to end: the WAN is down for 72 hours, including gateway restarts.

PRD 16: "Cached permitted flows work; fresh approvals use explicit fallback; events recover." PRD 9.3 outage runbook; EDGE-05;
NFR-09 (72 h buffer with restarts, no acknowledged-event loss).

The SAME scenario runs against the FakeCloud and against the REAL API (real HTTP, real PostgreSQL). SIMULATED time: 72 hours pass in
milliseconds on a virtual clock shared by gateway and cloud; the "WAN" is a switch in front of the real HTTP transport; restarts close and
reopen the real SQLite store. Not field evidence.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from tests.acceptance._edge_world import DATASET
from tests.acceptance._scene import Scene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at(
        "AT-06",
        dataset=DATASET
        + " | e2e: FakeCloud and the REAL API (uvicorn loopback, ephemeral PostgreSQL), virtual clock",
    ),
    pytest.mark.req(
        "EDGE-03",
        "EDGE-05",
        "EDGE-07",
        "NFR-09",
        "GATE-05",
        "GATE-06",
        "GATE-07",
        "INV-03",
        "INV-07",
    ),
]


def resident_cycle(s: Scene, actor, *, expect: str = "allow") -> str | None:  # type: ignore[no-untyped-def]
    ev = s.evaluate(actor, s.resident())
    assert ev["decision"]["outcome"] == expect, ev["decision"]
    if expect != "allow":
        return None
    e = s.gw.record_entry(
        actor, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=ev["evaluation_id"]
    )
    s.t.advance(120)
    s.gw.record_exit(
        actor, gate_id=s.gate_a, lane_id=s.lane_a_out, movement_id=uuid.UUID(e["movement_id"])
    )
    return str(e["movement_id"])


def test_72_hour_outage_with_restarts_cached_flows_work_fresh_approvals_fall_back_events_recover(
    scene: Scene,
) -> None:
    s = scene
    start = s.t.wall_now
    assert s.sync().policy == "applied"
    guard = s.actor(s.term_a)
    s.t.advance(60)
    resident_cycle(s, guard)
    s.sync()
    assert s.gw.status()["mode"] == "normal"

    s.set_cloud_online(
        False
    )  # ---- the WAN goes down ----------------------------------------------------------------------
    sched = [
        (1, False),
        (3, False),
        (6, True),
        (12, False),
        (18, True),
        (24, False),
        (36, True),
        (48, False),
        (60, True),
        (71, False),
    ]
    for hours, restart in sched:
        s.t.advance(max(0.0, (start + timedelta(hours=hours) - s.t.wall_now).total_seconds()))
        if restart:
            s.restart()  # gateway process restart WITHOUT any cloud contact: no trusted time
            guard = s.actor(s.term_a)
            assert not s.gw.clock_state().trusted
        # every attempt fails while the WAN is down; nothing is lost
        assert s.sync().failed
        assert resident_cycle(s, guard)  # cached permitted flow keeps working
        for _ in range(8):
            resident_cycle(s, guard)
        fb = s.gw.start_fresh_approval(guard, gate_id=s.gate_a, lane_id=s.lane_a_in, unit_id=s.unit)
        assert (
            fb["status"] == "fallback_required"
            and "intercom" in fb["fallback_options"]
            and fb["auto_allow_on_timeout"] is False
        )
        assert (
            s.gw.status()["mode"] == "wan_down" and s.gw.status()["connectivity"]["wan"] == "down"
        )
        d = s.evaluate(guard, s.guest(s.pass_multi))["decision"]
        if hours == 1:
            assert d["outcome"] == "allow"  # age 1 h, trusted clock, no restart yet
            s.t.advance(1)
        else:
            assert d["outcome"] in {"needs_guard", "needs_supervisor"}
            if restart:
                assert (
                    d["reason_code"] == "restart_without_trusted_time"
                    and d["outcome"] == "needs_supervisor"
                )
        assert (
            s.evaluate(guard, s.resident(), lane=s.lane_a_out)["decision"]["reason_code"]
            == "egress_always_permitted"
        )

    # ---- past 72 h of policy age: guard-assisted resident verification, never an automatic lockout --------------------
    s.t.advance(2 * 3600 + 600)  # 73 h 10 min
    d = s.evaluate(guard, s.resident())["decision"]
    assert d["outcome"] == "needs_guard" and d["reason_code"] in {
        "policy_stale_resident",
        "policy_expired",
    }
    assert d["fallback_options"] and d["auto_allow_on_timeout"] is False
    pend = s.evaluate(guard, s.resident())["pending_id"]
    out = s.gw.guard_decision(
        guard, pending_id=pend, resolution="admit", note="verified by face and unit intercom"
    )
    assert out["decided_via"] == "guard" and out["entry_observed"] is False
    s.gw.record_entry(guard, gate_id=s.gate_a, lane_id=s.lane_a_in, pending_id=pend)
    emerg = s.gw.emergency_entry(
        guard, gate_id=s.gate_a, lane_id=None, authority="medical_emergency", reason="ambulance"
    )
    assert emerg["entry_observed"] is True

    buffered = s.gw.outbox.stats()
    assert buffered["acked"] == 2  # only the pre-outage entry and exit were ever acknowledged
    assert (
        buffered["pending"] == buffered["last_seq"] - 2 > 150
    )  # everything observed since is buffered across restarts

    s.set_cloud_online(
        True
    )  # ---- the WAN returns -----------------------------------------------------------------------
    s.refresh_policy()
    before_ids = [r["event_id"] for r in s.gw.store.all("SELECT event_id FROM outbox ORDER BY seq")]
    res = s.sync()
    assert res.policy == "applied" and not res.failed
    assert s.gw.outbox.stats()["pending"] == 0

    total = buffered["last_seq"]
    assert s.cloud_seqs() == list(range(1, total + 1))  # complete and contiguous
    assert len(s.cloud_event_ids()) == total  # no duplicates
    assert [
        r["event_id"] for r in s.gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
    ] == before_ids  # same ids, nothing invented
    assert s.cloud_event_ids() == before_ids
    assert s.cloud_statuses() <= {"accepted", "duplicate"}
    occurred = s.cloud_occurred()
    assert occurred == sorted(
        occurred
    )  # ordering by device sequence is consistent with real observation times
    st = s.gw.status()
    assert (
        st["mode"] == "normal"
        and st["clock"]["trusted"]
        and st["policy"]["resident_verification"] == "automatic"
    )
    assert s.evaluate(guard, s.resident())["decision"]["outcome"] == "allow"
    if (
        s.kind == "real"
    ):  # REAL-ONLY (ADR-0019): events older than 72 h are NOT an implausible clock when an outage explains their age
        ew = s.ew  # type: ignore[attr-defined]
        assert ew.rows("SELECT count(*) FROM edge_events WHERE clock_flag = 'stale'") == [(0,)]
        assert ew.rows("SELECT count(*) FROM edge_quarantine") == [(0,)]
        assert [r[0] for r in ew.exceptions() if r[0] != "clock_implausible"] == [
            "manual_entry"
        ]  # the emergency entry, reviewed


def test_restart_with_clock_wrong_and_no_wan_still_serves_cached_resident_flows(
    scene: Scene,
) -> None:
    s = scene
    s.sync()
    s.set_cloud_online(False)
    s.t.advance(5 * 3600)
    s.restart()
    guard = s.actor(s.term_a)
    ev = s.evaluate(guard, s.resident())
    assert (
        ev["decision"]["outcome"] == "allow" and ev["decision"]["review_required"] is True
    )  # allowed, flagged
    e = s.gw.record_entry(
        guard, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=ev["evaluation_id"]
    )
    assert e["seq"] == 1 + s.gw.outbox.stats()["acked"]
    import json

    evt = s.gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (e["seq"],))
    wire = json.loads(s.gw.store.cipher.open("outbox", "wire", e["seq"], evt["wire_enc"]))
    assert (
        wire["clock_uncertainty_ms"] == 86_400_000
    )  # recorded honestly: unknown after a restart without trusted time
    s.set_cloud_online(True)
    assert s.sync().failed is None
    if (
        s.kind == "real"
    ):  # REAL-ONLY: the cloud flags the unknown clock once, accepts the entry, and does not call the resident an error
        ew = s.ew  # type: ignore[attr-defined]
        assert [r[0] for r in ew.exceptions()] == ["clock_implausible"]
        assert ew.rows("SELECT status, clock_flag FROM edge_events ORDER BY seq DESC LIMIT 1") == [
            ("accepted", "uncertain")
        ]


def test_policy_older_than_valid_until_goes_guard_assisted_even_for_known_residents(
    scene: Scene,
) -> None:
    s = scene
    s.sync()
    s.set_cloud_online(False)
    guard = s.actor(s.term_a)
    pol = s.gw.policy
    assert pol is not None
    s.t.advance(
        (pol.valid_until - s.t.wall_now).total_seconds() + 3600
    )  # one hour past the snapshot's valid_until
    d = s.evaluate(guard, s.resident())["decision"]
    assert d["outcome"] == "needs_guard" and d["reason_code"] in {
        "policy_expired",
        "policy_stale_resident",
    }
