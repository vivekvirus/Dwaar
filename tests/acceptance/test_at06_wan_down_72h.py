"""AT-06 (M1): the WAN is disconnected for 72 hours, including device (gateway) restarts.

PRD 16: "Cached permitted flows work; fresh approvals use explicit fallback; events recover."
PRD 9.3 outage runbook: WAN loss -> cached entries continue; remote approval falls back to intercom or call; recovery ->
sync, inspect sequence gaps, reconcile inside counts without inventing timestamps. EDGE-05: policy older than 72 h triggers
guard-assisted resident verification; after a restart without trusted time guest credentials need supervisor assistance.
NFR-09: 72 h buffer with restarts, no acknowledged-event loss.

EDGE-LEVEL, SIMULATED TIME: 72 hours pass in milliseconds through an injected clock; restarts close and reopen the real
SQLite store with a fresh clock model (the monotonic anchor is lost, as after a real restart). The cloud is FakeCloud, an
in-process implementation of the contract, switched offline for the outage. Not field evidence.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from tests.acceptance._edge_world import DATASET, RES, EdgeScene
from tests.integration.edge_gateway.support import START

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-06", dataset=DATASET),
    pytest.mark.req("EDGE-03", "EDGE-05", "NFR-09", "GATE-05", "GATE-06", "GATE-07", "INV-03"),
]


def resident_cycle(s: EdgeScene, actor, *, expect: str = "allow") -> str | None:  # type: ignore[no-untyped-def]
    """One resident entry and its exit through the local path. Returns the entry movement id when entered."""
    w = s.w
    ev = s.evaluate(actor, RES)
    assert ev["decision"]["outcome"] == expect, ev["decision"]
    if expect != "allow":
        return None
    e = s.gw.record_entry(
        actor, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
    )
    s.t.advance(120)
    s.gw.record_exit(
        actor, gate_id=w.gate_a, lane_id=w.lane_a_out, movement_id=uuid.UUID(e["movement_id"])
    )
    return str(e["movement_id"])


def test_72_hour_outage_with_restarts_cached_flows_work_fresh_approvals_fall_back_events_recover(
    tmp_path: Path,
) -> None:
    s = EdgeScene(tmp_path)
    w = s.w
    try:
        # ---- t0: online, policy applied and confirmed -------------------------------------------------------
        s.publish(1)
        assert s.sync().policy == "applied"
        guard = s.actor(w.term_a)
        s.t.advance(60)
        resident_cycle(s, guard)
        s.sync()
        assert s.gw.status()["mode"] == "normal"

        # ---- the WAN goes down ----------------------------------------------------------------------------------
        s.cloud.online = False
        entered: list[str] = []
        guest_cred = {
            "kind": "guest_pass",
            "invitation_id": str(s.inv_multi),
            "nonce": "nonce-abcdefgh",
        }
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
            s.t.advance(max(0.0, (START + timedelta(hours=hours) - s.t.wall_now).total_seconds()))
            if restart:
                s.restart()  # gateway process restart WITHOUT any cloud contact: no trusted time
                guard = s.actor(w.term_a)
                assert not s.gw.clock_state().trusted
            assert (
                s.client.sync_once().failed
            )  # every attempt fails while the WAN is down; nothing is lost
            # cached permitted flow keeps working (resident, within the 72 h validity)
            mid = resident_cycle(s, guard)
            assert mid
            entered.append(mid)
            for _ in range(8):
                resident_cycle(
                    s, guard
                )  # steady traffic: the outbox fills with real entries and exits
            # a FRESH remote approval cannot be obtained: explicit fallback path, never an allow
            fb = s.gw.start_fresh_approval(
                guard, gate_id=w.gate_a, lane_id=w.lane_a_in, unit_id=w.unit_1
            )
            assert (
                fb["status"] == "fallback_required"
                and "intercom" in fb["fallback_options"]
                and fb["auto_allow_on_timeout"] is False
            )
            assert s.gw.status()["mode"] == "wan_down"
            assert s.gw.status()["connectivity"]["wan"] == "down"
            # guest pass: automatic only inside the 2 h offline entitlement with a trusted clock
            d = s.evaluate(guard, guest_cred)["decision"]
            if hours == 1:
                assert d["outcome"] == "allow"  # age 1 h, trusted clock, no restart yet
                s.t.advance(1)
            else:
                assert d["outcome"] in {
                    "needs_guard",
                    "needs_supervisor",
                }  # stale (>2 h) or restarted without trusted time
                if restart:
                    assert (
                        d["reason_code"] == "restart_without_trusted_time"
                        and d["outcome"] == "needs_supervisor"
                    )
            # essential egress and emergency entry never depend on the cloud
            assert (
                s.evaluate(guard, RES, lane=w.lane_a_out)["decision"]["reason_code"]
                == "egress_always_permitted"
            )

        # ---- past 72 h of policy age: guard-assisted resident verification, never an automatic lockout ----------------
        s.t.advance(2 * 3600 + 600)  # 73 h 10 min
        d = s.evaluate(guard, RES)["decision"]
        assert d["outcome"] == "needs_guard" and d["reason_code"] == "policy_stale_resident"
        assert d["fallback_options"] and d["auto_allow_on_timeout"] is False
        pend = s.evaluate(guard, RES)["pending_id"]
        out = s.gw.guard_decision(
            guard, pending_id=pend, resolution="admit", note="verified by face and unit intercom"
        )
        assert out["decided_via"] == "guard" and out["entry_observed"] is False
        s.gw.record_entry(guard, gate_id=w.gate_a, lane_id=w.lane_a_in, pending_id=pend)
        emerg = s.gw.emergency_entry(
            guard, gate_id=w.gate_a, lane_id=None, authority="medical_emergency", reason="ambulance"
        )
        assert emerg["entry_observed"] is True

        buffered = s.gw.outbox.stats()
        assert buffered["acked"] == 2  # only the pre-outage entry and exit were ever acknowledged
        assert (
            buffered["pending"] == buffered["last_seq"] - 2 > 150
        )  # everything observed since is buffered across restarts

        # ---- the WAN returns -----------------------------------------------------------------------------------------------
        s.cloud.online = True
        s.publish(2)
        before_ids = [
            r["event_id"] for r in s.gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
        ]
        res = s.sync()
        assert res.policy == "applied" and not res.failed
        assert s.gw.outbox.stats()["pending"] == 0

        # events recovered: complete, contiguous, no duplicates, same ids, nothing invented
        total = buffered["last_seq"]
        assert s.cloud.accepted_seqs(w.gateway_device) == list(range(1, total + 1))
        assert len(s.cloud.events) == total
        assert [
            r["event_id"] for r in s.gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
        ] == before_ids
        assert {o["status"] for o in s.cloud.outcome_log} <= {"accepted", "duplicate"}
        occurred = [s.cloud.events[e]["occurred_at"] for e in before_ids]
        assert occurred == sorted(
            occurred
        )  # offline ordering by device sequence is consistent with real observation times
        st = s.gw.status()
        assert (
            st["mode"] == "normal"
            and st["clock"]["trusted"]
            and st["policy"]["resident_verification"] == "automatic"
        )
        assert s.evaluate(guard, RES)["decision"]["outcome"] == "allow"
    finally:
        s.close()


def test_restart_with_clock_wrong_and_no_wan_still_serves_cached_resident_flows(
    tmp_path: Path,
) -> None:
    s = EdgeScene(tmp_path)
    w = s.w
    try:
        s.publish(1)
        s.sync()
        s.cloud.online = False
        s.t.advance(5 * 3600)
        s.restart()
        guard = s.actor(w.term_a)
        ev = s.evaluate(guard, RES)
        assert (
            ev["decision"]["outcome"] == "allow" and ev["decision"]["review_required"] is True
        )  # allowed, flagged
        e = s.gw.record_entry(
            guard, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        assert e["seq"] == 1
        evt = s.gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (e["seq"],))
        import json

        wire = json.loads(s.gw.store.cipher.open("outbox", "wire", e["seq"], evt["wire_enc"]))
        assert (
            wire["clock_uncertainty_ms"] == 86_400_000
        )  # recorded honestly: unknown after a restart without trusted time
    finally:
        s.close()


def test_policy_older_than_valid_until_goes_guard_assisted_even_for_known_residents(
    tmp_path: Path,
) -> None:
    s = EdgeScene(tmp_path)
    try:
        s.publish(1, valid_for_hours=10)
        s.sync()
        s.cloud.online = False
        guard = s.actor(s.w.term_a)
        s.t.advance(11 * 3600)
        d = s.evaluate(guard, RES)["decision"]
        assert d["outcome"] == "needs_guard" and d["reason_code"] == "policy_expired"
    finally:
        s.close()
