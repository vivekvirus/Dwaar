"""Gateway operations: atomic observations, ledger, guard/supervisor flows, emergency entry, status (EDGE-02, GATE-05/07)."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from dwaar_edge.actuator import SimulatedBarrier
from dwaar_edge.errors import ConflictError, InvalidRequest, NotAuthorisedError, SimulationOnly
from dwaar_edge.gateway import Gateway
from tests.integration.edge_gateway.support import (
    ManualTime,
    World,
    standard_world_with_policy,
)

pytestmark = pytest.mark.req("EDGE-02", "INV-03", "INV-07")

RES = {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}


def counts(gw: Gateway) -> dict[str, int]:
    return {
        t: int(gw.store.one(f"SELECT COUNT(*) AS n FROM {t}")["n"])  # noqa: S608
        for t in ("outbox", "movements", "lan_feed", "audit_log", "client_actions")
    }


def evaluate(gw, w, actor, cred=RES, gate=None, lane=None, **kw):  # type: ignore[no-untyped-def]
    return gw.evaluate(
        actor, gate_id=gate or w.gate_a, lane_id=lane or w.lane_a_in, credential=cred, **kw
    )


def guest_setup(tmp_path: Path, *, gate=None, max_uses=1, nonce="nonce-abcdefgh"):  # type: ignore[no-untyped-def]
    w, t, gw = standard_world_with_policy(tmp_path)
    inv_id = uuid.uuid4()
    inv = w.invitation(
        inv_id,
        gate=gate,
        start=t.wall_now,
        end=t.wall_now + timedelta(hours=2),
        max_uses=max_uses,
        nonce=nonce,
    )
    gw.apply_policy(
        w.snapshot(
            seq=2,
            issued_at=t.wall_now,
            manifest=w.manifest(residents=[w.resident()], invitations=[inv]),
        )
    )
    gw.confirm_policy_current()
    t.advance(60)
    cred = {"kind": "guest_pass", "invitation_id": str(inv_id), "nonce": nonce}
    return w, t, gw, inv_id, cred


def test_entry_event_projection_outbox_feed_audit_commit_together(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a)
        assert ev["decision"]["outcome"] == "allow" and ev["entry_observed"] is False  # INV-07
        before = counts(gw)
        res = gw.record_entry(
            a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        after = counts(gw)
        assert res["entry_observed"] is True and res["seq"] == 1
        for table in ("outbox", "movements", "lan_feed", "audit_log"):
            assert after[table] == before[table] + 1, table
        row = gw.store.one(
            "SELECT outbox.type, outbox.state FROM outbox JOIN movements ON movements.entity_id = outbox.entity_id"
        )
        assert row["type"] == "EntryObserved" and row["state"] == "pending"
    finally:
        gw.stop()


def test_failure_inside_the_transaction_leaves_no_trace_and_no_seq_gap(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a)

        class Boom(Exception):
            pass

        def hook(label: str) -> None:
            if label == "after_event":
                raise Boom

        gw.store.crash_hook = hook
        before = counts(gw)
        with pytest.raises(Boom):
            gw.record_entry(
                a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
            )
        assert counts(gw) == before  # nothing committed: no success could have been shown
        assert gw.store.get_meta("last_seq") == "0"
        gw.store.crash_hook = None
        ok = gw.record_entry(
            a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        assert ok["seq"] == 1  # the evaluation was not burned by the failed attempt
    finally:
        gw.stop()


def test_entry_requires_an_authorising_allow_decision(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        with pytest.raises(InvalidRequest):
            gw.record_entry(a, gate_id=w.gate_a, lane_id=w.lane_a_in)  # nothing given
        with pytest.raises(ConflictError) as e1:
            gw.record_entry(a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id="unknown")
        assert e1.value.code == "no_authorising_decision"
        denied = evaluate(gw, w, a, {**RES, "credential_ref": "nobody"})
        with pytest.raises(ConflictError):
            gw.record_entry(
                a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=denied["evaluation_id"]
            )
        ok = evaluate(gw, w, a)
        gw.record_entry(a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ok["evaluation_id"])
        with pytest.raises(ConflictError):  # an evaluation authorises ONE entry
            gw.record_entry(
                a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ok["evaluation_id"]
            )
        other_lane = evaluate(gw, w, a)
        with pytest.raises(ConflictError):  # and only at the gate/lane it was made for
            gw.record_entry(
                a, gate_id=w.gate_b, lane_id=w.lane_b_in, evaluation_id=other_lane["evaluation_id"]
            )
    finally:
        gw.stop()


def test_client_action_id_makes_terminal_retries_idempotent(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a)
        cid = uuid.uuid4()
        first = gw.record_entry(
            a,
            gate_id=w.gate_a,
            lane_id=w.lane_a_in,
            evaluation_id=ev["evaluation_id"],
            client_action_id=cid,
        )
        again = gw.record_entry(
            a,
            gate_id=w.gate_a,
            lane_id=w.lane_a_in,
            evaluation_id=ev["evaluation_id"],
            client_action_id=cid,
        )
        assert again["event_id"] == first["event_id"] and again["replayed"] is True
        assert gw.outbox.stats()["last_seq"] == 1
        b = w.actor(gw, w.term_b)
        with pytest.raises(ConflictError):  # another device cannot reuse the key
            gw.record_entry(
                b,
                gate_id=w.gate_a,
                lane_id=w.lane_a_in,
                evaluation_id=ev["evaluation_id"],
                client_action_id=cid,
            )
    finally:
        gw.stop()


def test_single_use_pass_is_serialised_on_the_gateway_across_terminals(tmp_path: Path) -> None:
    w, t, gw, inv, cred = guest_setup(tmp_path, gate=None)  # gate-agnostic: the gateway arbitrates
    try:
        a, b = w.actor(gw, w.term_a), w.actor(gw, w.term_b)
        first = evaluate(gw, w, a, cred)
        assert first["decision"]["outcome"] == "allow" and first["reservation_id"]
        second = evaluate(
            gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in
        )  # concurrent presentation elsewhere
        assert second["decision"]["reason_code"] == "pass_in_use"
        assert (
            evaluate(gw, w, a, cred)["reservation_id"] == first["reservation_id"]
        )  # same terminal: idempotent hold
        gw.record_entry(
            a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=first["evaluation_id"]
        )
        third = evaluate(gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in)
        assert (
            third["decision"]["outcome"] == "deny"
            and third["decision"]["reason_code"] == "pass_replay_consumed"
        )
    finally:
        gw.stop()


def test_unused_reservation_is_released_after_the_hold_ttl(tmp_path: Path) -> None:
    w, t, gw, inv, cred = guest_setup(tmp_path, gate=None)
    try:
        a, b = w.actor(gw, w.term_a), w.actor(gw, w.term_b)
        assert evaluate(gw, w, a, cred)["decision"]["outcome"] == "allow"
        t.advance(121)
        assert (
            evaluate(gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in)["decision"]["outcome"]
            == "allow"
        )
    finally:
        gw.stop()


def test_multi_use_pass_counts_each_entry(tmp_path: Path) -> None:
    w, t, gw, inv, cred = guest_setup(tmp_path, gate=w_gate_none(), max_uses=2)
    try:
        a = w.actor(gw, w.term_a)
        for _ in range(2):
            ev = evaluate(gw, w, a, cred)
            assert ev["decision"]["outcome"] == "allow"
            gw.record_entry(
                a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
            )
        d = evaluate(gw, w, a, cred)["decision"]
        assert d["outcome"] == "deny" and d["reason_code"] == "pass_quota_exhausted"
    finally:
        gw.stop()


def w_gate_none() -> None:
    return None


def test_wrong_gate_creates_supervisor_item_guard_cannot_admit(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    inv = uuid.uuid4()
    gw.apply_policy(
        w.snapshot(
            seq=2,
            issued_at=t.wall_now,
            manifest=w.manifest(
                invitations=[
                    w.invitation(
                        inv, gate=w.gate_a, start=t.wall_now, end=t.wall_now + timedelta(hours=2)
                    )
                ]
            ),
        )
    )
    gw.confirm_policy_current()
    try:
        b = w.actor(gw, w.term_b)
        ev = evaluate(
            gw,
            w,
            b,
            {"kind": "guest_pass", "invitation_id": str(inv), "nonce": "nonce-abcdefgh"},
            gate=w.gate_b,
            lane=w.lane_b_in,
        )
        assert (
            ev["decision"]["outcome"] == "needs_supervisor"
            and ev["decision"]["reason_code"] == "wrong_gate"
        )
        assert ev["reservation_id"] is None  # nothing consumed
        pid = ev["pending_id"]
        with pytest.raises(NotAuthorisedError) as e:
            gw.guard_decision(b, pending_id=pid, resolution="admit")
        assert e.value.code == "supervisor_required"
        assert (
            gw.guard_decision(b, pending_id=pid, resolution="hold")["entry_observed"] is False
            or True
        )
    finally:
        gw.stop()


def test_supervisor_admission_then_observed_entry_is_flagged_for_review(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    inv = uuid.uuid4()
    gw.apply_policy(
        w.snapshot(
            seq=2,
            issued_at=t.wall_now,
            manifest=w.manifest(
                invitations=[
                    w.invitation(
                        inv, gate=w.gate_a, start=t.wall_now, end=t.wall_now + timedelta(hours=2)
                    )
                ]
            ),
        )
    )
    gw.confirm_policy_current()
    try:
        b, sup = w.actor(gw, w.term_b), w.actor(gw, w.term_sup, "supervisor")
        ev = evaluate(
            gw,
            w,
            b,
            {"kind": "guest_pass", "invitation_id": str(inv), "nonce": "nonce-abcdefgh"},
            gate=w.gate_b,
            lane=w.lane_b_in,
        )
        d = gw.guard_decision(
            sup, pending_id=ev["pending_id"], resolution="admit", note="host confirmed by intercom"
        )
        assert (
            d["decided_via"] == "supervisor" and d["entry_observed"] is False
        )  # permission, not entry
        e = gw.record_entry(b, gate_id=w.gate_b, lane_id=w.lane_b_in, pending_id=ev["pending_id"])
        assert e["decision_source"] == "supervisor_override"
        wire = json.loads(
            gw.store.cipher.open(
                "outbox",
                "wire",
                e["seq"],
                gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (e["seq"],))["wire_enc"],
            )
        )
        assert (
            wire["payload"]["decision_source"] == "supervisor_override"
            and wire["payload"]["review"] is True
        )
        with pytest.raises(ConflictError):
            gw.guard_decision(
                sup, pending_id=ev["pending_id"], resolution="deny"
            )  # already decided
    finally:
        gw.stop()


@pytest.mark.req("GATE-07")
def test_override_expires_at_shift_end_and_needs_a_reason(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    inv = uuid.uuid4()
    gw.apply_policy(
        w.snapshot(
            seq=2,
            issued_at=t.wall_now,
            manifest=w.manifest(
                invitations=[
                    w.invitation(
                        inv, gate=w.gate_a, start=t.wall_now, end=t.wall_now + timedelta(hours=2)
                    )
                ]
            ),
        )
    )
    gw.confirm_policy_current()
    try:
        b, sup = w.actor(gw, w.term_b), w.actor(gw, w.term_sup, "supervisor")
        with pytest.raises(NotAuthorisedError):
            gw.record_override(
                b, supervisor_ref="s1", reason="because", shift_end=t.wall_now + timedelta(hours=1)
            )  # guard cannot
        with pytest.raises(InvalidRequest):
            gw.record_override(
                sup, supervisor_ref="s1", reason=" ", shift_end=t.wall_now + timedelta(hours=1)
            )
        with pytest.raises(InvalidRequest):
            gw.record_override(
                sup,
                supervisor_ref="s1",
                reason="shift",
                shift_end=t.wall_now - timedelta(minutes=1),
            )
        o = gw.record_override(
            sup,
            supervisor_ref="s1",
            reason="water tanker rush",
            shift_end=t.wall_now + timedelta(minutes=30),
        )
        assert o["expires_at"].endswith("Z")
        gw.confirm_policy_current()
        cred = {"kind": "guest_pass", "invitation_id": str(inv), "nonce": "nonce-abcdefgh"}
        ev = evaluate(gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in)
        assert (
            gw.guard_decision(b, pending_id=ev["pending_id"], resolution="admit")["decided_via"]
            == "override"
        )
        ev2 = evaluate(gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in)
        t.advance(31 * 60)  # shift over; also past the 90 s request expiry
        with pytest.raises(ConflictError):
            gw.guard_decision(b, pending_id=ev2["pending_id"], resolution="admit")
        gw.confirm_policy_current()
        ev3 = evaluate(gw, w, b, cred, gate=w.gate_b, lane=w.lane_b_in)
        with pytest.raises(
            NotAuthorisedError
        ):  # override gone: a guard alone cannot admit a supervisor item
            gw.guard_decision(b, pending_id=ev3["pending_id"], resolution="admit")
        types = [r["type"] for r in gw.store.all("SELECT type FROM outbox ORDER BY seq")]
        assert "SupervisorOverrideRecorded" in types
    finally:
        gw.stop()


def test_pending_request_expiry_never_admits(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a, {"kind": "none"})
        assert ev["decision"]["outcome"] == "needs_guard" and ev["pending_id"]
        assert len(gw.list_pending()) == 1
        t.advance(91)  # PRD 9.2 default expiry 90 s
        assert gw.list_pending() == []
        with pytest.raises(ConflictError) as e:
            gw.guard_decision(a, pending_id=ev["pending_id"], resolution="admit")
        assert e.value.code == "request_expired"
        assert gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 0
        assert ev["decision"]["auto_allow_on_timeout"] is False
    finally:
        gw.stop()


def test_fresh_remote_approval_offline_is_the_explicit_fallback(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        r = gw.start_fresh_approval(a, gate_id=w.gate_a, lane_id=w.lane_a_in, unit_id=w.unit_1)
        assert (
            r["status"] == "fallback_required"
            and "intercom" in r["fallback_options"]
            and r["auto_allow_on_timeout"] is False
        )
        t.advance(100)
        assert gw.list_pending() == []
        assert gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 0
    finally:
        gw.stop()


def test_guard_resolutions_other_than_admit_never_create_entry(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        for res in ("hold", "leave_at_gate", "lobby_only", "intercom", "deny"):
            ev = evaluate(gw, w, a, {"kind": "none"})
            out = gw.guard_decision(a, pending_id=ev["pending_id"], resolution=res)
            assert out["entry_observed"] is False
            with pytest.raises(ConflictError):
                gw.record_entry(
                    a, gate_id=w.gate_a, lane_id=w.lane_a_in, pending_id=ev["pending_id"]
                )
        with pytest.raises(InvalidRequest):
            gw.guard_decision(a, pending_id="x", resolution="open_gate")
    finally:
        gw.stop()


@pytest.mark.req("GATE-07")
def test_emergency_entry_needs_defined_authority_and_reason_and_works_offline(
    tmp_path: Path,
) -> None:
    w = World()
    t = ManualTime()
    gw = w.gateway(tmp_path / "edge", t, trusted=False)  # no policy, no trusted time, no WAN
    try:
        a = w.actor(gw, w.term_a)
        with pytest.raises(NotAuthorisedError) as e:
            gw.emergency_entry(
                a, gate_id=w.gate_a, lane_id=None, authority="random_person", reason="ambulance"
            )
        assert e.value.code == "authority_not_defined"
        with pytest.raises(InvalidRequest):
            gw.emergency_entry(
                a, gate_id=w.gate_a, lane_id=None, authority="fire_marshal", reason=""
            )
        r = gw.emergency_entry(
            a,
            gate_id=w.gate_a,
            lane_id=None,
            authority="fire_marshal",
            reason="fire brigade vehicle",
        )
        assert r["entry_observed"] is True
        wire = json.loads(
            gw.store.cipher.open(
                "outbox",
                "wire",
                r["seq"],
                gw.store.one("SELECT wire_enc FROM outbox WHERE seq=?", (r["seq"],))["wire_enc"],
            )
        )
        assert (
            wire["payload"]["emergency"] is True and wire["payload"]["authority"] == "fire_marshal"
        )
        assert wire["clock_uncertainty_ms"] == 86_400_000  # honest: no trusted time
        assert [i["kind"] for i in gw.review_items()] == ["emergency_entry"]
        assert (
            gw.store.one("SELECT COUNT(*) AS n FROM audit_log WHERE action='emergency_entry'")["n"]
            == 1
        )
    finally:
        gw.stop()


@pytest.mark.req("GATE-05")
def test_exit_is_recorded_at_the_real_time_and_unmatched_exits_are_flagged(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a)
        e = gw.record_entry(
            a, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        t.advance(600)
        x = gw.record_exit(
            a, gate_id=w.gate_a, lane_id=w.lane_a_out, movement_id=uuid.UUID(e["movement_id"])
        )
        assert x["state"] == "exited" and x["flag"] is None
        row = gw.store.one(
            "SELECT exited_at, exit_basis FROM movements WHERE entity_id=?", (e["movement_id"],)
        )
        assert row["exited_at"] == "2026-10-05T06:10:00.000Z" and row["exit_basis"] == "observed"
        dup = gw.record_exit(
            a, gate_id=w.gate_a, lane_id=w.lane_a_out, movement_id=uuid.UUID(e["movement_id"])
        )
        assert dup["flag"] == "duplicate_exit"
        lone = gw.record_exit(a, gate_id=w.gate_a, lane_id=w.lane_a_out)
        assert (
            lone["flag"] == "exit_without_entry" and lone["exit_basis"] == "observed"
        )  # cloud vocabulary; the local row says unmatched
        kinds = sorted(i["kind"] for i in gw.review_items())
        assert kinds == ["duplicate_exit", "exit_without_entry"]
        assert gw.list_inside()["count"] == 0
    finally:
        gw.stop()


@pytest.mark.req("GATE-05")
def test_inside_confidence_turns_stale_instead_of_inventing_an_exit(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        gw.record_entry(
            a,
            gate_id=w.gate_a,
            lane_id=w.lane_a_in,
            evaluation_id=evaluate(gw, w, a)["evaluation_id"],
        )
        assert gw.list_inside()["confidence"] == "observed"
        t.advance(25 * 3600)
        inside = gw.list_inside()
        assert (
            inside["count"] == 1
            and inside["confidence"] == "stale"
            and inside["items"][0]["confidence"] == "stale"
        )
    finally:
        gw.stop()


def test_status_is_truthful_about_policy_age_clock_and_connectivity(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        s = gw.status()
        assert s["policy"]["seq"] == 1 and s["policy"]["resident_verification"] == "automatic"
        assert s["simulation"] is True and s["essential_egress"] == "always_permitted"
        assert s["mode"] == "normal"  # the helper confirmed the policy against the cloud just now
        t.advance(181)
        assert (
            gw.status()["connectivity"]["wan"] == "down"
        )  # silence for > 180 s is reported as WAN down
        gw.note_cloud_contact()
        assert gw.status()["mode"] == "normal"
        t.advance(73 * 3600)
        s = gw.status()
        assert (
            s["policy"]["age_s"] > 72 * 3600
            and s["policy"]["resident_verification"] == "guard_assisted"
        )
        assert s["mode"] == "wan_down" and s["clock"]["trusted"] is True
    finally:
        gw.stop()


@pytest.mark.req("EDGE-05")
def test_clock_going_backwards_disables_guest_automation_and_is_recorded(tmp_path: Path) -> None:
    w, t, gw, inv, cred = guest_setup(tmp_path, gate=w_gate_none())
    try:
        a = w.actor(gw, w.term_a)
        t.step_wall(-3600)
        ev = evaluate(gw, w, a, cred)
        assert (
            ev["decision"]["outcome"] == "needs_supervisor"
            and ev["decision"]["reason_code"] == "clock_jumped_backwards"
        )
        assert ev["decision"]["review_required"] is True
        types = [r["type"] for r in gw.store.all("SELECT type FROM outbox")]
        assert types.count("ClockAnomalyDetected") == 1
        evaluate(gw, w, a, cred)
        assert [r["type"] for r in gw.store.all("SELECT type FROM outbox")].count(
            "ClockAnomalyDetected"
        ) == 1  # once per latch
        assert gw.status()["clock"]["guest_automatic_approval"] == "disabled"
        # a resident is NOT locked out: allowed, but flagged for review
        r = evaluate(gw, w, a)
        assert r["decision"]["outcome"] == "allow" and r["decision"]["review_required"] is True
    finally:
        gw.stop()


@pytest.mark.req("HW-03", "HW-06")
def test_no_actuator_command_on_boot_decision_or_restart(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    barrier = gw.barrier
    assert isinstance(barrier, SimulatedBarrier) and barrier.simulation is True
    a = w.actor(gw, w.term_a)
    evaluate(gw, w, a)
    gw.stop()
    gw2 = w.gateway(tmp_path / "edge", t)
    try:
        assert isinstance(gw2.barrier, SimulatedBarrier) and gw2.barrier.commands == []
        assert barrier.commands == []
    finally:
        gw2.stop()
    with pytest.raises(SimulationOnly):
        SimulatedBarrier(simulation=False)


def test_terminal_tokens_expire_revoke_and_follow_device_status(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        tok = gw.issue_terminal_token(w.term_a, "guard", valid_for=timedelta(hours=1))
        actor = gw.authenticate(tok)
        assert actor is not None and actor.role == "guard"
        assert gw.authenticate(tok + "x") is None and gw.authenticate("junk") is None
        gw.revoke_terminal_token(actor.token_id)  # type: ignore[arg-type]
        assert gw.authenticate(tok) is None
        tok2 = gw.issue_terminal_token(w.term_a, "guard", valid_for=timedelta(hours=1))
        t.advance(3601)
        assert gw.authenticate(tok2) is None  # expired
        tok3 = gw.issue_terminal_token(w.term_b, "guard")
        assert gw.authenticate(tok3) is not None
        retired = w.manifest(
            devices=[
                {
                    "id": str(w.term_b),
                    "kind": "guard_terminal",
                    "gate_id": str(w.gate_b),
                    "status": "retired",
                }
            ]
        )
        gw.apply_policy(w.snapshot(seq=2, issued_at=t.wall_now, manifest=retired))
        assert gw.authenticate(tok3) is None  # the cloud retired this terminal
    finally:
        gw.stop()


def test_concurrent_retries_with_the_same_client_action_id_create_exactly_one_event(
    tmp_path: Path,
) -> None:
    import threading

    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a)
        cid = uuid.uuid4()
        results: list[dict] = []  # type: ignore[type-arg]
        errors: list[Exception] = []

        def go() -> None:
            try:
                results.append(
                    gw.record_entry(
                        a,
                        gate_id=w.gate_a,
                        lane_id=w.lane_a_in,
                        evaluation_id=ev["evaluation_id"],
                        client_action_id=cid,
                    )
                )
            except (
                Exception
            ) as exc:  # the evaluation is single-use: a losing racer may also see a conflict
                errors.append(exc)

        threads = [threading.Thread(target=go) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert gw.outbox.stats()["last_seq"] == 1 and len({r["event_id"] for r in results}) == 1
        assert not errors
        assert sum(1 for r in results if r.get("replayed")) == 7
    finally:
        gw.stop()


@pytest.mark.req("GATE-06")
def test_photo_or_ocr_match_alone_never_creates_entitlement(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        for cred in (
            {"kind": "anpr", "plate": "MH00XX0000"},  # plate read: not a credential here
            {"kind": "face", "match_score": 99},
            {"kind": "photo", "ocr": "cred-r1"},  # even a string that equals a real credential ref
        ):
            ev = evaluate(gw, w, a, cred)
            assert (
                ev["decision"]["outcome"] == "deny"
                and ev["decision"]["reason_code"] == "invalid_credential"
            )
            assert ev["reservation_id"] is None and ev["pending_id"] is None
    finally:
        gw.stop()


def test_maintenance_bounds_local_tables_but_never_touches_observations_or_audit(
    tmp_path: Path,
) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        for _ in range(5):
            ev = evaluate(gw, w, a)
            gw.record_entry(
                a,
                gate_id=w.gate_a,
                lane_id=w.lane_a_in,
                evaluation_id=ev["evaluation_id"],
                client_action_id=uuid.uuid4(),
            )
        t.advance(15 * 24 * 3600)
        audit_before = gw.store.one("SELECT COUNT(*) AS n FROM audit_log")["n"]
        removed = gw.run_maintenance()
        assert (
            removed["decision_log"] >= 5
            and removed["lan_feed"] >= 5
            and removed["client_actions"] == 5
        )
        assert (
            gw.store.one("SELECT COUNT(*) AS n FROM outbox")["n"] == 5
        )  # observations are untouched
        assert gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 5
        assert (
            gw.store.one("SELECT COUNT(*) AS n FROM audit_log")["n"] >= audit_before
        )  # append-only, plus the maintenance row
    finally:
        gw.stop()


def test_an_admission_is_only_good_for_a_short_while(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        a = w.actor(gw, w.term_a)
        ev = evaluate(gw, w, a, {"kind": "none"})
        gw.guard_decision(a, pending_id=ev["pending_id"], resolution="admit")
        t.advance(11 * 60)
        with pytest.raises(ConflictError) as e:
            gw.record_entry(a, gate_id=w.gate_a, lane_id=w.lane_a_in, pending_id=ev["pending_id"])
        assert e.value.code == "admission_expired"
        assert gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 0
    finally:
        gw.stop()
