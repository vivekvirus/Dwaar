"""AT-05 (M1): a guest QR is consumed at one gate and then presented at a second, isolated gate.

PRD 16: "Wrong-gate or replay rejection, or supervised manual path; never a silent global guarantee."
PRD 9.3: single-use consumption is serialised by the gateway while the LAN works; if gates partition, global single-use
cannot be guaranteed, so offline guest passes are gate-bound or need manual validation. D-13: bound to the assigned gate.

EDGE-LEVEL scenario with the real gateway and terminal-standalone logic, injected time and the FakeCloud contract fake
(simulation=true). It proves decisions and data; the terminal UI and real hardware are later slices.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from dwaar_edge.decision import OperatingMode, Outcome
from tests.acceptance._edge_world import DATASET, EdgeScene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-05", dataset=DATASET),
    pytest.mark.req("GATE-01", "GATE-06", "EDGE-05", "EDGE-06", "INV-03", "INV-07"),
]


@pytest.fixture
def scene(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = EdgeScene(tmp_path)
    s.publish(1)
    s.sync()  # the gateway holds the signed policy and a fresh cloud confirmation
    s.t.advance(60)
    yield s
    s.close()


def qr_cred(s: EdgeScene, inv, gate=None):  # type: ignore[no-untyped-def]
    return {"kind": "qr", "text": s.qr(inv, gate=gate)}


def test_gate_bound_qr_consumed_at_gate_a_is_not_silently_accepted_at_gate_b(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    ga, gb, sup = s.actor(w.term_a), s.actor(w.term_b), s.actor(w.term_sup, "supervisor")
    cred = qr_cred(s, s.inv_a, gate=w.gate_a)

    first = s.evaluate(ga, cred)
    assert first["decision"]["outcome"] == "allow"
    entry = s.gw.record_entry(
        ga, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=first["evaluation_id"]
    )
    assert entry["entry_observed"] is True

    # the SAME pass at the other gate: wrong gate -> confirmation by a supervisor, never an automatic allow
    at_b = s.evaluate(gb, cred, gate=w.gate_b)
    assert (
        at_b["decision"]["outcome"] == "needs_supervisor"
        and at_b["decision"]["reason_code"] == "wrong_gate"
    )
    assert at_b["decision"]["auto_allow_on_timeout"] is False and at_b["reservation_id"] is None
    # and the replay at the assigned gate is rejected by the arbiter
    replay = s.evaluate(ga, cred)
    assert (
        replay["decision"]["outcome"] == "deny"
        and replay["decision"]["reason_code"] == "pass_replay_consumed"
    )

    # no timeout ever admits: after the request expiry the item is closed and nobody entered
    s.t.advance(95)
    assert s.gw.list_pending() == []
    assert s.gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 1

    # the supervised manual path: supervisor decides, entry is observed separately, flagged for review
    again = s.evaluate(gb, cred, gate=w.gate_b)
    assert (
        s.gw.guard_decision(
            sup,
            pending_id=again["pending_id"],
            resolution="admit",
            note="host confirmed by intercom",
        )["decided_via"]
        == "supervisor"
    )
    manual = s.gw.record_entry(
        gb, gate_id=w.gate_b, lane_id=w.lane_b_in, pending_id=again["pending_id"]
    )
    assert manual["decision_source"] == "supervisor_override"
    assert [i["kind"] for i in s.gw.review_items()].count(
        "single_use_conflict"
    ) == 1  # the second use of a single-use pass is flagged


def test_qr_for_another_society_or_forged_signature_is_denied_not_confirmed(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    ga = s.actor(w.term_a)
    from dwaar_common.signing import Signer

    forged = w.qr(
        s.inv_a,
        "nonce-abcdefgh",
        nbf=s.t.wall_now - timedelta(minutes=1),
        exp=s.t.wall_now + timedelta(hours=1),
        gate=w.gate_a,
        signer=Signer(w.pass_signer.key_id, w.other_issuer.private_key),
    )
    d = s.evaluate(ga, {"kind": "qr", "text": forged})["decision"]
    assert d["outcome"] == "deny" and d["reason_code"] == "bad_signature"
    junk = s.evaluate(ga, {"kind": "qr", "text": "not-a-qr"})["decision"]
    assert junk["outcome"] == "deny" and junk["reason_code"] == "invalid_credential"


def test_isolated_gates_gate_bound_pass_is_consumed_locally_and_rejected_at_the_other_gate(
    scene: EdgeScene,
) -> None:
    """Gateway lost and the two gates cannot reach each other: each terminal runs restricted standalone."""
    s, w = scene, scene.w
    term_a, term_b = s.terminal(w.gate_a, w.term_a), s.terminal(w.gate_b, w.term_b)
    assert (
        term_a.banner == term_b.banner == "restricted_standalone"
        and term_a.mode is OperatingMode.RESTRICTED_STANDALONE
    )
    guest = s.guest(s.inv_a)

    first = term_a.evaluate(guest, w.lane_a_in)
    assert first.outcome is Outcome.ALLOW
    term_a.record_entry(first, guest, w.lane_a_in)
    assert (
        term_a.evaluate(guest, w.lane_a_in).reason_code == "pass_replay_consumed"
    )  # replay at gate A
    at_b = term_b.evaluate(
        guest, w.lane_b_in
    )  # gate B never saw the consumption, but the pass is not its own
    assert at_b.outcome is Outcome.NEEDS_SUPERVISOR and at_b.reason_code == "wrong_gate"


def test_isolated_gates_cannot_promise_global_single_use_for_an_unbound_pass(
    scene: EdgeScene,
) -> None:
    s, w = scene, scene.w
    term_a, term_b = s.terminal(w.gate_a, w.term_a), s.terminal(w.gate_b, w.term_b)
    guest = s.guest(s.inv_any)
    da, db = term_a.evaluate(guest, w.lane_a_in), term_b.evaluate(guest, w.lane_b_in)
    for d in (
        da,
        db,
    ):  # neither terminal claims a global guarantee: both go to a supervised manual path
        assert (
            d.outcome is Outcome.NEEDS_SUPERVISOR
            and d.reason_code == "global_single_use_not_guaranteed"
        )
        assert d.review_required and d.fallback_options

    # a supervisor at each isolated gate admits the same pass: possible by design of the partition. It is NOT hidden:
    term_a.record_entry(da, guest, w.lane_a_in, authorised_by="supervisor_override")
    term_b.record_entry(db, guest, w.lane_b_in, authorised_by="supervisor_override")

    # when the gateway is back, BOTH observations are kept and the double use is flagged for review
    ta, tb = s.actor(w.term_a), s.actor(w.term_b)
    for term, actor in ((term_a, ta), (term_b, tb)):
        out = s.gw.reconcile_standalone(
            actor, terminal_policy_seq=term.bundle.seq, observations=term.drain()
        )  # type: ignore[union-attr]
        assert out["results"][0]["status"] in {"accepted", "conflict_flagged"}
    statuses = [r["kind"] for r in s.gw.review_items()]
    assert statuses == ["single_use_conflict"]
    assert (
        s.gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 2
    )  # physical entries are never silently discarded

    # evidence reaches the cloud: both entries, the second marked as a conflict
    s.sync()
    entries = [e for e in s.cloud.events.values() if e["type"] == "EntryObserved"]
    assert len(entries) == 2 and sum(1 for e in entries if e["payload"].get("conflict")) == 1
    assert all(e["payload"]["restricted_standalone"] for e in entries)


def test_gateway_arbitrates_an_unbound_single_use_pass_across_gates_while_the_lan_works(
    scene: EdgeScene,
) -> None:
    """The contrast case: with the gateway reachable, serialised consumption IS guaranteed, and it says so."""
    s, w = scene, scene.w
    ga, gb = s.actor(w.term_a), s.actor(w.term_b)
    cred = {"kind": "guest_pass", "invitation_id": str(s.inv_any), "nonce": "nonce-abcdefgh"}
    first = s.evaluate(ga, cred)
    assert first["decision"]["outcome"] == "allow"
    s.gw.record_entry(
        ga, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=first["evaluation_id"]
    )
    d = s.evaluate(gb, cred, gate=w.gate_b)["decision"]
    assert d["outcome"] == "deny" and d["reason_code"] == "pass_replay_consumed"


def test_expired_pass_requires_confirmation_never_silent_allow(scene: EdgeScene) -> None:
    s, w = scene, scene.w
    ga = s.actor(w.term_a)
    s.t.advance(13 * 3600)  # past the 12 h pass window and well past the 2 h offline entitlement
    d = s.evaluate(ga, qr_cred(s, s.inv_a, gate=w.gate_a))["decision"]
    assert d["outcome"] in {"needs_guard", "needs_supervisor"} and d["outcome"] != "allow"
