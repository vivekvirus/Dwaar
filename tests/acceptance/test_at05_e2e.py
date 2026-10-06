"""AT-05 (M1) end to end: a guest QR is consumed at one gate and then presented at a second, isolated gate.

PRD 16: "Wrong-gate or replay rejection, or supervised manual path; never a silent global guarantee." PRD 9.3 / D-13.

The SAME scenario runs against the in-process FakeCloud (``fakecloud``) and against the REAL API over real HTTP with a real
ephemeral PostgreSQL and a gateway commissioned through the real enrolment routes (``realcloud``). Both legs are SIMULATION:
virtual clock shared by gateway and cloud, loopback network, no hardware. Assertions marked REAL-ONLY exist because the fake
cloud does not model them (docs/adr/0019, conformance).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import json

import pytest

from dwaar_common.events import canonical_json
from dwaar_common.signing import b64url_decode, b64url_encode, generate_private_key, sign_bytes
from dwaar_edge.decision import OperatingMode, Outcome
from dwaar_edge.qr import parse_qr
from tests.acceptance._edge_world import DATASET
from tests.acceptance._scene import Scene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at(
        "AT-05",
        dataset=DATASET
        + " | e2e: FakeCloud and the REAL API (uvicorn loopback, ephemeral PostgreSQL), virtual clock",
    ),
    pytest.mark.req("GATE-01", "GATE-06", "EDGE-05", "EDGE-06", "EDGE-07", "INV-03", "INV-07"),
]


@pytest.fixture
def started(scene: Scene) -> Scene:
    assert (
        scene.sync().policy == "applied"
    )  # the gateway holds the signed policy and a fresh cloud confirmation
    scene.t.advance(60)
    return scene


def test_gate_bound_qr_consumed_at_gate_a_is_not_silently_accepted_at_gate_b(
    started: Scene,
) -> None:
    s = started
    ga, gb, sup = s.actor(s.term_a), s.actor(s.term_b), s.actor(s.term_sup, "supervisor")
    first = s.evaluate(ga, s.qr(s.pass_a))
    assert first["decision"]["outcome"] == "allow"
    entry = s.gw.record_entry(
        ga, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=first["evaluation_id"]
    )
    assert entry["entry_observed"] is True

    at_b = s.evaluate(gb, s.qr(s.pass_a), gate=s.gate_b)
    assert (
        at_b["decision"]["outcome"] == "needs_supervisor"
        and at_b["decision"]["reason_code"] == "wrong_gate"
    )
    assert at_b["decision"]["auto_allow_on_timeout"] is False and at_b["reservation_id"] is None
    replay = s.evaluate(ga, s.qr(s.pass_a))
    assert (
        replay["decision"]["outcome"] == "deny"
        and replay["decision"]["reason_code"] == "pass_replay_consumed"
    )

    s.t.advance(95)  # no timeout ever admits: the pending item closes and nobody entered
    assert s.gw.list_pending() == []
    assert s.gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 1

    again = s.evaluate(gb, s.qr(s.pass_a), gate=s.gate_b)
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
        gb, gate_id=s.gate_b, lane_id=s.lane_b_in, pending_id=again["pending_id"]
    )
    assert manual["decision_source"] == "supervisor_override"
    assert [i["kind"] for i in s.gw.review_items()].count("single_use_conflict") == 1

    # the evidence reaches the cloud: BOTH physical entries are kept, the second marked as the conflict it is
    res = s.sync()
    assert res.failed is None and s.gw.outbox.stats()["pending"] == 0
    payloads = s.cloud_entry_payloads()
    assert len(payloads) == 2 and sum(1 for p in payloads if p.get("conflict")) == 1
    assert s.cloud_statuses() <= {"accepted"}
    if (
        s.kind == "real"
    ):  # REAL-ONLY: the cloud projects the entries and asks a supervisor to review the override (INV-07, GATE-07)
        ew = s.ew  # type: ignore[attr-defined]
        assert ew.rows("SELECT uses, state FROM invitations WHERE id = %s", (s.pass_a.id,)) == [
            (1, "consumed")
        ]
        assert sorted(r[0] for r in ew.exceptions()) == ["manual_entry"]
        assert ew.rows("SELECT count(*) FROM access_events") == [(2,)]


def test_qr_for_another_society_or_forged_signature_is_denied_not_confirmed(started: Scene) -> None:
    s = started
    ga = s.actor(s.term_a)
    # a QR signed by somebody else but naming the cloud's own key id: the gateway verifies against the PROVISIONED pass key
    body_part, _ = s.pass_a.qr.split(".", 1)
    payload = json.loads(b64url_decode(body_part))
    forged_body = canonical_json(payload)
    forged = f"{b64url_encode(forged_body)}.{sign_bytes(generate_private_key(), forged_body)}"
    d = s.evaluate(ga, {"kind": "qr", "text": forged})["decision"]
    assert d["outcome"] == "deny" and d["reason_code"] == "bad_signature"
    junk = s.evaluate(ga, {"kind": "qr", "text": "not-a-qr"})["decision"]
    assert junk["outcome"] == "deny" and junk["reason_code"] == "invalid_credential"
    assert s.gw.outbox.stats()["pending"] == 0  # nothing was observed, nothing queued


def test_isolated_gates_gate_bound_pass_is_consumed_locally_and_rejected_at_the_other_gate(
    started: Scene,
) -> None:
    s = started
    term_a, term_b = s.terminal(s.gate_a, s.term_a), s.terminal(s.gate_b, s.term_b)
    assert (
        term_a.banner == term_b.banner == "restricted_standalone"
        and term_a.mode is OperatingMode.RESTRICTED_STANDALONE
    )
    guest = s.gw.policy.invitations[s.pass_a.id]  # type: ignore[union-attr]
    parsed = parse_qr(s.pass_a.qr, s.gw.config.pass_keys, s.gw.config.society_id)
    assert parsed is not None and guest.id == s.pass_a.id
    cred = parsed[0]
    first = term_a.evaluate(cred, s.lane_a_in)
    assert first.outcome is Outcome.ALLOW
    term_a.record_entry(first, cred, s.lane_a_in)
    assert term_a.evaluate(cred, s.lane_a_in).reason_code == "pass_replay_consumed"
    at_b = term_b.evaluate(cred, s.lane_b_in)
    assert at_b.outcome is Outcome.NEEDS_SUPERVISOR and at_b.reason_code == "wrong_gate"


def test_isolated_gates_cannot_promise_global_single_use_for_an_unbound_pass(
    started: Scene,
) -> None:
    s = started
    term_a, term_b = s.terminal(s.gate_a, s.term_a), s.terminal(s.gate_b, s.term_b)
    parsed = parse_qr(s.pass_any.qr, s.gw.config.pass_keys, s.gw.config.society_id)
    assert parsed is not None
    guest = parsed[0]
    da, db = term_a.evaluate(guest, s.lane_a_in), term_b.evaluate(guest, s.lane_b_in)
    for d in (
        da,
        db,
    ):  # neither terminal claims a global guarantee: both go to a supervised manual path
        assert (
            d.outcome is Outcome.NEEDS_SUPERVISOR
            and d.reason_code == "global_single_use_not_guaranteed"
        )
        assert d.review_required and d.fallback_options
    term_a.record_entry(da, guest, s.lane_a_in, authorised_by="supervisor_override")
    term_b.record_entry(db, guest, s.lane_b_in, authorised_by="supervisor_override")

    ta, tb = s.actor(s.term_a), s.actor(s.term_b)
    for term, actor in ((term_a, ta), (term_b, tb)):
        out = s.gw.reconcile_standalone(
            actor, terminal_policy_seq=term.bundle.seq, observations=term.drain()
        )  # type: ignore[union-attr]
        assert out["results"][0]["status"] in {"accepted", "conflict_flagged"}
    assert [r["kind"] for r in s.gw.review_items()] == ["single_use_conflict"]
    assert (
        s.gw.store.one("SELECT COUNT(*) AS n FROM movements")["n"] == 2
    )  # physical entries are never silently discarded

    s.sync()
    payloads = s.cloud_entry_payloads()
    assert len(payloads) == 2 and sum(1 for p in payloads if p.get("conflict")) == 1
    assert all(p["restricted_standalone"] for p in payloads)
    if (
        s.kind == "real"
    ):  # REAL-ONLY: two overrides at two gates leave two manual-entry exceptions, the second names the over-used pass
        ew = s.ew  # type: ignore[attr-defined]
        ex = ew.exceptions("manual_entry")
        assert len(ex) == 2 and sum("more often than allowed" in r[4] for r in ex) == 1
        assert ew.rows("SELECT uses FROM invitations WHERE id = %s", (s.pass_any.id,)) == [(1,)]


def test_gateway_arbitrates_an_unbound_single_use_pass_across_gates_while_the_lan_works(
    started: Scene,
) -> None:
    s = started
    ga, gb = s.actor(s.term_a), s.actor(s.term_b)
    cred = s.guest(s.pass_any)
    first = s.evaluate(ga, cred)
    assert first["decision"]["outcome"] == "allow"
    s.gw.record_entry(
        ga, gate_id=s.gate_a, lane_id=s.lane_a_in, evaluation_id=first["evaluation_id"]
    )
    d = s.evaluate(gb, cred, gate=s.gate_b)["decision"]
    assert d["outcome"] == "deny" and d["reason_code"] == "pass_replay_consumed"
    s.sync()
    if (
        s.kind == "real"
    ):  # REAL-ONLY: exactly one use is counted in the cloud and the visitor is visible as inside
        ew = s.ew  # type: ignore[attr-defined]
        assert ew.rows("SELECT uses, state FROM invitations WHERE id = %s", (s.pass_any.id,)) == [
            (1, "consumed")
        ]
        assert ew.rows("SELECT count(*) FROM visits WHERE state = 'inside'") == [(1,)]


def test_expired_pass_requires_confirmation_never_silent_allow(started: Scene) -> None:
    s = started
    ga = s.actor(s.term_a)
    s.t.advance(13 * 3600)  # past the 12 h pass window and well past the 2 h offline entitlement
    d = s.evaluate(ga, s.qr(s.pass_a))["decision"]
    assert d["outcome"] in {"needs_guard", "needs_supervisor"} and d["outcome"] != "allow"
