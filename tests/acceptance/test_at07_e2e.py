"""AT-07 (M1) end to end: the gateway fails while the LAN is partitioned.

PRD 16: "Restricted terminal mode; correct single-use limits." EDGE-06, EDGE-10, PRD 9.3 (LAN split).

The SAME scenario against the FakeCloud and against the REAL API (real HTTP, real PostgreSQL, gateway commissioned through the real
enrolment routes). Terminal logic is ``StandaloneTerminal`` (the Android UI is a later slice); the gateway process is really stopped and
reopened on the same SQLite file. SIMULATED time and LAN. Not field evidence.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import copy

import pytest

from dwaar_edge.decision import OperatingMode, Outcome
from dwaar_edge.errors import PolicyRejected, TombstonesRequired
from dwaar_edge.qr import parse_qr
from tests.acceptance._edge_world import DATASET
from tests.acceptance._scene import Scene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at(
        "AT-07",
        dataset=DATASET
        + " | e2e: FakeCloud and the REAL API (uvicorn loopback, ephemeral PostgreSQL), virtual clock",
    ),
    pytest.mark.req("EDGE-06", "EDGE-07", "EDGE-10", "GATE-06", "INV-03", "INV-07"),
]


def guest_of(s: Scene, p):  # type: ignore[no-untyped-def]
    parsed = parse_qr(p.qr, s.gw.config.pass_keys, s.gw.config.society_id)
    assert parsed is not None
    return parsed[0]


def test_restricted_mode_correct_single_use_limits_then_reconcile(scene: Scene) -> None:
    s = scene
    assert s.sync().policy == "applied"
    s.t.advance(60)
    s.gw.allocate_escrow(
        s.pass_multi.id, {s.gate_a: 2, s.gate_b: 1}
    )  # the owner enabled per-gate escrow (4 uses in total)
    term_a, term_b = s.terminal(s.gate_a, s.term_a), s.terminal(s.gate_b, s.term_b)
    assert {term_a.mode, term_b.mode} == {OperatingMode.RESTRICTED_STANDALONE}
    assert term_a.escrow == {s.pass_multi.id: 2} and term_b.escrow == {s.pass_multi.id: 1}
    resident = s.resident()
    from dwaar_edge.decision import ResidentCredential

    res_cred = ResidentCredential(resident["credential_ref"], resident["revocation_version"])

    s.gw.stop()  # ---- the gateway fails; the two gates cannot see each other ---------------------------------------------
    s.t.advance(1800)

    bad = copy.deepcopy(term_a.bundle.raw)  # type: ignore[union-attr]
    bad["manifest"]["residents"][0]["status"] = "active"
    bad["manifest"]["timing"]["guest_offline_max_s"] = 99_999
    with pytest.raises(
        PolicyRejected
    ):  # signed cached entitlements only: a tampered cache is refused by the terminal itself
        term_a.load_cache({"policy": bad, "escrow": {}})

    for term, lane in ((term_a, s.lane_a_in), (term_b, s.lane_b_in)):
        d = term.evaluate(res_cred, lane)
        assert d.outcome is Outcome.ALLOW
        term.record_entry(d, res_cred, lane)

    g_a = guest_of(s, s.pass_a)
    d = term_a.evaluate(g_a, s.lane_a_in)
    assert d.outcome is Outcome.ALLOW
    term_a.record_entry(d, g_a, s.lane_a_in, alias="InvitedAlias")
    assert term_a.evaluate(g_a, s.lane_a_in).reason_code == "pass_replay_consumed"
    assert term_b.evaluate(g_a, s.lane_b_in).outcome is Outcome.NEEDS_SUPERVISOR

    g_any = guest_of(s, s.pass_any)
    assert term_a.evaluate(g_any, s.lane_a_in).reason_code == "global_single_use_not_guaranteed"
    assert term_b.evaluate(g_any, s.lane_b_in).reason_code == "global_single_use_not_guaranteed"

    g_multi = guest_of(s, s.pass_multi)
    used = {"a": 0, "b": 0}
    for key, term, lane in (("a", term_a, s.lane_a_in), ("b", term_b, s.lane_b_in)):
        while True:
            dm = term.evaluate(g_multi, lane)
            if dm.outcome is not Outcome.ALLOW:
                assert dm.outcome is Outcome.DENY and dm.reason_code == "pass_quota_exhausted"
                break
            term.record_entry(dm, g_multi, lane)
            used[key] += 1
    assert used == {"a": 2, "b": 1}  # each gate consumed ONLY its own pre-allocated quota

    s.t.advance(
        24 * 3600
    )  # at least 24 hours standalone: residents still verified from the signed cache
    assert term_a.evaluate(res_cred, s.lane_a_in).outcome is Outcome.ALLOW
    assert (
        term_a.evaluate(g_multi, s.lane_a_in).outcome is not Outcome.ALLOW
    )  # past the pass window: confirmation needed

    s.restart()  # ---- the gateway comes back; the cloud revoked the pass while the terminals were away -------------------
    s.refresh_policy(revoke=s.pass_a, valid_for_hours=200)
    assert s.sync().policy == "applied"
    ta, tb = s.actor(s.term_a), s.actor(s.term_b)
    stale_seq = term_a.bundle.seq  # type: ignore[union-attr]
    with pytest.raises(TombstonesRequired):  # EDGE-10: tombstones first
        s.gw.reconcile_standalone(
            ta, terminal_policy_seq=stale_seq, observations=term_a.observations
        )
    tomb = s.gw.tombstones_since(stale_seq)
    assert [t["ref"] for t in tomb["tombstones"]] == [str(s.pass_a.id)] and tomb["tombstones"][0][
        "version"
    ] >= 1
    s.gw.ack_tombstones(ta, tomb["current_seq"])
    s.gw.ack_tombstones(tb, tomb["current_seq"])
    obs_a, obs_b = term_a.drain(), term_b.drain()
    out = s.gw.reconcile_standalone(ta, terminal_policy_seq=stale_seq, observations=obs_a)
    assert [r["status"] for r in out["results"]].count("accepted") == len(obs_a)
    assert (
        s.gw.reconcile_standalone(ta, terminal_policy_seq=stale_seq, observations=obs_a)["results"][
            0
        ]["status"]
        == "duplicate"
    )
    s.gw.reconcile_standalone(tb, terminal_policy_seq=stale_seq, observations=obs_b)
    alias_rows = s.gw.store.all(
        "SELECT alias_enc FROM movements WHERE invitation_id=?", (str(s.pass_a.id),)
    )
    assert (
        len(alias_rows) == 1 and alias_rows[0]["alias_enc"] is None
    )  # the personal alias of the tombstoned pass was never kept
    n = s.gw.store.one(
        "SELECT COUNT(*) AS n FROM pass_uses WHERE invitation_id=? AND state='consumed'",
        (str(s.pass_multi.id),),
    )["n"]
    assert n == 3

    assert s.sync().failed is None
    total_obs = len(obs_a) + len(obs_b)
    entries = [p for p in s.cloud_entry_payloads() if p.get("restricted_standalone")]
    assert len(entries) == total_obs and len({id(e) for e in entries}) == total_obs
    assert not [p for p in s.cloud_entry_payloads() if p.get("conflict")]  # no double use happened
    assert s.gw.outbox.stats()["pending"] == 0
    if (
        s.kind == "real"
    ):  # REAL-ONLY: the cloud counted the multi-use pass exactly (3 of 4) and holds no review exception for legitimate entries
        ew = s.ew  # type: ignore[attr-defined]
        assert ew.rows("SELECT uses FROM invitations WHERE id = %s", (s.pass_multi.id,)) == [(3,)]
        assert [r[0] for r in ew.exceptions() if r[0] not in {"clock_implausible"}] == []
        assert ew.rows("SELECT count(*) FROM edge_quarantine") == [(0,)]


def test_a_gate_without_its_gateway_never_allows_on_timeout_or_unknown_state(scene: Scene) -> None:
    s = scene
    s.sync()
    term = s.terminal(s.gate_a, s.term_a)
    s.gw.stop()
    from dwaar_edge.decision import UnknownCredential

    d = term.evaluate(UnknownCredential(), s.lane_a_in)
    assert d.outcome is Outcome.NEEDS_GUARD and d.to_json()["auto_allow_on_timeout"] is False
    s.t.advance(3600 * 5)  # waiting does not change the answer
    assert term.evaluate(UnknownCredential(), s.lane_a_in).outcome is Outcome.NEEDS_GUARD
    assert term.evaluate(UnknownCredential(), s.lane_a_out).reason_code == "egress_always_permitted"
