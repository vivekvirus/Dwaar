"""AT-07 (M1): the gateway fails while the LAN is partitioned.

PRD 16: "Restricted terminal mode; correct single-use limits." EDGE-06: terminals run restricted standalone for at least
24 hours using signed cached entitlements only. PRD 9.3: LAN split -> gate-bound passes only; multi-use quota only through
per-gate escrow; EDGE-10: a returning stale device processes tombstones before uploading cached personal records.

EDGE-LEVEL: the terminal logic (``StandaloneTerminal``) is the same pure engine in ``RESTRICTED_STANDALONE`` mode with a local
ledger; the Android UI is a later slice. Time is injected; the gateway process is really stopped and restarted on the same
SQLite file; the cloud is FakeCloud. Simulation, not field evidence.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from dwaar_edge.decision import OperatingMode, Outcome, ResidentCredential
from dwaar_edge.errors import PolicyRejected, TombstonesRequired
from tests.acceptance._edge_world import DATASET, EdgeScene

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-07", dataset=DATASET),
    pytest.mark.req("EDGE-06", "EDGE-10", "GATE-06", "INV-03", "INV-07"),
]


def test_restricted_mode_correct_single_use_limits_then_reconcile(tmp_path: Path) -> None:
    s = EdgeScene(tmp_path)
    w = s.w
    try:
        s.publish(1)
        s.sync()
        s.t.advance(60)
        s.gw.allocate_escrow(
            s.inv_multi, {w.gate_a: 2, w.gate_b: 1}
        )  # owner enabled per-gate escrow (4 uses in total)
        term_a, term_b = s.terminal(w.gate_a, w.term_a), s.terminal(w.gate_b, w.term_b)
        assert {term_a.mode, term_b.mode} == {OperatingMode.RESTRICTED_STANDALONE}
        assert term_a.escrow == {s.inv_multi: 2} and term_b.escrow == {s.inv_multi: 1}

        s.gw.stop()  # ---- the gateway fails; the two gates cannot see each other ---------------------------------------------
        s.t.advance(1800)

        # signed cached entitlements only: a tampered cache is refused by the terminal itself
        bad = copy.deepcopy(term_a.bundle.raw)  # type: ignore[union-attr]
        bad["manifest"]["residents"][0]["status"] = "active"
        bad["manifest"]["timing"]["guest_offline_max_s"] = 99_999
        with pytest.raises(PolicyRejected):
            term_a.load_cache({"policy": bad, "escrow": {}})

        # resident flows keep working from the cache at both gates
        for term, lane in ((term_a, w.lane_a_in), (term_b, w.lane_b_in)):
            d = term.evaluate(ResidentCredential("cred-r1", 1), lane)
            assert d.outcome is Outcome.ALLOW
            term.record_entry(d, ResidentCredential("cred-r1", 1), lane)

        # gate-bound single-use pass (gate A): once at A, replay at A rejected, other gate is a supervised path
        g_a = s.guest(s.inv_a)
        d = term_a.evaluate(g_a, w.lane_a_in)
        assert d.outcome is Outcome.ALLOW
        term_a.record_entry(d, g_a, w.lane_a_in, alias="InvitedAlias")
        assert term_a.evaluate(g_a, w.lane_a_in).reason_code == "pass_replay_consumed"
        assert term_b.evaluate(g_a, w.lane_b_in).outcome is Outcome.NEEDS_SUPERVISOR

        # unbound single-use pass: neither isolated gate may claim a global guarantee
        g_any = s.guest(s.inv_any)
        assert term_a.evaluate(g_any, w.lane_a_in).reason_code == "global_single_use_not_guaranteed"
        assert term_b.evaluate(g_any, w.lane_b_in).reason_code == "global_single_use_not_guaranteed"

        # multi-use pass: each gate consumes ONLY its own pre-allocated quota (A: 2, B: 1; 3 of 4 total)
        g_multi = s.guest(s.inv_multi)
        used = {"a": 0, "b": 0}
        for key, term, lane in (("a", term_a, w.lane_a_in), ("b", term_b, w.lane_b_in)):
            while True:
                dm = term.evaluate(g_multi, lane)
                if dm.outcome is not Outcome.ALLOW:
                    assert dm.outcome is Outcome.DENY and dm.reason_code == "pass_quota_exhausted"
                    break
                term.record_entry(dm, g_multi, lane)
                used[key] += 1
        assert used == {"a": 2, "b": 1}

        # at least 24 hours standalone: residents still verified from the signed cache (policy age 24 h < 72 h)
        s.t.advance(24 * 3600)
        d24 = term_a.evaluate(ResidentCredential("cred-r1", 1), w.lane_a_in)
        assert d24.outcome is Outcome.ALLOW
        late_guest = term_a.evaluate(s.guest(s.inv_multi), w.lane_a_in)
        assert (
            late_guest.outcome is not Outcome.ALLOW
        )  # past the 2 h guest entitlement / pass window: confirmation needed

        # ---- the gateway comes back; the cloud revoked the pass while the terminals were away -------------------------------
        s.restart()
        s.publish(2, revocations=[{"ref": str(s.inv_a), "version": 1}], valid_for_hours=200)
        assert s.sync().policy == "applied"
        ta, tb = s.actor(w.term_a), s.actor(w.term_b)
        stale_seq = term_a.bundle.seq  # type: ignore[union-attr]
        with pytest.raises(TombstonesRequired):  # EDGE-10: tombstones first
            s.gw.reconcile_standalone(
                ta, terminal_policy_seq=stale_seq, observations=term_a.observations
            )
        tomb = s.gw.tombstones_since(stale_seq)
        assert tomb["tombstones"] == [{"ref": str(s.inv_a), "version": 1}]
        s.gw.ack_tombstones(ta, tomb["current_seq"])
        s.gw.ack_tombstones(tb, tomb["current_seq"])
        obs_a, obs_b = term_a.drain(), term_b.drain()
        out = s.gw.reconcile_standalone(ta, terminal_policy_seq=stale_seq, observations=obs_a)
        assert [r["status"] for r in out["results"]].count("accepted") == len(obs_a)
        assert (
            s.gw.reconcile_standalone(ta, terminal_policy_seq=stale_seq, observations=obs_a)[
                "results"
            ][0]["status"]
            == "duplicate"
        )  # idempotent re-upload
        s.gw.reconcile_standalone(tb, terminal_policy_seq=stale_seq, observations=obs_b)
        # the personal alias of the tombstoned pass was never uploaded (data minimisation)
        alias_rows = s.gw.store.all(
            "SELECT alias_enc FROM movements WHERE invitation_id=?", (str(s.inv_a),)
        )
        assert len(alias_rows) == 1 and alias_rows[0]["alias_enc"] is None

        # the escrow accounting is consistent after reconcile: 3 multi-use entries are in the gateway ledger
        n = s.gw.store.one(
            "SELECT COUNT(*) AS n FROM pass_uses WHERE invitation_id=? AND state='consumed'",
            (str(s.inv_multi),),
        )["n"]
        assert n == 3
        s.sync()
        total_obs = len(obs_a) + len(obs_b)
        entries = [e for e in s.cloud.events.values() if e["payload"].get("restricted_standalone")]
        assert len(entries) == total_obs and len({e["event_id"] for e in entries}) == total_obs
        assert not [
            e for e in s.cloud.events.values() if e["payload"].get("conflict")
        ]  # no double use happened
        assert s.gw.outbox.stats()["pending"] == 0
    finally:
        s.close()


def test_a_gate_without_its_gateway_never_allows_on_timeout_or_unknown_state(
    tmp_path: Path,
) -> None:
    s = EdgeScene(tmp_path)
    w = s.w
    try:
        s.publish(1)
        s.sync()
        term = s.terminal(w.gate_a, w.term_a)
        s.gw.stop()
        from dwaar_edge.decision import UnknownCredential

        d = term.evaluate(UnknownCredential(), w.lane_a_in)
        assert d.outcome is Outcome.NEEDS_GUARD and d.to_json()["auto_allow_on_timeout"] is False
        s.t.advance(3600 * 5)  # waiting does not change the answer
        assert term.evaluate(UnknownCredential(), w.lane_a_in).outcome is Outcome.NEEDS_GUARD
        # essential egress works regardless
        assert (
            term.evaluate(UnknownCredential(), w.lane_a_out).reason_code
            == "egress_always_permitted"
        )
    finally:
        s.close()
