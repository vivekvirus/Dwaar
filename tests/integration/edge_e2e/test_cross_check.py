"""Cross-checks between the real gateway and the real cloud (SIMULATION: loopback, ephemeral PostgreSQL, virtual clock).

REQ: EDGE-03 (exactly-once recording), EDGE-04 (signed policy; rollback and tampering rejected), EDGE-05 (stale policy, clock), EDGE-07,
EDGE-10 (revocations propagate; a revoked credential is denied after the next sync), INV-03, INV-07.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import copy
import json
import uuid
from typing import Any

import pytest

from dwaar_edge.errors import PolicyRejected
from dwaar_edge.sync import TransportResponse
from tests.integration.edge._support import EdgeWorld
from tests.integration.edge_e2e._cloud import Site
from tests.integration.edge_e2e._flows import enter, evaluate, leave, statuses

pytestmark = [
    pytest.mark.req("EDGE-03", "EDGE-04", "EDGE-05", "EDGE-07", "EDGE-10", "INV-03", "INV-07"),
    pytest.mark.simulation,
]

UNIT = "A-101"


@pytest.fixture
def household(ew: EdgeWorld) -> Any:
    return ew.household(UNIT, tenant=True, family=False)


def unit_id(ew: EdgeWorld) -> uuid.UUID:
    return ew.soc.units[UNIT]


class PolicyInterceptor:
    """A hostile or buggy path between gateway and cloud: answers GET /v1/edge/policy with a chosen body, passes everything else through."""

    def __init__(self, inner: Any) -> None:
        self.inner, self.serve = inner, None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def request(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        real = self.inner.request(method, target, headers, body)
        if self.serve is not None and method == "GET" and target.startswith("/v1/edge/policy"):
            return TransportResponse(200, self.serve, real.server_time, real.elapsed_ms)
        return real


# ------------------------------------------------------------------------------------------ exactly once
def test_events_observed_at_the_edge_appear_exactly_once_in_the_cloud_after_outage_restarts_and_duplicate_resend(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    p = site.make_pass(household.owner, unit_id(ew), max_uses=100)
    site.sync()
    cred = site.resident_cred(unit_id(ew))
    guard = site.actor()
    made: list[str] = []

    def burst(n: int, *, passes: bool) -> None:
        # guests are automatic only with a trusted clock: right after a restart without contact they need a supervisor (EDGE-05)
        for _ in range(n):
            e = enter(site, cred, actor=guard)
            site.advance(30)
            leave(site, e["movement_id"], actor=guard)
            made.append(e["event_id"])
            if passes:
                g = enter(site, {"kind": "qr", "text": p["qr"]}, actor=guard)
                made.append(g["event_id"])
            site.advance(30)

    burst(4, passes=True)
    site.wan.online = False  # outage 1
    burst(4, passes=True)
    assert site.sync().failed
    site.restart()  # a restart during the outage
    guard = site.actor()
    burst(3, passes=False)
    site.wan.online = True
    site.wan.lose_response_once = (
        True  # the cloud commits the batch, the answer is lost: the gateway MUST resend
    )
    first = site.sync()
    assert first.failed and "response lost" in first.failed
    assert site.gw.outbox.stats()["pending"] > 0  # not acknowledged, so still held
    site.restart()  # and a restart before the resend
    guard = site.actor()
    burst(2, passes=False)
    # a hostile or buggy duplicate: the very same batch body posted again by hand
    wires = [r.wire for r in site.gw.outbox.pending_batch()]
    pending_wire = (
        wires[:5] + wires[-2:]
    )  # five the cloud already committed (response lost) and two it has never seen
    raw_body = json.dumps(
        {"device_id": str(site.device.device_id), "events": pending_wire}, separators=(",", ":")
    ).encode()
    again = site.device.sync_raw(raw_body)
    assert again.status_code == 200 and {o["status"] for o in again.json()["outcomes"]} == {
        "accepted",
        "duplicate",
    }
    resend = site.sync()
    assert resend.failed is None and site.gw.outbox.stats()["pending"] == 0
    dup = site.device.sync_raw(raw_body)  # after everything: pure duplicates, nothing new
    assert dup.status_code == 200 and {o["status"] for o in dup.json()["outcomes"]} == {"duplicate"}

    local = site.gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
    ledger = [str(r[0]) for r in site.cloud_events()]
    accessed = [str(r[0]) for r in site.access_events()]
    assert len(set(ledger)) == len(ledger) and len(set(accessed)) == len(
        accessed
    )  # no event twice, in either table
    assert set(accessed) == set(ledger)  # every observation became one access_event
    assert set(made) <= set(ledger)  # every event the edge created is in the cloud
    assert site.gw.outbox.stats()["last_seq"] == len(ledger)  # and nothing the edge never made
    assert [int(r[1]) for r in site.cloud_events()] == list(range(1, len(ledger) + 1))
    assert len(local) <= len(ledger)  # acknowledged rows are pruned locally
    # the pass use was counted once per observed entry, not once per delivery
    entries_of_pass = len(
        [1 for r in site.access_events() if r[4] == "qr" and r[2] == "EntryObserved"]
    )
    assert ew.rows("SELECT uses FROM invitations") == [(entries_of_pass,)]
    assert ew.rows("SELECT count(*) FROM visits WHERE state IN ('inside','exited')") == [
        (entries_of_pass,)
    ]
    assert ew.rows("SELECT count(*) FROM edge_quarantine") == [(0,)]


# ------------------------------------------------------------------------------------------ revocation
def test_revocation_in_the_cloud_reaches_the_edge_and_an_offline_cached_resident_is_denied_after_sync(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    p = site.make_pass(household.owner, unit_id(ew), max_uses=3)
    site.sync()
    guard = site.actor()
    site.wan.online = False  # the gateway is cut off
    # in the cloud: the tenant's membership ends and the host revokes the pass
    ended = ew.rows("SELECT id FROM memberships WHERE person_id = %s", (household.tenant.id,))
    assert len(ended) == 1
    ew.sql(
        "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
        (household.tenant.id,),
    )
    version = site.revoke_pass(household.owner, p["id"])
    # still offline: the cached policy is all the gateway knows, and it keeps serving it (cached flows work)
    from dwaar_api.modules.edge.snapshot import person_ref

    ref_key = ew.app.state.edge_config.ref_key
    tenant_pref = person_ref(ref_key, ew.soc.id, household.tenant.id)
    refs = {r.credential_ref: r for r in site.gw.policy.residents.values()}  # type: ignore[union-attr]
    victim_ref = next(r for r, v in refs.items() if v.person_ref == tenant_pref)
    stays = {
        "kind": "resident",
        "credential_ref": next(r for r in refs if r != victim_ref),
        "revocation_version": 0,
    }
    victim = {
        "kind": "resident",
        "credential_ref": victim_ref,
        "revocation_version": refs[victim_ref].revocation_version,
    }
    assert evaluate(site, victim, actor=guard)["decision"]["outcome"] == "allow"
    assert (
        evaluate(site, {"kind": "qr", "text": p["qr"]}, actor=guard)["decision"]["outcome"]
        == "allow"
    )
    site.wan.online = True
    res = (
        site.sync()
    )  # policy first (EDGE-10): the revocations arrive before anything else is uploaded
    assert res.policy == "applied" and res.failed is None
    d = evaluate(site, victim, actor=guard)["decision"]
    assert d["outcome"] == "deny" and "revoked" in d["reason_code"]
    q = evaluate(site, {"kind": "qr", "text": p["qr"]}, actor=guard)["decision"]
    assert q["outcome"] == "deny" and "revoked" in q["reason_code"]
    assert (
        evaluate(site, stays, actor=guard)["decision"]["outcome"] == "allow"
    )  # the rest of the household is untouched
    known = dict(site.gw.policy.revocations)  # type: ignore[union-attr]
    assert known[victim_ref] > 0 and known[p["id"]] == version


# ------------------------------------------------------------------------------------------ rollback and tampering
def test_a_policy_rollback_attempt_is_rejected_by_the_gateway_and_by_the_cloud_cursor(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    first = site.device.policy(0).json()  # a legitimately signed snapshot, seq 1
    site.make_pass(household.owner, unit_id(ew))
    assert site.sync().policy == "applied"
    now_seq = site.gw.policy_seq()
    assert now_seq > first["seq"]
    with pytest.raises(PolicyRejected) as exc:
        site.gw.apply_policy(first)  # replayed by hand
    assert exc.value.code == "rollback"
    mitm = PolicyInterceptor(site.wan)
    site.client.transport = mitm  # type: ignore[assignment]
    mitm.serve = first  # served by a broken or hostile path in answer to a poll
    res = site.sync()
    assert res.policy == "rejected:rollback" and site.gw.policy_seq() == now_seq
    mitm.serve = None
    # and the cloud itself never answers 200 to a device that claims to be at least as new as its latest
    assert site.device.policy(now_seq).status_code == 204
    assert site.device.policy(now_seq + 5).status_code == 409


def test_a_tampered_snapshot_is_rejected_whatever_is_edited_and_the_old_policy_keeps_serving(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    good = site.device.policy(0).json()
    site.make_pass(household.owner, unit_id(ew))
    fresh = site.device.policy(1).json()
    edits: dict[str, Any] = {}
    t = copy.deepcopy(fresh)
    t["manifest"]["residents"][0]["status"] = (
        "revoked" if t["manifest"]["residents"][0]["status"] != "revoked" else "active"
    )
    edits["resident status"] = t
    t = copy.deepcopy(fresh)
    t["manifest"]["invitations"][0]["max_uses"] = 99
    edits["pass max_uses"] = t
    t = copy.deepcopy(fresh)
    t["manifest"]["timing"]["guest_offline_max_s"] = 10**6
    edits["timing"] = t
    t = copy.deepcopy(fresh)
    t["valid_until"] = "2099-01-01T00:00:00.000Z"
    edits["valid_until"] = t
    t = copy.deepcopy(fresh)
    t["signature"] = good["signature"]
    edits["another snapshot's signature"] = t
    t = copy.deepcopy(fresh)
    t["manifest"]["residents"][0]["phone"] = "+919999900001"
    edits["personal data smuggled in"] = t
    mitm = PolicyInterceptor(site.wan)
    site.client.transport = mitm  # type: ignore[assignment]
    seq_before = site.gw.policy_seq()
    for label, doc in edits.items():
        mitm.serve = doc
        r = site.sync()
        assert r.policy.startswith("rejected:"), label
        assert site.gw.policy_seq() == seq_before, label
    mitm.serve = None
    assert site.sync().policy == "applied"  # the genuine one still applies afterwards
    cred = site.resident_cred(unit_id(ew))
    assert evaluate(site, cred)["decision"]["outcome"] == "allow"


# ------------------------------------------------------------------------------------------ stale policy and clock
def test_a_policy_older_than_72_hours_forces_guard_assisted_verification_and_a_sync_restores_automatic(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    guard = site.actor()
    cred = site.resident_cred(unit_id(ew))
    site.wan.online = False
    site.advance(71 * 3600)
    assert evaluate(site, cred, actor=guard)["decision"]["outcome"] == "allow"
    site.advance(2 * 3600)  # 73 h since the last contact
    d = evaluate(site, cred, actor=guard)["decision"]
    assert (
        d["outcome"] == "needs_guard"
        and d["reason_code"] in {"policy_stale_resident", "policy_expired"}
        and d["auto_allow_on_timeout"] is False
    )
    assert (
        evaluate(site, {"kind": "none"}, lane=site.lane_a_out, actor=guard)["decision"][
            "reason_code"
        ]
        == "egress_always_permitted"
    )
    site.wan.online = True
    assert site.sync().policy == "applied"  # the cloud issues a fresh snapshot on the poll
    assert evaluate(site, cred, actor=guard)["decision"]["outcome"] == "allow"


def test_a_clock_moved_backwards_disables_time_sensitive_automatic_approvals_until_a_trusted_sync(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    p = site.make_pass(household.owner, unit_id(ew), max_uses=5)
    ew.call(
        household.owner,
        "POST",
        ew.s("standing-rules"),
        json={
            "unit_id": str(unit_id(ew)),
            "rule_kind": "allow_window",
            "visit_kind": "vendor",
            "category": "milk",
            "start_local": "00:00",
            "end_local": "23:59",
        },
    )
    site.sync()
    site.advance(300)
    guard = site.actor()
    guest = {"kind": "qr", "text": p["qr"]}
    milk = {
        "kind": "standing",
        "unit_id": str(unit_id(ew)),
        "category": "milk",
        "visit_kind": "vendor",
    }
    assert evaluate(site, guest, actor=guard)["decision"]["outcome"] == "allow"
    site.advance(130)
    assert evaluate(site, milk, actor=guard)["decision"]["outcome"] == "allow"
    site.t.step_wall(-2 * 3600)
    for cred in (guest, milk):
        d = evaluate(site, cred, actor=guard)["decision"]
        assert (
            d["outcome"] == "needs_supervisor"
            and d["reason_code"] == "clock_jumped_backwards"
            and d["auto_allow_on_timeout"] is False
        )
    res = evaluate(site, site.resident_cred(unit_id(ew)), actor=guard)
    assert (
        res["decision"]["outcome"] == "allow" and res["decision"]["review_required"] is True
    )  # never a lockout from home
    site.t.step_wall(
        2 * 3600
    )  # the operator fixes the wall clock, the cloud's authenticated time confirms it
    assert site.sync().failed is None
    assert evaluate(site, guest, actor=guard)["decision"]["outcome"] == "allow"
    assert statuses(site) == [] or all(st == "accepted" for _, _, st, _ in statuses(site))
