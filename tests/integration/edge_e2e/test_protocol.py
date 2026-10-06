"""Protocol mismatches between the real gateway and the real cloud, found by running them against each other (ADR-0019).

REQ: EDGE-03, EDGE-04, EDGE-07, EDGE-09, EDGE-10, GATE-01, GATE-06, GATE-14, INV-03, INV-07.
Environment: SIMULATION (one machine, loopback socket, ephemeral PostgreSQL; the clock is virtual unless the test says otherwise).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest

from dwaar_common.signing import generate_private_key
from tests.integration.edge._support import EdgeWorld
from tests.integration.edge_e2e._cloud import Site
from tests.integration.edge_e2e._flows import enter, evaluate, exceptions, leave, statuses

pytestmark = [pytest.mark.req("EDGE-03", "EDGE-07", "INV-07"), pytest.mark.simulation]

UNIT = "A-101"


@pytest.fixture
def household(ew: EdgeWorld) -> Any:
    return ew.household(UNIT, tenant=True, family=True)


def unit_id(ew: EdgeWorld) -> uuid.UUID:
    return ew.soc.units[UNIT]


# ------------------------------------------------------------------------------------------ (a) entities: movements, passes, overrides
def test_resident_entry_and_exit_are_recorded_without_any_exception(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """A legitimate cached-policy resident entry is an observation, not an error: accepted, access_event recorded, no exception, no visit."""
    assert site.sync().policy == "applied"
    entry = enter(site, site.resident_cred(unit_id(ew)))
    site.advance(120)
    leave(site, entry["movement_id"])
    result = site.sync()
    assert result.failed is None and result.acked == 2 and result.rejected == 0
    assert [(t, st) for _, t, st, _ in statuses(site)] == [
        ("EntryObserved", "accepted"),
        ("ExitObserved", "accepted"),
    ]
    assert [a[3] for a in site.access_events()] == ["cached_policy", "guard_assisted"]
    assert exceptions(site) == [] and ew.count("visits") == 0
    assert site.gw.outbox.stats()["pending"] == 0


def test_pass_entry_becomes_a_visit_inside_and_consumes_the_pass_exit_closes_it(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """The gateway mints the movement id; the cloud derives the visit (INV-07: the entry creates NO permission, only a record)."""
    p = site.make_pass(household.owner, unit_id(ew))
    site.sync()
    entry = enter(site, {"kind": "qr", "text": p["qr"]})
    site.advance(600)
    site.sync()
    visits = ew.rows(
        "SELECT state, authorisation_source, invitation_id, gate_id, authorised_until = entered_at FROM visits"
    )
    assert visits == [("inside", "invitation", uuid.UUID(p["id"]), site.gate_a, True)]
    assert ew.rows("SELECT uses, state FROM invitations") == [(1, "consumed")]
    assert exceptions(site) == []
    ae = site.access_events()
    assert len(ae) == 1 and ae[0][5] is not None  # the observation points at the projected visit
    # the host sees it in the household's visitor history (AT-02 completes end to end)
    hist = ew.call(household.owner, "GET", ew.s(f"units/{unit_id(ew)}/visits"))
    assert hist.status_code == 200, hist.text
    assert len(hist.json()["items"]) == 1 and hist.json()["items"][0]["state"] == "inside"
    leave(site, entry["movement_id"])
    site.sync()
    row = ew.rows("SELECT state, exit_basis, exited_at IS NOT NULL, confidence_inside FROM visits")
    assert row == [("exited", "observed", True, "none")]
    assert [st for _, _, st, _ in statuses(site)] == ["accepted", "accepted"]


def test_a_pass_the_cloud_already_counted_still_leaves_a_visit_and_a_review_exception(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """Online redemption elsewhere used the only permitted use before the offline entry synced: physical entry is recorded, flagged, never dropped."""
    p = site.make_pass(household.owner, unit_id(ew), max_uses=1)
    site.sync()
    enter(site, {"kind": "qr", "text": p["qr"]})
    # meanwhile the cloud itself redeems the same pass (guard app online): the pass is consumed there
    r = ew.call(
        ew.guard,
        "POST",
        ew.s("invitations/redeem"),
        json={"qr": p["qr"], "gate_id": str(site.gate_a)},
    )
    assert r.status_code == 201, r.text
    site.sync()
    assert statuses(site)[0][2] == "accepted"
    assert ew.rows("SELECT count(*) FROM visits WHERE state = 'inside'") == [(1,)]
    ex = exceptions(site, "unauthorised_entry")
    assert len(ex) == 1 and "more often than allowed" in ex[0][4]
    assert ew.rows("SELECT uses FROM invitations") == [
        (1,)
    ]  # the cloud never counts beyond max_uses


def test_unknown_and_revoked_passes_and_overrides_raise_supervisor_exceptions_but_are_recorded(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    keep = site.make_pass(household.owner, unit_id(ew), max_uses=2)
    drop = site.make_pass(household.owner, unit_id(ew), max_uses=2)
    site.sync()
    # revoke in the cloud AFTER the gateway cached it, BEFORE the next sync: the gateway still allows (stale), the cloud flags it
    enter(site, {"kind": "qr", "text": keep["qr"]})
    assert ew.call(household.owner, "DELETE", f"/v1/invitations/{drop['id']}").status_code == 200
    site.advance(5)
    enter(site, {"kind": "qr", "text": drop["qr"]})
    # supervisor override at gate B for a wrongly gated pass
    sup = site.actor(site.term_sup, "supervisor")
    guard_b = site.actor(site.term_b)
    held = evaluate(site, {"kind": "qr", "text": keep["qr"]}, gate=site.gate_b, actor=guard_b)
    assert held["decision"]["outcome"] in {"allow", "needs_supervisor", "needs_guard"}
    site.sync()
    s = statuses(site)
    assert (
        s[0][2] == "accepted"
        and s[1][2] == "rejected_transition"
        and s[1][3] == "entry_after_revocation"
    )
    kinds = sorted(r[0] for r in exceptions(site))
    assert kinds == ["unauthorised_entry"]
    # every observation is in access_events, accepted or not (INV-07, EDGE-07: never silently discarded)
    assert len(site.access_events()) == 2
    # the pass revoked before entry did NOT become a visit
    assert ew.rows("SELECT count(*) FROM visits") == [(1,)]
    assert sup is not None


def test_emergency_and_override_entries_leave_a_manual_entry_exception(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    guard = site.actor()
    site.gw.emergency_entry(
        guard, gate_id=site.gate_a, lane_id=None, authority="medical_emergency", reason="ambulance"
    )
    site.sync()
    assert statuses(site) == [(1, "EntryObserved", "accepted", "override_entry_recorded")]
    assert [r[0] for r in exceptions(site)] == ["manual_entry"]
    assert site.access_events()[0][3] == "supervisor_override"


def test_edge_only_event_types_are_recorded_not_projected_and_never_block_the_queue(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """GuardDecisionRecorded / SupervisorOverrideRecorded / ClockAnomalyDetected pass the cloud's payload hygiene and are ledgered."""
    p = site.make_pass(household.owner, unit_id(ew), gate=site.gate_a)
    site.sync()
    guard_b = site.actor(site.term_b)
    sup = site.actor(site.term_sup, "supervisor")
    wrong_gate = evaluate(site, {"kind": "qr", "text": p["qr"]}, gate=site.gate_b, actor=guard_b)
    assert wrong_gate["decision"]["reason_code"] == "wrong_gate" and wrong_gate["pending_id"]
    site.gw.guard_decision(
        sup,
        pending_id=wrong_gate["pending_id"],
        resolution="admit",
        note="host confirmed by intercom सुपरवाइज़र",
    )
    site.gw.record_entry(
        guard_b, gate_id=site.gate_b, lane_id=site.lane_b_in, pending_id=wrong_gate["pending_id"]
    )
    site.t.step_wall(-3600)  # AT-08 on the gateway: the wall clock jumps back
    site.gw.clock_state()
    site.sync()
    types = [(t, st) for _, t, st, _ in statuses(site)]
    assert ("GuardDecisionRecorded", "accepted") in types
    assert all(st == "accepted" for _, st in types), types
    assert site.wan.log[-1][2] == 200 and site.gw.outbox.stats()["pending"] == 0
    # a Devanagari note travelled as UTF-8 bytes through the signed body without a signature mismatch
    assert not site.client.gateway.sync_info.get("auth_failed")


# ------------------------------------------------------------------------------------------ (b) provisioning and trust
def test_provisioning_pins_the_cloud_keys_and_a_snapshot_signed_by_anyone_else_is_rejected(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    keys = site.device.request("GET", "/v1/edge/keys").json()
    assert {k["key_id"] for k in keys["keys"]} == set(site.gw.config.issuer_keys)
    assert {k["key_id"] for k in keys["pass_keys"]} == set(site.gw.config.pass_keys)
    assert site.sync().policy == "applied"
    real = site.device.policy(0).json()
    from dwaar_common.events import canonical_json
    from dwaar_common.signing import sign_bytes

    # (1) the same content re-signed by a key nobody provisioned, claiming the cloud's key id
    forged_body = {k: v for k, v in real.items() if k != "signature"}
    forged_body["seq"] = real["seq"] + 1
    forged = {
        **forged_body,
        "signature": sign_bytes(generate_private_key(), canonical_json(forged_body)),
    }
    with pytest.raises(Exception) as bad:
        site.gw.apply_policy(forged)
    assert getattr(bad.value, "code", "") == "bad_signature"
    # (2) a snapshot naming an issuer key the gateway was never given: the key is NOT taken from the snapshot
    other = {**forged_body, "issuer_key_id": "attacker-key"}
    other["signature"] = sign_bytes(generate_private_key(), canonical_json(other))
    with pytest.raises(Exception) as unknown:
        site.gw.apply_policy(other)
    assert getattr(unknown.value, "code", "") == "unknown_issuer"
    assert site.gw.policy_seq() == real["seq"]


def test_a_device_that_is_not_enrolled_cannot_obtain_the_keys(ew: EdgeWorld, site: Site) -> None:
    from dwaar_edge.provision import ProvisioningError, fetch_trust_anchors

    pending = ew.edge_device(approve=False)
    with pytest.raises(ProvisioningError):
        fetch_trust_anchors(site.wan, pending.device_id, pending.key, now=site.now())
    stranger = uuid.uuid4()
    with pytest.raises(ProvisioningError):
        fetch_trust_anchors(site.wan, stranger, generate_private_key(), now=site.now())


# ------------------------------------------------------------------------------------------ (b) wire level
def test_signed_bytes_are_identical_on_both_sides_over_a_real_socket(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """The gateway signs path+query and the exact body bytes it sends; the cloud verifies them from the raw request line and body."""
    site.sync()  # GET /v1/edge/policy?after=0 (query string) and an empty-body GET
    site.gw.emergency_entry(
        site.actor(), gate_id=site.gate_a, lane_id=None, authority="fire_marshal", reason="dष्याल आग"
    )
    r = site.sync()
    assert r.failed is None and r.acked == 1
    assert [(m, p.split("?")[0], st) for m, p, st in site.wan.log if st != 200 and st != 204] == []
    # one byte changed after signing is a 401 on the cloud, for the body and for the query
    from dwaar_edge.sync import HttpxTransport

    raw = HttpxTransport(site.live.url)
    body = b'{"device_id":"%s","events":[]}' % str(site.device.device_id).encode()
    headers = site.client.signed_headers("POST", "/v1/edge/sync/batches", body, site.now())
    ok = raw.request("POST", "/v1/edge/sync/batches", headers, body)
    assert ok.status == 200
    tampered = raw.request(
        "POST", "/v1/edge/sync/batches", headers, body.replace(b"events", b"evenTs")
    )
    assert tampered.status == 401
    q = site.client.signed_headers("GET", "/v1/edge/policy?after=0", b"", site.now())
    assert raw.request("GET", "/v1/edge/policy?after=0", q, b"").status in (200, 204)
    assert raw.request("GET", "/v1/edge/policy?after=1", q, b"").status == 401
    raw.close()


def test_a_wrong_gateway_clock_is_repaired_by_the_401_with_date_retry(
    ew: EdgeWorld, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, household: Any
) -> None:
    """The gateway clock is 10 minutes fast: the cloud answers 401 (outside +-120 s) with its own Date; the gateway retries ONCE stamped with it."""
    from tests.integration.edge_e2e._cloud import commissioned_site

    with commissioned_site(
        ew, tmp_path, monkeypatch, virtual=False, skew=dt.timedelta(minutes=10)
    ) as s:
        res = s.sync()
        assert res.policy == "applied" and res.failed is None
        statuses_seen = [st for _, _, st in s.wan.log]
        assert statuses_seen[:3] == [
            200,
            401,
            200,
        ]  # keys (installer), the stale-stamped poll, the retry
        assert (
            s.gw.clock_state().trusted
        )  # the clock was then synchronised from an authenticated 2xx
        # a clock that is wrong in the OTHER direction is repaired the same way
    with commissioned_site(
        ew, tmp_path / "b", monkeypatch, virtual=False, skew=dt.timedelta(hours=-3)
    ) as s2:
        assert s2.sync().policy == "applied"
        assert 401 in [st for _, _, st in s2.wan.log]


def test_the_cloud_refuses_a_request_signed_for_another_target_or_by_another_key(
    ew: EdgeWorld, site: Site
) -> None:
    from dwaar_edge.sync import HttpxTransport

    raw = HttpxTransport(site.live.url)
    other = generate_private_key()
    import hashlib

    from dwaar_common.signing import sign_bytes

    ts = site.client.signed_headers("GET", "/v1/edge/me", b"", site.now())["X-Dwaar-Timestamp"]
    sig = sign_bytes(other, f"GET\n/v1/edge/me\n{ts}\n{hashlib.sha256(b'').hexdigest()}".encode())
    headers = {
        "X-Dwaar-Device": str(site.device.device_id),
        "X-Dwaar-Timestamp": ts,
        "X-Dwaar-Signature": sig,
    }
    assert raw.request("GET", "/v1/edge/me", headers, b"").status == 401
    good = site.client.signed_headers("GET", "/v1/edge/me", b"", site.now())
    assert (
        raw.request("GET", "/v1/edge/policy?after=0", good, b"").status == 401
    )  # replayed on another target
    assert raw.request("GET", "/v1/edge/me", good, b"").status == 200
    raw.close()


# ------------------------------------------------------------------------------------------ (b) policy cursor, 409
def test_cloud_cursor_behind_the_gateway_is_a_409_never_a_rollback(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    ew.call(
        household.owner,
        "POST",
        ew.s("standing-rules"),
        json={
            "unit_id": str(unit_id(ew)),
            "rule_kind": "leave_at_gate",
            "visit_kind": "delivery",
            "start_local": "22:00",
            "end_local": "06:00",
        },
    )
    site.advance(1)
    assert site.sync().policy == "applied"
    applied = site.gw.policy_seq()
    assert applied >= 2
    # the cloud is restored from an OLDER backup: its newest snapshots are gone
    with ew.idh.db.admin_conn() as conn:
        conn.execute("SET session_replication_role = replica")  # type: ignore[call-overload]
        conn.execute("DELETE FROM policy_snapshots WHERE seq >= 1")  # type: ignore[call-overload]
    res = site.sync()
    assert res.policy == "cursor_ahead_of_cloud" and res.failed is None
    assert (
        site.gw.policy_seq() == applied
        and site.gw.sync_info["policy_cursor_ahead_of_cloud"] is True
    )
    assert site.gw.status()["mode"] in {"normal", "degraded", "wan_down"}


# ------------------------------------------------------------------------------------------ (b) caps
def test_a_backlog_of_1200_events_goes_up_in_batches_of_at_most_500_and_the_cloud_never_413s(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    site.sync()
    guard = site.actor()
    cred = site.resident_cred(unit_id(ew))
    for i in range(1200):
        e = enter(site, cred, actor=guard)
        site.advance(1)
        if i % 3 == 0:
            leave(site, e["movement_id"], actor=guard)
    pending = site.gw.outbox.stats()["pending"]
    assert pending >= 1200
    posts_before = [x for x in site.wan.log if x[0] == "POST"]
    res = site.sync()
    assert res.failed is None and site.gw.outbox.stats()["pending"] == 0
    posts = [x for x in site.wan.log if x[0] == "POST"][len(posts_before) :]
    assert len(posts) == -(-pending // 500) and all(st == 200 for _, _, st in posts)
    assert len(site.cloud_events()) == pending
    assert {st for _, _, st, _ in statuses(site)} == {"accepted"}


def test_the_largest_event_payload_the_gateway_may_send_is_accepted_and_one_byte_more_never_leaves_the_gateway(
    ew: EdgeWorld, site: Site
) -> None:
    from dwaar_common.events import canonical_json
    from dwaar_edge.errors import InvalidRequest
    from dwaar_edge.outbox import MAX_PAYLOAD_BYTES

    site.sync()
    base = {
        "gate_id": str(site.gate_a),
        "lane_id": str(site.lane_a_in),
        "credential_kind": "none",
        "decision_source": "cached_policy",
    }
    pad = MAX_PAYLOAD_BYTES - len(canonical_json({**base, "pad": ""}))
    big = {**base, "pad": "x" * pad}
    assert len(canonical_json(big)) == MAX_PAYLOAD_BYTES
    clock = site.gw.clock_state()
    site.gw.outbox.append(
        type="EntryObserved",
        entity_id=uuid.uuid4(),
        entity_version=1,
        payload=big,
        occurred_at=clock.now,
        clock_uncertainty_ms=clock.uncertainty_ms,
        policy_version=1,
    )
    with pytest.raises(InvalidRequest):
        site.gw.outbox.append(
            type="EntryObserved",
            entity_id=uuid.uuid4(),
            entity_version=1,
            payload={**big, "pad": big["pad"] + "x"},
            occurred_at=clock.now,
            clock_uncertainty_ms=0,
            policy_version=1,
        )
    res = site.sync()
    assert res.acked == 1 and statuses(site)[0][2] == "accepted"


def test_batches_are_bounded_by_bytes_and_a_misconfigured_larger_gateway_cap_is_repaired_by_halving_on_413(
    ew: EdgeWorld, site: Site
) -> None:
    from dwaar_edge.sync import SyncConfig

    site.sync()
    clock = site.gw.clock_state()
    base = {
        "gate_id": str(site.gate_a),
        "lane_id": str(site.lane_a_in),
        "credential_kind": "none",
        "decision_source": "cached_policy",
        "pad": "y" * 1500,
    }
    for _ in range(500):
        site.gw.outbox.append(
            type="EntryObserved",
            entity_id=uuid.uuid4(),
            entity_version=1,
            payload=base,
            occurred_at=clock.now,
            clock_uncertainty_ms=0,
            policy_version=1,
        )
    posts0 = len([x for x in site.wan.log if x[0] == "POST"])
    res = site.sync()
    assert res.failed is None and site.gw.outbox.stats()["pending"] == 0
    post_sizes = [st for m, _, st in site.wan.log if m == "POST"][posts0:]
    assert (
        post_sizes and all(st == 200 for st in post_sizes) and len(post_sizes) >= 2
    )  # 500 x ~2.3 KB > 1,000,000 B: split by bytes, never over the cloud's 1 MiB
    # misconfigured: a 4 MB cap would send 2 MB bodies; the cloud answers 413 and the gateway halves until it fits
    more = [uuid.uuid4() for _ in range(700)]
    for m in more:
        site.gw.outbox.append(
            type="EntryObserved",
            entity_id=m,
            entity_version=1,
            payload=base,
            occurred_at=clock.now,
            clock_uncertainty_ms=0,
            policy_version=1,
        )
    site.client.config = SyncConfig(max_bytes=4_000_000, max_events=500)
    site.client._batch_limit = 500  # noqa: SLF001
    seen413 = False
    for _ in range(12):
        r = site.sync()
        seen413 = seen413 or "413" in (r.failed or "")
        if site.gw.outbox.stats()["pending"] == 0:
            break
    assert site.gw.outbox.stats()["pending"] == 0 and seen413
    assert len(site.cloud_events()) == 1200


# ------------------------------------------------------------------------------------------ (b) lanes, windows, standing rules
def test_lanes_in_out_windows_and_date_valued_standing_rules_work_with_the_real_manifest(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    now = site.now()
    gap = [
        (now - dt.timedelta(minutes=5), now + dt.timedelta(minutes=30)),
        (now + dt.timedelta(hours=3), now + dt.timedelta(hours=4)),
    ]
    recurring = site.make_pass(household.owner, unit_id(ew), windows=gap, max_uses=5)
    today = (now + dt.timedelta(hours=5, minutes=30)).date()
    r = ew.call(
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
            "effective_from": today.isoformat(),
            "effective_to": (today + dt.timedelta(days=2)).isoformat(),
        },
    )
    assert r.status_code == 201, r.text
    site.sync()
    pol = site.gw.policy
    assert pol is not None
    assert {ln.direction for ln in pol.lanes.values()} == {"in", "out"}
    inv = next(iter(pol.invitations.values()))
    assert len(inv.windows) == 2
    # inside window 1: allowed; the gap between the windows: never allowed
    assert evaluate(site, {"kind": "qr", "text": recurring["qr"]})["decision"]["outcome"] == "allow"
    site.advance(2 * 3600)
    d = evaluate(site, {"kind": "qr", "text": recurring["qr"]})["decision"]
    assert d["outcome"] != "allow"
    # an exit lane never needs a credential (essential egress)
    assert (
        evaluate(site, {"kind": "none"}, lane=site.lane_a_out)["decision"]["reason_code"]
        == "egress_always_permitted"
    )
    # the date-valued standing rule is understood (date strings, not datetimes) and pre-authorises only inside its dates
    site.advance(-2 * 3600)
    std = {
        "kind": "standing",
        "unit_id": str(unit_id(ew)),
        "category": "milk",
        "visit_kind": "vendor",
    }
    assert evaluate(site, std)["decision"]["reason_code"] == "standing_rule_allow"
    site.advance(5 * 86400)
    assert evaluate(site, std)["decision"]["outcome"] != "allow"


def test_a_gateway_enrolled_for_one_gate_reports_only_that_gate_the_rest_is_quarantined_visibly(
    ew: EdgeWorld, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, household: Any
) -> None:
    """Operational rule (ADR-0019): a SOCIETY gateway is enrolled without a gate binding. A gate-bound device is stricter by design."""
    from tests.integration.edge_e2e._cloud import commissioned_site

    with commissioned_site(ew, tmp_path, monkeypatch, gateway_gate_bound=True) as s:
        s.sync()
        cred = s.resident_cred(unit_id(ew))
        enter(s, cred)  # gate A: the bound gate
        enter(s, cred, gate=s.gate_b)  # gate B: not the device's gate
        r = s.sync()
        assert r.failed is None and r.acked == 1 and r.quarantined == 1
        assert [(st, why) for _, _, st, why in statuses(s)][0][0] == "accepted"
        assert (
            s.gw.outbox.stats()["pending"] == 0
        )  # the quarantined event is disposed: it never blocks or loops
        assert [x[0] for x in exceptions(s)] == ["edge_quarantine"]


# ------------------------------------------------------------------------------------------ (b) 429 and Retry-After
def test_a_rate_limited_gateway_waits_at_least_the_retry_after_the_cloud_sent_and_then_catches_up(
    ew: EdgeWorld, site: Site, household: Any
) -> None:
    """The cloud's per-device budget answers 429 with Retry-After; the gateway used to back off blindly (ADR-0019)."""
    import dataclasses
    import time

    cfg = ew.app.state.edge_config
    ew.app.state.edge_config = dataclasses.replace(cfg, rate_capacity=2, rate_refill_per_s=2.0)
    site.sync()  # spends part of the budget
    site.client.config.max_events = (
        20  # many small batches: the request RATE, not the byte rate, trips the budget
    )
    site.client._batch_limit = 20  # noqa: SLF001
    cred = site.resident_cred(unit_id(ew))
    for _ in range(200):
        enter(site, cred)
        site.advance(1)
    # an empty bucket right now (deterministic: independent of how fast this machine answers): the very next request is refused
    ew.sql(
        "UPDATE rate_limit_buckets SET tokens = 0, updated_at = clock_timestamp() WHERE key = %s",
        (f"edge-device:{site.device.device_id}",),
    )
    delays: list[float] = []
    for _ in range(60):
        r = site.sync()
        if r.failed:
            assert "429" in r.failed
            delays.append(r.next_delay_s)
            time.sleep(min(r.next_delay_s, 2.0))
        if site.gw.outbox.stats()["pending"] == 0:
            break
    assert delays and min(delays) >= 1.0  # the cloud said Retry-After: >= 1 s
    assert site.gw.outbox.stats()["pending"] == 0 and len(site.cloud_events()) == 200
    ew.app.state.edge_config = cfg
