"""POST /v1/edge/sync/batches: the EDGE-07 conflict algorithm end to end, quarantine, idempotency, limits, concurrency.

REQ: EDGE-03, EDGE-07, EDGE-02, INV-01, INV-03, INV-07, PRD 9.3.
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_common.signing import generate_private_key
from tests.integration.edge._support import EdgeClient, EdgeWorld
from tests.integration.visits._support import UA

pytestmark = [pytest.mark.req("EDGE-03", "EDGE-07", "INV-07")]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device()


def statuses(response: Any) -> list[str]:
    assert response.status_code == 200, response.text
    return [o["status"] for o in response.json()["outcomes"]]


# ------------------------------------------------------------------------------------------ basics and durability
def test_accepted_entry_is_recorded_audited_outboxed_and_acknowledged(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    event = dev.entry(visit, payload={"decision_source": "cached_policy", "credential_kind": "qr"})
    r = dev.sync([event])
    body = r.json()
    assert r.status_code == 200
    assert body["outcomes"] == [
        {"index": 0, "event_id": event["event_id"], "seq": 1, "status": "accepted",
         "access_event_recorded": True, "outcome": "entered"}
    ]  # fmt: skip
    assert body["highest_contiguous_seq"] == 1 and body["gaps"] == []
    assert body["policy_cursor"] == {"latest_seq": 0}
    assert ew.visit_state(visit) == "inside"
    row = ew.rows(
        "SELECT device_id, seq, event_type, decision_source, credential_kind, occurred_at, signature, payload_hash, recorded_by,"
        " visit_id FROM access_events"
    )[0]
    assert row[0] == dev.device_id and row[1] == 1 and row[2] == "EntryObserved"
    assert row[3] == "cached_policy" and row[4] == "qr"
    assert (
        row[6] == event["signature"]
        and row[7] == event["payload_hash"]
        and row[8] is None
        and row[9] == visit
    )
    # the same transaction wrote the ledger, the audit row and the outbox row
    assert ew.count("edge_events", "status = 'accepted' AND projected") == 1
    audit = ew.audit("edge.entry_observed")
    assert len(audit) == 1 and audit[0][2] == "edge_device" and audit[0][1] is None
    assert audit[0][4]["changed"]["permission_created"]["after"] is False
    out = ew.outbox("EntryObserved")
    assert len(out) == 1 and out[0]["payload"]["outcome"] == "entered"
    assert out[0]["payload"]["device_id"] == str(dev.device_id)


def test_exit_after_entry_and_reconciled_unknown_never_manufactures_a_time(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    v1, v2 = ew.authorised_visit(), ew.authorised_visit(ew.soc.units["A-102"])
    assert statuses(dev.sync([dev.entry(v1), dev.entry(v2)])) == ["accepted", "accepted"]
    r = dev.sync([
        dev.exit(v1),
        dev.exit(v2, payload={"exit_basis": "reconciled_unknown", "decision_source": "guard_assisted"}),
    ])  # fmt: skip
    assert statuses(r) == ["accepted", "accepted"]
    assert ew.rows("SELECT state, exit_basis, exited_at IS NULL FROM visits WHERE id = %s", (v1,))[
        0
    ] == ("exited", "observed", False)
    state, basis, no_time, unknown = ew.rows(
        "SELECT state, exit_basis, exited_at IS NULL, confidence_inside FROM visits WHERE id = %s",
        (v2,),
    )[0]
    assert (state, basis, no_time, unknown) == ("exited", "reconciled_unknown", True, "unknown")
    assert [e[0] for e in ew.exceptions("exit_unknown")] == ["exit_unknown"]


def test_unknown_event_types_are_stored_but_not_interpreted(ew: EdgeWorld, dev: EdgeClient) -> None:
    ev = dev.event("DeviceHealth", uuid.uuid4(), payload={"disk_pct": 41})
    r = dev.sync([ev])
    out = r.json()["outcomes"][0]
    assert out["status"] == "accepted" and out["reason"] == "recorded_not_projected"
    assert ew.count("access_events") == 0
    assert ew.count("edge_events", "projected = false AND event_type = 'DeviceHealth'") == 1
    assert len(ew.outbox("EdgeEventRecorded")) == 1


# ------------------------------------------------------------------------------------------ the transition rules
def test_entry_for_an_expired_permission_is_recorded_and_raises_an_exception_never_permission(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    ew.age_authorisation(visit, minutes=600)
    r = dev.sync([dev.entry(visit)])
    out = r.json()["outcomes"][0]
    assert out["status"] == "rejected_transition" and out["reason"] == "entry_without_authorisation"
    assert out["access_event_recorded"] is True and out["exception_id"]
    assert (
        ew.count("access_events", "visit_id = %s", (visit,)) == 1
    )  # the physical entry is NEVER discarded
    assert ew.visit_state(visit) == "authorised"  # and it did not turn into permission
    assert ew.count("visits", "state = 'inside'") == 0
    kinds = ew.exceptions("unauthorised_entry")
    assert len(kinds) == 1 and kinds[0][1] == "open" and kinds[0][2] == visit
    ledger = ew.rows(
        "SELECT status, reason, projected, access_event_id IS NOT NULL FROM edge_events"
    )[0]
    assert ledger == ("rejected_transition", "entry_without_authorisation", False, True)


def test_entry_after_a_denied_request_is_recorded_and_flagged(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    unit = ew.soc.units["A-101"]
    household = ew.household("A-101", family=False)
    request = ew.raise_request(unit)
    assert ew.decide(household.owner, request, "deny").status_code == 200
    visit = uuid.UUID(request["visit_id"])
    out = dev.sync([dev.entry(visit)]).json()["outcomes"][0]
    assert out["status"] == "rejected_transition" and out["access_event_recorded"] is True
    assert ew.count("access_events") == 1 and ew.visit_state(visit) != "inside"
    assert len(ew.exceptions("unauthorised_entry")) == 1


def test_entry_for_a_request_that_expired_unanswered_is_recorded_and_flagged(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ew.household("A-102", family=False)
    request = ew.raise_request(ew.soc.units["A-102"])
    ew.expire_request(request["id"])
    visit = uuid.UUID(request["visit_id"])
    out = dev.sync([dev.entry(visit)]).json()["outcomes"][0]
    assert out["status"] == "rejected_transition"
    assert ew.count("access_events", "visit_id = %s", (visit,)) == 1
    assert ew.visit_state(visit) in {"requested", "expired"}
    assert len(ew.exceptions("unauthorised_entry")) == 1


def test_a_remote_decision_for_a_visit_the_cloud_does_not_know_is_recorded_without_a_visit(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    """A decision the resident app took can only be verified against a cloud visit: without one it is flagged (recorded, never discarded)."""
    ghost = uuid.uuid4()
    ev = dev.entry(
        ghost, payload={"decision_source": "resident_app", "credential_kind": "resident_app"}
    )
    out = dev.sync([ev]).json()["outcomes"][0]
    assert out["status"] == "rejected_transition" and out["reason"] == "entry_unknown_visit"
    assert ew.rows("SELECT visit_id FROM access_events")[0][0] is None
    assert len(ew.exceptions("unauthorised_entry")) == 1


def test_duplicate_entry_for_a_visit_already_inside_changes_nothing(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    assert statuses(dev.sync([dev.entry(visit)])) == ["accepted"]
    version = ew.rows("SELECT version FROM visits WHERE id = %s", (visit,))[0][0]
    assert statuses(dev.sync([dev.entry(visit)])) == ["accepted"]
    assert ew.rows("SELECT version FROM visits WHERE id = %s", (visit,))[0][0] == version
    assert ew.count("access_events") == 2  # both observations are preserved


def test_exit_is_never_gated_but_a_missing_entry_is_flagged(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()  # authorised, entry never observed
    out = dev.sync([dev.exit(visit)]).json()["outcomes"][0]
    assert out["status"] == "accepted" and out["outcome"] == "exit_without_observed_entry"
    assert ew.visit_state(visit) == "exited"
    assert len(ew.exceptions("exit_without_entry")) == 1
    ghost = dev.sync([dev.exit(uuid.uuid4())]).json()["outcomes"][0]
    assert ghost["status"] == "rejected_transition" and ew.count("access_events") == 2


def test_a_permission_window_is_widened_by_stated_uncertainty_but_never_beyond_the_limit(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    ew.age_authorisation(visit, minutes=0)
    # just outside the window by 30 s, with 40 s stated uncertainty: inside the widened window
    until = ew.rows("SELECT authorised_until FROM visits WHERE id = %s", (visit,))[0][0]
    from datetime import timedelta

    late = until + timedelta(seconds=30)
    ok = dev.sync([dev.entry(visit, occurred_at=late, clock_uncertainty_ms=40_000)])
    assert statuses(ok) == ["accepted"]
    other = ew.authorised_visit(ew.soc.units["A-102"])
    until2 = ew.rows("SELECT authorised_until FROM visits WHERE id = %s", (other,))[0][0]
    too_late = until2 + timedelta(seconds=90)
    # 50 s uncertainty is below the 60 s limit but 90 s past the window: rejected
    assert statuses(
        dev.sync([dev.entry(other, occurred_at=too_late, clock_uncertainty_ms=50_000)])
    ) == ["rejected_transition"]


# ------------------------------------------------------------------------------------------ idempotency
def test_resending_a_batch_creates_no_rows_and_answers_duplicate(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visits = [ew.authorised_visit(ew.soc.units[u]) for u in ("A-101", "A-102")]
    batch = [dev.entry(visits[0]), dev.entry(visits[1]), dev.event("DeviceHealth", uuid.uuid4())]
    first = dev.sync(batch).json()
    counts = {
        t: ew.count(t)
        for t in ("access_events", "edge_events", "audit_log", "outbox", "edge_quarantine")
    }
    again = dev.sync(batch).json()
    assert [o["status"] for o in first["outcomes"]] == ["accepted"] * 3
    assert [o["status"] for o in again["outcomes"]] == ["duplicate"] * 3
    assert [o["original_status"] for o in again["outcomes"]] == ["accepted"] * 3
    assert counts == {t: ew.count(t) for t in counts}
    assert again["highest_contiguous_seq"] == first["highest_contiguous_seq"] == 3
    assert [o["event_id"] for o in again["outcomes"]] == [o["event_id"] for o in first["outcomes"]]


def test_resending_a_rejected_transition_repeats_that_status_and_adds_nothing(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ev = dev.entry(uuid.uuid4(), payload={"decision_source": "ivr"})
    first = dev.sync([ev]).json()["outcomes"][0]
    exceptions = ew.count("exceptions")
    again = dev.sync([ev]).json()["outcomes"][0]
    assert first["status"] == again["status"] == "rejected_transition"
    assert (
        again["replayed"] is True
        and ew.count("exceptions") == exceptions
        and ew.count("access_events") == 1
    )


def test_duplicate_events_inside_one_batch(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()
    ev = dev.entry(visit)
    assert statuses(dev.sync([ev, ev, ev])) == ["accepted", "duplicate", "duplicate"]
    assert ew.count("access_events") == 1


def test_overlapping_batches_and_a_partially_acknowledged_resend(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    events = [dev.event("DeviceHealth", uuid.uuid4()) for _ in range(6)]
    assert statuses(dev.sync(events[:4])) == ["accepted"] * 4
    r = dev.sync(events[2:])  # the first two of these were already acknowledged
    assert statuses(r) == ["duplicate", "duplicate", "accepted", "accepted"]
    assert r.json()["highest_contiguous_seq"] == 6
    assert ew.count("edge_events") == 6


def test_concurrent_identical_batches_from_one_device_create_each_event_once(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visits = [ew.authorised_visit(ew.soc.units[u]) for u in ("A-101", "A-102", "A-103")]
    batch = [dev.entry(v) for v in visits]
    body = json.dumps({"device_id": str(dev.device_id), "events": batch}).encode()

    def send(_: int) -> Any:
        client = TestClient(ew.app, raise_server_exceptions=False, headers=UA)
        headers = {
            **dev.headers("POST", "/v1/edge/sync/batches", body),
            "Content-Type": "application/json",
        }
        return client.post("/v1/edge/sync/batches", content=body, headers=headers)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(send, range(6)))
    assert all(r.status_code == 200 for r in results)
    accepted = sum(1 for r in results for o in r.json()["outcomes"] if o["status"] == "accepted")
    dup = sum(1 for r in results for o in r.json()["outcomes"] if o["status"] == "duplicate")
    assert (accepted, dup) == (3, 15)
    assert ew.count("access_events") == 3 and ew.count("edge_events") == 3
    assert ew.count("audit_log", "operation = 'edge.entry_observed'") == 3
    assert ew.count("outbox", "event_type = 'EntryObserved'") == 3


def test_concurrent_overlapping_batches_from_two_devices_on_the_same_visits(ew: EdgeWorld) -> None:
    a, b = ew.edge_device(), ew.edge_device()
    visits = [ew.authorised_visit(ew.soc.units[u]) for u in ("A-101", "A-102", "A-103")]

    def send(client: EdgeClient, order: list[uuid.UUID]) -> Any:
        c = TestClient(ew.app, raise_server_exceptions=False, headers=UA)
        body = json.dumps(
            {"device_id": str(client.device_id), "events": [client.entry(v) for v in order]}
        ).encode()
        headers = {
            **client.headers("POST", "/v1/edge/sync/batches", body),
            "Content-Type": "application/json",
        }
        return c.post("/v1/edge/sync/batches", content=body, headers=headers)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fa = pool.submit(send, a, visits)
        fb = pool.submit(
            send, b, list(reversed(visits))
        )  # opposite lock order: a deadlock candidate
    assert fa.result().status_code == 200 and fb.result().status_code == 200
    assert (
        ew.count("access_events") == 6
    )  # both gates saw all three people: both observations preserved
    assert ew.count("visits", "state = 'inside'") == 3


# ------------------------------------------------------------------------------------------ out of order, gaps
def test_out_of_order_delivery_gaps_and_contiguous_ack(ew: EdgeWorld, dev: EdgeClient) -> None:
    ev = {n: dev.event("DeviceHealth", uuid.uuid4(), seq=n) for n in range(1, 8)}
    r = dev.sync([ev[3], ev[5]]).json()
    assert r["highest_contiguous_seq"] == 0 and r["gaps"] == [[1, 2], [4, 4]]
    r = dev.sync([ev[1]]).json()
    assert r["highest_contiguous_seq"] == 1 and r["gaps"] == [[2, 2], [4, 4]]
    r = dev.sync([ev[2]]).json()
    assert r["highest_contiguous_seq"] == 3 and r["gaps"] == [[4, 4]]
    r = dev.sync([ev[7], ev[4]]).json()
    assert r["highest_contiguous_seq"] == 5 and r["gaps"] == [[6, 6]]
    r = dev.sync([ev[6]]).json()
    assert r["highest_contiguous_seq"] == 7 and r["gaps"] == []
    assert dev.me().json()["sync"]["highest_contiguous_seq"] == 7


def test_one_batch_in_reverse_order_is_processed_and_acknowledged_as_a_set(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    events = [dev.event("DeviceHealth", uuid.uuid4(), seq=n) for n in range(1, 11)]
    r = dev.sync(list(reversed(events))).json()
    assert [o["status"] for o in r["outcomes"]] == ["accepted"] * 10
    assert r["highest_contiguous_seq"] == 10 and r["gaps"] == []


def test_sequences_are_per_device(ew: EdgeWorld) -> None:
    a, b = ew.edge_device(), ew.edge_device()
    ra = a.sync(
        [a.event("DeviceHealth", uuid.uuid4(), seq=1), a.event("DeviceHealth", uuid.uuid4(), seq=2)]
    ).json()
    rb = b.sync([b.event("DeviceHealth", uuid.uuid4(), seq=2)]).json()
    assert ra["highest_contiguous_seq"] == 2
    assert rb["highest_contiguous_seq"] == 0 and rb["gaps"] == [[1, 1]]


def test_gap_list_is_bounded(ew: EdgeWorld, dev: EdgeClient) -> None:
    events = [
        dev.event("DeviceHealth", uuid.uuid4(), seq=n) for n in range(2, 600, 2)
    ]  # 299 events, every even seq
    r1 = dev.sync(events[:150]).json()
    r2 = dev.sync(events[150:]).json()
    assert r1["highest_contiguous_seq"] == r2["highest_contiguous_seq"] == 0
    assert len(r2["gaps"]) == 200 and r2["gaps"][0] == [1, 1]


# ------------------------------------------------------------------------------------------ quarantine
def test_a_bad_event_is_quarantined_and_never_blocks_the_events_around_it(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    v1, v2 = ew.authorised_visit(), ew.authorised_visit(ew.soc.units["A-102"])
    tampered = dev.entry(uuid.uuid4(), sign=False)
    tampered["signature"] = "ed25519:" + "A" * 86
    r = dev.sync([dev.entry(v1), tampered, dev.entry(v2)])
    assert statuses(r) == ["accepted", "quarantined", "accepted"]
    body = r.json()
    assert body["outcomes"][1]["reason"] == "bad_signature"
    assert (
        body["highest_contiguous_seq"] == 3
    )  # the quarantined seq counts as disposed: the cursor is not frozen
    assert ew.visit_state(v1) == ew.visit_state(v2) == "inside"
    assert ew.count("edge_quarantine") == 1 and ew.count("access_events") == 2
    follow = dev.sync([dev.event("DeviceHealth", uuid.uuid4())])
    assert statuses(follow) == ["accepted"] and follow.json()["highest_contiguous_seq"] == 4
    # supervisors see it: an exception and the quarantine list
    assert len(ew.exceptions("edge_quarantine")) == 1
    listing = ew.call(ew.guard_sup, "GET", ew.s("edge/quarantine"))
    assert listing.status_code == 200 and listing.json()["items"][0]["reason"] == "bad_signature"


def test_tampered_payload_and_forged_key_are_quarantined(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()
    edited = dev.entry(visit)
    edited["payload"] = {
        "decision_source": "supervisor_override"
    }  # payload changed after signing; hash now stale
    other_key = dev.entry(uuid.uuid4(), signer=generate_private_key())
    unsigned = dev.entry(uuid.uuid4(), sign=False)
    r = dev.sync([edited, other_key, unsigned])
    assert statuses(r) == ["quarantined"] * 3
    assert {o["reason"] for o in r.json()["outcomes"]} == {"bad_signature"}
    assert ew.visit_state(visit) == "authorised" and ew.count("access_events") == 0


def test_event_for_another_society_is_quarantined_and_never_written_there(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    other = ew.idh.society("Rival Heights", units=("Z-1",))
    foreign = dev.event(
        "EntryObserved", uuid.uuid4(), society_id=other.id
    )  # validly signed by THIS device's key
    r = dev.sync([foreign])
    out = r.json()["outcomes"][0]
    assert out["status"] == "quarantined" and out["reason"] == "wrong_society"
    for table in ("access_events", "edge_events", "exceptions", "edge_quarantine"):
        assert ew.count(table, "society_id = %s", (other.id,)) == 0, table
    row = ew.rows("SELECT society_id, claimed_society_id FROM edge_quarantine")[0]
    assert (
        row[0] == ew.soc.id and row[1] == other.id
    )  # evidence lives in the AUTHENTICATED society only


def test_event_claiming_another_device_is_quarantined(ew: EdgeWorld, dev: EdgeClient) -> None:
    peer = ew.edge_device()
    r = dev.sync([dev.event("DeviceHealth", uuid.uuid4(), device_id=peer.device_id)])
    assert r.json()["outcomes"][0]["reason"] == "wrong_device"
    assert ew.count("edge_events") == 0


def test_cross_society_batch_body_is_not_a_door(ew: EdgeWorld, dev: EdgeClient) -> None:
    other = ew.idh.society("Rival Heights", units=("Z-1",))
    foreign_dev = EdgeClient(ew, uuid.uuid4(), dev.key, other.id, None)
    r = dev.sync_raw(json.dumps({"device_id": str(foreign_dev.device_id), "events": []}).encode())
    assert r.status_code == 400 and r.json()["code"] == "invalid_schema"


def test_schema_problems_are_quarantined_per_event(ew: EdgeWorld, dev: EdgeClient) -> None:
    good = dev.event("DeviceHealth", uuid.uuid4())
    extra = {**dev.event("DeviceHealth", uuid.uuid4()), "unexpected": 1}
    bad_hash = {**dev.event("DeviceHealth", uuid.uuid4()), "payload_hash": "sha256:xyz"}
    versioned = {**dev.event("DeviceHealth", uuid.uuid4()), "schema_version": 2}
    missing = {k: v for k, v in dev.event("DeviceHealth", uuid.uuid4()).items() if k != "seq"}
    r = dev.sync([extra, bad_hash, versioned, missing, "not an object", 7, None, good])
    assert statuses(r) == ["quarantined"] * 7 + ["accepted"]
    reasons = [o.get("reason") for o in r.json()["outcomes"]]
    assert reasons[:7] == [
        "schema_invalid",
        "schema_invalid",
        "schema_version_mismatch",
        "schema_invalid",
        "schema_invalid",
        "schema_invalid",
        "schema_invalid",
    ]
    assert (
        r.json()["outcomes"][7]["seq"] == 1
    )  # the good event (made first, seq 1) still got its place


def test_batch_level_schema_version_mismatch_is_refused(dev: EdgeClient) -> None:
    r = dev.sync([], schema_version=2)
    assert r.status_code == 400 and r.json()["code"] == "invalid_schema"
    assert dev.sync([], schema_version=1).status_code == 200


def test_seq_and_event_id_conflicts_preserve_both_observations(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    v1, v2 = ew.authorised_visit(), ew.authorised_visit(ew.soc.units["A-102"])
    first = dev.entry(v1, seq=5)
    assert statuses(dev.sync([first])) == ["accepted"]
    same_seq_other_event = dev.entry(v2, seq=5)
    same_event_other_seq = dev.entry(v2, seq=9, event_id=uuid.UUID(first["event_id"]))
    r = dev.sync([same_seq_other_event, same_event_other_seq])
    assert [o["reason"] for o in r.json()["outcomes"]] == ["seq_conflict", "event_id_conflict"]
    assert ew.visit_state(v2) == "authorised"  # a conflicting claim does not move state
    assert ew.count("edge_events") == 1 and ew.count("edge_quarantine") == 2
    # the same event id and seq with other content
    changed = dev.entry(
        v1, seq=5, event_id=uuid.UUID(first["event_id"]), payload={"decision_source": "rfid"}
    )
    assert dev.sync([changed]).json()["outcomes"][0]["reason"] == "payload_mismatch"
    # resending a quarantined event is stable and adds no row
    rows = ew.count("edge_quarantine")
    again = dev.sync([same_seq_other_event]).json()["outcomes"][0]
    assert (
        again["status"] == "quarantined"
        and again["reason"] == "seq_conflict"
        and again["replayed"] is True
    )
    assert ew.count("edge_quarantine") == rows


def test_payload_hygiene(ew: EdgeWorld, dev: EdgeClient) -> None:
    huge = dev.event("DeviceHealth", uuid.uuid4(), payload={"blob": "x" * 3000})
    pii_keys = [
        dev.event("DeviceHealth", uuid.uuid4(), payload={"visitor_phone": "x"}),
        dev.event("DeviceHealth", uuid.uuid4(), payload={"nested": {"full_name": "x"}}),
        dev.event("DeviceHealth", uuid.uuid4(), payload={"items": [{"upiId": "x"}]}),
    ]
    r = dev.sync([huge, *pii_keys])
    assert [o["reason"] for o in r.json()["outcomes"]] == ["payload_too_large"] + [
        "pii_in_payload"
    ] * 3
    blob = json.dumps([row[0] for row in ew.rows("SELECT raw FROM edge_quarantine")])
    assert "visitor_phone" not in blob or "[REDACTED]" in blob  # evidence is masked


def test_observation_vocabulary_and_place_are_validated(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()
    other_gate = ew.make_gate("Back gate")
    cases = {
        "bad_source": dev.entry(visit, payload={"decision_source": "telepathy"}),
        "bad_kind": dev.entry(visit, payload={"credential_kind": "magic"}),
        "bad_lane": dev.entry(visit, payload={"lane_id": str(uuid.uuid4())}),
        "lane_not_a_uuid": dev.entry(visit, payload={"lane_id": "nope"}),
        "exit_basis_on_entry": dev.entry(visit, payload={"exit_basis": "scanned"}),
        "wrong_gate": dev.entry(visit, payload={"gate_id": str(other_gate)}),
        "bad_exit_basis": dev.exit(visit, payload={"exit_basis": "guessed"}),
    }
    r = dev.sync(list(cases.values()))
    assert [o["reason"] for o in r.json()["outcomes"]] == [
        "invalid_payload", "invalid_payload", "unknown_lane", "invalid_payload", "invalid_payload",
        "device_wrong_gate", "invalid_payload",
    ]  # fmt: skip
    assert ew.visit_state(visit) == "authorised" and ew.count("access_events") == 0


def test_gateway_without_a_bound_gate_needs_the_gate_in_the_payload(ew: EdgeWorld) -> None:
    free = ew.edge_device(bind_gate=False)
    visit = ew.authorised_visit()
    out = free.sync([free.entry(visit)]).json()["outcomes"][0]
    assert out["status"] == "quarantined" and out["reason"] == "gate_unresolved"
    ok = free.sync([free.entry(visit, payload={"gate_id": str(ew.gate_id)})]).json()["outcomes"][0]
    assert ok["status"] == "accepted"


# ------------------------------------------------------------------------------------------ request limits
def test_batch_of_501_events_is_refused_whole(ew: EdgeWorld, dev: EdgeClient) -> None:
    events = [{"x": i} for i in range(501)]
    r = dev.sync(events)
    assert r.status_code == 413
    body = r.json()
    assert (
        body["code"] == "invalid_schema"
        and body["details"]["reason"] == "too_many_events"
        and body["request_id"]
    )
    assert ew.count("edge_quarantine") == 0 and ew.count("edge_events") == 0


def test_oversized_body_is_refused_with_413_before_anything_is_stored(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    big = json.dumps(
        {"device_id": str(dev.device_id), "events": [], "cursor": "x" * 1_100_000}
    ).encode()
    r = dev.sync_raw(big)
    assert r.status_code == 413 and r.json()["code"] == "invalid_schema"
    just_over = b" " * 1_048_577
    assert dev.sync_raw(just_over).status_code == 413
    assert ew.count("edge_events") == 0


def test_exactly_500_events_and_malformed_bodies(ew: EdgeWorld, dev: EdgeClient) -> None:
    events = [dev.event("DeviceHealth", uuid.uuid4()) for _ in range(500)]
    r = dev.sync(events)
    assert r.status_code == 200 and r.json()["highest_contiguous_seq"] == 500
    for raw in (b"not json", b"[]", b'{"events": 5, "device_id": "%s"}' % str(dev.device_id).encode(), b'{"device_id": 1, "events": []}',
                b'{"device_id": "%s", "events": [], "extra": 1}' % str(dev.device_id).encode()):  # fmt: skip
        r = dev.sync_raw(raw)
        assert r.status_code == 400 and r.json()["code"] == "invalid_schema", raw


# ------------------------------------------------------------------------------------------ atomicity
def test_a_failure_while_processing_one_event_rolls_back_only_that_event(
    ew: EdgeWorld, dev: EdgeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dwaar_api.modules.edge import sync as sync_mod

    real = sync_mod.mutation
    calls = {"n": 0}

    def flaky(conn: Any, ctx: Any, **kw: Any) -> Any:
        if kw.get("operation") == "edge.entry_observed":
            calls["n"] += 1
            if calls["n"] == 2:
                inner = kw["apply"]

                def broken(c: Any) -> Any:
                    inner(c)  # the domain rows are written ...
                    raise RuntimeError("boom after the writes")  # ... and then the event fails

                kw["apply"] = broken
        return real(conn, ctx, **kw)

    monkeypatch.setattr(sync_mod, "mutation", flaky)
    visits = [ew.authorised_visit(ew.soc.units[u]) for u in ("A-101", "A-102", "A-103")]
    r = dev.sync([dev.entry(v) for v in visits])
    assert statuses(r) == ["accepted", "quarantined", "accepted"]
    assert r.json()["outcomes"][1]["reason"] == "processing_error"
    assert [ew.visit_state(v) for v in visits] == ["inside", "authorised", "inside"]
    assert (
        ew.count("access_events") == 2 and ew.count("edge_events") == 2
    )  # nothing of the failed event survived
    assert ew.count("audit_log", "operation = 'edge.entry_observed'") == 2
    assert ew.count("outbox", "event_type = 'EntryObserved'") == 2
    assert r.json()["highest_contiguous_seq"] == 3 and ew.count("edge_quarantine") == 1


def test_counters_are_exposed_for_observability(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()
    bad = dev.entry(uuid.uuid4(), sign=False)
    dev.sync([dev.entry(visit), bad])
    metrics = ew.app.state.edge_metrics
    assert metrics.get("events_total", device=str(dev.device_id), status="accepted") == 1
    assert metrics.get("events_total", device=str(dev.device_id), status="quarantined") == 1
    assert metrics.get("batches_total", device=str(dev.device_id)) == 1
    text = metrics.render_text()
    assert "dwaar_edge_events_total" in text and "phone" not in text


def test_a_supervisor_reviews_and_resolves_what_the_edge_raised_through_the_slice_2_queue(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    visit = ew.authorised_visit()
    ew.age_authorisation(visit, minutes=600)
    out = dev.sync([dev.entry(visit)]).json()["outcomes"][0]
    listing = ew.call(
        ew.guard_sup, "GET", ew.s("exceptions"), params={"kind": "unauthorised_entry"}
    ).json()["items"]
    assert [e["id"] for e in listing] == [out["exception_id"]]
    assert (
        listing[0]["raised_by_system"] is True
        and listing[0]["visit_id"] == str(visit)
        and listing[0]["entry_happened"] is True
    )
    item = listing[0]
    r = ew.call(
        ew.guard_sup,
        "POST",
        f"/v1/exceptions/{item['id']}/transition",
        json={"action": "start_review", "expected_version": item["version"]},
    )
    assert r.status_code == 200, r.text
    r = ew.call(
        ew.guard_sup, "POST", f"/v1/exceptions/{item['id']}/transition",
        json={"action": "resolve", "expected_version": 2, "note": "Resident confirmed the visitor; permission had just lapsed"},
    )  # fmt: skip
    assert r.status_code == 200 and r.json()["state"] == "resolved"
    assert (
        ew.visit_state(visit) == "authorised"
    )  # resolving the review does not turn the entry into permission either
