"""Outbox + sync client against FakeCloud (the in-process contract fake; NOT the real API) (EDGE-03, EDGE-10, NFR-09)."""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from dwaar_common.ids import uuid7
from dwaar_common.signing import verify_bytes
from dwaar_common.timeutil import format_iso_utc
from dwaar_edge.gateway import Gateway
from dwaar_edge.outbox import MAX_BATCH_BYTES, MAX_BATCH_EVENTS
from dwaar_edge.sync import SyncClient, SyncConfig, TransportError, TransportResponse
from tests.integration.edge_gateway.fakecloud import FakeCloud
from tests.integration.edge_gateway.support import START, World, standard_world_with_policy

pytestmark = pytest.mark.req("EDGE-03")


def bulk(gw: Gateway, n: int, *, pad: int = 0, etype: str = "EntryObserved") -> list[uuid.UUID]:
    ids = []
    with gw.store.transaction():
        for _ in range(n):
            ent = uuid7()
            ids.append(ent)
            gw.outbox.append(
                type=etype,
                entity_id=ent,
                entity_version=1,
                payload={"gate_id": "g", "pad": "x" * pad},
                occurred_at=gw.clock.assess().now,
                clock_uncertainty_ms=50,
                policy_version=1,
            )
    return ids


def setup(tmp_path: Path, **gw_kw):  # type: ignore[no-untyped-def]
    w, t, gw = standard_world_with_policy(tmp_path, **gw_kw)
    cloud = FakeCloud(w.society_id, t.wall)
    cloud.register_device(w.gateway_device, w.device_signer.public_key)
    return w, t, gw, cloud


def client(gw: Gateway, cloud: FakeCloud, **kw) -> SyncClient:  # type: ignore[no-untyped-def]
    cfg = kw.pop("config", SyncConfig())
    return SyncClient(gw, cloud.transport(), cfg, sleep=lambda s: None, rng=random.Random(7), **kw)


def test_requests_are_signed_over_method_path_timestamp_and_body_hash(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        seen: dict[str, object] = {}

        class Spy:
            def request(self, method, path, headers, body):  # type: ignore[no-untyped-def]
                seen.update(method=method, path=path, headers=headers, body=body)
                return cloud.handle(method, path, headers, body)

        bulk(gw, 1)
        SyncClient(gw, Spy(), SyncConfig(), sleep=lambda s: None).push_batch()  # type: ignore[arg-type]
        h = seen["headers"]
        canonical = f"POST\n/v1/edge/sync/batches\n{h['X-Dwaar-Timestamp']}\n{hashlib.sha256(seen['body']).hexdigest()}".encode()  # type: ignore[index,arg-type]
        assert h["X-Dwaar-Device"] == str(w.gateway_device)  # type: ignore[index]
        assert verify_bytes(w.device_signer.public_key, canonical, h["X-Dwaar-Signature"])  # type: ignore[index]
        assert h["X-Dwaar-Timestamp"].endswith("Z")  # type: ignore[index]
        # tampering with the body after signing is rejected by the cloud
        tampered = cloud.handle("POST", "/v1/edge/sync/batches", h, seen["body"] + b" ")  # type: ignore[arg-type,operator]
        assert tampered.status == 401
    finally:
        gw.stop()


def test_policy_is_pulled_before_events_are_pushed(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        cloud.publish_policy(
            w.snapshot(seq=2, issued_at=t.wall_now, manifest=w.manifest(residents=[w.resident()]))
        )
        bulk(gw, 3)
        r = client(gw, cloud).sync_once()
        assert r.policy == "applied" and r.acked == 3
        assert [m for m, _ in cloud.requests] == ["GET", "POST"]  # EDGE-10 ordering
        assert gw.policy_seq() == 2
        assert client(gw, cloud).sync_once().policy == "up_to_date"
    finally:
        gw.stop()


def test_batches_never_exceed_500_events_or_1mb(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 1100)  # event-count limit
        bulk(gw, 600, pad=1900)  # byte limit: ~2.6 KB per event
        sizes: list[tuple[int, int]] = []
        tr = cloud.transport()
        orig = tr.request

        def spy(method, path, headers, body):  # type: ignore[no-untyped-def]
            if method == "POST":
                sizes.append((len(json.loads(body)["events"]), len(body)))
            return orig(method, path, headers, body)

        tr.request = spy  # type: ignore[method-assign]
        r = SyncClient(gw, tr, SyncConfig(), sleep=lambda s: None, rng=random.Random(1)).sync_once()
        assert r.acked == 1700 and gw.outbox.stats()["pending"] == 0
        assert max(n for n, _ in sizes) <= MAX_BATCH_EVENTS == 500
        assert max(b for _, b in sizes) <= MAX_BATCH_BYTES == 1_000_000
        assert any(n == 500 for n, _ in sizes) and any(b > 900_000 for _, b in sizes)
        assert cloud.accepted_seqs(w.gateway_device) == list(range(1, 1701))
    finally:
        gw.stop()


def test_lost_response_is_resent_idempotently_with_the_same_event_ids(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 5)
        ids = [r["event_id"] for r in gw.store.all("SELECT event_id FROM outbox ORDER BY seq")]
        cloud.drop_response_once = True
        c = client(gw, cloud)
        first = c.sync_once()
        assert (
            first.failed and gw.outbox.stats()["pending"] == 5
        )  # the cloud has them, but we never heard
        assert len(cloud.events) == 5
        second = c.sync_once()
        assert second.acked == 5 and gw.outbox.stats()["pending"] == 0
        assert len(cloud.events) == 5  # no duplicates stored
        assert {o["status"] for o in cloud.outcome_log[-5:]} == {"duplicate"}
        assert [
            r["event_id"] for r in gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
        ] == ids  # ids never regenerated
        assert all(r["attempts"] >= 2 for r in gw.store.all("SELECT attempts FROM outbox"))
    finally:
        gw.stop()


def test_a_bad_event_is_quarantined_without_blocking_later_events(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 5)
        row = gw.store.one("SELECT seq, wire_enc FROM outbox WHERE seq=3")
        wire = json.loads(gw.store.cipher.open("outbox", "wire", 3, row["wire_enc"]))
        wire["payload"]["gate_id"] = "forged"  # payload no longer matches payload_hash / signature
        with gw.store.transaction() as c:
            c.execute(
                "UPDATE outbox SET wire_enc=? WHERE seq=3",
                (gw.store.cipher.seal("outbox", "wire", 3, json.dumps(wire)),),
            )
        r = client(gw, cloud).sync_once()
        assert r.acked == 4 and r.quarantined == 1
        states = {int(x["seq"]): x["state"] for x in gw.store.all("SELECT seq, state FROM outbox")}
        assert states == {1: "acked", 2: "acked", 3: "quarantined", 4: "acked", 5: "acked"}
        calls = len(cloud.requests)
        client(gw, cloud).sync_once()
        assert [m for m, _ in cloud.requests[calls:]] == [
            "GET"
        ]  # the quarantined event is not resent
        assert cloud.quarantine  # kept for inspection on both sides
    finally:
        gw.stop()


def test_rejected_transition_goes_to_exception_state_not_retried(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        ent = uuid7()
        with gw.store.transaction():
            for typ, ver in (("EntryObserved", 1), ("EntryObserved", 1), ("ExitObserved", 2)):
                gw.outbox.append(
                    type=typ,
                    entity_id=ent,
                    entity_version=ver,
                    payload={"gate_id": "g"},
                    occurred_at=gw.clock.assess().now,
                    clock_uncertainty_ms=0,
                    policy_version=1,
                )
        r = client(gw, cloud).sync_once()
        assert r.acked == 2 and r.rejected == 1
        assert (
            gw.store.one("SELECT state FROM outbox WHERE seq=2")["state"] == "rejected"
        )  # physical entry preserved, queued for review
    finally:
        gw.stop()


def test_gaps_reported_by_the_cloud_are_resent(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 10)
        c = client(gw, cloud)
        assert c.sync_once().acked == 10
        lost = [e for (d, s), e in list(cloud.by_device_seq.items()) if 4 <= s <= 6]
        for key in [k for k in cloud.by_device_seq if 4 <= k[1] <= 6]:
            del cloud.by_device_seq[key]
        for e in lost:
            del cloud.events[e]
        bulk(gw, 1)  # the next batch reveals the hole: highest contiguous = 3, gaps = [[4,6]]
        r = c.sync_once()
        assert r.requeued == 3
        c.sync_once()
        assert cloud.accepted_seqs(w.gateway_device) == list(range(1, 12))
    finally:
        gw.stop()


def test_backoff_is_exponential_with_full_jitter_and_capped(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 2)
        cloud.online = False
        c = SyncClient(
            gw,
            cloud.transport(),
            SyncConfig(backoff_base_s=1.0, backoff_cap_s=60.0),
            sleep=lambda s: None,
            rng=random.Random(3),
        )
        delays = [c.sync_once().next_delay_s for _ in range(12)]
        for n, d in enumerate(delays, start=1):
            assert 0 <= d <= min(60.0, 2.0**n)
        assert max(delays[6:]) > 8  # the ceiling grows
        assert len(set(delays)) > 6  # jittered, not a fixed schedule
        assert gw.outbox.stats()["pending"] == 2  # nothing lost while offline
        cloud.online = True
        assert c.sync_once().acked == 2
        assert c._failures == 0
    finally:
        gw.stop()


def test_auth_failure_keeps_events_and_is_reported(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 2)
        cloud.device_keys.clear()
        r = client(gw, cloud).sync_once()
        assert r.failed and gw.outbox.stats()["pending"] == 2
        assert gw.status()["sync"]["last_error"]
    finally:
        gw.stop()


def test_http_413_halves_the_batch(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 40)
        c = client(gw, cloud)
        c.pull_policy()
        cloud.fail_status_once = 413
        with pytest.raises(TransportError):
            c.push_batch()
        assert c._batch_limit == 1 or c._batch_limit < 40
        assert c.sync_once().acked == 40
    finally:
        gw.stop()


def test_one_event_the_cloud_refuses_outright_is_locally_quarantined(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 1)

        class Refuse:
            def request(self, method, path, headers, body):  # type: ignore[no-untyped-def]
                if method == "POST":
                    return TransportResponse(422, {"code": "invalid"}, t.wall_now)
                return cloud.handle(method, path, headers, body)

        r = SyncClient(gw, Refuse(), SyncConfig(), sleep=lambda s: None).sync_once()  # type: ignore[arg-type]
        assert r.quarantined == 1 and gw.outbox.stats()["quarantined"] == 1
        bulk(gw, 1)
        assert (
            SyncClient(gw, cloud.transport(), SyncConfig(), sleep=lambda s: None).sync_once().acked
            == 1
        )
    finally:
        gw.stop()


def test_sync_resumes_after_a_restart_without_loss_or_duplicates(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    bulk(gw, 30)
    c = client(gw, cloud, config=SyncConfig(max_events=10, max_batches_per_cycle=1))
    assert c.sync_once().acked == 10
    gw.stop()  # process restart
    gw2 = w.gateway(tmp_path / "edge", t)
    try:
        bulk(gw2, 5)
        r = client(gw2, cloud).sync_once()
        assert r.acked == 25
        assert cloud.accepted_seqs(w.gateway_device) == list(range(1, 36))
        assert len(cloud.events) == 35
    finally:
        gw2.stop()


def test_device_sequence_is_monotonic_and_never_reused_even_after_pruning(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 10)
        client(gw, cloud).sync_once()
        assert gw.outbox.prune_acked(keep_last=0) == 10
        assert gw.store.one("SELECT COUNT(*) AS n FROM outbox")["n"] == 0
        bulk(gw, 1)
        assert gw.store.one("SELECT MIN(seq) AS s FROM outbox")["s"] == 11  # not 1 again
    finally:
        gw.stop()


def test_trusted_time_is_taken_from_the_cloud_response(tmp_path: Path) -> None:
    w = World()
    from tests.integration.edge_gateway.support import ManualTime

    t = ManualTime()
    gw = w.gateway(tmp_path / "edge", t, trusted=False)
    cloud = FakeCloud(w.society_id, t.wall)
    cloud.register_device(w.gateway_device, w.device_signer.public_key)
    try:
        assert not gw.clock_state().trusted
        client(gw, cloud).sync_once()
        s = gw.clock_state()
        assert s.trusted and s.uncertainty_ms <= 1100  # Date has 1 s resolution
    finally:
        gw.stop()


def test_stale_or_tampered_policy_from_the_cloud_is_rejected_and_old_policy_kept(
    tmp_path: Path,
) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        cloud.serve_policy_always = True
        cloud.publish_policy(
            w.snapshot(seq=1, issued_at=t.wall_now, manifest=w.manifest())
        )  # replay of an applied seq
        r = client(gw, cloud).sync_once()
        assert r.policy.startswith("rejected:")
        assert gw.policy and gw.policy.seq == 1
        assert gw.status()["sync"]["last_policy_error"] in {"duplicate", "rollback"}
    finally:
        gw.stop()


def test_policy_cursor_in_the_ack_triggers_a_pull(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 1)
        c = client(gw, cloud)
        c.sync_once()
        cloud.publish_policy(w.snapshot(seq=5, issued_at=t.wall_now, manifest=w.manifest()))
        bulk(gw, 1)
        c.push_batch()
        assert c._pull_policy_next is True
    finally:
        gw.stop()


def test_pending_batch_respects_ordering(tmp_path: Path) -> None:
    w, t, gw, cloud = setup(tmp_path)
    try:
        bulk(gw, 7)
        rows = gw.outbox.pending_batch(max_events=5)
        assert [r.seq for r in rows] == [1, 2, 3, 4, 5]
        assert all(format_iso_utc(START) <= r.wire["occurred_at"] for r in rows)
        _ = timedelta
    finally:
        gw.stop()
