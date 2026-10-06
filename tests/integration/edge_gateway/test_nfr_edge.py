"""Edge NFR measurements: NFR-02 (decision latency), NFR-04 (LAN propagation), NFR-09 (72 h buffer), NFR-10 (reconcile).

HONESTY: every number here is measured (or, for NFR-10, simulated) on the BUILD MACHINE, which is NOT the certified gateway
hardware (EDGE-08), has a virtualised disk whose fsync is fast, and runs loopback networking. The targets are checked as a
regression guard; they are not certification. Set ``DWAAR_BENCH_OUT`` to a file to append the JSON of each measurement.
"""

from __future__ import annotations

import json
import os
import platform
import random
import resource
import statistics
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from dwaar_common.ids import uuid7
from dwaar_edge.api import create_app
from dwaar_edge.sync import SyncClient, SyncConfig
from tests.integration.edge_gateway.fakecloud import FakeCloud, ThrottledTransport
from tests.integration.edge_gateway.support import (
    START,
    LiveServer,
    ManualTime,
    World,
    percentile,
    standard_world_with_policy,
)


def record(name: str, data: dict[str, Any]) -> None:
    data = {
        "measurement": name,
        "machine": f"{platform.machine()} {os.cpu_count()} cpu",
        "certified_hardware": False,
        **data,
    }
    print(f"\nEDGE-MEASUREMENT {json.dumps(data, sort_keys=True)}")  # noqa: T201
    out = os.environ.get("DWAAR_BENCH_OUT")
    if out:
        with open(out, "a") as fh:  # noqa: PTH123
            fh.write(json.dumps(data, sort_keys=True) + "\n")


def big_policy(w: World, t: ManualTime, n: int) -> dict[str, Any]:
    residents = [
        {
            "credential_ref": f"cred-{i:06d}",
            "person_ref": f"p-{i:06d}",
            "unit_id": str(w.unit_1),
            "status": "active",
            "valid_from": None,
            "valid_until": None,
            "revocation_version": 1,
        }
        for i in range(n)
    ]
    return w.snapshot(seq=2, issued_at=t.wall_now, manifest=w.manifest(residents=residents))


@pytest.mark.slow
@pytest.mark.req("NFR-02", "GATE-06")
def test_nfr02_decision_latency_50k_credentials_20_per_second_burst(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        raw = big_policy(w, t, 50_000)
        t0 = time.perf_counter()
        gw.apply_policy(raw)
        apply_s = time.perf_counter() - t0
        assert (gw.policy and len(gw.policy.residents) == 50_001 - 1 + 0) or len(
            gw.policy.residents
        ) == 50_000
        rng = random.Random(11)

        def cred() -> dict[str, Any]:
            r = rng.random()
            if r < 0.85:
                return {
                    "kind": "resident",
                    "credential_ref": f"cred-{rng.randrange(50_000):06d}",
                    "revocation_version": 1,
                }
            if r < 0.95:
                return {
                    "kind": "resident",
                    "credential_ref": f"unknown-{rng.randrange(10**6)}",
                    "revocation_version": 1,
                }
            return {"kind": "none"}

        actor = w.actor(gw, w.term_a)
        # (a) in-process service time, closed loop (decision + decision log + feed, one durable transaction each)
        direct: list[float] = []
        pure: list[float] = []
        for _ in range(3000):
            c = cred()
            s0 = time.perf_counter()
            gw.evaluate_decision_only(gate_id=w.gate_a, lane_id=w.lane_a_in, credential=c)
            pure.append((time.perf_counter() - s0) * 1000)
            s0 = time.perf_counter()
            gw.evaluate(actor, gate_id=w.gate_a, lane_id=w.lane_a_in, credential=c)
            direct.append((time.perf_counter() - s0) * 1000)

        # (b) 20 events/second burst through the real local API over loopback: 20 concurrent terminals, one burst per second
        token = gw.issue_terminal_token(w.term_a, "guard")
        http: list[float] = []
        lock = threading.Lock()
        with LiveServer(create_app(gw)) as srv:
            clients = [
                httpx.Client(
                    base_url=srv.url, headers={"Authorization": f"Bearer {token}"}, timeout=10
                )
                for _ in range(20)
            ]
            try:
                for _ in range(30):  # 30 bursts of 20 = 600 decisions at 20 per second
                    barrier = threading.Barrier(20)
                    started = time.perf_counter()

                    def one(
                        client: httpx.Client,
                        body: dict[str, Any],
                        barrier: threading.Barrier = barrier,
                    ) -> None:
                        barrier.wait()
                        s0 = time.perf_counter()
                        r = client.post("/v1/terminal/evaluate", json=body)
                        dt = (time.perf_counter() - s0) * 1000
                        assert r.status_code == 200, r.text
                        with lock:
                            http.append(dt)

                    threads = [
                        threading.Thread(
                            target=one,
                            args=(
                                c,
                                {
                                    "gate_id": str(w.gate_a),
                                    "lane_id": str(w.lane_a_in),
                                    "credential": cred(),
                                },
                            ),
                        )
                        for c in clients
                    ]
                    for th in threads:
                        th.start()
                    for th in threads:
                        th.join()
                    time.sleep(max(0.0, 1.0 - (time.perf_counter() - started)))
            finally:
                for c in clients:
                    c.close()
        rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        result = {
            "credentials_cached": 50_000,
            "policy_apply_s": round(apply_s, 2),
            "engine_only_ms": {
                "p50": round(percentile(pure, 50), 3),
                "p95": round(percentile(pure, 95), 3),
                "p99": round(percentile(pure, 99), 3),
            },
            "service_closed_loop_ms": {
                "p50": round(percentile(direct, 50), 3),
                "p95": round(percentile(direct, 95), 3),
                "p99": round(percentile(direct, 99), 3),
                "n": len(direct),
            },
            "api_burst_20_per_s_ms": {
                "p50": round(percentile(http, 50), 2),
                "p95": round(percentile(http, 95), 2),
                "p99": round(percentile(http, 99), 2),
                "max": round(max(http), 2),
                "n": len(http),
            },
            "peak_rss_mb": round(rss_mb),
            "target": {"p95_ms": 150, "p99_ms": 300},
        }
        record("NFR-02", result)
        assert percentile(http, 95) <= 150 and percentile(http, 99) <= 300
        assert percentile(direct, 95) <= 150
    finally:
        gw.stop()


@pytest.mark.req("NFR-04", "EDGE-01")
def test_nfr04_lan_propagation_between_two_terminals_on_loopback(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        tok_a = gw.issue_terminal_token(w.term_a, "guard")
        tok_b = gw.issue_terminal_token(
            w.term_a, "guard"
        )  # terminal B observes gate A's feed (same gate, second terminal)
        latencies: list[float] = []
        with LiveServer(create_app(gw)) as srv:
            ca = httpx.Client(
                base_url=srv.url, headers={"Authorization": f"Bearer {tok_a}"}, timeout=10
            )
            cb = httpx.Client(
                base_url=srv.url, headers={"Authorization": f"Bearer {tok_b}"}, timeout=10
            )
            try:
                last = cb.get("/v1/terminal/feed").json()["last_id"]
                for _ in range(100):
                    ev = ca.post(
                        "/v1/terminal/evaluate",
                        json={
                            "gate_id": str(w.gate_a),
                            "lane_id": str(w.lane_a_in),
                            "credential": {
                                "kind": "resident",
                                "credential_ref": "cred-r1",
                                "revocation_version": 1,
                            },
                        },
                    ).json()
                    last = cb.get(f"/v1/terminal/feed?after={last}").json()[
                        "last_id"
                    ]  # B catches up on the decision row
                    seen: list[float] = []

                    def poll(after: int = last, seen: list[float] = seen) -> None:
                        r = cb.get(f"/v1/terminal/feed?after={after}&wait_ms=5000").json()
                        if any(i["kind"] == "entry_observed" for i in r["items"]):
                            seen.append(time.perf_counter())

                    th = threading.Thread(target=poll)
                    th.start()
                    time.sleep(0.02)  # B's long poll is parked on the gateway
                    t_send = time.perf_counter()
                    r = ca.post(
                        "/v1/terminal/entries",
                        json={
                            "gate_id": str(w.gate_a),
                            "lane_id": str(w.lane_a_in),
                            "evaluation_id": ev["evaluation_id"],
                        },
                    )
                    assert r.status_code == 200
                    th.join(timeout=10)
                    assert seen, "terminal B never saw the entry"
                    latencies.append((seen[0] - t_send) * 1000)
                    last = cb.get(f"/v1/terminal/feed?after={last}").json()["last_id"]
            finally:
                ca.close()
                cb.close()
        record(
            "NFR-04",
            {
                "samples": len(latencies),
                "p50_ms": round(percentile(latencies, 50), 2),
                "p95_ms": round(percentile(latencies, 95), 2),
                "p99_ms": round(percentile(latencies, 99), 2),
                "max_ms": round(max(latencies), 2),
                "target_p95_ms": 1000,
                "note": "loopback, one process; not a real LAN",
            },
        )
        assert percentile(latencies, 95) <= 1000
    finally:
        gw.stop()


def bulk_events(gw: Any, n: int, pad: int, at: Any) -> None:
    with gw.store.transaction():
        for _ in range(n):
            gw.outbox.append(
                type="EntryObserved",
                entity_id=uuid7(),
                entity_version=1,
                payload={"gate_id": "g", "pad": "x" * pad},
                occurred_at=at,
                clock_uncertainty_ms=50,
                policy_version=1,
            )


@pytest.mark.slow
@pytest.mark.req("NFR-09", "EDGE-03", "EDGE-08")
def test_nfr09_72_hours_60000_events_with_restarts_no_loss(tmp_path: Path) -> None:
    """60,000 observed entries over 72 SIMULATED hours through the real evaluate/record_entry path, 6 process restarts
    (store closed and reopened, full integrity check each time), WAN down throughout, then recovery to FakeCloud."""
    w, t, gw = standard_world_with_policy(tmp_path)
    cloud = FakeCloud(w.society_id, t.wall)
    cloud.register_device(w.gateway_device, w.device_signer.public_key)
    cloud.online = False
    total, restarts = 60_000, 6
    per_slice = total // restarts
    cred = {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}
    acked_ids: list[str] = []
    restart_ms: list[float] = []
    t_start = time.perf_counter()
    try:
        for _slice_no in range(restarts):
            actor = w.actor(gw, w.term_a)
            step = 12 * 3600 / per_slice
            for _ in range(per_slice):
                t.advance(step)
                ev = gw.evaluate(actor, gate_id=w.gate_a, lane_id=w.lane_a_in, credential=cred)
                if (
                    ev["decision"]["outcome"] != "allow"
                ):  # between 12 h boundaries the policy is < 72 h old
                    pytest.fail(f"unexpected decision {ev['decision']}")
                r = gw.record_entry(
                    actor, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
                )
                acked_ids.append(r["event_id"])
            gw.stop()
            r0 = time.perf_counter()
            gw = w.gateway(
                tmp_path / "edge", t, trusted=False
            )  # restart: integrity check + policy reload
            restart_ms.append((time.perf_counter() - r0) * 1000)
        record_s = time.perf_counter() - t_start
        stats = gw.outbox.stats()
        assert stats["last_seq"] == total and stats["pending"] == total
        assert [
            r["event_id"] for r in gw.store.all("SELECT event_id FROM outbox ORDER BY seq")
        ] == acked_ids  # nothing lost, nothing reordered
        db_mb = sum(p.stat().st_size for p in (tmp_path / "edge").glob("edge.sqlite3*")) / 1e6
        # recovery: WAN back, trusted time restored through the first response
        cloud.online = True
        cloud.now = t.wall
        client = SyncClient(
            gw, cloud.transport(), SyncConfig(), sleep=lambda s: None, rng=random.Random(2)
        )
        s0 = time.perf_counter()
        res = client.sync_once()
        sync_s = time.perf_counter() - s0
        assert res.acked == total and not res.failed
        assert (
            cloud.accepted_seqs(w.gateway_device) == list(range(1, total + 1))
            and len(cloud.events) == total
        )
        record(
            "NFR-09",
            {
                "events": total,
                "simulated_hours": 72,
                "restarts": restarts,
                "record_wall_s": round(record_s, 1),
                "per_event_ms": round(record_s / total * 1000, 2),
                "restart_ms_max": round(max(restart_ms)),
                "db_mb_at_60k_events": round(db_mb, 1),
                "sync_cpu_s_incl_fake_cloud_verification": round(sync_s, 1),
                "lost": 0,
                "duplicates": 0,
            },
        )
    finally:
        gw.stop()


@pytest.mark.slow
@pytest.mark.req("NFR-10", "EDGE-03")
@pytest.mark.parametrize(
    ("name", "overhead", "rtt_s"),
    [("ideal_5mbps", 1.0, 0.05), ("pessimistic_5mbps_25pct_overhead_200ms_rtt", 1.25, 0.2)],
)
def test_nfr10_reconcile_60000_events_at_5mbps_SIMULATED(
    tmp_path: Path, name: str, overhead: float, rtt_s: float
) -> None:
    """SIMULATION: a throttled fake transport charges body_bits / 5 Mbps (x overhead) + RTT per request on a VIRTUAL clock. It
    shows the batching and acknowledgement logic fits the 10-minute target; it does NOT measure a real uplink."""
    w, t, gw = standard_world_with_policy(tmp_path)
    cloud = FakeCloud(w.society_id, t.wall)
    cloud.register_device(w.gateway_device, w.device_signer.public_key)
    try:
        bulk_events(gw, 60_000, 1450, gw.clock.assess().now)
        sizes = [
            int(r["size_bytes"]) for r in gw.store.all("SELECT size_bytes FROM outbox LIMIT 500")
        ]
        avg = statistics.mean(sizes)
        assert 1900 <= avg <= 2300, avg  # ~2 KB per event, as the NFR assumes
        throttled = ThrottledTransport(
            cloud.transport(), bits_per_s=5_000_000 / overhead, rtt_s=rtt_s
        )
        client = SyncClient(gw, throttled, SyncConfig(), sleep=lambda s: None, rng=random.Random(4))  # type: ignore[arg-type]
        c0 = time.perf_counter()
        res = client.sync_once()
        cpu_s = time.perf_counter() - c0
        assert res.acked == 60_000 and not res.failed
        assert cloud.accepted_seqs(w.gateway_device) == list(range(1, 60_001))
        record(
            "NFR-10-SIMULATION",
            {
                "variant": name,
                "events": 60_000,
                "avg_event_bytes": round(avg),
                "batches": res.batches,
                "bytes_up_mb": round(res.bytes_sent / 1e6, 1),
                "virtual_seconds": round(throttled.virtual_seconds, 1),
                "target_s": 600,
                "real_cpu_s": round(cpu_s, 1),
            },
        )
        assert throttled.virtual_seconds <= 600
        _ = (uuid, timedelta, START)
    finally:
        gw.stop()
