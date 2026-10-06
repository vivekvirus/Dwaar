# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022
"""Measured on this machine with the REAL wiring (gateway + real HTTP + real API + real PostgreSQL). A VM, NOT certified gateway hardware.

REQ: NFR-02 (a local decision never waits for the cloud), NFR-10 (reconcile), NFR-09 (no loss). Numbers are printed (and appended to
``DWAAR_BENCH_OUT`` when set); the assertions are deliberately generous so a loaded machine does not make the suite flaky: the point of
the test is that decisions stay local while a real upload is running, and that the drain over real HTTP completes with zero loss.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any

import pytest

from tests.integration.edge._support import EdgeWorld
from tests.integration.edge_e2e._cloud import Site
from tests.integration.edge_e2e._flows import enter, evaluate
from tests.integration.edge_gateway.support import percentile

pytestmark = [
    pytest.mark.req("NFR-02", "NFR-09", "NFR-10"),
    pytest.mark.simulation,
    pytest.mark.slow,
]


def record(name: str, value: dict[str, Any]) -> None:
    line = json.dumps({"bench": name, "environment": "VM, not certified hardware", **value})
    print("BENCH", line)
    out = os.environ.get("DWAAR_BENCH_OUT")
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def test_decisions_stay_local_and_fast_while_a_real_upload_drains_and_the_drain_loses_nothing(
    ew: EdgeWorld, site: Site
) -> None:
    ew.household("A-101", tenant=False, family=False)
    site.sync()
    cred = site.resident_cred(ew.soc.units["A-101"])
    guard = site.actor()
    n = 3000
    t0 = time.perf_counter()
    for _ in range(n):  # a backlog as after an outage
        enter(site, cred, actor=guard)
        site.advance(1)
    build_s = time.perf_counter() - t0
    assert site.gw.outbox.stats()["pending"] == n

    done = threading.Event()
    drained: dict[str, float] = {}

    def upload() -> None:
        started = time.perf_counter()
        for _ in range(60):
            site.sync()
            if site.gw.outbox.stats()["pending"] == 0:
                break
        drained["s"] = time.perf_counter() - started
        done.set()

    worker = threading.Thread(target=upload)
    worker.start()
    latencies: list[float] = []
    while not done.is_set() or len(latencies) < 300:
        started = time.perf_counter()
        decision = evaluate(site, cred, actor=guard)["decision"]
        latencies.append((time.perf_counter() - started) * 1000)
        assert decision["outcome"] == "allow"
        if len(latencies) >= 2000:
            break
    worker.join(timeout=300)
    assert done.is_set() and site.gw.outbox.stats()["pending"] == 0
    cloud_rows = site.cloud_events()
    assert len(cloud_rows) == n and [int(r[1]) for r in cloud_rows] == list(
        range(1, n + 1)
    )  # zero loss, contiguous
    p50, p95, p99 = (percentile(latencies, p) for p in (50, 95, 99))
    record(
        "decision_during_real_upload",
        {
            "decisions": len(latencies), "p50_ms": round(p50, 2), "p95_ms": round(p95, 2), "p99_ms": round(p99, 2),
            "backlog_events": n, "drain_s": round(drained["s"], 2), "drain_events_per_s": round(n / drained["s"], 1),
            "build_backlog_s": round(build_s, 2), "target": "NFR-02 p95 <= 150 ms (certified hardware, 50,000 credentials: NOT claimed)",
        },
    )  # fmt: skip
    assert p95 < 500, (
        f"decision p95 {p95:.1f} ms while uploading (a loaded VM; the NFR target is 150 ms on certified hardware)"
    )


def test_a_policy_with_2000_residents_applies_over_real_http(ew: EdgeWorld, site: Site) -> None:
    """The size the cloud publishes for a mid-sized society; 50,000 credentials (NFR-02 sizing) are measured in-process by the edge suite."""
    with ew.idh.db.admin_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))  # type: ignore[call-overload]
        unit = ew.soc.units["A-101"]
        for _ in range(2000):
            person = uuid.uuid4()
            conn.execute(  # type: ignore[call-overload]
                "INSERT INTO iam.persons (id, display_name, phone_token, status) VALUES (%s, 'Bench Resident', %s, 'active')",
                (person, uuid.uuid4().hex),
            )
            conn.execute(  # type: ignore[call-overload]
                "INSERT INTO memberships (id, society_id, person_id, unit_id, kind, lives_in_unit, verification, effective_from, created_by)"
                " VALUES (gen_random_uuid(), %s, %s, %s, 'tenant', true, 'verified', current_date - 1, %s)",
                (ew.soc.id, person, unit, person),
            )
    started = time.perf_counter()
    res = site.sync()
    elapsed = time.perf_counter() - started
    pol = site.gw.policy
    assert res.policy == "applied" and pol is not None and len(pol.residents) >= 2000
    record(
        "policy_2000_residents_real_http",
        {"residents": len(pol.residents), "publish_download_verify_apply_s": round(elapsed, 2)},
    )
