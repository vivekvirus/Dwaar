"""Helpers for the visit scenarios (AT-01 replays, AT-02, AT-03, AT-04) on the seeded acceptance world.

The ids come from the seeded database through the test ORACLE (``World.admin_rows``): they are what the API would hide.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient

from tests.acceptance._world import UA, Session, World


@dataclass(frozen=True)
class VisitIds:
    """The seeded visit objects of one society (the 'object IDs of A' of AT-01 that belong to this slice)."""

    society: uuid.UUID
    gate: uuid.UUID
    lane: uuid.UUID
    device: uuid.UUID
    pending_device: uuid.UUID | None
    invitation: uuid.UUID
    request: uuid.UUID
    visit: uuid.UUID
    exception: uuid.UUID | None
    unit: uuid.UUID

    def all_ids(self) -> set[str]:
        return {
            str(i)
            for i in (
                self.gate,
                self.lane,
                self.device,
                self.pending_device,
                self.invitation,
                self.request,
                self.visit,
                self.exception,
            )
            if i is not None
        }


def society_key(world: World, society: uuid.UUID) -> str:
    return "mh" if society == world.society_ref("mh").id else "ka"


def visit_ids(world: World, key: str = "mh") -> VisitIds:
    """Ids of the seeded gate, lane, device, pass, request, visit and exception of society ``key`` (mh = A)."""
    sid = world.society_ref(key).id

    def one(sql: str, *params: Any) -> Any:
        rows = world.admin_rows(sql, (sid, *params))
        return rows[0][0] if rows else None

    gate = one("SELECT id FROM gates WHERE society_id = %s ORDER BY created_at, id LIMIT 1")
    return VisitIds(
        society=sid,
        gate=gate,
        lane=one("SELECT id FROM lanes WHERE society_id = %s ORDER BY created_at, id LIMIT 1"),
        device=one(
            "SELECT id FROM devices WHERE society_id = %s AND state = 'active' ORDER BY created_at, id LIMIT 1"
        ),
        pending_device=one(
            "SELECT id FROM devices WHERE society_id = %s AND state = 'pending_approval' LIMIT 1"
        ),
        invitation=one(
            "SELECT id FROM invitations WHERE society_id = %s ORDER BY created_at, id LIMIT 1"
        ),
        request=one(
            "SELECT id FROM approval_requests WHERE society_id = %s ORDER BY created_at, id LIMIT 1"
        ),
        visit=one("SELECT id FROM visits WHERE society_id = %s ORDER BY created_at, id LIMIT 1"),
        exception=one(
            "SELECT id FROM exceptions WHERE society_id = %s ORDER BY created_at, id LIMIT 1"
        ),
        unit=one(
            "SELECT unit_id FROM approval_requests WHERE society_id = %s ORDER BY created_at, id LIMIT 1"
        ),
    )


def post_with_own_client(
    world: World,
    who: Session,
    path: str,
    body: dict[str, Any],
    society: uuid.UUID,
    key: str | None = None,
) -> Any:
    """One POST on a client of its own (its own event loop, its own database transaction): what a phone does."""
    client = TestClient(world.app, raise_server_exceptions=False, headers=UA)
    return client.post(
        path,
        json=body,
        headers={
            **who.headers,
            "X-Society-Id": str(society),
            "Idempotency-Key": key or f"acc-{uuid.uuid4()}",
        },
    )


def race(jobs: list[Callable[[], Any]]) -> list[Any]:
    """Run every job at the same instant on its own thread and return the results in order."""
    barrier = threading.Barrier(len(jobs))

    def run(job: Callable[[], Any]) -> Any:
        barrier.wait()
        return job()

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        return [f.result() for f in [pool.submit(run, job) for job in jobs]]


def raise_request(
    world: World, guard: Session, ids: VisitIds, unit: uuid.UUID, alias: str, **extra: Any
) -> dict[str, Any]:
    body = {
        "unit_id": str(unit), "kind": "guest", "visitor_alias": alias, "people_count": 1, "gate_id": str(ids.gate),
        "destination_confirmed": True,
        "notice": {"version": "visitor-notice-v1", "language": "en", "consent_given": True},
        **extra,
    }  # fmt: skip
    r = world.call(
        guard,
        "POST",
        "/v1/approval-requests",
        json=body,
        headers={"X-Society-Id": str(ids.society)},
    )
    assert r.status_code == 201, r.text
    out: dict[str, Any] = r.json()
    return out


def decision_body(decision: str, version: int) -> dict[str, Any]:
    return {
        "decision": decision,
        "expected_version": version,
        "client_action_id": str(uuid.uuid4()),
    }
