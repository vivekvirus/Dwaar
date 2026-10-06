"""The worker jobs as the ``dwaar_worker`` role: the edge policy publisher and the visits expiry / overstay sweep (idempotent re-runs).

REQ: EDGE-04, PRD 13 (workers), GATE-02, GATE-05, GATE-11, PRD 12.4 (audit + outbox with every mutation), INV-01, INV-03.
Environment: real PostgreSQL, real roles; no Redis (the actors use the in-memory StubBroker in test_actors.py).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest

from dwaar_api.core.db import Database
from dwaar_api.modules.edge.config import EdgeConfig
from dwaar_worker import jobs
from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("EDGE-04", "GATE-02", "GATE-05", "GATE-11", "INV-01", "INV-03")]


def make_pass(ew: EdgeWorld, owner: Any, unit: uuid.UUID, hours: float = 2) -> dict[str, Any]:
    start = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    r = ew.call(
        owner, "POST", ew.s("invitations"),
        json={"unit_id": str(unit), "purpose": "Dinner", "visitor_alias": "Aunt Sulabha", "people_count": 2,
              "windows": [{"start": start.isoformat(), "end": (start + dt.timedelta(hours=hours)).isoformat()}], "max_uses": 1},
    )  # fmt: skip
    assert r.status_code == 201, r.text
    view: dict[str, Any] = r.json()
    return view


# ------------------------------------------------------------------------------------------ the policy publisher
def test_the_worker_lists_active_societies_without_a_cross_society_read(
    ew: EdgeWorld, worker_db: Database
) -> None:
    other = ew.idh.society("Other Heights", units=("A-1",))
    ids = jobs.active_society_ids(worker_db)
    assert {ew.soc.id, other.id} <= set(ids)
    # the worker role itself still sees NO society row without a context (FORCE RLS), only ids through the reviewed function
    with worker_db.worker_tx() as conn:
        from sqlalchemy import text

        assert conn.execute(text("SELECT count(*) FROM societies")).scalar_one() == 0


def test_publish_job_writes_the_first_snapshot_per_society_and_a_rerun_changes_nothing(
    ew: EdgeWorld, worker_db: Database, edge_cfg: EdgeConfig
) -> None:
    other = ew.idh.society("Other Heights", units=("A-1",))
    first = jobs.publish_policies(worker_db, edge_cfg)
    assert first.failed == {} and first.societies >= 2 and first.changed >= 2
    rows = ew.rows("SELECT society_id, seq, reason FROM policy_snapshots ORDER BY seq, society_id")
    assert (
        {r[0] for r in rows} >= {ew.soc.id, other.id}
        and {r[1] for r in rows} == {1}
        and {r[2] for r in rows} == {"initial"}
    )
    audits = ew.rows("SELECT count(*) FROM audit_log WHERE operation = 'edge.policy_publish'")[0][0]
    events = ew.rows("SELECT count(*) FROM outbox WHERE event_type = 'PolicyPublished'")[0][0]
    assert (
        audits == events == len(rows)
    )  # audit + outbox with the mutation, written by the worker role
    again = jobs.publish_policies(
        worker_db, edge_cfg
    )  # idempotent: nothing changed, nothing written
    assert again.failed == {} and again.changed == 0
    assert ew.rows("SELECT count(*) FROM policy_snapshots")[0][0] == len(rows)
    assert (
        ew.rows("SELECT count(*) FROM audit_log WHERE operation = 'edge.policy_publish'")[0][0]
        == audits
    )


def test_publish_job_follows_changes_and_serves_the_same_snapshot_the_device_endpoint_serves(
    ew: EdgeWorld, worker_db: Database, edge_cfg: EdgeConfig
) -> None:
    dev = ew.edge_device()
    jobs.publish_policies(worker_db, edge_cfg)
    h = ew.household("A-101", tenant=False, family=False)
    make_pass(ew, h.owner, ew.soc.units["A-101"])
    done = jobs.publish_policies(worker_db, edge_cfg, societies=[ew.soc.id])
    assert done.changed == 1 and done.detail == {"published_changed": 1}
    latest = ew.rows(
        "SELECT seq, jsonb_array_length(manifest -> 'invitations'), jsonb_array_length(manifest -> 'residents') FROM policy_snapshots WHERE society_id = %s ORDER BY seq DESC LIMIT 1",
        (ew.soc.id,),
    )
    assert latest == [(2, 1, 1)]
    served = dev.policy(
        0
    )  # the worker's snapshot is what a gateway receives (publish-on-poll finds nothing new to publish)
    assert served.status_code == 200 and served.json()["seq"] == 2
    forced = jobs.publish_policies(worker_db, edge_cfg, societies=[ew.soc.id], force=True)
    assert forced.changed == 1 and forced.detail == {"published_forced": 1}


def test_one_failing_society_does_not_stop_the_others(
    ew: EdgeWorld, worker_db: Database, edge_cfg: EdgeConfig
) -> None:
    ghost = (
        uuid.uuid4()
    )  # a society id that does not exist: the publisher cannot write a snapshot for it
    result = jobs.publish_policies(worker_db, edge_cfg, societies=[ghost, ew.soc.id])
    assert ghost in result.failed and result.changed == 1


# ------------------------------------------------------------------------------------------ the visits sweep
def test_sweep_expires_requests_and_authorisations_flags_overstays_and_expires_passes_then_reruns_idempotently(
    ew: EdgeWorld, worker_db: Database
) -> None:
    h = ew.household("A-101", tenant=False, family=False)
    unit = ew.soc.units["A-101"]
    ew.device_id = ew.make_device(ew.gate_id)  # the approved terminal that observes the entry below
    # 1. a pending approval request whose time is up -> expired (never allowed)
    pending = ew.raise_request(unit)
    ew.expire_request(pending["id"])
    # 2. an authorised visit that never entered, permission window over -> expired
    visit = ew.authorised_visit(ew.soc.units["A-102"])
    ew.age_authorisation(visit, minutes=600)
    # 3. a delivery that entered and stayed far too long -> exactly one overstay exception
    inside = ew.authorised_visit(ew.soc.units["B-201"])
    r = ew.observe(inside, "entry")
    assert r.status_code == 201, r.text
    ew.sql(
        "UPDATE visits SET kind = 'delivery', entered_at = now() - interval '3 hours' WHERE id = %s",
        (inside,),
    )
    # 4. a pass whose last window is over -> expired
    p = make_pass(ew, h.owner, unit, hours=1)
    ew.sql(
        "UPDATE invitation_windows SET window_start = now() - interval '3 hours', window_end = now() - interval '2 hours' WHERE invitation_id = %s",
        (p["id"],),
    )
    ew.sql(
        "UPDATE invitations SET window_start = now() - interval '3 hours', window_end = now() - interval '2 hours' WHERE id = %s",
        (p["id"],),
    )

    first = jobs.sweep_visits(worker_db, societies=[ew.soc.id])
    assert first.failed == {}, first.failed
    assert first.detail == {
        "requests_expired": 1,
        "authorisations_expired": 1,
        "overstays_opened": 1,
        "invitations_expired": 1,
    }
    assert ew.visit_state(visit) == "expired" and ew.visit_state(inside) == "inside"
    assert [r[0] for r in ew.exceptions()] == ["overstay"]
    assert ew.rows("SELECT state FROM invitations WHERE id = %s", (p["id"],)) == [("expired",)]
    assert ew.rows("SELECT state FROM approval_requests WHERE id = %s", (pending["id"],)) == [
        ("expired",)
    ]
    audits = ew.rows(
        "SELECT operation, count(*) FROM audit_log WHERE operation IN ('visit.expire','approval.expire','exception.open','invitation.expire') GROUP BY 1 ORDER BY 1"
    )
    assert dict(audits) == {
        "approval.expire": 1,
        "exception.open": 1,
        "invitation.expire": 1,
        "visit.expire": 1,
    }

    second = jobs.sweep_visits(
        worker_db, societies=[ew.soc.id]
    )  # idempotent: nothing left to do, nothing written
    assert second.failed == {} and second.detail == {
        "requests_expired": 0,
        "authorisations_expired": 0,
        "overstays_opened": 0,
        "invitations_expired": 0,
    }
    assert second.changed == 0
    assert dict(
        ew.rows(
            "SELECT operation, count(*) FROM audit_log WHERE operation IN ('visit.expire','approval.expire','exception.open','invitation.expire') GROUP BY 1 ORDER BY 1"
        )
    ) == dict(audits)
    assert ew.rows("SELECT count(*) FROM exceptions WHERE kind = 'overstay'") == [(1,)]


def test_a_timeout_never_allows_anyone_in(ew: EdgeWorld, worker_db: Database) -> None:
    unit = ew.soc.units["A-101"]
    ew.household("A-101", tenant=False, family=False)
    request = ew.raise_request(unit)
    ew.expire_request(request["id"])
    jobs.sweep_visits(worker_db, societies=[ew.soc.id])
    assert ew.visit_state(uuid.UUID(request["visit_id"])) == "expired"
    assert ew.rows("SELECT count(*) FROM visits WHERE state IN ('authorised', 'inside')") == [(0,)]
    assert ew.rows("SELECT count(*) FROM approval_decisions") == [(0,)]
