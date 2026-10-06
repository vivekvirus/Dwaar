"""The notification job function and the Dramatiq actor over the StubBroker (Redis never started), plus the two-device withdrawal measured through the
real scheduler loop.

REQ: NOTIF-03 (idempotent job functions safe under restarts and duplicate delivery), NOTIF-04 (decision -> other devices withdrawn within 2 s; MEASURED
here in the simulator, one process, real scheduler cadence of 1 s), PRD 13 (Dramatiq actors on StubBroker), INV-01 (one society's failure does not stop
the others), IAM-11.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import dramatiq
import pytest

from dwaar_api.core.db import Database
from dwaar_worker.actors import Actors, Runtime, build_actors
from dwaar_worker.broker import make_stub_broker
from dwaar_worker.config import WorkerConfig
from dwaar_worker.notification_jobs import notification_tick
from dwaar_worker.scheduler import run_scheduler
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("NOTIF-03", "NOTIF-04")]
CONFIG = WorkerConfig(queue="dwaar-notify-it", notify_interval_s=1)


class _Idle:
    def send(self) -> None:
        return None


@contextmanager
def running(nw: NW) -> Iterator[tuple[Any, Actors, dramatiq.Worker, Runtime]]:
    broker = make_stub_broker()
    runtime = Runtime(nw.database, None, providers=nw.providers, notifications=nw.cfg)  # type: ignore[arg-type]
    actors = build_actors(broker, runtime, CONFIG)
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()
    try:
        yield broker, actors, worker, runtime
    finally:
        worker.stop()
        broker.close()


def _prepare(nw: NW) -> tuple[Any, Any, dict[str, Any]]:
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    nw.register_device(family, "family-phone")
    nw.set_settings(
        owner,
        nw.unit("A-101"),
        primary_person_id=owner.id,
        approver_person_ids=[owner.id, family.id],
    )
    return owner, family, nw.raise_request(nw.unit("A-101"))


def test_the_job_function_reports_what_it_did_and_a_rerun_changes_nothing(nw: NW) -> None:
    owner, family, request = _prepare(nw)
    t0 = nw.created_at(request["id"])
    assert nw.database is not None
    first = notification_tick(
        nw.database, nw.providers, cfg=nw.cfg, clock=lambda: t0, societies=[nw.soc.id]
    )
    assert first.failed == {} and first.societies == 1 and first.changed == 1
    assert (
        first.detail["cascades_started"] == 1
        and first.detail["created_push"] == 2
        and first.detail["accepted_push"] == 2
    )
    again = notification_tick(
        nw.database, nw.providers, cfg=nw.cfg, clock=lambda: t0, societies=[nw.soc.id]
    )
    assert again.changed == 0 and again.detail.get("created_push", 0) == 0
    assert nw.count("notifications", "request_id = %s", (request["id"],)) == 2


def test_all_societies_default_and_a_failing_society_does_not_stop_the_others(nw: NW) -> None:
    owner, family, request = _prepare(nw)
    assert nw.database is not None
    t0 = nw.created_at(request["id"])
    bogus = uuid.uuid4()  # a society id the database does not know: its transaction finds no rows and does nothing, the real one still runs
    result = notification_tick(
        nw.database, nw.providers, cfg=nw.cfg, clock=lambda: t0, societies=[bogus, nw.soc.id]
    )
    assert result.societies == 2 and result.detail["cascades_started"] == 1
    default = notification_tick(
        nw.database, nw.providers, cfg=nw.cfg, clock=lambda: t0
    )  # every active society
    assert default.societies >= 1 and default.failed == {}


def test_the_actor_runs_the_tick_and_duplicate_messages_are_harmless(nw: NW) -> None:
    owner, family, request = _prepare(nw)
    t0 = nw.created_at(request["id"])
    with running(nw) as (broker, actors, worker, runtime):
        for _ in range(3):
            actors.notifications_tick.send()  # a duplicated or replayed message
        broker.join(CONFIG.queue)
        worker.join()
    assert runtime.last is not None and runtime.last["notifications_tick"].failed == {}
    assert nw.count("notification_cascades", "request_id = %s", (request["id"],)) == 1
    assert (
        nw.count("notifications", "request_id = %s", (request["id"],)) == 2
    )  # once per approver, not three times
    assert len(nw.sims.push.sent) == 2
    assert t0 is not None


def test_a_decision_withdraws_the_other_device_within_two_seconds_through_the_real_scheduler_loop(
    nw: NW,
) -> None:
    owner, family, request = _prepare(nw)
    stop = threading.Event()
    with running(nw) as (broker, actors, worker, _runtime):
        only_notify = Actors(
            _Idle(), _Idle(), actors.notifications_tick
        )  # the other two jobs are not under test here
        loop = threading.Thread(
            target=lambda: run_scheduler(
                only_notify,
                WorkerConfig(
                    queue=CONFIG.queue,
                    policy_interval_s=3600,
                    sweep_interval_s=3600,
                    notify_interval_s=1,
                ),
                should_stop=stop.is_set,
            ),
            daemon=True,
        )
        loop.start()
        try:
            deadline = time.monotonic() + 5
            while (
                time.monotonic() < deadline
                and nw.count("notifications", "request_id = %s", (request["id"],)) < 2
            ):
                time.sleep(0.05)
            assert (
                nw.count("notifications", "request_id = %s", (request["id"],)) == 2
            )  # the cascade started by itself, no manual tick
            time.sleep(0.4)  # let the tick settle at a point that is NOT aligned with the next one
            family_nid = nw.rows(
                "SELECT id FROM notifications WHERE request_id = %s AND recipient_person_id = %s",
                (request["id"], family.id),
            )[0][0]
            started = time.monotonic()
            d = nw.call(owner, "POST", nw.s(f"notifications/{nw.rows('SELECT id FROM notifications WHERE request_id = %s AND recipient_person_id = %s', (request['id'], owner.id))[0][0]}/action"),
                        json={"action": "approve", "client_action_id": str(uuid.uuid4())})  # fmt: skip
            assert d.status_code == 200, d.text
            while time.monotonic() - started < 3:
                if (
                    nw.rows("SELECT state FROM notifications WHERE id = %s", (family_nid,))[0][0]
                    == "expired"
                ):
                    break
                time.sleep(0.02)
            elapsed = time.monotonic() - started
        finally:
            stop.set()
            loop.join(timeout=5)
            broker.join(CONFIG.queue)
            worker.join()
    assert nw.rows(
        "SELECT state, closed_reason FROM notifications WHERE id = %s", (family_nid,)
    ) == [("expired", "request_decided")]
    print(f"NOTIF04_MEASURED_SECONDS={elapsed:.3f}")
    assert elapsed < 2.0, (
        elapsed
    )  # NOTIF-04 target (SIMULATION: StubBroker, one process, 1 s scheduler cadence); the number is recorded in the ADR
    assert nw.sims.push.cancelled


def test_a_restarted_worker_with_a_fresh_runtime_continues_the_same_cascade(nw: NW) -> None:
    owner, family, request = _prepare(nw)
    nw.sim_device("owner-phone").force_stopped = True
    t0 = nw.created_at(request["id"])
    assert nw.database is not None
    notification_tick(
        nw.database, nw.providers, cfg=nw.cfg, clock=lambda: t0, societies=[nw.soc.id]
    )
    fresh_db = Database.from_settings(
        nw.app.state.settings
    )  # a new process: new engines, no memory of the old one
    try:
        notification_tick(
            fresh_db, nw.providers, cfg=nw.cfg, clock=lambda: t0 + secs(20), societies=[nw.soc.id]
        )
        notification_tick(
            fresh_db, nw.providers, cfg=nw.cfg, clock=lambda: t0 + secs(20), societies=[nw.soc.id]
        )
    finally:
        fresh_db.dispose()
    channels = [(r["channel"], r["recipient_role"]) for r in nw.nrows(request["id"])]
    assert channels.count(("ivr_call", "primary")) == 1 and channels.count(("push", "primary")) == 1
