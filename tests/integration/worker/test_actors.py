"""The Dramatiq actors over the in-memory StubBroker (Redis is never started) and the scheduler: duplicate and replayed messages are harmless.

REQ: EDGE-04, PRD 13 (workers: Dramatiq + Redis adapter, job logic = plain functions, StubBroker in tests), GATE-02, GATE-11.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import dramatiq
import pytest

from dwaar_worker.actors import Actors, Runtime, build_actors
from dwaar_worker.broker import make_stub_broker
from dwaar_worker.config import WorkerConfig
from dwaar_worker.scheduler import run_scheduler
from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("EDGE-04", "GATE-02", "GATE-11")]

CONFIG = WorkerConfig(queue="dwaar-test", policy_interval_s=5, sweep_interval_s=10)


@contextmanager
def running(runtime: Runtime) -> Iterator[tuple[object, Actors, dramatiq.Worker]]:
    broker = make_stub_broker()
    actors = build_actors(broker, runtime, CONFIG)
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()
    try:
        yield broker, actors, worker
    finally:
        worker.stop()
        broker.close()


def drain(broker: object, worker: dramatiq.Worker) -> None:
    broker.join(CONFIG.queue)  # type: ignore[attr-defined]
    worker.join()


def test_publish_actor_runs_the_job_and_a_duplicate_message_is_harmless(
    ew: EdgeWorld, runtime: Runtime
) -> None:
    with running(runtime) as (broker, actors, worker):
        actors.publish_policy.send()
        actors.publish_policy.send()  # a duplicated or replayed message
        drain(broker, worker)
    assert runtime.last is not None and runtime.last["publish_policy"].failed == {}
    assert ew.rows("SELECT count(*) FROM policy_snapshots WHERE society_id = %s", (ew.soc.id,)) == [
        (1,)
    ]  # published once, not twice


def test_sweep_actor_runs_the_sweep_and_never_double_applies(
    ew: EdgeWorld, runtime: Runtime
) -> None:
    ew.household("A-101", tenant=False, family=False)
    request = ew.raise_request(ew.soc.units["A-101"])
    ew.expire_request(request["id"])
    with running(runtime) as (broker, actors, worker):
        for _ in range(3):
            actors.sweep_visits.send()
        drain(broker, worker)
    assert runtime.last is not None and runtime.last["sweep_visits"].failed == {}
    assert ew.rows("SELECT state FROM approval_requests WHERE id = %s", (request["id"],)) == [
        ("expired",)
    ]
    assert ew.rows("SELECT count(*) FROM audit_log WHERE operation = 'approval.expire'") == [(1,)]


def test_the_actors_are_registered_on_the_configured_queue_without_touching_redis(
    runtime: Runtime,
) -> None:
    with running(runtime) as (broker, actors, _worker):
        assert {a.actor_name for a in (actors.publish_policy, actors.sweep_visits)} == {
            "edge_publish_policy",
            "visits_sweep",
        }
        assert {a.queue_name for a in (actors.publish_policy, actors.sweep_visits)} == {
            CONFIG.queue
        }
        assert type(broker).__name__ == "StubBroker"


def test_scheduler_sends_each_actor_on_its_own_cadence() -> None:
    sent: list[str] = []

    class Spy:
        def __init__(self, name: str) -> None:
            self.name = name

        def send(self) -> None:
            sent.append(self.name)

    now = {"t": 0.0}

    def clock() -> float:
        return now["t"]

    def sleep(seconds: float) -> None:
        now["t"] += 5.0  # a virtual 5 seconds per round

    stops = {"n": 0}

    def should_stop() -> bool:
        stops["n"] += 1
        return stops["n"] > 7  # seven rounds at t = 0, 5, ..., 30 virtual seconds

    total = run_scheduler(
        Actors(Spy("publish"), Spy("sweep")),
        CONFIG,
        should_stop=should_stop,
        sleep=sleep,
        clock=clock,
    )
    assert (
        sent.count("publish") == 7 and sent.count("sweep") == 4 and total == 11
    )  # every 5 s and every 10 s, the first round at once
