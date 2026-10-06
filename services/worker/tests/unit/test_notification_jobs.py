# ruff: noqa: PT018
"""Notification worker wiring that needs no database: configuration, actor registration on the StubBroker, scheduler cadence.

REQ: NOTIF-03 / NOTIF-04 (the cascade tick runs every second by default), PRD 13 (Dramatiq actors over plain job functions; StubBroker in tests, Redis
never started), ARCH-04 (configuration from the environment, values never in error messages).
"""

from __future__ import annotations

import pytest

from dwaar_api.modules.notifications.providers import ProviderSet, SimulatedProviders
from dwaar_worker.actors import Actors, Runtime, build_actors
from dwaar_worker.broker import make_stub_broker
from dwaar_worker.config import WorkerConfig, WorkerConfigError
from dwaar_worker.scheduler import run_scheduler

pytestmark = [pytest.mark.req("NOTIF-03", "NOTIF-04")]


def test_the_notification_tick_defaults_to_one_second_and_is_bounded() -> None:
    assert WorkerConfig.from_env({}).notify_interval_s == 1
    assert WorkerConfig.from_env({"DWAAR_WORKER_NOTIFY_INTERVAL_S": "5"}).notify_interval_s == 5
    for bad in ("0", "61", "often", "-1"):
        with pytest.raises(WorkerConfigError) as e:
            WorkerConfig.from_env({"DWAAR_WORKER_NOTIFY_INTERVAL_S": bad})
        assert "DWAAR_WORKER_NOTIFY_INTERVAL_S" in str(e.value)
        assert "often" not in str(e.value)  # the message names the variable, never the value


def test_the_notification_actor_is_registered_on_the_configured_queue_without_redis() -> None:
    broker = make_stub_broker()
    config = WorkerConfig(queue="dwaar-notify-test")
    runtime = Runtime(None, None)  # type: ignore[arg-type]
    actors = build_actors(broker, runtime, config)
    try:
        assert actors.notifications_tick.actor_name == "notifications_tick"
        assert actors.notifications_tick.queue_name == "dwaar-notify-test"
        assert (
            actors.notifications_tick.options.get("max_retries") == 0
        )  # the next tick is a second away: no retry storm
        assert type(broker).__name__ == "StubBroker"
    finally:
        broker.close()


def test_the_runtime_carries_labelled_simulators_not_vendors() -> None:
    sims = SimulatedProviders()
    providers = ProviderSet.from_simulators(sims)
    assert {p.kind.value for p in providers.all()} == {"push", "ivr_call", "sms", "whatsapp"}
    assert all(p.simulation is True for p in providers.all())
    assert ProviderSet().all() == [] and ProviderSet().get(next(iter(providers.kinds()))) is None


def test_the_scheduler_sends_the_notification_tick_every_second_and_the_others_on_their_own_cadence() -> (
    None
):
    sent: list[str] = []

    class Spy:
        def __init__(self, name: str) -> None:
            self.name = name

        def send(self) -> None:
            sent.append(self.name)

    now = {"t": 0.0}
    rounds = {"n": 0}

    def sleep(_seconds: float) -> None:
        now["t"] += 1.0  # one virtual second per round

    def should_stop() -> bool:
        rounds["n"] += 1
        return rounds["n"] > 12  # t = 0 .. 11

    total = run_scheduler(
        Actors(Spy("publish"), Spy("sweep"), Spy("notify")),
        WorkerConfig(policy_interval_s=5, sweep_interval_s=10, notify_interval_s=1),
        should_stop=should_stop,
        sleep=sleep,
        clock=lambda: now["t"],
    )
    assert (
        sent.count("notify") == 12
        and sent.count("publish") == 3
        and sent.count("sweep") == 2
        and total == 17
    )


def test_a_scheduler_without_the_notification_actor_is_unchanged() -> None:
    sent: list[str] = []

    class Spy:
        def __init__(self, name: str) -> None:
            self.name = name

        def send(self) -> None:
            sent.append(self.name)

    now = {"t": 0.0}
    rounds = {"n": 0}

    def should_stop() -> bool:
        rounds["n"] += 1
        return rounds["n"] > 3

    def sleep(_s: float) -> None:
        now["t"] += 5.0

    run_scheduler(
        Actors(Spy("publish"), Spy("sweep")),
        WorkerConfig(policy_interval_s=5, sweep_interval_s=10),
        should_stop=should_stop,
        sleep=sleep,
        clock=lambda: now["t"],
    )
    assert "notify" not in sent and sent.count("publish") == 3
