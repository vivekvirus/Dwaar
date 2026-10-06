"""Dramatiq actors for the worker jobs. Built against an explicit broker so tests use ``StubBroker`` and production uses Redis.

``build_actors(broker, runtime)`` registers two actors on ``queue`` and returns them. The actors take no business data (just a trigger),
so a replayed or duplicated message is harmless: the jobs are idempotent (jobs.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dramatiq

from dwaar_api.core.db import Database
from dwaar_api.modules.edge.config import EdgeConfig
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.providers import ProviderSet

from . import jobs, notification_jobs
from .config import WorkerConfig


@dataclass
class Runtime:
    """What the jobs need: the database (worker role) and the policy issuer configuration."""

    db: Database
    edge: EdgeConfig
    last: dict[str, jobs.JobResult] | None = None
    #: notifications slice: the provider adapters the cascade may use (labelled simulators in local/test, none otherwise) and its configuration
    providers: ProviderSet | None = None
    notifications: NotificationsConfig | None = None


@dataclass(frozen=True)
class Actors:
    publish_policy: Any
    sweep_visits: Any
    notifications_tick: Any = None


def build_actors(broker: dramatiq.Broker, runtime: Runtime, config: WorkerConfig) -> Actors:
    runtime.last = {}

    @dramatiq.actor(
        broker=broker, queue_name=config.queue, actor_name="edge_publish_policy", max_retries=3
    )
    def edge_publish_policy() -> None:
        runtime.last["publish_policy"] = jobs.publish_policies(runtime.db, runtime.edge)  # type: ignore[index]

    @dramatiq.actor(
        broker=broker, queue_name=config.queue, actor_name="visits_sweep", max_retries=3
    )
    def visits_sweep() -> None:
        runtime.last["sweep_visits"] = jobs.sweep_visits(runtime.db)  # type: ignore[index]

    # max_retries=0: the tick is re-sent every second, a retry of a failed one would only duplicate work (the jobs are idempotent anyway)
    @dramatiq.actor(
        broker=broker,
        queue_name=config.queue,
        actor_name="notifications_tick",
        max_retries=0,
        time_limit=30_000,
    )
    def notifications_tick() -> None:
        runtime.last["notifications_tick"] = notification_jobs.notification_tick(  # type: ignore[index]
            runtime.db, runtime.providers or ProviderSet(), cfg=runtime.notifications
        )

    return Actors(edge_publish_policy, visits_sweep, notifications_tick)
