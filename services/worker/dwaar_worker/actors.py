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

from . import jobs
from .config import WorkerConfig


@dataclass
class Runtime:
    """What the jobs need: the database (worker role) and the policy issuer configuration."""

    db: Database
    edge: EdgeConfig
    last: dict[str, jobs.JobResult] | None = None


@dataclass(frozen=True)
class Actors:
    publish_policy: Any
    sweep_visits: Any


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

    return Actors(edge_publish_policy, visits_sweep)
