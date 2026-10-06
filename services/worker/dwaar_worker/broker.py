"""Dramatiq broker construction: Redis from the environment, the in-memory ``StubBroker`` for tests (Redis is never started by a test)."""

from __future__ import annotations

import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker

from .config import WorkerConfig


def make_redis_broker(config: WorkerConfig) -> dramatiq.Broker:
    """A Redis broker for ``config.redis_url``. Construction does not connect; the first enqueue does."""
    return RedisBroker(url=config.redis_url)  # type: ignore[no-untyped-call]


def make_stub_broker() -> StubBroker:
    broker = StubBroker()
    broker.emit_after("process_boot")
    return broker
