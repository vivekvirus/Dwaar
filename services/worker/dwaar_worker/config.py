"""Worker configuration (environment only; no secrets in the repository).

REQ: ARCH-04 (configuration from the environment), PRD 13 (workers: edge policy publisher, visits sweeps).

``DWAAR_REDIS_URL``            the Dramatiq broker (Redis). Tests use the in-memory ``StubBroker`` and never start Redis.
``DWAAR_WORKER_QUEUE``         queue name the actors use (default ``dwaar``).
``DWAAR_WORKER_POLICY_INTERVAL_S`` / ``DWAAR_WORKER_SWEEP_INTERVAL_S``  scheduler cadence in seconds (default 60, range 5..86400).
``DWAAR_WORKER_NOTIFY_INTERVAL_S``  cadence of the notification cascade tick (default 1, range 1..60): the cascade steps are 10 s apart and a
decision must withdraw the other devices within 2 s (NOTIF-04), so this is the one job that runs every second.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

_QUEUE: Final = re.compile(r"^[a-z][a-z0-9_.-]{0,63}\Z")


class WorkerConfigError(Exception):
    """Invalid worker configuration; the message names the variable, never a value."""


@dataclass(frozen=True)
class WorkerConfig:
    redis_url: str = "redis://127.0.0.1:56379/0"
    queue: str = "dwaar"
    policy_interval_s: int = 60
    sweep_interval_s: int = 60
    notify_interval_s: int = 1

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> WorkerConfig:
        env = os.environ if environ is None else environ
        queue = env.get("DWAAR_WORKER_QUEUE", "").strip() or cls.queue
        if not _QUEUE.match(queue):
            raise WorkerConfigError("DWAAR_WORKER_QUEUE is not a valid queue name")
        redis_url = env.get("DWAAR_REDIS_URL", "").strip() or cls.redis_url
        if not redis_url.startswith(("redis://", "rediss://", "unix://")):
            raise WorkerConfigError("DWAAR_REDIS_URL must be a redis:// URL")
        return cls(
            redis_url=redis_url,
            queue=queue,
            policy_interval_s=_interval(env, "DWAAR_WORKER_POLICY_INTERVAL_S"),
            sweep_interval_s=_interval(env, "DWAAR_WORKER_SWEEP_INTERVAL_S"),
            notify_interval_s=_notify_interval(env),
        )


def _interval(env: Mapping[str, str], name: str) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return 60
    try:
        value = int(raw)
    except ValueError:
        raise WorkerConfigError(f"{name} must be an integer") from None
    if not 5 <= value <= 86_400:
        raise WorkerConfigError(f"{name} must be between 5 and 86400")
    return value


def _notify_interval(env: Mapping[str, str]) -> int:
    raw = env.get("DWAAR_WORKER_NOTIFY_INTERVAL_S", "").strip()
    if not raw:
        return 1
    try:
        value = int(raw)
    except ValueError:
        raise WorkerConfigError("DWAAR_WORKER_NOTIFY_INTERVAL_S must be an integer") from None
    if not 1 <= value <= 60:
        raise WorkerConfigError("DWAAR_WORKER_NOTIFY_INTERVAL_S must be between 1 and 60")
    return value
