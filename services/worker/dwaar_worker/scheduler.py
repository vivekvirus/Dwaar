"""A minimal periodic trigger: enqueue the policy publisher and the visits sweep on their cadence.

Dramatiq has no scheduler; this loop only SENDS messages (the work happens in the worker processes). Run it as one process:
``python -m dwaar_worker.scheduler``. Stoppable and testable: ``sleep`` and ``stop`` are injected.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .actors import Actors
from .config import WorkerConfig


def run_scheduler(
    actors: Actors,
    config: WorkerConfig,
    *,
    should_stop: Callable[[], bool],
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Send each actor when its interval has elapsed; returns the number of messages sent. The first round is immediate."""
    due = {"publish": 0.0, "sweep": 0.0}
    sent = 0
    start = clock()
    while not should_stop():
        elapsed = clock() - start
        if elapsed >= due["publish"]:
            actors.publish_policy.send()
            due["publish"] = elapsed + config.policy_interval_s
            sent += 1
        if elapsed >= due["sweep"]:
            actors.sweep_visits.send()
            due["sweep"] = elapsed + config.sweep_interval_s
            sent += 1
        sleep(min(1.0, config.policy_interval_s, config.sweep_interval_s))
    return sent
