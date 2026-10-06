"""A minimal periodic trigger: enqueue the policy publisher, the notification tick and the sweeps on their cadence.

Dramatiq has no scheduler; this loop only SENDS messages (the work happens in the worker processes). Run it as one process:
``python -m dwaar_worker.scheduler``. Stoppable and testable: ``sleep`` and ``stop`` are injected.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .actors import Actors
from .config import WorkerConfig

_SWEEPS = (
    "helpdesk_sweep",
    "notices_publish_due",
    "polls_close_due",
    "parcels_reminders",
    "shifts_sweep",
)


def run_scheduler(
    actors: Actors,
    config: WorkerConfig,
    *,
    should_stop: Callable[[], bool],
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Send each actor when its interval has elapsed; returns the number of messages sent. The first round is immediate."""
    due = {"publish": 0.0, "sweep": 0.0, "notify": 0.0}
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
        notify = getattr(actors, "notifications_tick", None)
        if notify is not None and elapsed >= due["notify"]:
            notify.send()
            due["notify"] = elapsed + config.notify_interval_s
            sent += 1
        # slice 4 sweeps (helpdesk SLA and closure, scheduled notices, poll closing, parcel reminders, shift handover escalation) share the sweep cadence:
        # every job is idempotent and cheap when nothing is due, and a one-minute delay changes nothing the PRD promises in minutes or hours.
        for name in _SWEEPS:
            actor = getattr(actors, name, None)
            if actor is not None and elapsed >= due.get(name, 0.0):
                actor.send()
                due[name] = elapsed + config.sweep_interval_s
                sent += 1
        sleep(min(1.0, config.policy_interval_s, config.sweep_interval_s, config.notify_interval_s))
    return sent
