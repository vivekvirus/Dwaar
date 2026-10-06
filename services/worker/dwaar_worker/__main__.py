"""``python -m dwaar_worker``: send the periodic triggers (the work itself runs in ``dramatiq dwaar_worker.app``)."""

from __future__ import annotations

import signal
import threading

from .app import actors, config
from .scheduler import run_scheduler


def main() -> int:
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    run_scheduler(actors, config, should_stop=stop.is_set)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
