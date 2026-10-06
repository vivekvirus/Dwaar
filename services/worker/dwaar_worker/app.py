"""Process entry points. ``dramatiq dwaar_worker.app`` runs the workers (Redis from ``DWAAR_REDIS_URL``);
``python -m dwaar_worker.scheduler`` (see ``__main__``) sends the periodic triggers.

Importing this module needs the real environment (database URLs, issuer key): it is the deployment entry point, never imported by tests.
"""

from __future__ import annotations

import dramatiq

from dwaar_api.core.config import load_settings
from dwaar_api.core.db import Database
from dwaar_api.modules.edge.config import EdgeConfig

from .actors import Actors, Runtime, build_actors
from .broker import make_redis_broker
from .config import WorkerConfig

config = WorkerConfig.from_env()
settings = load_settings()
broker = make_redis_broker(config)
dramatiq.set_broker(broker)
runtime = Runtime(Database.from_settings(settings), EdgeConfig.from_environment(settings))
actors: Actors = build_actors(broker, runtime, config)
