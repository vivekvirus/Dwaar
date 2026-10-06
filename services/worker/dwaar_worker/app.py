"""Process entry points. ``dramatiq dwaar_worker.app`` runs the workers (Redis from ``DWAAR_REDIS_URL``);
``python -m dwaar_worker.scheduler`` (see ``__main__``) sends the periodic triggers.

Importing this module needs the real environment (database URLs, issuer key): it is the deployment entry point, never imported by tests.
"""

from __future__ import annotations

import dramatiq

from dwaar_api.core.config import load_settings
from dwaar_api.core.db import Database
from dwaar_api.modules.edge.config import EdgeConfig
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.providers import ProviderSet, SimulatedProviders

from .actors import Actors, Runtime, build_actors
from .broker import make_redis_broker
from .config import WorkerConfig

config = WorkerConfig.from_env()
settings = load_settings()
broker = make_redis_broker(config)
dramatiq.set_broker(broker)
notifications = NotificationsConfig.from_environment(settings)
# Real vendor adapters are not built (D-21): outside local/test the set is empty, every send is recorded as ``provider_not_configured`` and the guard
# is shown the assisted options and the intercom / office process.
providers = (
    ProviderSet.from_simulators(SimulatedProviders()) if notifications.simulation else ProviderSet()
)
runtime = Runtime(
    Database.from_settings(settings),
    EdgeConfig.from_environment(settings),
    providers=providers,
    notifications=notifications,
)
actors: Actors = build_actors(broker, runtime, config)
