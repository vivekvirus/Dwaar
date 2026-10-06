"""Notifications module configuration (environment only; no secrets here: provider credentials do not exist in this build).

REQ: D-21 (vendors TBD: the registry reports what is missing), NOTIF-03 (timings come from the society policy / ``dwaar_packs``, not from here),
CALL-01 (proxy session TTL), CALL-02 (link host whitelist), OBS-02.

* ``DWAAR_NOTIFICATION_PROVIDERS``      ``simulator`` (honoured only when ``DWAAR_ENV`` is local or test) or empty (= none configured).
* ``DWAAR_NOTIFICATION_LINK_HOSTS``     comma-separated hosts an SMS / WhatsApp link may use (default ``links.dwaar.example``).
* ``DWAAR_NOTIFICATION_CALL_TTL_S``     lifetime of a proxy-call session (default 120, range 30..600).
* ``DWAAR_NOTIFICATION_EVENT_LOOKBACK_H`` how far back the outbox consumer looks for unprocessed events (default 48, range 1..720).
* ``DWAAR_NOTIFICATION_FALLBACK_ALERT`` fallback share above which operations is told (default 0.30, range 0.01..1).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from ...core.config import ConfigError, Settings
from .categories import link_hosts
from .providers.registry import providers_mode

DEFAULT_TTL: Final = 120


@dataclass(frozen=True)
class NotificationsConfig:
    providers_mode: str = "none"  # simulator | none
    link_hosts: frozenset[str] = frozenset({"links.dwaar.example"})
    call_ttl_seconds: int = DEFAULT_TTL
    event_lookback_hours: int = 48
    fallback_alert_share: float = 0.30
    max_events_per_tick: int = 500
    max_cascades_per_tick: int = 200

    @property
    def simulation(self) -> bool:
        return self.providers_mode == "simulator"

    @classmethod
    def from_environment(
        cls,
        settings: Settings | None = None,
        environ: Mapping[str, str] | None = None,
        *,
        simulation_allowed: bool | None = None,
    ) -> NotificationsConfig:
        env = os.environ if environ is None else environ
        allowed = (
            simulation_allowed
            if simulation_allowed is not None
            else bool(settings and settings.simulation)
        )
        return cls(
            providers_mode=providers_mode(env, simulation_allowed=allowed),
            link_hosts=link_hosts(env),
            call_ttl_seconds=_int(env, "DWAAR_NOTIFICATION_CALL_TTL_S", DEFAULT_TTL, 30, 600),
            event_lookback_hours=_int(env, "DWAAR_NOTIFICATION_EVENT_LOOKBACK_H", 48, 1, 720),
            fallback_alert_share=_share(env),
        )


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _share(env: Mapping[str, str]) -> float:
    raw = env.get("DWAAR_NOTIFICATION_FALLBACK_ALERT", "").strip()
    if not raw:
        return 0.30
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError("DWAAR_NOTIFICATION_FALLBACK_ALERT must be a number") from None
    if not 0.01 <= value <= 1.0:
        raise ConfigError("DWAAR_NOTIFICATION_FALLBACK_ALERT must be between 0.01 and 1")
    return value
