"""The adapter registry: what is configured, and, for what is not, the SPECIFIC missing dependency (administrators only).

REQ: D-21 (telephony, SMS, WhatsApp vendors are [TBD]), BUILD_BRIEF 6 (a requirement that depends on external reality is
``blocked-external``: adapter interface + simulator, disabled by default, the missing dependency shown to authorised admins only),
CALL-01 (an outage exposes the intercom or office process), CALL-02.

Real vendor adapters are NOT built. ``DWAAR_NOTIFICATION_PROVIDERS=simulator`` selects the labelled simulators and is honoured ONLY when the
environment is local or test (``Settings.simulation``). Anywhere else every kind reports ``not configured: <dependency>`` and the cascade
degrades to what needs no provider: the guard-assisted options and the intercom / office process.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Final

from .base import Kind, Provider, ProviderStatus
from .simulators import SimulatedProviders

#: the specific, honest reason each kind cannot be live (no vendor name is invented: D-21 says [TBD])
MISSING: Final[dict[Kind, tuple[str, str]]] = {
    Kind.PUSH: (
        "push",
        "not configured: FCM project credentials and an APNs auth key, plus an envelope key to store device tokens "
        "(the simulated registry keeps only a hash)",
    ),
    Kind.IVR: (
        "ivr",
        "not configured: Indian cloud-telephony account with a masked-number and IVR product (D-21 vendor is TBD)",
    ),
    Kind.SMS: (
        "sms",
        "not configured: DLT principal-entity registration, a registered sender header, registered template ids and an "
        "SMS gateway account (D-21 vendor is TBD)",
    ),
    Kind.WHATSAPP: (
        "whatsapp",
        "not configured: WhatsApp Business API provider account and approved utility templates (D-21 vendor is TBD)",
    ),
}
SIMULATOR_NAMES: Final[dict[Kind, str]] = {
    Kind.PUSH: "simulated-push",
    Kind.IVR: "simulated-ivr",
    Kind.SMS: "simulated-sms",
    Kind.WHATSAPP: "simulated-whatsapp",
}


def providers_mode(environ: Mapping[str, str] | None = None, *, simulation_allowed: bool) -> str:
    """``simulator`` only when asked for AND the environment allows simulators; otherwise ``none``."""
    env = os.environ if environ is None else environ
    wanted = env.get("DWAAR_NOTIFICATION_PROVIDERS", "").strip().lower()
    if wanted == "simulator" and simulation_allowed:
        return "simulator"
    if not wanted and simulation_allowed:
        return (
            "simulator"  # local and test default: the demonstrator works out of the box, labelled
        )
    return "none"


def registry_status(mode: str) -> list[ProviderStatus]:
    rows: list[ProviderStatus] = []
    for kind in Kind:
        if mode == "simulator":
            rows.append(
                ProviderStatus(
                    kind.value,
                    SIMULATOR_NAMES[kind],
                    "simulator",
                    True,
                    "labelled simulator (simulation=true): no message leaves this machine",
                )
            )
        else:
            rows.append(
                ProviderStatus(kind.value, "none", "not_configured", False, MISSING[kind][1])
            )
    return rows


class ProviderSet:
    """The adapters a job may use, by kind. A kind with no adapter is simply absent: the sender records ``provider_not_configured`` and the
    cascade carries on with what remains (the guard-assisted options never need a provider)."""

    def __init__(self, providers: Iterable[Provider] = ()) -> None:
        self._by_kind: dict[Kind, Provider] = {p.kind: p for p in providers}

    def get(self, kind: Kind) -> Provider | None:
        return self._by_kind.get(kind)

    def kinds(self) -> list[Kind]:
        return list(self._by_kind)

    def all(self) -> list[Provider]:
        return list(self._by_kind.values())

    @classmethod
    def from_simulators(cls, sims: SimulatedProviders) -> ProviderSet:
        return cls([sims.push, sims.ivr, sims.sms, sims.whatsapp])
