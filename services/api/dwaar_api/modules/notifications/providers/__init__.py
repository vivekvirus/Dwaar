"""Provider adapters (interfaces, labelled simulators, registry). Real vendors are not built (D-21)."""

from .base import (
    DeviceTelemetry,
    Kind,
    OutboundMessage,
    Provider,
    ProviderEvent,
    ProviderStatus,
    SendResult,
)
from .registry import MISSING, ProviderSet, providers_mode, registry_status
from .simulators import (
    SimDevice,
    SimulatedIvr,
    SimulatedProviders,
    SimulatedPush,
    SimulatedSms,
    SimulatedWhatsApp,
)

__all__ = [
    "MISSING",
    "DeviceTelemetry",
    "Kind",
    "OutboundMessage",
    "Provider",
    "ProviderEvent",
    "ProviderSet",
    "ProviderStatus",
    "SendResult",
    "SimDevice",
    "SimulatedIvr",
    "SimulatedProviders",
    "SimulatedPush",
    "SimulatedSms",
    "SimulatedWhatsApp",
    "providers_mode",
    "registry_status",
]
