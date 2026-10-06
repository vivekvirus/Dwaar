"""Provider adapter interfaces for push, IVR / proxy call, SMS and WhatsApp (D-21: vendors are TBD).

REQ: NOTIF-02 (a provider's acceptance is one fact, the app's receipt another), CALL-01 (provider outage exposes the intercom or office
process), CALL-02 (SMS only through DLT header + template), D-21, BUILD_BRIEF 6 (simulators are labelled ``simulation=true``; real vendor
adapters are NOT built, the registry says what is missing).

An adapter has three verbs and one rule: ``send`` hands a message to the provider and reports ONLY whether the provider accepted it;
``cancel`` withdraws a message or hangs a call up; ``drain_events`` returns what the provider (or the device, for a push) reported since,
in the order the provider produced it. Nothing here may ever claim that a person was reached: that claim needs an ``app_received`` /
``answered`` event, which arrives through ``drain_events`` (or the device's own receipt endpoint).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class Kind(StrEnum):
    PUSH = "push"
    IVR = "ivr_call"
    SMS = "sms"
    WHATSAPP = "whatsapp"


@dataclass(frozen=True)
class OutboundMessage:
    """One message to one recipient. ``contact_ref`` is an OPAQUE reference resolved by the provider; the number never travels through
    this package (no raw phone in a request, a log or a response). ``text`` is the final, already lock-screen-safe copy (NOTIF-09)."""

    notification_id: str
    kind: Kind
    contact_ref: str
    language: str
    text: str
    title: str | None = None
    link: str | None = None
    dlt_header: str | None = None
    dlt_template_id: str | None = None
    token_ref: str | None = None
    session_ttl_seconds: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SendResult:
    """The provider's answer to ``send``. ``accepted`` is NEVER "delivered"."""

    accepted: bool
    provider_ref: str | None = None
    error_code: str | None = (
        None  # a stable code (``provider_unavailable``, ``invalid_token`` ...), never provider text
    )
    retryable: bool = False


@dataclass(frozen=True)
class ProviderEvent:
    """Something a provider or the simulated device reported. ``event_id`` is the provider's id for the fact: a duplicate callback carries
    the same id and is recorded once."""

    event_id: str
    provider_ref: str
    event: str  # provider_accepted | app_received | displayed | answered | dtmf | completed | failed | no_answer | busy | delivered_to_handset
    observed_at: dt.datetime
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeviceTelemetry:
    """What a (simulated) device reports about itself. Real telemetry comes from the app's own diagnostic."""

    phone_model: str
    manufacturer: str
    os_name: str
    os_version: str


@runtime_checkable
class Provider(Protocol):
    kind: Kind
    name: str
    simulation: bool

    def send(self, message: OutboundMessage, *, now: dt.datetime) -> SendResult: ...

    def cancel(self, provider_ref: str, *, now: dt.datetime) -> bool: ...

    def drain_events(self, *, now: dt.datetime) -> list[ProviderEvent]: ...


@dataclass(frozen=True)
class ProviderStatus:
    """One line of the adapter registry shown to authorised administrators ONLY."""

    kind: str
    provider: str
    state: str  # simulator | not_configured
    simulation: bool
    detail: str  # for not_configured: "not configured: <the specific missing dependency>"

    def as_view(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "provider": self.provider,
            "state": self.state,
            "simulation": self.simulation,
            "detail": self.detail,
        }
