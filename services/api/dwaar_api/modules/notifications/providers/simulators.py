"""Deterministic, labelled provider simulators: push, IVR / proxy call, SMS, WhatsApp (``simulation = True`` on every one).

REQ: NOTIF-02, NOTIF-03, NOTIF-06 (fake device telemetry), CALL-01, CALL-02, D-21 (real vendors are TBD), BUILD_BRIEF 6.

They are test and demonstrator doubles, NOT stand-ins for a vendor's behaviour. What they can do on purpose, so the cascade is tested against
the awkward cases and not only the happy one:

* **fail** (``fail_next`` / ``fail_always``) with a stable error code; **delay** (every event has a ready-time on the injected clock);
  **drop** an acknowledgement (``drop_ack``: the provider accepted, the phone never reports: a force-stopped app); **reorder**
  (``reorder``: the later fact is reported first); **duplicate** (``duplicate``: every event is reported twice with the same id);
* report **fake device telemetry** (phone model, manufacturer, OS) so the delivery dashboard by model and OS can be exercised.

They never reach the network, never read an environment secret and never hold a real phone number: a ``contact_ref`` is an opaque string.
Time is the ``now`` argument of each call (an injectable clock): nothing sleeps.
"""

from __future__ import annotations

import datetime as dt
import itertools
from dataclasses import dataclass, field
from typing import Any

from .base import DeviceTelemetry, Kind, OutboundMessage, ProviderEvent, SendResult

_DEFAULT_TELEMETRY = DeviceTelemetry("Simulated Phone", "other", "Android", "14")


@dataclass
class SimDevice:
    """How one simulated phone (identified by its push ``token_ref``) behaves."""

    online: bool = True
    permission_granted: bool = True
    force_stopped: bool = False
    ack_delay_ms: int = 400
    display_delay_ms: int = 150
    telemetry: DeviceTelemetry = _DEFAULT_TELEMETRY

    @property
    def reachable(self) -> bool:
        return self.online and self.permission_granted and not self.force_stopped


@dataclass
class _Queued:
    ready_at: dt.datetime
    seq: int
    event: ProviderEvent


class _SimBase:
    simulation = True
    kind: Kind
    name: str

    def __init__(self) -> None:
        self.fail_always: str | None = None
        self._fail_next: list[str] = []
        self.drop_ack = False
        self.reorder = False
        self.duplicate = False
        self.sent: list[OutboundMessage] = []
        self.cancelled: list[str] = []
        self._queue: list[_Queued] = []
        self._ids = itertools.count(1)
        self._seq = itertools.count(1)

    # ------------------------------------------------------------------------------------------ scripting
    def fail_next(self, code: str = "provider_unavailable", times: int = 1) -> None:
        self._fail_next.extend([code] * times)

    def _failure(self) -> str | None:
        if self._fail_next:
            return self._fail_next.pop(0)
        return self.fail_always

    # ------------------------------------------------------------------------------------------ helpers
    def _ref(self) -> str:
        return f"sim-{self.kind.value}-{next(self._ids):05d}"

    def _emit(
        self,
        ref: str,
        event: str,
        ready_at: dt.datetime,
        *,
        suffix: str | None = None,
        **detail: Any,
    ) -> None:
        ev = ProviderEvent(f"{ref}:{suffix or event}", ref, event, ready_at, dict(detail))
        self._queue.append(_Queued(ready_at, next(self._seq), ev))
        if self.duplicate:
            self._queue.append(_Queued(ready_at, next(self._seq), ev))

    def drain_events(self, *, now: dt.datetime) -> list[ProviderEvent]:
        ready = [q for q in self._queue if q.ready_at <= now]
        self._queue = [q for q in self._queue if q.ready_at > now]
        ready.sort(key=lambda q: (q.ready_at, q.seq))
        if self.reorder:
            ready.reverse()  # the later fact is reported first
        return [q.event for q in ready]

    def pending_events(self) -> int:
        return len(self._queue)

    def cancel(self, provider_ref: str, *, now: dt.datetime) -> bool:
        self.cancelled.append(provider_ref)
        self._queue = [q for q in self._queue if q.event.provider_ref != provider_ref]
        return True


class SimulatedPush(_SimBase):
    """FCM / APNs stand-in. ``accepted`` means the simulator took the message, nothing more."""

    kind = Kind.PUSH
    name = "simulated-push"

    def __init__(self) -> None:
        super().__init__()
        self.devices: dict[str, SimDevice] = {}
        self.default_device = SimDevice()

    def device(self, token_ref: str) -> SimDevice:
        if token_ref not in self.devices:
            d = self.default_device
            self.devices[token_ref] = SimDevice(
                d.online,
                d.permission_granted,
                d.force_stopped,
                d.ack_delay_ms,
                d.display_delay_ms,
                d.telemetry,
            )
        return self.devices[token_ref]

    def send(self, message: OutboundMessage, *, now: dt.datetime) -> SendResult:
        self.sent.append(message)
        code = self._failure()
        if code is not None:
            return SendResult(False, None, code, retryable=code != "invalid_token")
        if not message.token_ref:
            return SendResult(False, None, "invalid_token")
        ref = self._ref()
        dev = self.device(message.token_ref)
        if dev.reachable and not self.drop_ack:
            received = now + dt.timedelta(milliseconds=dev.ack_delay_ms)
            tele = {
                "phone_model": dev.telemetry.phone_model,
                "manufacturer": dev.telemetry.manufacturer,
                "os_name": dev.telemetry.os_name,
                "os_version": dev.telemetry.os_version,
            }
            self._emit(ref, "app_received", received, **tele)
            self._emit(
                ref, "displayed", received + dt.timedelta(milliseconds=dev.display_delay_ms), **tele
            )
        # an unreachable phone: the provider still ACCEPTED the message; nothing else ever comes back
        return SendResult(True, ref)


class SimulatedIvr(_SimBase):
    """Masked IVR / proxy-call stand-in. Scripts are keyed by the opaque ``contact_ref`` of the callee."""

    kind = Kind.IVR
    name = "simulated-ivr"

    def __init__(self) -> None:
        super().__init__()
        self.scripts: dict[str, dict[str, Any]] = {}
        self.default_script: dict[str, Any] = {
            "outcome": "no_answer",
            "dtmf": None,
            "answer_delay_s": 4,
            "duration_s": 12,
        }

    def script(
        self,
        contact_ref: str,
        *,
        outcome: str = "answered",
        dtmf: str | None = None,
        answer_delay_s: int = 4,
        duration_s: int = 12,
    ) -> None:
        self.scripts[contact_ref] = {
            "outcome": outcome,
            "dtmf": dtmf,
            "answer_delay_s": answer_delay_s,
            "duration_s": duration_s,
        }

    def send(self, message: OutboundMessage, *, now: dt.datetime) -> SendResult:
        self.sent.append(message)
        code = self._failure()
        if code is not None:
            return SendResult(False, None, code, retryable=True)
        ref = self._ref()
        sc = self.scripts.get(message.contact_ref, self.default_script)
        outcome = str(sc["outcome"])
        if outcome == "answered":
            answered = now + dt.timedelta(seconds=int(sc["answer_delay_s"]))
            self._emit(ref, "answered", answered)
            if sc["dtmf"] is not None and not self.drop_ack:
                self._emit(ref, "dtmf", answered + dt.timedelta(seconds=2), digit=str(sc["dtmf"]))
            self._emit(
                ref,
                "completed",
                now + dt.timedelta(seconds=int(sc["duration_s"])),
                outcome="answered",
                duration_seconds=max(0, int(sc["duration_s"]) - int(sc["answer_delay_s"])),
            )
        else:
            self._emit(
                ref,
                "completed",
                now + dt.timedelta(seconds=int(sc["duration_s"])),
                outcome=outcome,
                duration_seconds=0,
            )
        return SendResult(True, ref)

    def cancel(self, provider_ref: str, *, now: dt.datetime) -> bool:
        """Hang up: what had not happened yet will not, and the call ends with what it had."""
        self.cancelled.append(provider_ref)
        self._queue = [q for q in self._queue if q.event.provider_ref != provider_ref]
        self._emit(
            provider_ref,
            "completed",
            now,
            suffix="completed_by_cancel",
            outcome="cancelled",
            duration_seconds=0,
        )
        return True


class SimulatedSms(_SimBase):
    """DLT SMS stand-in. It refuses a message without a registered header and template id (CALL-02), like the gateway would."""

    kind = Kind.SMS
    name = "simulated-sms"

    def send(self, message: OutboundMessage, *, now: dt.datetime) -> SendResult:
        self.sent.append(message)
        if not message.dlt_header or not message.dlt_template_id:
            return SendResult(False, None, "dlt_template_missing")
        code = self._failure()
        if code is not None:
            return SendResult(False, None, code, retryable=True)
        ref = self._ref()
        if not self.drop_ack:
            self._emit(ref, "handset_report", now + dt.timedelta(seconds=3))
        return SendResult(True, ref)


class SimulatedWhatsApp(_SimBase):
    """WhatsApp utility-template stand-in."""

    kind = Kind.WHATSAPP
    name = "simulated-whatsapp"

    def send(self, message: OutboundMessage, *, now: dt.datetime) -> SendResult:
        self.sent.append(message)
        code = self._failure()
        if code is not None:
            return SendResult(False, None, code, retryable=True)
        ref = self._ref()
        if not self.drop_ack:
            self._emit(ref, "handset_report", now + dt.timedelta(seconds=2))
        return SendResult(True, ref)


@dataclass
class SimulatedProviders:
    """The four simulators as one bundle (what the worker and the tests hand to the jobs)."""

    push: SimulatedPush = field(default_factory=SimulatedPush)
    ivr: SimulatedIvr = field(default_factory=SimulatedIvr)
    sms: SimulatedSms = field(default_factory=SimulatedSms)
    whatsapp: SimulatedWhatsApp = field(default_factory=SimulatedWhatsApp)

    def all(self) -> tuple[_SimBase, ...]:
        return (self.push, self.ivr, self.sms, self.whatsapp)

    def by_kind(self, kind: Kind) -> _SimBase:
        return {
            Kind.PUSH: self.push,
            Kind.IVR: self.ivr,
            Kind.SMS: self.sms,
            Kind.WHATSAPP: self.whatsapp,
        }[kind]

    def total_sent(self) -> int:
        return sum(len(p.sent) for p in self.all())

    def set_outage(self, code: str | None = "provider_unavailable") -> None:
        """Every provider fails every send (a provider outage, CALL-01); ``None`` ends it."""
        for p in self.all():
            p.fail_always = code
