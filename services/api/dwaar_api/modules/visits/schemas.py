"""Request models of the visits API.

REQ: GATE-01, GATE-02, GATE-03, GATE-05, GATE-07, GATE-13, INV-01 (no model has a society_id input: the society comes from
the validated path or header, never from a body), PRD 12.3 (decision payload).

``extra="forbid"`` everywhere: an unknown field (for example a smuggled ``society_id``) is a 400. A visitor number is accepted
as INPUT only (``visitor_phone``); it is converted to the keyed visitor contact token at once and is never stored, echoed,
audited or logged.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

VisitKind = Literal["guest", "delivery", "service", "cab", "staff", "vendor"]
VISIT_KINDS: Final = ("guest", "delivery", "service", "cab", "staff", "vendor")
_PLATE: Final = re.compile(r"^[A-Z0-9][A-Z0-9 -]{1,18}[A-Z0-9]\Z")
_KEY: Final = re.compile(r"^[A-Za-z0-9_-]{43}\Z")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _no_control(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


def _plate(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().upper()
    if not cleaned:
        return None
    if not _PLATE.match(cleaned):
        raise ValueError("invalid_plate")
    return cleaned


def _check_json(value: Any, depth: int = 0) -> None:
    if depth > 4:
        raise ValueError("too_deep")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non_string_key")
            _check_json(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _check_json(item, depth + 1)
        return
    raise ValueError("unsupported_value")


ShortText = Annotated[str, Field(min_length=1, max_length=200)]
Alias = Annotated[str, Field(min_length=1, max_length=100)]
Reason = Annotated[str, Field(min_length=5, max_length=500)]
Version = Annotated[int, Field(ge=1, le=2_000_000_000)]


# ------------------------------------------------------------------------------------------ gates and devices
class GateCreate(Strict):
    name: Annotated[str, Field(min_length=1, max_length=100)]
    kind: Literal["vehicle", "pedestrian", "mixed"]

    @field_validator("name")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)


class LaneCreate(Strict):
    label: Annotated[str, Field(min_length=1, max_length=100)]
    direction: Literal["in", "out", "both"]

    @field_validator("label")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)


class DeviceEnrol(Strict):
    kind: Literal["terminal", "gateway", "reader", "camera", "relay", "meter_gw"]
    name: Annotated[str, Field(min_length=1, max_length=100)]
    gate_id: uuid.UUID | None = None
    public_key: str
    firmware: Annotated[str, Field(max_length=100)] | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    simulation: bool = False

    @field_validator("name")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)

    @field_validator("public_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _KEY.match(value):
            raise ValueError("invalid_public_key")
        return value

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, value: dict[str, Any]) -> dict[str, Any]:
        _check_json(value)
        return value


class DeviceDecision(Strict):
    decision: Literal["approve", "reject"]
    expected_version: Version
    reason: Annotated[str, Field(max_length=500)] | None = None


class DeviceRevoke(Strict):
    expected_version: Version
    reason: Reason


class PolicyPut(Strict):
    """Absolute policy. A missing field keeps the current value. Bounds are checked by the service against the approved
    cascade pack (expiry) and the PRD defaults ranges (overstay), never by this model."""

    expected_version: Annotated[int, Field(ge=0, le=2_000_000_000)] = 0
    approval_expiry_seconds: Annotated[int, Field(ge=10, le=3600)] | None = None
    permission_validity_minutes: Annotated[int, Field(ge=1, le=1440)] | None = None
    override_validity_minutes: Annotated[int, Field(ge=1, le=1440)] | None = None
    overstay_minutes: dict[str, Annotated[int, Field(ge=1, le=1440)]] | None = None


# ------------------------------------------------------------------------------------------ invitations
class Window(Strict):
    start: dt.datetime
    end: dt.datetime

    @field_validator("start", "end")
    @classmethod
    def _aware(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_required")
        return value.astimezone(dt.UTC)


class InvitationCreate(Strict):
    unit_id: uuid.UUID
    kind: VisitKind = "guest"
    purpose: ShortText
    visitor_alias: Alias | None = None
    visitor_phone: Annotated[str, Field(max_length=32)] | None = None
    people_count: Annotated[int, Field(ge=1, le=50)] = 1
    gate_id: uuid.UUID | None = None
    windows: Annotated[list[Window], Field(min_length=1, max_length=62)]
    max_uses: Annotated[int, Field(ge=1, le=100)] = 1
    vehicle_plate: str | None = None
    expected_minutes: Annotated[int, Field(ge=5, le=480)] | None = None
    with_code: bool = True

    @field_validator("purpose", "visitor_alias")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else _no_control(value)

    @field_validator("vehicle_plate")
    @classmethod
    def _plate_ok(cls, value: str | None) -> str | None:
        return _plate(value)


class InvitationRedeem(Strict):
    """Present the QR text OR (the 6-digit code AND the destination unit). The gate is the gate where it is presented."""

    gate_id: uuid.UUID
    qr: Annotated[str, Field(min_length=20, max_length=2000)] | None = None
    code: Annotated[str, Field(pattern=r"^[0-9]{6}$")] | None = None
    unit_id: uuid.UUID | None = None


# ------------------------------------------------------------------------------------------ approval requests
class VisitorNotice(Strict):
    """Visitor notice and consent (GATE-02): which notice text the visitor was shown and whether they agreed."""

    version: Annotated[str, Field(min_length=1, max_length=50)]
    language: Literal["en", "hi", "mr", "kn"]
    consent_given: bool


class ApprovalRequestCreate(Strict):
    unit_id: uuid.UUID
    kind: VisitKind = "guest"
    visitor_alias: Alias
    visitor_phone: Annotated[str, Field(max_length=32)] | None = None
    people_count: Annotated[int, Field(ge=1, le=50)] = 1
    vehicle_plate: str | None = None
    gate_id: uuid.UUID
    destination_confirmed: bool
    notice: VisitorNotice
    expected_minutes: Annotated[int, Field(ge=5, le=480)] | None = None
    photo_ref: Annotated[str, Field(max_length=300)] | None = None

    @field_validator("visitor_alias")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)

    @field_validator("vehicle_plate")
    @classmethod
    def _plate_ok(cls, value: str | None) -> str | None:
        return _plate(value)


class DecisionIn(Strict):
    """PRD 12.3 exactly: decision, expected_version, client_action_id (plus an optional channel; only ``app`` is open to
    this API, the other channels belong to the notification slice)."""

    decision: Literal["approve", "deny"]
    expected_version: Version
    client_action_id: uuid.UUID
    channel: Literal["app"] = "app"


class ReversalIn(Strict):
    expected_version: Version
    client_action_id: uuid.UUID
    reason: Reason


class CancelIn(Strict):
    expected_version: Version
    reason: Annotated[str, Field(max_length=500)] | None = None


class StopAdd(Strict):
    unit_id: uuid.UUID
    destination_confirmed: bool
    expected_version: Version


class VisitCancel(Strict):
    expected_version: Version
    reason: Reason


# ------------------------------------------------------------------------------------------ observations
class ObservationIn(Strict):
    type: Literal["entry", "exit"]
    gate_id: uuid.UUID
    lane_id: uuid.UUID | None = None
    device_id: uuid.UUID
    event_id: uuid.UUID
    seq: Annotated[int, Field(ge=0, le=2**62)]
    occurred_at: dt.datetime
    clock_uncertainty_ms: Annotated[int, Field(ge=0, le=86_400_000)] = 0
    credential_kind: Literal[
        "qr", "code", "guard_assisted", "resident_app", "rfid", "anpr", "none"
    ] = "guard_assisted"
    decision_source: Literal[
        "cached_policy",
        "resident_app",
        "ivr",
        "guard_assisted",
        "supervisor_override",
        "rfid",
        "anpr",
    ] = "guard_assisted"
    exit_basis: Literal["scanned", "observed", "reconciled_unknown"] | None = None
    policy_version: Annotated[int, Field(ge=0, le=2**62)] | None = None

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_required")
        return value.astimezone(dt.UTC)


# ------------------------------------------------------------------------------------------ exceptions
class ExceptionCreate(Strict):
    kind: Literal["manual_entry", "emergency_entry", "unauthorised_entry", "exit_unknown", "other"]
    reason: Reason
    visit_id: uuid.UUID | None = None
    evidence_ref: Annotated[str, Field(max_length=300)] | None = None
    entry_happened: bool | None = None
    # manual / emergency entry creates an authorised visit (supervisor override)
    visit_kind: VisitKind = "guest"
    visitor_alias: Alias | None = None
    unit_id: uuid.UUID | None = None
    gate_id: uuid.UUID | None = None
    people_count: Annotated[int, Field(ge=1, le=50)] = 1


class ExceptionTransition(Strict):
    action: Literal["start_review", "escalate", "resolve"]
    expected_version: Version
    note: Annotated[str, Field(max_length=500)] | None = None
