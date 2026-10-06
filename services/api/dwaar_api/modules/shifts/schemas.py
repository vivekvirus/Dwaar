"""Request models of the shifts API (PRD 9.6 SHIFT-01/02, UX-08, UX-09).

REQ: SHIFT-01, SHIFT-02, UX-08, UX-09, INV-01 (no society_id input), INV-08 (no field can lock anything).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Version = Annotated[int, Field(ge=1, le=2_000_000_000)]
Reason = Annotated[str, Field(min_length=5, max_length=500)]
SCENARIO_TYPES: Final = (
    "guest_entry", "delivery_entry", "service_entry", "cab_entry", "staff_checkin", "parcel_receive", "parcel_pickup",
    "emergency_entry", "shift_handover", "incident_report",
)  # fmt: skip
ScenarioType = Literal[
    "guest_entry", "delivery_entry", "service_entry", "cab_entry", "staff_checkin", "parcel_receive", "parcel_pickup",
    "emergency_entry", "shift_handover", "incident_report",
]  # fmt: skip
Health = Literal["ok", "degraded", "fault", "unknown"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _aware(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
    return value.astimezone(dt.UTC)


class ProfilePut(Strict):
    """UX-08: the guard's language, chosen per guard (not per site). English, Hindi and Marathi at M1; Kannada is M2 and is refused."""

    language: Literal["en", "hi", "mr", "kn"]
    expected_version: Annotated[int, Field(ge=0, le=2_000_000_000)] = 0


class TrainingRecord(Strict):
    """UX-09: a practice-mode completion (dummy units). Nothing here touches real gate data."""

    scenario_type: ScenarioType


class ShiftCreate(Strict):
    gate_id: uuid.UUID
    guard_id: uuid.UUID
    planned_start: dt.datetime
    planned_end: dt.datetime

    @field_validator("planned_start", "planned_end")
    @classmethod
    def _tz(cls, value: dt.datetime) -> dt.datetime:
        return _aware(value)

    @model_validator(mode="after")
    def _order(self) -> ShiftCreate:
        if self.planned_end <= self.planned_start:
            raise ValueError("end_must_follow_start")
        if self.planned_end - self.planned_start > dt.timedelta(hours=24):
            raise ValueError("longer_than_24_hours")
        return self


class StartChecklist(Strict):
    """SHIFT-01 start checklist: what the TERMINAL reports (battery, network, relay and sensor health, keys). The server adds what it knows
    (policy age, pending visits, unresolved incidents, parcels). Nothing here can block the start (INV-08)."""

    battery_percent: Annotated[int, Field(ge=0, le=100)] | None = None
    network: Literal["ok", "degraded", "offline"] | None = None
    relay_health: Health | None = None
    sensor_health: Health | None = None
    keys_count: Annotated[int, Field(ge=0, le=1000)] | None = None
    note: Annotated[str, Field(max_length=500)] | None = None


class EndChecklist(Strict):
    """SHIFT-01 end checklist: the guard's physical parcel count, confirmation that inside records were reviewed, keys handed back."""

    parcels_counted: Annotated[int, Field(ge=0, le=100_000)]
    inside_records_reviewed: bool
    keys_returned: Annotated[int, Field(ge=0, le=1000)] | None = None
    note: Annotated[str, Field(max_length=500)] | None = None


class ShiftStart(Strict):
    checklist: StartChecklist = Field(default_factory=StartChecklist)


class ShiftEnd(Strict):
    checklist: EndChecklist


class OverrideGrant(Strict):
    reason: Reason
    minutes: Annotated[int, Field(ge=1, le=1440)] | None = None


class HandoverAck(Strict):
    expected_version: Version | None = None
