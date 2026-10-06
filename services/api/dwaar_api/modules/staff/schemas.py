"""Request models of the staff API (PRD 9.6).

REQ: STAFF-01, STAFF-02, STAFF-04 (consent first), STAFF-05 (code or card ONLY: there is no face, selfie-match or biometric field in any
model), PRIV-03/PRIV-04 (an ID number is accepted as INPUT only and masked at once), INV-01 (no model has a society_id input), INV-02 (money in
integer paise).
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Version = Annotated[int, Field(ge=1, le=2_000_000_000)]
Reason = Annotated[str, Field(min_length=5, max_length=500)]
DAYS: Final = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HHMM: Final = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]\Z|^24:00\Z")
PURPOSES: Final = (
    "engagement_record",
    "attendance",
    "id_capture",
    "photo",
    "police_verification_status",
)
StaffType = Literal["domestic_help", "cook", "driver", "nanny", "gardener", "caretaker", "other"]
Purpose = Literal[
    "engagement_record", "attendance", "id_capture", "photo", "police_verification_status"
]
PoliceStatus = Literal["not_recorded", "requested", "verified", "not_verified", "expired"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


def _aware(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
    return value.astimezone(dt.UTC)


class ConsentCapture(Strict):
    """The consent_receipt (STAFF-04, PRIV-03/04): captured on the assisted tablet in the staff member's language BEFORE any data capture.

    ``staff_action_recorded`` must be true: a guard's tap is not consent evidence, the staff member's own affirmative action is. The
    ``ivr_assisted`` channel is M2 and is only accepted from the labelled simulator hook (``simulation``), never from this API.
    """

    language: Literal["en", "hi", "mr", "kn"]
    notice_version: Annotated[str, Field(min_length=1, max_length=50)]
    purposes: Annotated[list[Purpose], Field(min_length=1, max_length=5)]
    staff_action_recorded: bool
    notice_read_aloud: bool = False
    channel: Literal["assisted_tablet"] = "assisted_tablet"

    @field_validator("purposes")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate_purpose")
        return value


class ConsentWithdraw(Strict):
    expected_version: Version
    reason: Reason


class IdDocument(Strict):
    """An ID as shown to the guard. The NUMBER is masked at once to its last 4 characters and never stored (PRIV-04)."""

    kind: Literal["aadhaar", "driving_licence", "voter_id", "other"]
    number: Annotated[str, Field(min_length=4, max_length=40)]


class StaffRegister(Strict):
    consent_id: uuid.UUID
    display_name: Annotated[str, Field(min_length=1, max_length=120)]
    phone: Annotated[str, Field(min_length=8, max_length=32)]
    staff_type: StaffType
    id_document: IdDocument | None = None
    photo_ref: Annotated[str, Field(max_length=300)] | None = None
    police_verification_status: PoliceStatus = "not_recorded"

    @field_validator("display_name", "photo_ref")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean(value)


class StaffUpdate(Strict):
    expected_version: Version
    staff_type: StaffType | None = None
    id_document: IdDocument | None = None
    photo_ref: Annotated[str, Field(max_length=300)] | None = None
    police_verification_status: PoliceStatus | None = None

    @field_validator("photo_ref")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean(value)


class CredentialIssue(Strict):
    """Check-in by CODE or CARD (STAFF-05). A card is identified by the UID the reader reports; only a keyed hash is stored."""

    kind: Literal["code", "card"]
    card_uid: Annotated[str, Field(min_length=4, max_length=64)] | None = None
    expected_version: Version

    @model_validator(mode="after")
    def _shape(self) -> CredentialIssue:
        if (self.kind == "card") != (self.card_uid is not None):
            raise ValueError("card_uid_only_for_cards")
        return self


class Schedule(Strict):
    """Valid hours in Asia/Kolkata: the days and the daily window ``from`` .. ``to`` (``24:00`` allowed as the end)."""

    days: Annotated[
        list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]],
        Field(min_length=1, max_length=7),
    ]
    from_: Annotated[str, Field(alias="from")]
    to: str

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)

    @field_validator("from_", "to")
    @classmethod
    def _hhmm(cls, value: str) -> str:
        if not _HHMM.match(value):
            raise ValueError("invalid_time")
        return value

    @model_validator(mode="after")
    def _order(self) -> Schedule:
        if len(set(self.days)) != len(self.days):
            raise ValueError("duplicate_day")
        if self.from_ >= self.to:
            raise ValueError("window_end_must_follow_start")
        return self


class EngagementCreate(Strict):
    """One engagement of one staff person in ONE household. ``staff_ref`` is the opaque reference printed on the staff card."""

    staff_ref: Annotated[str, Field(pattern=r"^[A-Z2-7]{10}$")] | None = None
    staff_id: uuid.UUID | None = None
    unit_id: uuid.UUID
    duty: Annotated[str, Field(min_length=1, max_length=60)]
    schedule: Schedule
    effective_from: dt.date | None = None
    effective_to: dt.date | None = None

    @field_validator("duty")
    @classmethod
    def _text(cls, value: str) -> str:
        return _clean(value) or value

    @model_validator(mode="after")
    def _who(self) -> EngagementCreate:
        if (self.staff_ref is None) == (self.staff_id is None):
            raise ValueError("exactly_one_of_staff_ref_or_staff_id")
        if self.effective_from and self.effective_to and self.effective_to < self.effective_from:
            raise ValueError("end_before_start")
        return self


class EngagementUpdate(Strict):
    expected_version: Version
    duty: Annotated[str, Field(min_length=1, max_length=60)] | None = None
    schedule: Schedule | None = None
    effective_to: dt.date | None = None


class EngagementEnd(Strict):
    expected_version: Version
    reason: Reason


class Credential(Strict):
    kind: Literal["code", "card"]
    value: Annotated[str, Field(min_length=4, max_length=64)]


class AttendanceCreate(Strict):
    """A check-in or check-out observation. ``unit_id`` names the destination when the person works for several households."""

    credential: Credential
    direction: Literal["in", "out"]
    client_event_id: uuid.UUID
    occurred_at: dt.datetime | None = None
    unit_id: uuid.UUID | None = None
    device_id: uuid.UUID | None = None
    seq: Annotated[int, Field(ge=0, le=2**62)] | None = None

    @field_validator("occurred_at")
    @classmethod
    def _tz(cls, value: dt.datetime | None) -> dt.datetime | None:
        return None if value is None else _aware(value)

    @model_validator(mode="after")
    def _device_pair(self) -> AttendanceCreate:
        if (self.device_id is None) != (self.seq is None):
            raise ValueError("device_id_and_seq_go_together")
        return self


class AttendanceCorrection(Strict):
    kind: Literal["void", "amend_time", "amend_direction"]
    new_occurred_at: dt.datetime | None = None
    new_direction: Literal["in", "out"] | None = None
    reason: Reason

    @field_validator("new_occurred_at")
    @classmethod
    def _tz(cls, value: dt.datetime | None) -> dt.datetime | None:
        return None if value is None else _aware(value)

    @model_validator(mode="after")
    def _shape(self) -> AttendanceCorrection:
        ok = (
            (self.kind == "void" and self.new_occurred_at is None and self.new_direction is None)
            or (
                self.kind == "amend_time"
                and self.new_occurred_at is not None
                and self.new_direction is None
            )
            or (
                self.kind == "amend_direction"
                and self.new_direction is not None
                and self.new_occurred_at is None
            )
        )
        if not ok:
            raise ValueError("correction_fields_do_not_match_kind")
        return self


class PayrollPropose(Strict):
    engagement_id: uuid.UUID
    kind: Literal["bonus", "deduction", "advance_recovery", "attendance_credit"]
    amount_paise: Annotated[int, Field(ge=1, le=100_000_000, strict=True)]
    period: Annotated[str, Field(pattern=r"^[0-9]{4}-(0[1-9]|1[0-2])$")]
    reason: Reason


class PayrollDecision(Strict):
    decision: Literal["approve", "reject"]
    expected_version: Version
    note: Annotated[str, Field(max_length=500)] | None = None
