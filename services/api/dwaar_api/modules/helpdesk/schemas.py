"""Request models of the helpdesk API. ``extra="forbid"``: a smuggled ``society_id`` or ``raised_by`` is a 400.

REQ: OPS-01..OPS-04, OPS-09, UX-07, INV-01 (no model has a society_id input).
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal[
    "plumbing", "electrical", "lift", "gas", "fire_safety", "cleaning", "security", "parking", "noise",
    "common_area", "water_supply", "garden", "pest", "civil", "other",
]  # fmt: skip
Priority = Literal["emergency", "urgent", "normal", "low"]
Scope = Literal["private", "block", "society"]
Hazard = Literal["lift", "electrical", "gas", "fire", "general"]
_PHOTO: Final = re.compile(r"^[A-Za-z0-9_-]{8,100}\Z")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _no_control(value: str) -> str:
    if any((ord(ch) < 32 and ch not in "\n\t") or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


class TicketCreate(Strict):
    """OPS-03: the STANDARD FORM (always available, no AI). ``submit=false`` keeps a draft the resident confirms later."""

    scope: Scope = "private"
    unit_id: uuid.UUID | None = None
    block_id: uuid.UUID | None = None
    category: Category
    title: Annotated[str, Field(min_length=3, max_length=200)]
    description: Annotated[str, Field(max_length=4000)] = ""
    photo_refs: Annotated[list[str], Field(max_length=6)] = Field(default_factory=list)
    #: "Is this unsafe / is anyone in danger?" (OPS-09). Never lowers a priority; only raises it.
    unsafe_observation: bool = False
    #: managers only; ignored (400) for anyone else
    priority: Priority | None = None
    submit: bool = True

    _t = field_validator("title", "description")(_no_control)

    @field_validator("photo_refs")
    @classmethod
    def _photos(cls, value: list[str]) -> list[str]:
        if any(not _PHOTO.match(v) for v in value) or len(set(value)) != len(value):
            raise ValueError("invalid_photo_ref")
        return value


class SupportRequestCreate(Strict):
    """UX-07: a support or privacy issue, available while the membership is pending or DISPUTED."""

    title: Annotated[str, Field(min_length=3, max_length=200)]
    description: Annotated[str, Field(max_length=4000)] = ""
    unit_id: uuid.UUID | None = None

    _t = field_validator("title", "description")(_no_control)


class Versioned(Strict):
    expected_version: Annotated[int, Field(ge=1)] | None = None


class Note(Versioned):
    note: Annotated[str, Field(max_length=1000)] | None = None

    _n = field_validator("note")(lambda v: _no_control(v) if v else v)


class TriageIn(Note):
    category: Category | None = None
    priority: Priority | None = None
    beyond_staff_competence: bool | None = None


class AssignIn(Note):
    assignee_id: uuid.UUID | None = None
    contractor_name: Annotated[str, Field(min_length=2, max_length=200)] | None = None


class TransitionIn(Note):
    to: Literal["in_progress", "awaiting_material", "awaiting_resident", "resolved"]
    #: who approved a pause (awaiting_*); defaults to the actor
    approver_id: uuid.UUID | None = None


class PriorityIn(Versioned):
    priority: Priority
    reason: Annotated[str, Field(min_length=5, max_length=500)]
    approver_id: uuid.UUID | None = None


class ReasonIn(Versioned):
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class MergeIn(Versioned):
    into_ticket_id: uuid.UUID
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class SettingsIn(Strict):
    timezone: Annotated[str, Field(min_length=3, max_length=64)] = "Asia/Kolkata"
    working_days: Annotated[list[int], Field(min_length=1, max_length=7)]
    opens_at: dt.time
    closes_at: dt.time
    holidays: Annotated[list[dt.date], Field(max_length=400)] = Field(default_factory=list)
    sla: dict[str, Any]
    feedback_window_hours: Annotated[int, Field(ge=1, le=720)] = 48
    reopen_window_days: Annotated[int, Field(ge=1, le=90)] = 7
    duplicate_similarity: Annotated[float, Field(ge=0.10, le=1.0)] = 0.45
    expected_version: Annotated[int, Field(ge=1)] | None = None


class Contact(Strict):
    role: Annotated[str, Field(min_length=2, max_length=80)]
    name: Annotated[str, Field(min_length=2, max_length=120)]
    phone: Annotated[str, Field(min_length=3, max_length=20)]


class EmergencyProcedureIn(Strict):
    headline: Annotated[str, Field(min_length=3, max_length=200)]
    steps: Annotated[str, Field(min_length=3, max_length=2000)]
    contacts: Annotated[list[Contact], Field(max_length=12)] = Field(default_factory=list)
    qualified_contractor: Annotated[str, Field(min_length=2, max_length=200)] | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None

    _t = field_validator("headline", "steps")(_no_control)
