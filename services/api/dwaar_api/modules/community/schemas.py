"""Request models of the community API. ``extra="forbid"``: a smuggled ``society_id``, sponsor field or link attachment is a 400.

REQ: COM-01..COM-06, COM-05 (the emergency model has no field that could carry an advertisement), INV-01.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Language = Literal["en", "hi", "mr", "kn"]
Kind = Literal["general", "legal", "safety"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _no_control(value: str) -> str:
    if any((ord(ch) < 32 and ch not in "\n\t") or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


def _opt_no_control(value: str | None) -> str | None:
    return _no_control(value) if value else value


class Audience(Strict):
    """COM-01 recipient scope: the society, blocks, units or roles."""

    scope: Literal["society", "block", "unit", "role"] = "society"
    block_ids: Annotated[list[uuid.UUID], Field(max_length=200)] = Field(default_factory=list)
    unit_ids: Annotated[list[uuid.UUID], Field(max_length=500)] = Field(default_factory=list)
    roles: Annotated[list[str], Field(max_length=20)] = Field(default_factory=list)


class NoticeCreate(Strict):
    kind: Kind = "general"
    audience: Audience = Field(default_factory=Audience)
    language: Language = "en"
    title: Annotated[str, Field(min_length=3, max_length=200)]
    body: Annotated[str, Field(min_length=3, max_length=20000)]
    target_languages: Annotated[list[Language], Field(max_length=4)] = Field(default_factory=list)
    #: COM-03: set when a model produced the draft. Forces the human approval step; never skips it.
    drafted_by_ai: bool = False
    ai_run_ref: Annotated[str, Field(max_length=100)] | None = None

    _t = field_validator("title", "body")(_no_control)


class NoticeEdit(Strict):
    title: Annotated[str, Field(min_length=3, max_length=200)] | None = None
    body: Annotated[str, Field(min_length=3, max_length=20000)] | None = None
    language: Language | None = None
    audience: Audience | None = None
    target_languages: Annotated[list[Language], Field(max_length=4)] | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None

    _t = field_validator("title", "body")(_opt_no_control)


class RevisionCreate(Strict):
    title: Annotated[str, Field(min_length=3, max_length=200)]
    body: Annotated[str, Field(min_length=3, max_length=20000)]
    language: Language | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None

    _t = field_validator("title", "body")(_no_control)


class ApproveIn(Strict):
    #: COM-03: for an AI-drafted notice the approver confirms they read the draft in full
    confirm_ai_review: bool = False
    expected_version: Annotated[int, Field(ge=1)] | None = None


class PublishIn(Strict):
    publish_at: dt.datetime | None = None
    supersedes_notice_id: uuid.UUID | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None


class ArchiveIn(Strict):
    reason: Annotated[str, Field(min_length=3, max_length=500)]
    expected_version: Annotated[int, Field(ge=1)] | None = None


class TranslationIn(Strict):
    language: Language
    title: Annotated[str, Field(min_length=3, max_length=200)]
    body: Annotated[str, Field(min_length=3, max_length=20000)]

    _t = field_validator("title", "body")(_no_control)


class TranslationReviewIn(Strict):
    decision: Literal["approve", "reject"]
    note: Annotated[str, Field(max_length=500)] | None = None

    _t = field_validator("note")(_opt_no_control)


class ReceiptIn(Strict):
    kind: Literal["read", "acknowledged"]


class EmergencyBroadcastIn(Strict):
    """COM-05: plain text only. No links, attachments, images or sponsor fields exist, so the channel cannot carry an ad."""

    title: Annotated[str, Field(min_length=3, max_length=120)] = "Emergency alert"
    message: Annotated[str, Field(min_length=3, max_length=500)]
    language: Language = "en"
    audience: Audience = Field(default_factory=Audience)
    hazard: Literal["lift", "electrical", "gas", "fire", "general"] | None = None

    _t = field_validator("title", "message")(_no_control)


class DocumentCreate(Strict):
    doc_type: Literal["bye_laws", "minutes", "audit_report", "circular", "policy", "other"]
    title: Annotated[str, Field(min_length=3, max_length=200)]
    authority: Annotated[str, Field(min_length=2, max_length=200)]
    access_level: Literal["all_residents", "owners", "committee", "managers"] = "all_residents"

    _t = field_validator("title", "authority")(_no_control)


class VersionCreate(Strict):
    effective_from: dt.date
    authority: Annotated[str, Field(min_length=2, max_length=200)] | None = None
    change_note: Annotated[str, Field(max_length=500)] | None = None

    _t = field_validator("authority", "change_note")(_opt_no_control)


class WithdrawIn(Strict):
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class PollCreate(Strict):
    question: Annotated[str, Field(min_length=5, max_length=300)]
    description: Annotated[str, Field(max_length=2000)] = ""
    options: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=200)]],
        Field(min_length=2, max_length=12),
    ]
    eligibility: Literal["all_members", "owners_only"] = "all_members"
    result_visibility: Literal["live", "after_close", "managers_only"] = "after_close"

    _t = field_validator("question", "description")(_no_control)

    @field_validator("options")
    @classmethod
    def _distinct(cls, value: list[str]) -> list[str]:
        cleaned = [_no_control(v.strip()) for v in value]
        if len({v.lower() for v in cleaned}) != len(cleaned) or any(not v for v in cleaned):
            raise ValueError("options_must_be_distinct_and_not_empty")
        return cleaned


class PollOpenIn(Strict):
    closes_at: dt.datetime | None = None
    #: needed when the neutral-wording check flagged the poll (a person decides, with a reason)
    override_reason: Annotated[str, Field(min_length=10, max_length=500)] | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None


class PollCloseIn(Strict):
    expected_version: Annotated[int, Field(ge=1)] | None = None


class PollResponseIn(Strict):
    option_id: uuid.UUID
