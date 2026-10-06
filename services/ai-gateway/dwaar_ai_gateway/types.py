"""Shared types of the gateway pipeline (PRD 10.1, 10.2, AI-SYS-04)."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskClass(StrEnum):
    """PRD 10.2 permission classes."""

    A = "A"  # read-only answer within the user's rights
    B = "B"  # draft requiring the user's confirmation
    C = "C"  # specialist or second-approver review
    X = "X"  # FORBIDDEN autonomous action: never proposed, never executed by or because of a model


class Tier(StrEnum):
    """Model routing tiers (PRD 10.5, D-18)."""

    NONE = "none"  # deterministic feature, no model at all
    EXTRACT = "extract"  # classification, extraction, short translation -> Haiku
    DRAFT = "draft"  # drafting, reasoning, grounded Q&A -> Sonnet
    COMPLEX = "complex"  # rare offline jobs -> Opus, only where Sonnet fails evaluation


class Outcome(StrEnum):
    ACCEPTED = "accepted"
    EDITED = "edited"
    REJECTED = "rejected"
    ABSTAINED = "abstained"
    FAILED = "failed"


class ProposalState(StrEnum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass(frozen=True)
class Caller:
    """The server-derived identity of one AI request (never taken from the body, never from a token claim)."""

    society_id: uuid.UUID
    person_id: uuid.UUID
    role: str
    society_wide: bool = False
    unit_ids: frozenset[uuid.UUID] = frozenset()
    language: str = "en"

    def covers_unit(self, unit_id: uuid.UUID) -> bool:
        return self.society_wide or unit_id in self.unit_ids


@dataclass(frozen=True)
class SourceDoc:
    """One retrievable item (document section, ticket, shift event ...). The retrieval layer proposes them; the POLICY layer decides."""

    source_id: str
    society_id: uuid.UUID
    kind: str
    text: str
    unit_id: uuid.UUID | None = None
    visible_to_roles: frozenset[str] | None = None  # None = every role of the society
    status: str = "published"  # published | deleted | superseded | archived
    version: int = 1
    meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UntrustedSegment:
    """A piece of DATA (uploaded document, ticket, transcript, message) that the model must never treat as instructions."""

    segment_id: str
    kind: str  # document | ticket | transcript | message | notice_text | poll_text | telemetry
    text: str


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ProviderRequest:
    feature_id: str
    tier: Tier
    model_id: str
    system: str
    task: Mapping[str, Any]  # structured instruction written by the server (never from users)
    untrusted: Sequence[UntrustedSegment]
    schema: Mapping[str, Any]
    allowed_tools: tuple[str, ...]
    language: str
    max_output_tokens: int
    request_nonce: str


@dataclass(frozen=True)
class ProviderResponse:
    raw_text: str  # the model's JSON text; parsed and validated by the gateway, never trusted
    tool_calls: Sequence[ToolCall] = ()
    model_id: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    simulation: bool = True
    provider: str = ""


@dataclass(frozen=True)
class Labels:
    """AI-SYS-08 labelling shown to the user with every AI output."""

    ai_draft: bool
    simulation: bool
    sources: list[dict[str, Any]]
    what_will_be_saved: str
    correction_route: str
    declining_ai_reduces_service: bool
    original_text_offered: bool
    human_review_required: bool
    reasons: list[str]  # G9: every flag or score carries a plain-language reason
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ai_draft": self.ai_draft,
            "simulation": self.simulation,
            "sources": self.sources,
            "what_will_be_saved": self.what_will_be_saved,
            "correction_route": self.correction_route,
            "declining_ai_reduces_service": self.declining_ai_reduces_service,
            "original_text_offered": self.original_text_offered,
            "human_review_required": self.human_review_required,
            "reasons": self.reasons,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class ProposalDraft:
    """AI-SYS-04 action proposal object, before persistence."""

    feature_id: str
    intent: str
    command: str
    risk_class: RiskClass
    payload: dict[str, Any]
    target_ids: tuple[uuid.UUID, ...]
    target_versions: tuple[int, ...]
    evidence: list[dict[str, Any]]
    missing_fields: list[str]
    estimated_effect: str
    expires_at: dt.datetime


@dataclass
class GatewayResult:
    """What the pipeline returns to the API module."""

    status: str  # ok | unavailable | rejected
    feature_id: str
    kind: str  # answer | proposal | none
    fallback: dict[str, Any] | None = None
    reason: str | None = None
    answer: dict[str, Any] | None = None
    proposal: ProposalDraft | None = None
    labels: Labels | None = None
    # audit facts for ai_runs (never raw prompts)
    model: str = "none"
    provider: str = "none"
    simulation: bool = True
    prompt_version: str = "none"
    schema_version: str = "none"
    source_ids: list[str] = field(default_factory=list)
    latency_ms: int = 0
    cost_paise: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    model_called: bool = False
    outcome: Outcome | None = None
    input_hash: str = ""
    redaction_counts: dict[str, int] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    tools_executed: list[str] = field(default_factory=list)
