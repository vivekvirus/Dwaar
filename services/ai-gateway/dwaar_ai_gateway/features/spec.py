"""Feature specification, handler protocol and shared input helpers."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from jsonschema import Draft202012Validator

from ..pii import TokenVault
from ..types import Caller, RiskClass, SourceDoc, Tier


class InvalidInput(Exception):
    def __init__(self, fields: Sequence[tuple[str, str]]) -> None:
        super().__init__("invalid_input")
        self.fields = list(fields)


@dataclass(frozen=True)
class FeatureSpec:
    id: str
    name: str
    risk_class: RiskClass
    tier: Tier
    roles: frozenset[str]
    command: str | None
    purpose: str
    milestone: str = "M1"
    uses_model: bool = True
    available: bool = True
    unavailable_reason: str | None = None
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    ttl_seconds: int = 1800
    allowed_tools: tuple[str, ...] = ()
    summary_key: str = ""
    # G3: why this feature may produce text for a resident at all (it never messages anyone itself)
    g3_basis: str = "user_initiated_draft"


@dataclass
class LocationRef:
    unit_id: uuid.UUID
    block: str
    label: str
    version: int


@dataclass
class LocationDirectory:
    """The units the CALLER may name (their own grants), resolved server-side by the API; never free text."""

    units: list[LocationRef] = field(default_factory=list)
    common_areas: tuple[str, ...] = (
        "lobby",
        "terrace",
        "parking",
        "garden",
        "gate",
        "clubhouse",
        "playground",
        "lift",
        "staircase",
        "basement",
        "podium",
    )


@dataclass
class Prepared:
    segments: list[tuple[str, str, str]]  # (segment_id, kind, text)
    task: dict[str, Any]
    tier: Tier | None = None
    allowed_ids: frozenset[str] = frozenset()
    checks: list[Callable[[dict[str, Any]], None]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    sources_used: list[SourceDoc] = field(default_factory=list)


@dataclass
class FeatureOutput:
    kind: str  # answer | draft
    payload: dict[str, Any]
    summary: str
    missing_fields: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    target_ids: tuple[uuid.UUID, ...] = ()
    target_versions: tuple[int, ...] = ()
    human_review_required: bool = True
    original_text_offered: bool = False
    what_will_be_saved: str = ""
    estimated_effect: str = ""


class GatewayRequestLike(Protocol):
    feature_id: str
    caller: Caller
    inputs: Mapping[str, Any]
    sources: Sequence[SourceDoc]
    locations: LocationDirectory | None


class FeatureHandler(Protocol):
    spec: FeatureSpec

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared: ...

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput: ...


def validate_inputs(schema: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(dict(schema)).iter_errors(dict(inputs)), key=lambda e: list(e.path)
    )
    if errors:
        fields: list[tuple[str, str]] = []
        for e in errors[:10]:
            path = ".".join(str(p) for p in e.path) or (
                e.validator_value[0]
                if e.validator == "required" and e.validator_value
                else "inputs"
            )
            if e.validator == "required":
                missing = sorted(set(e.validator_value) - set(e.instance))
                path = missing[0] if missing else path
            fields.append((str(path), str(e.validator)))
        raise InvalidInput(fields)


def reidentify_value(value: Any, vault: TokenVault) -> Any:
    """Re-identify tokens in every string of a payload (only the authorised caller of THIS request ever receives it)."""
    if isinstance(value, str):
        return vault.reidentify(value, authorised=True)
    if isinstance(value, dict):
        return {k: reidentify_value(v, vault) for k, v in value.items()}
    if isinstance(value, list):
        return [reidentify_value(v, vault) for v in value]
    return value
