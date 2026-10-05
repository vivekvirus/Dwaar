"""Pydantic models for packs. Shapes follow PRD 8.2 ``legal_packs`` (jurisdiction, entity_type, version,
rules, legal_sources, approved_by, approved_at, effective_from, effective_to).

INV-10: nothing here encodes a legal value. Values live in YAML packs under packages/legal-packs and
packages/tax-packs; shipped packs are all unapproved because counsel/CA approval is an external step.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .frozen import freeze

Label = Literal["LEGAL", "VERIFY", "CA", "TBD"]
PackStatus = Literal["draft", "unapproved", "approved", "retired"]


class PackModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="after")
    @classmethod
    def _deep_freeze(cls, value: Any) -> Any:
        """Pack data is read-only law: nested dicts and lists become immutable (INV-10)."""
        return freeze(value)


class LegalSource(PackModel):
    """A named source. ``url`` stays null unless the PRD names an exact URL (never invented)."""

    ref_id: str
    citation: str
    prd_ref: str
    labels: list[Label]
    url: str | None = None


class PackHeader(PackModel):
    pack_id: str
    version: str
    title: str = ""
    status: PackStatus
    enabled: bool = True
    disabled_reason: str | None = None
    approved_by: str | None
    approved_at: datetime | None
    effective_from: date
    effective_to: date | None
    next_review: date | None = None
    labels: list[Label]
    notes: str | None = None
    legal_sources: list[LegalSource]

    @model_validator(mode="after")
    def _check_header(self) -> PackHeader:
        # GOV-01: approval is all-or-nothing and only the "approved" status carries an approver.
        has_approver = self.approved_by is not None and self.approved_at is not None
        half = (self.approved_by is None) != (self.approved_at is None)
        if half:
            raise ValueError("approved_by and approved_at must be set together")
        if self.status == "approved" and not has_approver:
            raise ValueError("status 'approved' requires approved_by and approved_at")
        if self.status != "approved" and has_approver:
            raise ValueError("approver fields set but status is not 'approved'")
        if self.effective_to is not None and self.effective_to < self.effective_from:
            raise ValueError("effective_to precedes effective_from")
        ids = [s.ref_id for s in self.legal_sources]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate legal_sources ref_id")
        return self

    @property
    def source_ids(self) -> set[str]:
        return {s.ref_id for s in self.legal_sources}

    @property
    def is_approved(self) -> bool:
        return self.status == "approved" and self.approved_by is not None


class Rule(PackModel):
    """One keyed rule. ``value`` is JSON; ``None`` means unconfigured (must be set with a legal reference)."""

    value: Any
    unit: str | None = None
    note: str | None = None
    labels: list[Label]
    legal_source_ref: str
    legal_reference: str | None = None
    configurable: bool = False


class PackConfiguration(PackModel):
    configurable_by: Literal["secretary"] | None = None
    legal_reference_required: bool = True
    counsel_approval_required: bool = True


class LegalPack(PackHeader):
    pack_type: Literal["legal-pack"] = "legal-pack"
    jurisdiction: str
    entity_type: Literal["chs", "apartment_assoc", "society_reg", "company", "any"]
    configuration: PackConfiguration | None = None
    rules: dict[str, Rule]

    @model_validator(mode="after")
    def _check_rules(self) -> LegalPack:
        known = self.source_ids
        for key, rule in self.rules.items():
            if rule.legal_source_ref not in known:
                raise ValueError(f"rule {key}: unknown legal_source_ref {rule.legal_source_ref!r}")
            if rule.value is None and not rule.configurable:
                raise ValueError(f"rule {key}: null value must be marked configurable")
        return self

    def to_db_row(self) -> dict[str, Any]:
        """Shape of the PRD 8.2 ``legal_packs`` row (jsonb columns as plain dicts/lists)."""
        return {
            "jurisdiction": self.jurisdiction,
            "entity_type": self.entity_type,
            "version": self.version,
            "rules": {k: r.model_dump(mode="json") for k, r in self.rules.items()},
            "legal_sources": [s.model_dump(mode="json") for s in self.legal_sources],
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "effective_from": self.effective_from,
            "effective_to": self.effective_to,
        }


# ------------------------------------------------------------------ retention (PRIV-06, PRD Appendix B)
class RetentionOperational(PackModel):
    days: int | None
    until: str | None = None
    extendable_to_days: int | None = None
    extension_requires_justification: bool = False
    visibility: str


class RetentionArchiveComponent(PackModel):
    min_days: int | None
    legal_source_ref: str


class RetentionArchive(PackModel):
    scope: str
    min_days: int | None
    expiry_basis: str | None = None
    legal_source_ref: str
    note: str | None = None
    components: list[RetentionArchiveComponent] = []


class RetentionErasure(PackModel):
    method: str
    trigger: str
    unless_hold: bool


class RetentionRule(PackModel):
    record_class: str = ""
    name: str
    purpose: str
    operational: RetentionOperational
    archive: RetentionArchive
    erasure: RetentionErasure
    legal_source_ref: str


class RetentionPack(PackHeader):
    pack_type: Literal["retention"] = "retention"
    jurisdiction: str
    classes: dict[str, RetentionRule]

    @model_validator(mode="after")
    def _check_refs(self) -> RetentionPack:
        known = self.source_ids
        for cid, c in self.classes.items():
            refs = [c.legal_source_ref, c.archive.legal_source_ref]
            refs += [x.legal_source_ref for x in c.archive.components]
            for r in refs:
                if r not in known:
                    raise ValueError(f"class {cid}: unknown legal_source_ref {r!r}")
        return self


# ------------------------------------------------------------------ cascade / offline (D-13, D-15)
class CascadeStep(PackModel):
    step: int
    at_seconds: int
    action: str
    condition: str
    note: str | None = None
    guard_options: list[str] = []


class ExpiryBounds(PackModel):
    min: int
    max: int
    default: int


class CascadeBounds(PackModel):
    min_seconds_between_steps: int
    expiry_seconds: ExpiryBounds


class CascadeSection(PackModel):
    steps: list[CascadeStep]
    auto_allow_on_timeout: Literal[False]
    bounds: CascadeBounds


class OfflineDefaults(PackModel):
    resident_credential_validity_hours: int
    guest_pass_max_hours: int
    guest_pass_bound_to_assigned_gate: bool = True
    clock_uncertainty_disable_auto_approvals_seconds: int
    supervisor_override_validity: str
    policy_age_guard_assisted_verification_hours: int
    edge_event_buffer_hours: int
    terminal_standalone_min_hours: int


class MaxBound(PackModel):
    max: int = Field(ge=1)


class OfflineBounds(PackModel):
    """Approved UPPER bounds for the safety-relevant offline settings (a society may only tighten them)."""

    resident_credential_validity_hours: MaxBound
    clock_uncertainty_disable_auto_approvals_seconds: MaxBound
    policy_age_guard_assisted_verification_hours: MaxBound
    edge_event_buffer_hours: MaxBound


class CascadeOfflinePack(PackHeader):
    pack_type: Literal["cascade-offline"] = "cascade-offline"
    cascade: CascadeSection
    offline: OfflineDefaults
    offline_bounds: OfflineBounds

    @model_validator(mode="after")
    def _defaults_within_bounds(self) -> CascadeOfflinePack:
        for name in OfflineBounds.model_fields:
            default, ceiling = getattr(self.offline, name), getattr(self.offline_bounds, name).max
            if default > ceiling:
                raise ValueError(f"offline.{name} default {default} exceeds its bound {ceiling}")
        return self
