"""Quorum and voting evaluators. All parameters come from the pack (INV-10); arithmetic is exact (Fraction).

REQ: GOV-01, GOV-02, AT-38.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from fractions import Fraction
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .approvals import ApprovalRegistry
from .binding import binding_status, rule_value
from .models import LegalPack
from .rule_values import is_number


class _Frac(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    numerator: int
    denominator: int


class QuorumParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fraction: _Frac
    of: Literal["members", "total_members", "owners"]
    rounding: Literal["ceil", "floor"] = "ceil"
    cap: int | None = None
    adjourn_after_minutes: int | None = None
    registrar_representative_required: bool = False
    video_recording_mandatory: bool = False
    developer_selection_pct_of_total_members: int | None = None


def _count(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a non-negative integer")
    return value


def check_quorum_params(params: QuorumParams) -> None:
    """Refuse parameters that would make quorum trivially (or never) true. Fraction above one stays legal
    but unattainable, which fails closed."""
    if params.fraction.denominator <= 0 or params.fraction.numerator <= 0:
        raise ValueError("fraction must be positive")
    if params.cap is not None and params.cap < 1:
        raise ValueError(
            "quorum cap must be at least 1 (a cap of 0 or less means quorum with nobody)"
        )
    if params.adjourn_after_minutes is not None and params.adjourn_after_minutes < 0:
        raise ValueError("adjourn_after_minutes must be >= 0")


def quorum_required(params: QuorumParams, total: int) -> int:
    """Required attendee count: round(fraction x total), then min with the cap if the pack sets one."""
    _count(total, "total")
    check_quorum_params(params)
    exact = Fraction(params.fraction.numerator, params.fraction.denominator) * total
    n = math.ceil(exact) if params.rounding == "ceil" else math.floor(exact)
    return n if params.cap is None else min(n, params.cap)


@dataclass(frozen=True)
class QuorumResult:
    rule_key: str
    pack_id: str
    total: int
    required: int
    attending: int
    count_met: bool
    met: bool
    unmet_conditions: list[str] = field(default_factory=list)
    adjourn_after_minutes: int | None = None
    binding: bool = (
        False  # True only if the pack is approved WITH evidence, in range and complete (GOV-01)
    )
    binding_blockers: tuple[str, ...] = ()


def evaluate_quorum(
    pack: LegalPack,
    rule_key: str,
    *,
    total: int,
    verified_attendees: int,
    registrar_representative_present: bool = False,
    video_recording_active: bool = False,
    at_date: date | None = None,
    registry: ApprovalRegistry | None = None,
) -> QuorumResult:
    """Evaluate ``quorum.ordinary`` / ``quorum.redevelopment`` (or any key with QuorumParams shape).

    The arithmetic runs on any pack; ``result.binding`` says whether the pack was allowed to bind on
    ``at_date`` (default today). ``met`` from a non-binding result is advisory only (GOV-01).
    """
    params = QuorumParams.model_validate(rule_value(pack, rule_key))
    _count(total, "total")
    _count(verified_attendees, "verified_attendees")
    if verified_attendees > total:
        raise ValueError("verified_attendees cannot exceed total")
    binding, blockers = binding_status(pack, at_date, registry=registry, require_complete=True)
    required = quorum_required(params, total)
    count_met = verified_attendees >= required
    unmet: list[str] = []
    if not count_met:
        unmet.append("attendance_below_required")
    if params.registrar_representative_required and not registrar_representative_present:
        unmet.append("registrar_representative_missing")
    if params.video_recording_mandatory and not video_recording_active:
        unmet.append("video_recording_missing")
    return QuorumResult(
        rule_key=rule_key,
        pack_id=pack.pack_id,
        total=total,
        required=required,
        attending=verified_attendees,
        count_met=count_met,
        met=not unmet,
        unmet_conditions=unmet,
        adjourn_after_minutes=params.adjourn_after_minutes,
        binding=binding,
        binding_blockers=blockers,
    )


def developer_selection_met(pack: LegalPack, *, total_members: int, votes_for: int) -> bool:
    """Developer selection threshold as a share of TOTAL members (not of those present)."""
    _count(total_members, "total_members")
    _count(votes_for, "votes_for")
    if votes_for > total_members:
        raise ValueError("votes_for cannot exceed total_members")
    params = QuorumParams.model_validate(rule_value(pack, "quorum.redevelopment"))
    pct = params.developer_selection_pct_of_total_members
    if pct is None:
        raise ValueError("pack has no developer_selection_pct_of_total_members")
    return total_members > 0 and Fraction(votes_for, total_members) >= Fraction(pct, 100)


def _resolution_fraction(raw: object) -> Fraction:
    """The configured percentage as an exact fraction of one (66.67 stays 66.67 %, never truncated)."""
    if not is_number(raw) or not 0 < raw <= 100:  # type: ignore[operator]
        raise ValueError("resolution_pct_of_members_present must be a number in (0, 100]")
    return Fraction(Decimal(str(raw))) / 100


@dataclass(frozen=True)
class ResolutionResult:
    passes: bool
    pack_id: str
    present: int
    votes_for: int
    required_fraction: Fraction
    binding: bool = False
    binding_blockers: tuple[str, ...] = ()


def evaluate_resolution(
    pack: LegalPack,
    *,
    present: int,
    votes_for: int,
    at_date: date | None = None,
    registry: ApprovalRegistry | None = None,
) -> ResolutionResult:
    """Ordinary resolution: ``resolution_pct_of_members_present`` of members present (video included).

    Exact arithmetic; ``0 <= votes_for <= present`` is enforced. ``binding`` says whether the pack was
    allowed to bind on ``at_date`` (GOV-01).
    """
    _count(present, "present")
    _count(votes_for, "votes_for")
    if votes_for > present:
        raise ValueError("votes_for cannot exceed members present")
    basis = rule_value(pack, "voting.basis")
    if not isinstance(basis, dict) or "resolution_pct_of_members_present" not in basis:
        raise ValueError("voting.basis has no resolution_pct_of_members_present")
    needed = _resolution_fraction(basis["resolution_pct_of_members_present"])
    binding, blockers = binding_status(pack, at_date, registry=registry, require_complete=True)
    passes = present > 0 and Fraction(votes_for, present) >= needed
    return ResolutionResult(passes, pack.pack_id, present, votes_for, needed, binding, blockers)


def resolution_passes(pack: LegalPack, *, present: int, votes_for: int) -> bool:
    """Arithmetic only (see ``evaluate_resolution``): True/False says nothing about whether the pack may bind."""
    return evaluate_resolution(pack, present=present, votes_for=votes_for).passes
