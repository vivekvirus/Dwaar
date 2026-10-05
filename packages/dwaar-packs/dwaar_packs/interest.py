"""Interest cap check (FIN-04, AT-37). The cap comes from the pack, never from code."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from fractions import Fraction

from .approvals import ApprovalRegistry
from .binding import binding_status
from .models import LegalPack
from .rule_values import is_number

CAP_KEY = "interest.max_simple_pct_pa"


@dataclass(frozen=True)
class InterestViolation:
    code: str  # interest_exceeds_simple_cap | interest_cap_not_configured
    message: str
    rule_key: str
    pack_id: str
    rate_bp: int
    cap_bp: int | None
    excess_bp: int | None
    legal_source_ref: str


@dataclass(frozen=True)
class InterestCapResult:
    ok: bool
    rate_bp: int
    cap_bp: int | None
    violation: InterestViolation | None
    binding: bool = False  # True only if the pack is approved WITH evidence and in range (GOV-01)
    binding_blockers: tuple[str, ...] = ()

    @property
    def blocks_approval(self) -> bool:
        """A bill-run preview with a violation fails and cannot be approved (AT-37)."""
        return not self.ok


def _cap_bp(pct: object) -> Fraction:
    if isinstance(pct, bool) or not isinstance(pct, int | float | str | Decimal):
        raise ValueError("interest cap must be numeric")
    try:
        value = Decimal(str(pct))
    except InvalidOperation:
        raise ValueError("interest cap must be numeric") from None
    if not is_number(value) or value < 0:
        raise ValueError("interest cap must be a finite, non-negative number")
    return Fraction(value) * 100


def check_interest_cap(
    rate_bp: int,
    pack: LegalPack,
    *,
    at_date: date | None = None,
    registry: ApprovalRegistry | None = None,
) -> InterestCapResult:
    """Compare a simple-interest rate in basis points (1800 = 18% p.a.) with the pack cap.

    Fail-closed: an unconfigured cap is a violation, so a bill run cannot proceed on guesswork. The result
    says whether the pack was allowed to bind on ``at_date`` (default today); ``ok`` from a non-binding
    result is a preview only (GOV-01).
    """
    if isinstance(rate_bp, bool) or not isinstance(rate_bp, int) or rate_bp < 0:
        raise ValueError("rate_bp must be a non-negative integer")
    binding, blockers = binding_status(pack, at_date, registry=registry)
    result = _check(rate_bp, pack)
    return InterestCapResult(
        result.ok, result.rate_bp, result.cap_bp, result.violation, binding, blockers
    )


def _check(rate_bp: int, pack: LegalPack) -> InterestCapResult:
    rule = pack.rules.get(CAP_KEY)
    ref = rule.legal_source_ref if rule else ""
    if rule is None or rule.value is None:
        v = InterestViolation(
            "interest_cap_not_configured",
            f"{pack.pack_id} has no configured {CAP_KEY}; interest cannot be validated",
            CAP_KEY,
            pack.pack_id,
            rate_bp,
            None,
            None,
            ref,
        )
        return InterestCapResult(False, rate_bp, None, v)
    cap = _cap_bp(rule.value)
    if rate_bp <= cap:
        return InterestCapResult(True, rate_bp, int(cap), None)
    cap_bp = int(cap)
    excess = rate_bp - cap_bp
    v = InterestViolation(
        "interest_exceeds_simple_cap",
        f"interest {rate_bp / 100:g}% exceeds the {cap_bp / 100:g}% simple cap in {pack.pack_id}",
        CAP_KEY,
        pack.pack_id,
        rate_bp,
        cap_bp,
        excess,
        ref,
    )
    return InterestCapResult(False, rate_bp, cap_bp, v)
