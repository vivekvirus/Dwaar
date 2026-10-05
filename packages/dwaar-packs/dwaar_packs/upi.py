"""UPI MDR from the effective-dated fee schedule (PAY-05). VERIFY with acquirer.

The MDR is never passed to the resident; AT-46: Rs 3,000 settles net of 0.4% => bank Rs 2,988, fee Rs 12.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from functools import cache

from dwaar_common.money import ensure_paise

from .errors import RuleNotEffective
from .loader import load_typed
from .paths import tax_packs_dir
from .rounding import RoundingMode, round_div
from .tax_models import FeeSchedule


@cache
def default_upi_schedule() -> FeeSchedule:
    return load_typed(tax_packs_dir() / "fee-schedules" / "upi-mdr.yaml", FeeSchedule)


@dataclass(frozen=True)
class UpiMdrQuote:
    amount_paise: int
    fee_paise: int
    net_settlement_paise: int
    rule: str  # none_at_or_below_threshold | percentage | percentage_capped | flat_category
    schedule_id: str
    schedule_approved: bool


def upi_mdr_quote(
    amount_paise: int,
    category: str | None,
    at_date: date,
    *,
    schedule: FeeSchedule | None = None,
    rounding: RoundingMode | None = None,
) -> UpiMdrQuote:
    s = schedule or default_upi_schedule()
    amount_paise = ensure_paise(
        amount_paise, "amount_paise"
    )  # int only: no float, no bool, 64-bit range
    if amount_paise < 0:
        raise ValueError("amount_paise must be a non-negative integer")
    if at_date < s.effective_from or (s.effective_to is not None and at_date > s.effective_to):
        raise RuleNotEffective(f"{s.pack_id}@{s.version} not effective on {at_date}")
    mode = rounding or s.default_rounding
    sid = f"{s.pack_id}@{s.version}"
    if category is not None and category in s.flat_fee_categories.categories:
        fee, rule = s.flat_fee_categories.fee_paise, "flat_category"
    elif amount_paise <= s.percentage.applies_above_amount_paise:
        fee, rule = 0, "none_at_or_below_threshold"
    else:
        fee, rule = round_div(amount_paise * s.percentage.rate_bp, 10_000, mode), "percentage"
        if amount_paise >= s.cap.applies_from_amount_paise and fee > s.cap.max_fee_paise:
            fee, rule = s.cap.max_fee_paise, "percentage_capped"
    return UpiMdrQuote(amount_paise, fee, amount_paise - fee, rule, sid, s.is_approved)


def upi_mdr_paise(
    amount_paise: int,
    category: str | None,
    at_date: date,
    *,
    schedule: FeeSchedule | None = None,
    rounding: RoundingMode | None = None,
) -> int:
    """MDR fee in integer paise (e.g. 300_000 paise => 1_200 paise, i.e. Rs 3,000 => Rs 12)."""
    return upi_mdr_quote(
        amount_paise, category, at_date, schedule=schedule, rounding=rounding
    ).fee_paise
