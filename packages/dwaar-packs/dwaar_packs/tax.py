"""Deterministic tax calculators driven by tax packs (TAX-01..05). No tax value is hard-coded here.

Every result carries the rule ID and an explanation (TAX-05). Missing configuration raises
RuleNotConfigured so the caller routes the item into review instead of posting a guess. An LLM never
chooses a rate: these functions only read the pack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from functools import cache
from typing import Literal

from dwaar_common.money import ensure_paise

from .approvals import ApprovalRegistry
from .binding import binding_status
from .errors import PackError, RuleNotConfigured, RuleNotEffective, RuleNotFound
from .loader import load_typed
from .paths import tax_packs_dir
from .rounding import round_div
from .tax_models import GstEinvoicePack, GstRwaPack, TdsPack

PayeeCategory = Literal["individual_huf", "others"]


@cache
def default_tds_pack() -> TdsPack:
    return load_typed(tax_packs_dir() / "packs" / "income-tax-tds.yaml", TdsPack)


@cache
def default_gst_rwa_pack() -> GstRwaPack:
    return load_typed(tax_packs_dir() / "packs" / "gst-rwa.yaml", GstRwaPack)


@cache
def default_gst_einvoice_pack() -> GstEinvoicePack:
    return load_typed(tax_packs_dir() / "packs" / "gst-einvoice.yaml", GstEinvoicePack)


# ------------------------------------------------------------------ TDS (TAX-04)
@dataclass(frozen=True)
class LowerDeductionCertificate:
    """Lower or nil deduction certificate. ``rate_bp=None`` means a nil certificate."""

    certificate_no: str
    valid_from: date
    valid_to: date
    rate_bp: int | None
    max_amount_paise: int | None = None


@dataclass(frozen=True)
class TdsResult:
    rule_id: str
    category: str
    payee_category: str
    deduct: bool
    rate_bp: int
    base_paise: int
    tds_paise: int
    explanation: list[str] = field(default_factory=list)
    # GOV-01 / INV-10: the figure is arithmetic on a pack. ``binding`` is True only if that pack is enabled,
    # approved WITH registry evidence and effective on the trigger date; otherwise the number is a draft
    # estimate and must not be posted as final. ``binding_blockers`` says why (codes, never legal values).
    binding: bool = False
    binding_blockers: tuple[str, ...] = ()


def resolve_tds_category(pack: TdsPack, label: str) -> str:
    """Map a category id or a legacy alias (194C/194J/194I) to the current category id."""
    if label in pack.categories:
        return label
    for a in pack.legacy_aliases:
        if a.alias == label:
            return a.category
    raise RuleNotFound(f"{pack.pack_id}: unknown TDS category or alias {label!r}")


def _note_if_draft(notes: list[str], binding: bool, blockers: tuple[str, ...]) -> None:
    if not binding:
        notes.append(
            "DRAFT: pack is not approved/binding ("
            + ", ".join(blockers)
            + "); estimate only, do not post"
        )


def compute_tds(
    pack: TdsPack,
    *,
    category: str,
    payee_category: PayeeCategory,
    amount_paise: int,
    trigger_date: date,
    cumulative_prior_paise: int = 0,
    pan_available: bool = True,
    certificate: LowerDeductionCertificate | None = None,
    registry: ApprovalRegistry | None = None,
) -> TdsResult:
    """TDS on one credit/payment. ``trigger_date`` is the credit or payment date selecting the rule.

    Threshold comparison (strict ``gt`` unless the pack says ``gte``) and the crossing basis come from the pack.
    The arithmetic runs on any pack; ``result.binding`` says whether the pack was allowed to bind on
    ``trigger_date`` (approved with evidence, enabled, in range). A non-binding result is a draft estimate.
    """
    amount_paise = ensure_paise(amount_paise, "amount_paise")
    cumulative_prior_paise = ensure_paise(cumulative_prior_paise, "cumulative_prior_paise")
    if amount_paise < 0 or cumulative_prior_paise < 0:
        raise ValueError("amounts must be >= 0")
    if trigger_date < pack.effective_from or (
        pack.effective_to is not None and trigger_date > pack.effective_to
    ):
        raise RuleNotEffective(f"{pack.pack_id} has no rule for {trigger_date}")
    cat_id = resolve_tds_category(pack, category)
    cat = pack.categories[cat_id]
    rule_id = f"{pack.pack_id}@{pack.version}:{cat_id}:{payee_category}"
    binding, blockers = binding_status(pack, trigger_date, registry=registry)
    notes: list[str] = []
    if category != cat_id:
        notes.append(f"legacy label {category} treated as {cat_id} (historical alias)")
    base_rate = cat.payees[payee_category].rate_bp
    if base_rate is None:
        raise RuleNotConfigured(f"{rule_id}: rate not configured; CA must configure it")

    def over(value: int, limit: int) -> bool:
        return value > limit if pack.threshold_comparison == "gt" else value >= limit

    single = cat.thresholds.single_payment_paise
    agg = cat.thresholds.aggregate_per_financial_year_paise
    base = amount_paise
    if single is not None and agg is not None:
        single_hit = over(amount_paise, single)
        agg_hit = over(cumulative_prior_paise + amount_paise, agg)
        if not single_hit and not agg_hit:
            notes.append("below single-payment and cumulative thresholds: no deduction")
            _note_if_draft(notes, binding, blockers)
            return TdsResult(
                rule_id, cat_id, payee_category, False, 0, amount_paise, 0, notes, binding, blockers
            )
        if agg_hit and not single_hit and cumulative_prior_paise > 0:
            basis = cat.thresholds.aggregate_crossing_basis
            if basis is None:
                raise RuleNotConfigured(f"{rule_id}: aggregate_crossing_basis not configured [CA]")
            if basis == "cumulative_amount":
                base = cumulative_prior_paise + amount_paise
            notes.append(f"cumulative threshold crossed; base is {basis}")
        else:
            notes.append("threshold crossed")
    rate = base_rate
    if not pan_available:
        if pack.missing_pan.rate_bp is None:
            raise RuleNotConfigured(f"{rule_id}: missing-PAN rate not configured [CA]")
        rate = pack.missing_pan.rate_bp
        notes.append("PAN missing: pack missing-PAN rate applied")
    elif certificate is not None:
        in_date = certificate.valid_from <= trigger_date <= certificate.valid_to
        in_cap = certificate.max_amount_paise is None or (
            cumulative_prior_paise + amount_paise <= certificate.max_amount_paise
        )
        if in_date and in_cap:
            rate = 0 if certificate.rate_bp is None else certificate.rate_bp
            notes.append(f"certificate {certificate.certificate_no} applied")
        else:
            notes.append(
                f"certificate {certificate.certificate_no} not applicable (date or amount limit)"
            )
    unit = pack.rounding.unit_paise
    tds = round_div(base * rate, 10_000 * unit, pack.rounding.mode) * unit
    notes.append(f"{rate} bp on base {base} paise")
    _note_if_draft(notes, binding, blockers)
    return TdsResult(
        rule_id, cat_id, payee_category, tds > 0, rate, base, tds, notes, binding, blockers
    )


# ------------------------------------------------------------------ GST for RWAs (TAX-02)
@dataclass(frozen=True)
class GstRwaAssessment:
    rule_id: str
    exemption_available: bool
    taxable_base_paise: int
    gst_paise: int | None
    turnover_above_threshold: bool
    requires_ca_classification: bool
    explanation: list[str]
    binding: bool = False  # see TdsResult: True only for an approved, evidenced, effective pack
    binding_blockers: tuple[str, ...] = ()


def assess_gst_rwa(
    pack: GstRwaPack,
    *,
    per_member_monthly_paise: int,
    aggregate_turnover_paise: int,
    on_date: date | None = None,
    registry: ApprovalRegistry | None = None,
) -> GstRwaAssessment:
    """Contribution-limit assessment. Above the limit GST applies to the FULL amount, not the excess.

    The result is advisory: GST status and covered supply are never inferred from the amount alone
    (TAX-01), so ``requires_ca_classification`` stays true.
    """
    per_member_monthly_paise = ensure_paise(per_member_monthly_paise, "per_member_monthly_paise")
    aggregate_turnover_paise = ensure_paise(aggregate_turnover_paise, "aggregate_turnover_paise")
    if per_member_monthly_paise < 0 or aggregate_turnover_paise < 0:
        raise ValueError("amounts must be >= 0")
    limit = pack.exemption.per_member_per_month_paise
    exempt = per_member_monthly_paise <= limit
    base = 0 if exempt else per_member_monthly_paise
    gst = None
    if pack.gst_rate_bp is not None:
        gst = round_div(base * pack.gst_rate_bp, 10_000, pack.rounding.mode)
    above = aggregate_turnover_paise > pack.turnover_threshold_paise
    notes = [
        f"limit {limit} paise per member per month: "
        + ("within limit, exempt" if exempt else "above limit, GST on full amount"),
        "turnover above threshold" if above else "turnover within threshold",
    ]
    if not exempt and gst is None:
        notes.append("GST rate not configured; CA must configure")
    binding, blockers = binding_status(pack, on_date, registry=registry)
    if not binding:
        notes.append(
            "DRAFT: pack is not approved/binding (" + ", ".join(blockers) + "); advisory only"
        )
    return GstRwaAssessment(
        f"{pack.pack_id}@{pack.version}", exempt, base, gst, above, True, notes, binding, blockers
    )


# ------------------------------------------------------------------ e-invoice (TAX-03)
def einvoice_reporting_deadline(
    pack: GstEinvoicePack, *, aato_paise: int, invoice_date: date
) -> date | None:
    """Last day to report to the IRP when the AATO threshold applies; ``None`` when the window is N/A."""
    aato_paise = ensure_paise(aato_paise, "aato_paise")
    w = pack.reporting_window
    applies = (
        aato_paise > w.aato_threshold_paise
        if w.comparison == "gt"
        else (aato_paise >= w.aato_threshold_paise)
    )
    return invoice_date + timedelta(days=w.limit_days) if applies else None


def irp_integration_applicable(pack: GstEinvoicePack, *, turnover_paise: int) -> bool:
    """Turnover above the pack threshold for covered transactions; still disabled unless configured."""
    turnover_paise = ensure_paise(turnover_paise, "turnover_paise")
    return turnover_paise > pack.irp_integration_turnover_threshold_paise


__all__ = [
    "LowerDeductionCertificate",
    "PackError",
    "TdsResult",
    "assess_gst_rwa",
    "compute_tds",
    "default_gst_einvoice_pack",
    "default_gst_rwa_pack",
    "default_tds_pack",
    "einvoice_reporting_deadline",
    "irp_integration_applicable",
    "resolve_tds_category",
]
