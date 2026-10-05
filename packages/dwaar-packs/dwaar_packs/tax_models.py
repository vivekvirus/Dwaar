"""Tax and fee pack models (TAX-01..04, PAY-05). Amounts are integer paise; rates are basis points."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import model_validator

from .models import Label, PackHeader, PackModel
from .rounding import RoundingMode


class RoundingSpec(PackModel):
    mode: RoundingMode
    unit_paise: int = 1


class TdsPayeeRate(PackModel):
    rate_bp: int | None


class TdsThresholds(PackModel):
    single_payment_paise: int | None
    aggregate_per_financial_year_paise: int | None
    aggregate_crossing_basis: Literal["payment_amount", "cumulative_amount"] | None


class TdsCategory(PackModel):
    description: str
    section_ref: str
    legal_source_ref: str
    labels: list[Label]
    payees: dict[Literal["individual_huf", "others"], TdsPayeeRate]
    thresholds: TdsThresholds


class TdsLegacyAlias(PackModel):
    alias: str
    category: str
    historical: Literal[True]
    valid_through: str


class MissingPan(PackModel):
    rate_bp: int | None
    note: str | None = None


class TdsPack(PackHeader):
    pack_type: Literal["tds"] = "tds"
    trigger_date_basis: Literal["credit_or_payment"]
    rounding: RoundingSpec
    threshold_comparison: Literal["gt", "gte"]
    missing_pan: MissingPan
    lower_deduction_certificate: dict[str, Any]
    cumulative_thresholds: dict[str, Any]
    challan_and_returns: dict[str, Any] = {}
    legacy_aliases: list[TdsLegacyAlias]
    categories: dict[str, TdsCategory]

    @model_validator(mode="after")
    def _check_refs(self) -> TdsPack:
        for cid, c in self.categories.items():
            if c.legal_source_ref not in self.source_ids:
                raise ValueError(f"category {cid}: unknown legal_source_ref")
        for a in self.legacy_aliases:
            if a.category not in self.categories:
                raise ValueError(f"alias {a.alias}: unknown category {a.category}")
        return self


class GstExemption(PackModel):
    per_member_per_month_paise: int
    basis_when_above_threshold: Literal["full_amount"]


class GstRwaPack(PackHeader):
    pack_type: Literal["gst-rwa"] = "gst-rwa"
    entity_type: Literal["rwa"]
    supply_type: str
    exemption: GstExemption
    turnover_threshold_paise: int
    gst_rate_bp: int | None
    reimbursement_and_pure_agent_heads: str | None = None
    requires_ca_classification: Literal[True]
    rounding: RoundingSpec


class EinvoiceReportingWindow(PackModel):
    aato_threshold_paise: int
    comparison: Literal["gt", "gte"]
    limit_days: int


class GstEinvoicePack(PackHeader):
    pack_type: Literal["gst-einvoice"] = "gst-einvoice"
    irp_integration_turnover_threshold_paise: int
    reporting_window: EinvoiceReportingWindow
    integration: dict[str, Any] = {}


class PercentageFee(PackModel):
    applies_above_amount_paise: int
    rate_bp: int


class FeeCap(PackModel):
    applies_from_amount_paise: int
    max_fee_paise: int


class FlatFeeCategories(PackModel):
    fee_paise: int
    categories: list[str]


class FeeSchedule(PackHeader):
    pack_type: Literal["fee-schedule"] = "fee-schedule"
    channel: str
    acquirer_classification: str = "default"
    percentage: PercentageFee
    cap: FeeCap
    flat_fee_categories: FlatFeeCategories
    p2pm_classification: dict[str, Any] = {}
    pass_to_resident: Literal[False]
    default_rounding: RoundingMode
