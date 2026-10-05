"""Cascade/offline bounds, retention, TDS, GST, e-invoice, UPI MDR."""

from __future__ import annotations

from datetime import date

import pytest

from dwaar_packs import (
    ConfigBoundsError,
    RoundingMode,
    RuleNotConfigured,
    RuleNotEffective,
    RuleNotFound,
    assess_gst_rwa,
    cascade_config,
    compute_tds,
    einvoice_reporting_deadline,
    retention_rule,
    upi_mdr_paise,
    upi_mdr_quote,
)
from dwaar_packs.retention import operational_days
from dwaar_packs.tax import (
    LowerDeductionCertificate,
    default_gst_einvoice_pack,
    default_gst_rwa_pack,
    default_tds_pack,
    irp_integration_applicable,
    resolve_tds_category,
)
from dwaar_packs.upi import default_upi_schedule

D = date(2026, 10, 20)


# ------------------------------------------------------------------ cascade (D-15, D-13)
@pytest.mark.req("D-15", "NOTIF-03")
def test_cascade_defaults() -> None:
    c = cascade_config()
    assert [s.at_seconds for s in c.steps] == [0, 10, 20, 35, 90]
    assert c.expiry_seconds == 90 and c.auto_allow_on_timeout is False
    assert c.steps[-1].guard_options == ["hold", "leave_at_gate", "lobby_only", "intercom", "deny"]


@pytest.mark.req("D-13")
def test_offline_defaults() -> None:
    o = cascade_config().offline
    assert o.resident_credential_validity_hours == 72
    assert o.guest_pass_max_hours == 2
    assert o.clock_uncertainty_disable_auto_approvals_seconds == 60
    assert o.supervisor_override_validity == "until_shift_end_or_earlier"
    assert o.policy_age_guard_assisted_verification_hours == 72
    assert o.edge_event_buffer_hours == 72
    assert o.terminal_standalone_min_hours == 24


@pytest.mark.req("D-15")
def test_cascade_overrides_within_bounds() -> None:
    c = cascade_config({"step_at_seconds": {2: 15, 3: 30, 4: 50}, "expiry_seconds": 180})
    assert [s.at_seconds for s in c.steps] == [0, 15, 30, 50, 180]
    assert cascade_config({"expiry_seconds": 60}).expiry_seconds == 60
    assert (
        cascade_config({"offline": {"guest_pass_max_hours": 1}}).offline.guest_pass_max_hours == 1
    )


@pytest.mark.parametrize(
    ("ov", "needle"),
    [
        ({"expiry_seconds": 59}, "outside 60-180"),
        ({"expiry_seconds": 181}, "outside 60-180"),
        ({"step_at_seconds": {2: 5}}, "below minimum 10s"),
        ({"step_at_seconds": {3: 15}}, "below minimum 10s"),  # 10 -> 15
        ({"step_at_seconds": {1: 5}}, "not overridable"),
        ({"step_at_seconds": {5: 100}}, "not overridable"),
        ({"step_at_seconds": {4: 25}, "expiry_seconds": 30}, "outside 60-180"),
        ({"auto_allow_on_timeout": True}, "auto-allow"),
        ({"offline": {"guest_pass_max_hours": 3}}, "above maximum 2"),
        ({"offline": {"terminal_standalone_min_hours": 12}}, "below minimum 24"),
        ({"offline": {"edge_event_buffer_hours": 0}}, "positive integer"),
        ({"offline": {"bogus": 1}}, "not overridable"),
    ],
)
def test_cascade_bounds_violations(ov: dict[str, object], needle: str) -> None:
    with pytest.raises(ConfigBoundsError, match=needle):
        cascade_config(ov)


# ------------------------------------------------------------------ retention (PRIV-06, D-16)
@pytest.mark.req("PRIV-06", "D-16")
def test_retention_classes() -> None:
    for cid in ["VIS", "VISPH", "DEL", "ANPR", "CRED", "RES", "STF", "FIN", "LOG", "BKP", "HOLD"]:
        assert retention_rule(cid).record_class == cid
    vis = retention_rule("VIS")
    assert vis.operational.days == 30 and vis.operational.extendable_to_days == 90
    assert vis.archive.min_days == 365 and vis.erasure.method == "crypto_shred"
    assert (
        retention_rule("DEL").operational.days == 7 and retention_rule("ANPR").operational.days == 7
    )
    assert retention_rule("BKP").archive.min_days == 35
    log = retention_rule("LOG")
    assert sorted(c.min_days or 0 for c in log.archive.components) == [180, 365]
    assert log.archive.min_days == 365
    with pytest.raises(RuleNotFound):
        retention_rule("XYZ")


@pytest.mark.req("D-16")
def test_visitor_extension_needs_justification() -> None:
    vis = retention_rule("VIS")
    assert operational_days(vis) == 30
    assert operational_days(vis, extension_days=90, justification="police request 123") == 90
    with pytest.raises(ValueError, match="justification"):
        operational_days(vis, extension_days=60)
    with pytest.raises(ValueError, match="between"):
        operational_days(vis, extension_days=91, justification="x")
    with pytest.raises(ValueError, match="not extendable"):
        operational_days(retention_rule("DEL"), extension_days=10, justification="x")


# ------------------------------------------------------------------ TDS (TAX-04)
@pytest.mark.req("TAX-04")
def test_tds_pack_structure() -> None:
    p = default_tds_pack()
    assert p.effective_from == date(2026, 4, 1) and not p.is_approved
    c = p.categories["contractor"]
    assert c.payees["individual_huf"].rate_bp == 100 and c.payees["others"].rate_bp == 200
    assert c.thresholds.single_payment_paise == 3_000_000
    assert c.thresholds.aggregate_per_financial_year_paise == 10_000_000
    assert {a.alias for a in p.legacy_aliases} == {"194C", "194J", "194I"}
    assert all(a.historical for a in p.legacy_aliases)
    assert resolve_tds_category(p, "194C") == "contractor"
    assert resolve_tds_category(p, "194I") == "rent"
    assert set(p.categories) == {"contractor", "professional", "rent"}
    with pytest.raises(RuleNotFound):
        resolve_tds_category(p, "194Z")


@pytest.mark.req("TAX-04", "TAX-05")
def test_tds_contractor_rates_and_thresholds() -> None:
    p = default_tds_pack()
    t = date(2026, 5, 1)
    r = compute_tds(
        p,
        category="contractor",
        payee_category="individual_huf",
        amount_paise=5_000_000,
        trigger_date=t,
    )
    assert r.deduct and r.tds_paise == 50_000 and r.rate_bp == 100
    assert r.rule_id == "income-tax-tds@2026.1.0-draft:contractor:individual_huf" and r.explanation
    r = compute_tds(
        p, category="194C", payee_category="others", amount_paise=5_000_000, trigger_date=t
    )
    assert r.tds_paise == 100_000 and "legacy label 194C" in r.explanation[0]
    # at the single threshold exactly: strict "exceeds"
    r = compute_tds(
        p, category="contractor", payee_category="others", amount_paise=3_000_000, trigger_date=t
    )
    assert not r.deduct and r.tds_paise == 0
    # cumulative crossing needs CA-configured basis
    with pytest.raises(RuleNotConfigured, match="aggregate_crossing_basis"):
        compute_tds(
            p,
            category="contractor",
            payee_category="others",
            amount_paise=2_500_000,
            cumulative_prior_paise=8_000_000,
            trigger_date=t,
        )
    # no prior payments and below both thresholds: nothing
    assert not compute_tds(
        p,
        category="contractor",
        payee_category="others",
        amount_paise=2_500_000,
        cumulative_prior_paise=0,
        trigger_date=t,
    ).deduct


@pytest.mark.req("TAX-04")
def test_tds_cumulative_basis_when_configured() -> None:
    p = default_tds_pack()
    cat = p.categories["contractor"]
    cfg = cat.model_copy(
        update={
            "thresholds": cat.thresholds.model_copy(
                update={"aggregate_crossing_basis": "cumulative_amount"}
            )
        }
    )
    p2 = p.model_copy(update={"categories": {**p.categories, "contractor": cfg}})
    r = compute_tds(
        p2,
        category="contractor",
        payee_category="others",
        amount_paise=2_500_000,
        cumulative_prior_paise=8_000_000,
        trigger_date=date(2026, 5, 1),
    )
    assert r.base_paise == 10_500_000 and r.tds_paise == 210_000


@pytest.mark.req("TAX-04", "TAX-05")
def test_tds_missing_config_blocks_and_date_selects_rule() -> None:
    p = default_tds_pack()
    with pytest.raises(RuleNotConfigured):
        compute_tds(
            p, category="professional", payee_category="others", amount_paise=1, trigger_date=D
        )
    with pytest.raises(RuleNotConfigured, match="missing-PAN"):
        compute_tds(
            p,
            category="contractor",
            payee_category="others",
            amount_paise=5_000_000,
            trigger_date=D,
            pan_available=False,
        )
    with pytest.raises(RuleNotEffective):
        compute_tds(
            p,
            category="194C",
            payee_category="others",
            amount_paise=5_000_000,
            trigger_date=date(2026, 3, 31),
        )


@pytest.mark.req("TAX-04")
def test_tds_certificates_and_missing_pan_configured() -> None:
    p = default_tds_pack()
    t = date(2026, 6, 1)
    nil = LowerDeductionCertificate("TEST-1", date(2026, 4, 1), date(2027, 3, 31), None)
    low = LowerDeductionCertificate("TEST-2", date(2026, 4, 1), date(2027, 3, 31), 50)
    expired = LowerDeductionCertificate("TEST-3", date(2026, 4, 1), date(2026, 5, 31), None)
    args = {
        "category": "contractor",
        "payee_category": "others",
        "amount_paise": 5_000_000,
        "trigger_date": t,
    }
    assert compute_tds(p, certificate=nil, **args).tds_paise == 0  # type: ignore[arg-type]
    assert compute_tds(p, certificate=low, **args).tds_paise == 25_000  # type: ignore[arg-type]
    assert compute_tds(p, certificate=expired, **args).tds_paise == 100_000  # type: ignore[arg-type]
    p2 = p.model_copy(update={"missing_pan": p.missing_pan.model_copy(update={"rate_bp": 2000})})
    assert compute_tds(p2, pan_available=False, **args).tds_paise == 1_000_000  # type: ignore[arg-type]


# ------------------------------------------------------------------ GST (TAX-02, TAX-03)
@pytest.mark.req("TAX-02")
def test_gst_rwa_full_amount_above_limit() -> None:
    p = default_gst_rwa_pack()
    assert p.exemption.per_member_per_month_paise == 750_000
    assert p.turnover_threshold_paise == 200_000_000
    a = assess_gst_rwa(p, per_member_monthly_paise=750_000, aggregate_turnover_paise=300_000_000)
    assert a.exemption_available and a.taxable_base_paise == 0 and a.turnover_above_threshold
    b = assess_gst_rwa(p, per_member_monthly_paise=750_001, aggregate_turnover_paise=300_000_000)
    assert (
        not b.exemption_available and b.taxable_base_paise == 750_001
    )  # full amount, not the excess
    assert b.gst_paise is None and b.requires_ca_classification  # rate unconfigured: CA must set


@pytest.mark.req("TAX-02")
def test_gst_rwa_rate_from_pack_when_configured() -> None:
    p = default_gst_rwa_pack().model_copy(update={"gst_rate_bp": 1800})
    b = assess_gst_rwa(p, per_member_monthly_paise=1_000_000, aggregate_turnover_paise=0)
    assert b.gst_paise == 180_000 and not b.turnover_above_threshold


@pytest.mark.req("TAX-03")
def test_einvoice_window() -> None:
    p = default_gst_einvoice_pack()
    assert p.reporting_window.aato_threshold_paise == 10_000_000_000
    assert p.irp_integration_turnover_threshold_paise == 5_000_000_000
    d = date(2026, 11, 1)
    assert einvoice_reporting_deadline(p, aato_paise=10_000_000_000, invoice_date=d) == date(
        2026, 12, 1
    )
    assert einvoice_reporting_deadline(p, aato_paise=9_999_999_999, invoice_date=d) is None
    assert irp_integration_applicable(p, turnover_paise=5_000_000_001)
    assert not irp_integration_applicable(p, turnover_paise=5_000_000_000)
    assert p.integration["irp_enabled_by_default"] is False


# ------------------------------------------------------------------ UPI MDR (PAY-05, AT-46)
@pytest.mark.at("AT-46")
@pytest.mark.req("PAY-05", "FIN-04")
def test_at46_rs3000_net_of_mdr() -> None:
    q = upi_mdr_quote(300_000, None, D)
    assert q.fee_paise == 1_200 and q.net_settlement_paise == 298_800  # fee Rs 12, bank Rs 2,988
    assert q.rule == "percentage" and not q.schedule_approved
    assert upi_mdr_paise(300_000, None, D) == 1_200


@pytest.mark.req("PAY-05")
def test_mdr_thresholds_cap_and_effective_date() -> None:
    assert upi_mdr_paise(200_000, None, D) == 0  # Rs 2,000 itself: not above threshold
    assert upi_mdr_paise(200_001, None, D) == 800  # 0.4% of 200,001 = 800.004 -> 800
    assert upi_mdr_paise(7_499_900, None, D) == 30_000  # rounds to cap value
    q = upi_mdr_quote(10_000_000, None, D)
    assert q.fee_paise == 30_000 and q.rule == "percentage_capped"  # Rs 300 cap above Rs 75,000
    assert upi_mdr_paise(7_500_000, None, D) == 30_000
    with pytest.raises(RuleNotEffective):
        upi_mdr_paise(300_000, None, date(2026, 10, 14))
    assert upi_mdr_paise(300_000, None, date(2026, 10, 15)) == 1_200


@pytest.mark.req("PAY-05")
def test_mdr_rounding_modes() -> None:
    amt = 200_125  # 0.4% = 800.5 paise
    assert upi_mdr_paise(amt, None, D, rounding=RoundingMode.HALF_UP) == 801
    assert upi_mdr_paise(amt, None, D, rounding=RoundingMode.HALF_EVEN) == 800
    assert upi_mdr_paise(amt, None, D, rounding=RoundingMode.DOWN) == 800
    assert upi_mdr_paise(amt, None, D, rounding=RoundingMode.UP) == 801


@pytest.mark.req("PAY-05")
def test_mdr_flat_category_when_configured() -> None:
    s = default_upi_schedule()
    assert s.flat_fee_categories.categories == []  # PRD does not list them; never invented
    assert (
        upi_mdr_quote(300_000, "essential_x", D).rule == "percentage"
    )  # unknown category: no flat fee
    cfg = s.model_copy(
        update={
            "flat_fee_categories": s.flat_fee_categories.model_copy(
                update={"categories": ["essential_x"]}
            )
        }
    )
    q = upi_mdr_quote(300_000, "essential_x", D, schedule=cfg)
    assert q.fee_paise == 500 and q.rule == "flat_category"
    assert upi_mdr_quote(1_000, "essential_x", D, schedule=cfg).fee_paise == 500
    with pytest.raises(ValueError, match="non-negative"):
        upi_mdr_paise(-1, None, D)
