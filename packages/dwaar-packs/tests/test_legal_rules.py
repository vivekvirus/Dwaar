"""Rule resolution, binding gate, quorum, interest cap, secretary overrides, repository."""

from __future__ import annotations

from datetime import date

import pytest

from dwaar_packs import (
    FilePackRepository,
    RuleNotConfigured,
    RuleNotFound,
    binding_blockers,
    check_interest_cap,
    developer_selection_met,
    evaluate_quorum,
    is_binding_allowed,
    is_binding_ready,
    load_pack,
    quorum_required,
    resolution_passes,
    resolve_rule,
    unconfigured_rule_keys,
    with_secretary_overrides,
)
from dwaar_packs.paths import legal_packs_dir
from dwaar_packs.quorum import QuorumParams

AT = date(2026, 10, 5)


@pytest.mark.req("INV-10")
def test_maharashtra_appendix_a_rule_keys_exact(mh) -> None:
    assert set(mh.rules) == {
        "charges.service.basis",
        "charges.lift.basis",
        "charges.insurance.basis",
        "charges.lease_rent.basis",
        "charges.water.basis",
        "interest.max_simple_pct_pa",
        "charges.non_occupancy",
        "funds.sinking.min_pct_construction_cost_pa",
        "funds.repair_maintenance.min_pct_construction_cost_pa",
        "funds.major_repair.basis",
        "funds.election.basis",
        "funds.education.per_member_per_month",
        "agm.deadline",
        "notice.agm_clear_days",
        "notice.sgm_clear_days",
        "notice.redevelopment_clear_days",
        "quorum.ordinary",
        "quorum.redevelopment",
        "voting.basis",
        "meetings.video_participation",
        "committee.one_time_repair_limit",
        "recovery.route",
    }
    v = {k: r.value for k, r in mh.rules.items()}
    assert v["interest.max_simple_pct_pa"] == 12
    assert (
        v["notice.agm_clear_days"],
        v["notice.sgm_clear_days"],
        v["notice.redevelopment_clear_days"],
    ) == (14, 5, 14)
    assert v["funds.education.per_member_per_month"] == 1000  # Rs 10 in paise
    tiers = v["committee.one_time_repair_limit"]["tiers"]
    assert [t["limit_paise"] for t in tiers] == [
        10_000_000,
        20_000_000,
        30_000_000,
        40_000_000,
        50_000_000,
    ]


@pytest.mark.req("GOV-01")
def test_resolve_rule(mh) -> None:
    assert resolve_rule(mh, "notice.agm_clear_days").value == 14
    with pytest.raises(RuleNotFound):
        resolve_rule(mh, "no.such.key")
    ka = load_pack(legal_packs_dir() / "packs" / "karnataka-aoa-1972.yaml")
    assert resolve_rule(ka, "quorum.ordinary").value is None
    with pytest.raises(RuleNotConfigured):
        resolve_rule(ka, "quorum.ordinary", require_value=True)


@pytest.mark.req("GOV-01")
def test_binding_disabled_until_approved_and_in_range(mh, approve) -> None:
    assert not is_binding_allowed(mh, AT)
    assert [b.code for b in binding_blockers(mh, AT)] == ["not_approved"]
    ok = approve(mh)
    assert is_binding_allowed(ok, AT)
    assert not is_binding_allowed(ok, date(2026, 6, 17))  # before effective_from
    expired = approve(
        ok.model_copy(update={"effective_to": date(2026, 12, 31)})
    )  # new content: re-approved
    assert is_binding_allowed(expired, date(2026, 12, 31))
    assert not is_binding_allowed(expired, date(2027, 1, 1))
    assert "expired" in [b.code for b in binding_blockers(expired, date(2027, 1, 1))]


@pytest.mark.req("GOV-01")
def test_disabled_variant_never_binding_even_if_approved(approve) -> None:
    v = approve(load_pack(legal_packs_dir() / "packs" / "karnataka-bill-2026-variant.yaml"))
    assert not is_binding_allowed(v, AT)
    assert "pack_disabled" in [b.code for b in binding_blockers(v, AT)]


@pytest.mark.req("GOV-01")
def test_binding_ready_needs_complete_pack(approve) -> None:
    ka = approve(load_pack(legal_packs_dir() / "packs" / "karnataka-aoa-1972.yaml"))
    assert is_binding_allowed(ka, AT)
    assert unconfigured_rule_keys(ka)
    assert not is_binding_ready(ka, AT)


@pytest.mark.at("AT-38")
@pytest.mark.req("GOV-01", "GOV-02", "INV-10")
def test_at38_300_members_20_attendees(mh) -> None:
    ordinary = evaluate_quorum(mh, "quorum.ordinary", total=300, verified_attendees=20)
    assert ordinary.required == 20 and ordinary.met and ordinary.adjourn_after_minutes == 30
    redev = evaluate_quorum(
        mh,
        "quorum.redevelopment",
        total=300,
        verified_attendees=20,
        registrar_representative_present=True,
        video_recording_active=True,
    )
    assert redev.required == 200 and not redev.met
    assert redev.unmet_conditions == ["attendance_below_required"]


@pytest.mark.req("GOV-01")
def test_redevelopment_needs_registrar_and_video(mh) -> None:
    r = evaluate_quorum(mh, "quorum.redevelopment", total=300, verified_attendees=250)
    assert r.count_met and not r.met
    assert set(r.unmet_conditions) == {
        "registrar_representative_missing",
        "video_recording_missing",
    }
    ok = evaluate_quorum(
        mh,
        "quorum.redevelopment",
        total=300,
        verified_attendees=200,
        registrar_representative_present=True,
        video_recording_active=True,
    )
    assert ok.met


@pytest.mark.req("GOV-01")
@pytest.mark.parametrize(
    ("members", "ordinary", "redev"),
    [
        (1, 1, 1),
        (3, 2, 2),
        (10, 7, 7),
        (29, 20, 20),
        (30, 20, 20),
        (31, 20, 21),
        (301, 20, 201),
        (1000, 20, 667),
    ],
)
def test_quorum_exact_ceil(mh, members: int, ordinary: int, redev: int) -> None:
    assert (
        evaluate_quorum(mh, "quorum.ordinary", total=members, verified_attendees=0).required
        == ordinary
    )
    assert (
        evaluate_quorum(mh, "quorum.redevelopment", total=members, verified_attendees=0).required
        == redev
    )


def test_quorum_params_drive_result_not_code() -> None:
    p = QuorumParams.model_validate(
        {
            "fraction": {"numerator": 1, "denominator": 2},
            "of": "owners",
            "rounding": "ceil",
            "cap": None,
        }
    )
    assert quorum_required(p, 9) == 5
    assert quorum_required(p.model_copy(update={"cap": 3}), 9) == 3


def test_unconfigured_quorum_raises() -> None:
    ka = load_pack(legal_packs_dir() / "packs" / "karnataka-aoa-1972.yaml")
    with pytest.raises(RuleNotConfigured):
        evaluate_quorum(ka, "quorum.ordinary", total=100, verified_attendees=100)  # type: ignore[arg-type]


def test_developer_selection_and_resolution(mh) -> None:
    assert developer_selection_met(mh, total_members=300, votes_for=153)  # 51% of total
    assert not developer_selection_met(mh, total_members=300, votes_for=152)
    assert resolution_passes(mh, present=20, votes_for=11)  # 55% of present
    assert not resolution_passes(mh, present=100, votes_for=50)
    assert resolution_passes(mh, present=100, votes_for=51)


@pytest.mark.at("AT-37")
@pytest.mark.req("FIN-04", "INV-10")
def test_at37_interest_18_pct_exceeds_12_pct_cap(mh) -> None:
    res = check_interest_cap(1800, mh)
    assert not res.ok and res.blocks_approval
    v = res.violation
    assert v is not None
    assert v.code == "interest_exceeds_simple_cap"
    assert (v.rate_bp, v.cap_bp, v.excess_bp) == (1800, 1200, 600)
    assert v.rule_key == "interest.max_simple_pct_pa" and v.pack_id == "maharashtra-chs"
    assert v.legal_source_ref == "mcs-rules-amendment-2026"


@pytest.mark.req("FIN-04")
def test_interest_at_or_below_cap_ok(mh) -> None:
    assert check_interest_cap(1200, mh).ok
    assert check_interest_cap(0, mh).violation is None
    assert not check_interest_cap(1201, mh).ok


@pytest.mark.req("FIN-04")
def test_interest_cap_comes_from_pack_not_code(mh) -> None:
    rule = mh.rules["interest.max_simple_pct_pa"].model_copy(update={"value": 15})
    pack = mh.model_copy(update={"rules": {**mh.rules, "interest.max_simple_pct_pa": rule}})
    assert check_interest_cap(1500, pack).ok
    assert not check_interest_cap(1501, pack).ok


@pytest.mark.req("FIN-04")
def test_interest_unconfigured_cap_fails_closed() -> None:
    ka = load_pack(legal_packs_dir() / "packs" / "karnataka-aoa-1972.yaml")
    res = check_interest_cap(100, ka)  # type: ignore[arg-type]
    assert not res.ok and res.violation is not None
    assert res.violation.code == "interest_cap_not_configured"


@pytest.mark.req("GOV-01")
def test_generic_pack_secretary_config_needs_legal_reference() -> None:
    g = load_pack(legal_packs_dir() / "packs" / "generic.yaml")
    assert all(r.value is None for r in g.rules.values())  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="legal_reference"):
        with_secretary_overrides(g, {"notice.agm_clear_days": (14, "  ")})  # type: ignore[arg-type]
    cfg = with_secretary_overrides(g, {"notice.agm_clear_days": (14, "Bye-law 12 (adopted 2020)")})  # type: ignore[arg-type]
    assert cfg.rules["notice.agm_clear_days"].value == 14
    assert cfg.rules["notice.agm_clear_days"].legal_reference == "Bye-law 12 (adopted 2020)"
    assert not is_binding_allowed(cfg, AT)  # still needs counsel approval


def test_repository_selection() -> None:
    repo = FilePackRepository()
    assert repo.find_legal_pack("IN-MH", "chs", AT).pack_id == "maharashtra-chs"
    assert repo.find_legal_pack("IN-KA", "apartment_assoc", AT).pack_id == "karnataka-aoa-1972"
    with pytest.raises(RuleNotFound):
        repo.find_legal_pack("IN-MH", "chs", date(2026, 1, 1))  # before effective_from
    # the pending-Bill variant is never selected by default, even though it is the same jurisdiction
    assert repo.find_legal_pack("IN-KA", "apartment_assoc", AT).enabled
    assert repo.get_pack("upi-mdr").pack_id == "upi-mdr"
    assert len(repo.list_packs()) == 11
