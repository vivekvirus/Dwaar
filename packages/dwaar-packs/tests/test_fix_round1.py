"""Fix round 1 for packs: approval evidence, immutability, strict YAML, bounds, validated overrides, money input.

REQ: GOV-01, INV-10, INV-02, INV-03, D-13.
"""

from __future__ import annotations

import copy
import logging
import pickle
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from dwaar_packs import (
    ConfigBoundsError,
    EnvApprovalRegistry,
    FilePackRepository,
    LegalPack,
    MappingApprovalRegistry,
    PackValidationError,
    approval_pin,
    binding_blockers,
    binding_status,
    build_pack,
    cascade_config,
    check_interest_cap,
    evaluate_quorum,
    evaluate_resolution,
    is_binding_allowed,
    load_pack,
    pack_content_hash,
    with_secretary_overrides,
)
from dwaar_packs.approvals import APPROVALS_ENV, pack_ref
from dwaar_packs.frozen import FrozenDict, FrozenList, freeze, thaw
from dwaar_packs.loader import read_yaml
from dwaar_packs.paths import legal_packs_dir, packages_root
from dwaar_packs.quorum import QuorumParams, quorum_required
from dwaar_packs.rounding import RoundingMode, round_div
from dwaar_packs.rule_values import validate_rule_value
from dwaar_packs.upi import upi_mdr_quote

AT = date(2026, 10, 20)


def _approved(pack: Any, by: str = "counsel") -> Any:
    return pack.model_copy(
        update={
            "status": "approved",
            "approved_by": by,
            "approved_at": datetime(2026, 10, 6, tzinfo=UTC),
        }
    )


# ----------------------------------------------------------------------------- F28: approval evidence
def test_a_self_asserted_approval_has_no_evidence(mh: LegalPack) -> None:
    claimed = _approved(mh, "mallory")
    assert claimed.is_approved  # the claim is just data
    assert not is_binding_allowed(claimed, AT, registry=MappingApprovalRegistry())
    assert [b.code for b in binding_blockers(claimed, AT, registry=MappingApprovalRegistry())] == [
        "no_approval_evidence"
    ]


def test_evidence_pins_exactly_this_content(mh: LegalPack) -> None:
    claimed = _approved(mh)
    registry = MappingApprovalRegistry({pack_ref(claimed): pack_content_hash(claimed)})
    assert is_binding_allowed(claimed, AT, registry=registry)
    # approval fields and the operational switch are not part of what counsel approved ...
    assert pack_content_hash(claimed) == pack_content_hash(mh)
    assert pack_content_hash(claimed.model_copy(update={"enabled": False})) == pack_content_hash(mh)
    # ... but any change of content (a rule value, a date) revokes the evidence
    edited = claimed.model_copy(update={"effective_to": date(2026, 12, 31)})
    assert not is_binding_allowed(edited, AT, registry=registry)
    rules = thaw(dict(claimed.rules))
    rules["interest.max_simple_pct_pa"] = claimed.rules["interest.max_simple_pct_pa"].model_copy(
        update={"value": 1200}
    )
    tampered = claimed.model_copy(update={"rules": freeze(rules)})
    assert not is_binding_allowed(tampered, AT, registry=registry)


def test_env_registry_reads_pins_from_deployment_configuration(mh: LegalPack) -> None:
    claimed = _approved(mh)
    pin = approval_pin(claimed)
    assert pin.startswith("maharashtra-chs@2026.1.0=sha256:")
    env = {APPROVALS_ENV: f"garbage; {pin};\nother@1=sha256:{'0' * 64}"}
    registry = EnvApprovalRegistry(env)
    assert registry.has_evidence(claimed)
    assert not registry.has_evidence(mh.model_copy(update={"version": "9.9.9"}))
    assert not EnvApprovalRegistry({}).has_evidence(claimed)
    assert not EnvApprovalRegistry({APPROVALS_ENV: "maharashtra-chs@2026.1.0=nothex"}).has_evidence(
        claimed
    )


def test_repository_serves_unproven_approval_claims_as_unapproved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import shutil

    import yaml

    root = tmp_path / "packages"
    shutil.copytree(packages_root() / "legal-packs", root / "legal-packs")
    shutil.copytree(packages_root() / "tax-packs", root / "tax-packs")
    target = root / "legal-packs" / "packs" / "maharashtra-chs.yaml"
    doc = yaml.safe_load(target.read_text())
    doc.update(status="approved", approved_by="mallory", approved_at="2026-07-01T00:00:00+00:00")
    target.write_text(yaml.safe_dump(doc))
    monkeypatch.setenv("DWAAR_ENV", "test")
    monkeypatch.setenv("DWAAR_PACKS_ROOT", str(root))
    with caplog.at_level(logging.WARNING, logger="dwaar_packs"):
        pack = FilePackRepository(MappingApprovalRegistry()).find_legal_pack("IN-MH", "chs", AT)
    assert not pack.is_approved
    assert pack.approved_by is None
    assert "without registry evidence" in caplog.text
    # with a genuine pin for exactly that content the claim stands
    proven = build_pack(read_yaml(target))
    repo = FilePackRepository(
        MappingApprovalRegistry({pack_ref(proven): pack_content_hash(proven)})
    )
    assert repo.find_legal_pack("IN-MH", "chs", AT).is_approved


@pytest.mark.parametrize("env", [None, "production", "staging", ""])
def test_packs_root_override_is_ignored_outside_local_and_test(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    env: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    real = packages_root()
    if env is None:
        monkeypatch.delenv("DWAAR_ENV", raising=False)
    else:
        monkeypatch.setenv("DWAAR_ENV", env)
    monkeypatch.setenv("DWAAR_PACKS_ROOT", str(tmp_path))
    with caplog.at_level(logging.WARNING, logger="dwaar_packs"):
        assert packages_root() == real
    assert "DWAAR_PACKS_ROOT ignored" in caplog.text
    monkeypatch.setenv("DWAAR_ENV", "local")
    assert packages_root() == tmp_path


def test_results_carry_the_binding_status_of_their_pack(mh: LegalPack) -> None:
    quorum = evaluate_quorum(mh, "quorum.ordinary", total=30, verified_attendees=20, at_date=AT)
    assert quorum.met
    assert quorum.binding is False
    assert "not_approved" in quorum.binding_blockers
    resolution = evaluate_resolution(mh, present=10, votes_for=9, at_date=AT)
    assert resolution.binding is False
    interest = check_interest_cap(1200, mh, at_date=AT)
    assert interest.ok
    assert interest.binding is False
    assert interest.binding_blockers == ("not_approved",)
    # a complete, approved, evidenced pack in range is binding
    approved = _approved(mh)
    registry = MappingApprovalRegistry({pack_ref(approved): pack_content_hash(approved)})
    ok, blockers = binding_status(approved, AT, registry=registry)
    assert ok is (not blockers)
    assert check_interest_cap(1200, approved, at_date=AT, registry=registry).binding is True
    assert (
        check_interest_cap(1200, approved, at_date=date(2020, 1, 1), registry=registry).binding
        is False
    )


# ----------------------------------------------------------------------------- F29: statutory arithmetic
def test_quorum_parameters_that_would_make_quorum_trivial_are_refused() -> None:
    frac = {"numerator": 1, "denominator": 3}
    for cap in (0, -5):
        with pytest.raises(ValueError, match="cap"):
            quorum_required(
                QuorumParams.model_validate({"fraction": frac, "of": "members", "cap": cap}), 30
            )
    with pytest.raises(ValueError):  # noqa: PT011
        quorum_required(QuorumParams.model_validate({"fraction": frac, "of": "members"}), True)
    assert (
        quorum_required(
            QuorumParams.model_validate({"fraction": frac, "of": "members", "cap": 4}), 30
        )
        == 4
    )


def test_resolution_percentage_is_exact_not_truncated(mh: LegalPack) -> None:
    def pack_with_pct(pct: Any) -> LegalPack:
        doc = copy.deepcopy(read_yaml(legal_packs_dir() / "packs" / "maharashtra-chs.yaml"))
        doc["rules"]["voting.basis"]["value"] = {"resolution_pct_of_members_present": pct}
        pack = build_pack(doc)
        assert isinstance(pack, LegalPack)
        return pack

    strict = pack_with_pct(66.67)
    assert not evaluate_resolution(strict, present=3, votes_for=2).passes  # 66.666..% < 66.67%
    assert evaluate_resolution(strict, present=3, votes_for=3).passes
    assert evaluate_resolution(pack_with_pct(50), present=4, votes_for=2).passes
    assert not evaluate_resolution(pack_with_pct(50), present=4, votes_for=1).passes
    for bad in (0, -1, 101, True, "66", float("nan")):
        with pytest.raises(ValueError):  # noqa: PT011
            evaluate_resolution(pack_with_pct(bad), present=3, votes_for=2)


def test_vote_and_attendance_counts_are_validated(mh: LegalPack) -> None:
    for kwargs in (
        {"present": 1, "votes_for": 1000},
        {"present": -1, "votes_for": 0},
        {"present": 3, "votes_for": -1},
    ):
        with pytest.raises(ValueError):  # noqa: PT011
            evaluate_resolution(mh, **kwargs)
    for attendees in (-3, 11, True):
        with pytest.raises(ValueError):  # noqa: PT011
            evaluate_quorum(mh, "quorum.ordinary", total=10, verified_attendees=attendees)


def test_interest_cap_garbage_is_a_value_error_not_a_decimal_exception(mh: LegalPack) -> None:
    def with_cap(value: Any) -> LegalPack:
        rule = mh.rules["interest.max_simple_pct_pa"].model_copy(update={"value": value})
        return mh.model_copy(
            update={"rules": freeze({**mh.rules, "interest.max_simple_pct_pa": rule})}
        )

    for bad in ("twelve", "NaN", "Infinity", -1, True, [12]):
        with pytest.raises(ValueError):  # noqa: PT011
            check_interest_cap(100, with_cap(bad))
    assert check_interest_cap(1200, with_cap("12")).ok
    for bad_rate in (-1, 1.5, True):
        with pytest.raises(ValueError):  # noqa: PT011
            check_interest_cap(bad_rate, mh)  # type: ignore[arg-type]


# ----------------------------------------------------------------------------- F30: immutability, strict YAML
def test_pack_data_is_deeply_immutable_and_survives_copy_and_pickle(mh: LegalPack) -> None:
    value = mh.rules["charges.non_occupancy"].value
    assert isinstance(value, FrozenDict)
    with pytest.raises(TypeError):
        value["pct_of_service_charges"] = 99
    with pytest.raises(TypeError):
        value.update({"x": 1})
    with pytest.raises(TypeError):
        mh.rules.pop("charges.non_occupancy")
    assert isinstance(mh.legal_sources, FrozenList)
    with pytest.raises(TypeError):
        mh.legal_sources.append(mh.legal_sources[0])
    assert copy.deepcopy(mh) == mh
    assert pickle.loads(pickle.dumps(mh)) == mh  # noqa: S301 - our own object
    assert mh.model_dump(mode="json")["rules"]["charges.non_occupancy"]["value"] == dict(value)
    assert thaw(value) == dict(value)
    assert type(thaw(value)) is dict


def test_yaml_duplicate_keys_are_rejected_at_any_depth(tmp_path: Path) -> None:
    for text in (
        "a: 1\na: 2\n",
        "outer:\n  inner: 1\n  inner: 2\n",
        "pack_type: legal-pack\nrules:\n  k: {value: 1}\n  k: {value: 2}\n",
    ):
        path = tmp_path / "dup.yaml"
        path.write_text(text)
        with pytest.raises(PackValidationError, match="duplicate key"):
            load_pack(path)


def test_yaml_merge_keys_are_not_mistaken_for_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "merge.yaml"
    path.write_text("base: &b {x: 1}\nother: &c {y: 2}\nmerged:\n  <<: *b\n  z: 3\n")
    assert read_yaml(path)["merged"] == {"x": 1, "z": 3}


# ----------------------------------------------------------------------------- F31: overrides and bounds
def test_override_values_are_validated_by_shape_and_range(mh: LegalPack) -> None:
    generic = FilePackRepository().find_legal_pack("IN", "any", AT)
    ok = {
        "interest.max_simple_pct_pa": 12,
        "notice.agm_clear_days": 14,
        "quorum.ordinary": {
            "fraction": {"numerator": 1, "denominator": 5},
            "of": "members",
            "cap": 20,
        },
        "voting.basis": {"resolution_pct_of_members_present": 66.67},
        "charges.service.basis": {"basis": "per_sqft"},
    }
    for key, value in ok.items():
        assert (
            with_secretary_overrides(generic, {key: (value, "Bye-law 12")}).rules[key].value
            == value
        )
    bad: dict[str, list[Any]] = {
        "interest.max_simple_pct_pa": ["banana", True, [1], {"x": 1}, -5, float("nan"), 101, None],
        "notice.agm_clear_days": [0, -1, 367, 14.5, "14", True],
        "quorum.ordinary": [{"fraction": {"numerator": 1, "denominator": 5}, "cap": 0}, "x", {}, 5],
        "voting.basis": [
            {"resolution_pct_of_members_present": 0},
            [1],
            "x",
            {"resolution_pct_of_members_present": "66"},
        ],
        "charges.service.basis": [float("inf"), {"k": float("nan")}, [object()]],
    }
    for key, values in bad.items():
        for value in values:
            with pytest.raises(ValueError):  # noqa: PT011
                with_secretary_overrides(generic, {key: (value, "Bye-law 12")})
    with pytest.raises(ValueError, match="legal_reference"):
        with_secretary_overrides(generic, {"notice.agm_clear_days": (14, None)})  # type: ignore[arg-type]
    with pytest.raises(ValueError):  # noqa: PT011
        validate_rule_value(
            "charges.water.basis",
            {"deep": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}}},
        )


def test_the_cascade_pack_carries_upper_bounds_and_defaults_sit_inside_them() -> None:
    from dwaar_packs.cascade import default_cascade_pack

    pack = default_cascade_pack()
    bounds = pack.offline_bounds
    assert (
        pack.offline.resident_credential_validity_hours
        <= bounds.resident_credential_validity_hours.max
    )
    assert bounds.resident_credential_validity_hours.max == 72  # D-13: never longer than 72 hours
    assert bounds.clock_uncertainty_disable_auto_approvals_seconds.max == 60  # EDGE-05
    assert bounds.policy_age_guard_assisted_verification_hours.max == 72  # EDGE-05
    doc = copy.deepcopy(read_yaml(legal_packs_dir() / "defaults" / "cascade-offline.yaml"))
    doc["offline"]["resident_credential_validity_hours"] = 100  # default above its own bound
    with pytest.raises(PackValidationError, match="exceeds its bound"):
        build_pack(doc)


@pytest.mark.parametrize(
    ("field", "ok", "too_big"),
    [
        ("resident_credential_validity_hours", 24, 73),
        ("clock_uncertainty_disable_auto_approvals_seconds", 30, 61),
        ("policy_age_guard_assisted_verification_hours", 48, 73),
        ("edge_event_buffer_hours", 100, 169),
    ],
)
def test_offline_settings_may_be_tightened_never_relaxed(field: str, ok: int, too_big: int) -> None:
    assert getattr(cascade_config({"offline": {field: ok}}).offline, field) == ok
    with pytest.raises(ConfigBoundsError, match="above approved maximum"):
        cascade_config({"offline": {field: too_big}})


def test_cascade_override_shapes_are_checked_and_auto_allow_is_unrepresentable() -> None:
    for bad in (
        {"step_at_seconds": []},
        {"step_at_seconds": {"x": 5}},
        {"offline": []},
        {"offline": "x"},
    ):
        with pytest.raises(ConfigBoundsError):
            cascade_config(bad)
    from dwaar_packs.cascade import CascadeConfig

    assert CascadeConfig.model_fields["auto_allow_on_timeout"].annotation is not bool


# ----------------------------------------------------------------------------- F32: paise inputs + one rounding
def test_money_inputs_are_ints_in_range() -> None:
    from dwaar_packs.tax import assess_gst_rwa, compute_tds, default_gst_rwa_pack, default_tds_pack

    for bad in (300000.5, 2**70, -1, True, "100"):
        with pytest.raises((ValueError, TypeError)):
            upi_mdr_quote(bad, None, AT)  # type: ignore[arg-type]
    gst = default_gst_rwa_pack()
    for bad in (800000.5, 2**70, True):
        with pytest.raises((ValueError, TypeError)):
            assess_gst_rwa(gst, per_member_monthly_paise=bad, aggregate_turnover_paise=0)  # type: ignore[arg-type]
        with pytest.raises((ValueError, TypeError)):
            assess_gst_rwa(gst, per_member_monthly_paise=0, aggregate_turnover_paise=bad)  # type: ignore[arg-type]
    tds = default_tds_pack()
    category = next(iter(tds.categories))
    for bad in (1000.5, 2**70):
        with pytest.raises((ValueError, TypeError)):
            compute_tds(
                tds, category=category, payee_category="others", amount_paise=bad, trigger_date=AT
            )  # type: ignore[arg-type]
        with pytest.raises((ValueError, TypeError)):
            compute_tds(
                tds, category=category, payee_category="others", amount_paise=1,
                trigger_date=AT, cumulative_prior_paise=bad,
            )  # type: ignore[arg-type]  # fmt: skip


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (RoundingMode.DOWN, 2),
        (RoundingMode.UP, 3),
        (RoundingMode.HALF_UP, 3),
        (RoundingMode.HALF_EVEN, 2),
    ],
)
def test_pack_rounding_is_the_money_library_rounding(mode: RoundingMode, expected: int) -> None:
    from dwaar_common import money

    assert round_div(5, 2, mode) == expected  # 2.5
    names = {
        RoundingMode.DOWN: "floor",
        RoundingMode.UP: "ceil",
        RoundingMode.HALF_UP: "half_up",
        RoundingMode.HALF_EVEN: "half_even",
    }
    assert money.div_round(5, 2, names[mode]) == expected  # type: ignore[arg-type]
    with pytest.raises(ValueError):  # noqa: PT011
        round_div(1, 2, "banana")  # type: ignore[arg-type]
