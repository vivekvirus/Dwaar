"""Regression tests from W1 verification and fix round 1: legal/tax packs as the only source of law
(INV-10, GOV-01, INV-02, INV-03). Fixed in round 1: F28 (binding gate and approval evidence), F29 (statutory
arithmetic), F30 (immutability, duplicate YAML keys), F31 (overrides and offline bounds), F32 (paise inputs).
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import copy
import shutil
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml

from dwaar_packs import (
    ConfigBoundsError,
    FilePackRepository,
    MappingApprovalRegistry,
    PackError,
    PackValidationError,
    build_pack,
    cascade_config,
    check_interest_cap,
    evaluate_quorum,
    is_binding_allowed,
    is_binding_ready,
    load_pack,
    pack_content_hash,
    resolution_passes,
    upi_mdr_quote,
    with_secretary_overrides,
)
from dwaar_packs.approvals import pack_ref
from dwaar_packs.cascade import CascadeConfig
from dwaar_packs.loader import read_yaml
from dwaar_packs.models import LegalPack
from dwaar_packs.paths import packages_root
from dwaar_packs.quorum import QuorumParams, quorum_required
from dwaar_packs.tax import assess_gst_rwa, default_gst_rwa_pack

pytestmark = pytest.mark.req("INV-10", "GOV-01", "INV-02", "INV-03")

TODAY = date(2026, 10, 20)  # inside the shipped UPI draft schedule's effective range


def _mh_doc() -> dict[str, Any]:
    return read_yaml(packages_root() / "legal-packs" / "packs" / "maharashtra-chs.yaml")


def _pack_with(rules: dict[str, Any], **header: Any) -> LegalPack:
    doc = copy.deepcopy(_mh_doc())
    for key, value in rules.items():
        doc["rules"][key] = {
            **doc["rules"].get(
                key, {"labels": ["LEGAL"], "legal_source_ref": "mcs-rules-amendment-2026"}
            ),
            "value": value,
        }
    doc.update(header)
    pack = build_pack(doc)
    assert isinstance(pack, LegalPack)
    return pack


# ------------------------------------------------------------------------------------------------
# (11) can a malformed or unapproved pack become binding?
# ------------------------------------------------------------------------------------------------
def test_shipped_packs_are_all_unapproved_and_cannot_bind() -> None:
    """Attack that failed: nothing shipped is approved; URLs are only present where the PRD named them."""
    repo = FilePackRepository()
    assert repo.list_packs()
    for pack in repo.list_packs():
        assert not pack.is_approved, pack.pack_id
        assert pack.approved_by is None and pack.approved_at is None, pack.pack_id
        assert not is_binding_allowed(pack, TODAY), pack.pack_id


@pytest.mark.parametrize(
    "patch",
    [
        {"status": "approved"},  # approved without approver
        {"status": "approved", "approved_by": "counsel"},  # approver without timestamp
        {"status": "unapproved", "approved_by": "counsel", "approved_at": "2026-07-01T00:00:00Z"},
        {"status": "approved", "approved_by": "", "approved_at": "2026-07-01T00:00:00Z"},
        {"status": "retired", "approved_by": "x", "approved_at": "2026-07-01T00:00:00Z"},
        {"effective_to": "2020-01-01"},
        {"enabled": "yes"},
        {"pack_type": "tds"},
        {"rules": {}},
        {"legal_sources": []},
    ],
)
def test_malformed_approval_or_header_data_is_rejected(patch: dict[str, Any]) -> None:
    doc = copy.deepcopy(_mh_doc())
    doc.update(patch)
    with pytest.raises((PackValidationError, PackError)):
        build_pack(doc)


def test_a_pack_file_claiming_approval_does_not_become_binding_without_evidence() -> None:
    """GOV-01 says binding stays disabled until COUNSEL approves. Approval is just two fields in a YAML file:
    anyone able to edit a pack file (or point DWAAR_PACKS_ROOT at another directory) flips the gate by typing
    an arbitrary approver string. There is no signature, hash pin or approval ledger to check."""
    doc = copy.deepcopy(_mh_doc())
    doc.update(status="approved", approved_by="mallory", approved_at="2026-07-01T00:00:00Z")
    pack = build_pack(doc)
    assert not is_binding_allowed(pack, TODAY), "self-asserted approval made the pack binding"


def test_is_binding_allowed_is_not_the_same_as_is_binding_ready() -> None:
    """Naming trap: an approved pack with unconfigured (null) rules is 'allowed' to bind but not 'ready'."""
    doc = copy.deepcopy(_mh_doc())
    doc.update(status="approved", approved_by="counsel", approved_at="2026-07-01T00:00:00Z")
    doc["rules"]["interest.max_simple_pct_pa"]["value"] = None
    doc["rules"]["interest.max_simple_pct_pa"]["configurable"] = True
    pack = build_pack(doc)
    registry = MappingApprovalRegistry(
        {pack_ref(pack): pack_content_hash(pack)}
    )  # genuine evidence
    assert is_binding_allowed(pack, TODAY, registry=registry)
    assert not is_binding_ready(pack, TODAY, registry=registry)


def test_yaml_duplicate_keys_are_rejected_not_silently_last_wins(tmp_path: Path) -> None:
    """A reviewer reads 'interest: 12' near the top; the file also says 'interest: 1200' further down and the
    loader keeps the last one without a warning."""
    text = (packages_root() / "legal-packs" / "packs" / "maharashtra-chs.yaml").read_text()
    needle = "  interest.max_simple_pct_pa:\n    value: 12\n"
    assert needle in text
    evil = text.replace(needle, needle + "  interest.max_simple_pct_pa:\n    value: 1200\n", 1)
    path = tmp_path / "dup.yaml"
    path.write_text(evil)
    with pytest.raises((PackValidationError, PackError)):
        load_pack(path)


def test_yaml_alias_bombs_and_python_tags_are_rejected_cheaply(tmp_path: Path) -> None:
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join('*' + chr(97 + i) for _ in range(9))}]\n"
        for i in range(8)
    )
    path = tmp_path / "bomb.yaml"
    path.write_text(bomb + "pack_type: legal-pack\n")
    with pytest.raises((PackValidationError, PackError)):
        load_pack(path)
    tagged = tmp_path / "tag.yaml"
    tagged.write_text("pack_type: !!python/object/apply:os.system ['id']\n")
    with pytest.raises((PackValidationError, PackError)):
        load_pack(tagged)


def test_packs_root_override_cannot_smuggle_an_approved_pack_into_the_default_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "packages"
    shutil.copytree(packages_root() / "legal-packs", root / "legal-packs")
    shutil.copytree(packages_root() / "tax-packs", root / "tax-packs")
    target = root / "legal-packs" / "packs" / "maharashtra-chs.yaml"
    doc = yaml.safe_load(target.read_text())
    doc.update(status="approved", approved_by="mallory", approved_at="2026-07-01T00:00:00+00:00")
    doc["effective_from"] = "2026-06-18"
    target.write_text(yaml.safe_dump(doc))
    monkeypatch.setenv("DWAAR_PACKS_ROOT", str(root))
    pack = FilePackRepository().find_legal_pack("IN-MH", "chs", TODAY)
    assert not pack.is_approved, "DWAAR_PACKS_ROOT swapped in an approved Maharashtra pack"


def test_pack_objects_returned_by_the_repository_cannot_be_mutated_in_place() -> None:
    """Pydantic ``frozen=True`` stops attribute assignment but the pack's dicts/lists stay mutable and the
    repository hands out the SAME object every time, so one handler editing a rule changes the law for every
    later caller in the process (every society)."""
    repo = FilePackRepository()
    pack = repo.find_legal_pack("IN-MH", "chs", TODAY)
    original = copy.deepcopy(pack.rules["charges.non_occupancy"].value["pct_of_service_charges"])
    try:
        pack.rules["charges.non_occupancy"].value["pct_of_service_charges"] = 99
    except TypeError:
        return  # deeply immutable: the secure outcome
    again = repo.find_legal_pack(
        "IN-MH", "chs", TODAY
    )  # if the edit succeeded it must not be shared
    assert again.rules["charges.non_occupancy"].value["pct_of_service_charges"] == original, (
        "in-place edit of a rule leaked to later callers"
    )


def test_rules_dict_itself_is_immutable() -> None:
    pack = FilePackRepository().find_legal_pack("IN-MH", "chs", TODAY)
    with pytest.raises(TypeError):
        pack.rules["interest.max_simple_pct_pa"] = pack.rules["charges.service.basis"]  # type: ignore[index]


# ------------------------------------------------------------------------------------------------
# GOV-01: evaluators are only meaningful on a pack that is allowed to bind
# ------------------------------------------------------------------------------------------------
def test_quorum_and_interest_results_carry_or_enforce_the_binding_gate() -> None:
    """evaluate_quorum / resolution_passes / check_interest_cap compute from the pack's values and never
    look at approval, effective dates or the enabled flag. 'met=True' from an unapproved, expired or
    disabled pack is indistinguishable from a binding result unless every caller remembers the gate."""
    pack = FilePackRepository().find_legal_pack("IN-MH", "chs", TODAY)
    assert not is_binding_allowed(pack, TODAY)
    try:
        quorum = evaluate_quorum(pack, "quorum.ordinary", total=30, verified_attendees=20)
        interest = check_interest_cap(1200, pack)
    except PackError:
        return
    assert getattr(quorum, "binding", True) is False, (
        "quorum result from an unapproved pack is not marked non-binding"
    )
    assert getattr(interest, "binding", True) is False, (
        "interest result from an unapproved pack is not marked non-binding"
    )


def test_quorum_cap_cannot_be_zero_or_negative() -> None:
    """A malformed/overridden ``cap`` of 0 or -5 makes the required attendance <= 0, so quorum is 'met' with
    nobody present (fail-open)."""
    for cap in (0, -5):
        params = QuorumParams.model_validate(
            {"fraction": {"numerator": 1, "denominator": 3}, "of": "members", "cap": cap}
        )
        try:
            required = quorum_required(params, 30)
        except ValueError:
            continue
        assert required >= 1, f"cap={cap} gives required={required}"


def test_quorum_fraction_above_one_or_absurd_totals_fail_closed() -> None:
    params = QuorumParams.model_validate(
        {"fraction": {"numerator": 3, "denominator": 2}, "of": "members"}
    )
    assert (
        quorum_required(params, 10) == 15
    )  # unattainable, therefore no quorum can ever be met: fail closed
    with pytest.raises(ValueError):  # noqa: PT011
        quorum_required(params, -1)


def test_resolution_percentage_is_not_truncated_to_an_integer() -> None:
    """``int(pct)`` silently truncates 66.67 to 66, so 2 of 3 present (66.667 %) passes a 66.67 % rule."""
    pack = _pack_with(
        {
            "voting.basis": {
                "vote_weight": "one_member_one_vote",
                "resolution_pct_of_members_present": 66.67,
            }
        }
    )
    assert not resolution_passes(pack, present=3, votes_for=2), (
        "66.67 percent threshold treated as 66"
    )


def test_votes_cannot_exceed_members_present() -> None:
    pack = FilePackRepository().find_legal_pack("IN-MH", "chs", TODAY)
    with pytest.raises(ValueError):  # noqa: PT011
        resolution_passes(pack, present=1, votes_for=1000)
    with pytest.raises(ValueError):  # noqa: PT011
        evaluate_quorum(pack, "quorum.ordinary", total=10, verified_attendees=-3)


def test_interest_cap_comparison_is_exact_and_fail_closed_on_unconfigured_or_garbage() -> None:
    pack = FilePackRepository().find_legal_pack("IN-MH", "chs", TODAY)
    assert check_interest_cap(1200, pack).ok
    assert not check_interest_cap(1201, pack).ok
    generic = FilePackRepository().find_legal_pack("IN", "any", TODAY)
    unconfigured = check_interest_cap(1, generic)
    assert (
        not unconfigured.ok
        and unconfigured.violation
        and unconfigured.violation.code == "interest_cap_not_configured"
    )
    garbage = _pack_with({"interest.max_simple_pct_pa": "twelve"})
    with pytest.raises((ValueError, PackError)):
        check_interest_cap(100, garbage)


def test_secretary_overrides_validate_the_value_not_only_the_reference() -> None:
    pack = FilePackRepository().find_legal_pack("IN", "any", TODAY)
    configurable = [k for k, r in pack.rules.items() if r.configurable]
    assert configurable
    key = "interest.max_simple_pct_pa"
    assert key in configurable
    for bad in ("banana", True, [1], {"x": 1}, -5, float("nan")):
        with pytest.raises((ValueError, PackError)):
            with_secretary_overrides(pack, {key: (bad, "Some Act s.1")})
    overridden = with_secretary_overrides(pack, {key: (12, "Some Act s.1")})
    assert overridden.status == "unapproved" and overridden.approved_by is None
    assert not is_binding_allowed(overridden, TODAY)


# ------------------------------------------------------------------------------------------------
# INV-03 / D-13 / D-15: cascade and offline bounds
# ------------------------------------------------------------------------------------------------
def test_cascade_never_auto_allows_and_the_flag_cannot_be_overridden() -> None:
    assert cascade_config().auto_allow_on_timeout is False
    for overrides in (
        {"auto_allow_on_timeout": True},
        {"auto_allow": True},
        {"offline": {"auto_allow": 1}},
    ):
        with pytest.raises(ConfigBoundsError):
            cascade_config(overrides)


def test_cascade_config_model_cannot_represent_auto_allow() -> None:
    """The pack model has Literal[False]; the resolved CascadeConfig has a plain bool, so a bug (or a later
    module) can construct a config that auto-allows on timeout."""
    base = cascade_config()
    with pytest.raises(ValueError):  # noqa: PT011
        CascadeConfig(
            steps=base.steps,
            expiry_seconds=base.expiry_seconds,
            offline=base.offline,
            auto_allow_on_timeout=True,
        )


@pytest.mark.parametrize(
    "field",
    [
        "resident_credential_validity_hours",
        "clock_uncertainty_disable_auto_approvals_seconds",
        "policy_age_guard_assisted_verification_hours",
        "edge_event_buffer_hours",
    ],
)
def test_every_offline_safety_setting_has_an_approved_upper_bound(field: str) -> None:
    """Only guest_pass_max_hours and terminal_standalone_min_hours are bounded. A society may set the resident
    credential validity, the clock-uncertainty cut-off or the policy-age guard to 10^9 and thereby disable
    the safeguard it parameterises (credentials that never expire, clock checks that never trigger)."""
    with pytest.raises(ConfigBoundsError):
        cascade_config({"offline": {field: 10**9}})


def test_cascade_override_garbage_is_a_bounds_error_not_a_crash() -> None:
    for bad in (
        {"step_at_seconds": {"x": 5}},
        {"step_at_seconds": {"2": "10"}},
        {"step_at_seconds": []},
        {"expiry_seconds": 10**30},
        {"offline": {"guest_pass_max_hours": 10**9}},
    ):
        with pytest.raises(ConfigBoundsError):
            cascade_config(bad)


# ------------------------------------------------------------------------------------------------
# INV-02 inside the packs package: integer paise only, bounded
# ------------------------------------------------------------------------------------------------
def test_upi_and_gst_calculators_reject_floats_and_out_of_range_paise() -> None:
    for bad in (300000.5, 2**70, -1, True):
        with pytest.raises((ValueError, TypeError, PackError)):
            upi_mdr_quote(bad, None, TODAY)  # type: ignore[arg-type]
    gst = default_gst_rwa_pack()
    for bad in (800000.5, 2**70):
        with pytest.raises((ValueError, TypeError, PackError)):
            assess_gst_rwa(gst, per_member_monthly_paise=bad, aggregate_turnover_paise=10**9)  # type: ignore[arg-type]


def test_upi_quote_net_settlement_is_never_negative() -> None:
    schedule_amounts = (1, 99, 100, 200_000, 200_001)
    for amount in schedule_amounts:
        quote = upi_mdr_quote(amount, None, TODAY)
        assert 0 <= quote.fee_paise <= amount
        assert quote.net_settlement_paise == amount - quote.fee_paise
        assert isinstance(quote.fee_paise, int)
