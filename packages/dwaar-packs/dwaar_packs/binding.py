"""Binding gate and rule resolution.

GOV-01: binding governance is disabled until the pack is approved. INV-10: law is configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from .approvals import ApprovalRegistry, default_registry
from .errors import RuleNotConfigured, RuleNotFound
from .frozen import freeze
from .models import LegalPack, PackHeader, Rule
from .rule_values import validate_rule_value


@dataclass(frozen=True)
class BindingBlocker:
    code: str
    message: str


def in_effective_range(pack: PackHeader, at_date: date) -> bool:
    if at_date < pack.effective_from:
        return False
    return pack.effective_to is None or at_date <= pack.effective_to


def binding_blockers(
    pack: PackHeader, at_date: date, *, registry: ApprovalRegistry | None = None
) -> list[BindingBlocker]:
    out: list[BindingBlocker] = []
    if not pack.enabled:
        out.append(BindingBlocker("pack_disabled", pack.disabled_reason or "pack is disabled"))
    if not pack.is_approved:
        out.append(BindingBlocker("not_approved", "pack has no counsel/CA approval (GOV-01)"))
    elif not (registry or default_registry()).has_evidence(pack):
        # The claim lives in the pack file; the evidence (a pin of this exact content) must live outside it.
        out.append(
            BindingBlocker(
                "no_approval_evidence",
                "pack claims approval but no registry pin matches this exact content (GOV-01)",
            )
        )
    if at_date < pack.effective_from:
        out.append(BindingBlocker("not_yet_effective", f"effective from {pack.effective_from}"))
    elif pack.effective_to is not None and at_date > pack.effective_to:
        out.append(BindingBlocker("expired", f"effective until {pack.effective_to}"))
    return out


def is_binding_allowed(
    pack: PackHeader, at_date: date, *, registry: ApprovalRegistry | None = None
) -> bool:
    """False unless the pack is enabled, approved WITH EVIDENCE and ``at_date`` is in its effective range.

    A pack file that merely claims ``status: approved`` is not binding (see ``dwaar_packs.approvals``).
    """
    return not binding_blockers(pack, at_date, registry=registry)


def today_utc() -> date:
    return datetime.now(UTC).date()


def binding_status(
    pack: PackHeader,
    at_date: date | None = None,
    *,
    registry: ApprovalRegistry | None = None,
    require_complete: bool = False,
) -> tuple[bool, tuple[str, ...]]:
    """``(binding, blocker_codes)`` for a result computed from ``pack`` on ``at_date`` (default: today, UTC).

    Evaluators (quorum, resolution, interest cap) compute from ANY pack so a simulation or preview can run
    on an unapproved one; they stamp their result with this status so nothing can mistake such a result for
    a binding decision (GOV-01). ``require_complete`` also demands that no rule is still unconfigured.
    """
    codes = [b.code for b in binding_blockers(pack, at_date or today_utc(), registry=registry)]
    if require_complete and isinstance(pack, LegalPack) and unconfigured_rule_keys(pack):
        codes.append("unconfigured_rules")
    return (not codes, tuple(codes))


def resolve_rule(pack: LegalPack, key: str, *, require_value: bool = False) -> Rule:
    """Look up one rule by its dotted key. ``require_value`` rejects unconfigured (null) values."""
    try:
        rule = pack.rules[key]
    except KeyError:
        raise RuleNotFound(f"{pack.pack_id}: no rule {key!r}") from None
    if require_value and rule.value is None:
        raise RuleNotConfigured(f"{pack.pack_id}: rule {key!r} is not configured")
    return rule


def rule_value(pack: LegalPack, key: str) -> Any:
    return resolve_rule(pack, key, require_value=True).value


def unconfigured_rule_keys(pack: LegalPack) -> list[str]:
    """Keys whose value is still null. GOV-01: binding voting needs a complete pack, not only approval."""
    return sorted(k for k, r in pack.rules.items() if r.value is None)


def is_binding_ready(
    pack: LegalPack, at_date: date, *, registry: ApprovalRegistry | None = None
) -> bool:
    """Approved with evidence, in range AND no unconfigured rules."""
    return is_binding_allowed(pack, at_date, registry=registry) and not unconfigured_rule_keys(pack)


def with_secretary_overrides(pack: LegalPack, overrides: dict[str, tuple[Any, str]]) -> LegalPack:
    """Return a copy with secretary-configured values. Each override needs a non-empty legal reference.

    The result is never approved: approval stays an external counsel step (PRD Appendix A, Generic pack).
    """
    rules = dict(pack.rules)
    for key, (value, legal_reference) in overrides.items():
        if key not in rules:
            raise RuleNotFound(f"{pack.pack_id}: no rule {key!r}")
        if not rules[key].configurable:
            raise ValueError(f"rule {key!r} is not configurable")
        if not isinstance(legal_reference, str) or not legal_reference.strip():
            raise ValueError(f"rule {key!r}: legal_reference is mandatory")
        validate_rule_value(key, value, rules[key].value)  # shape/range only, never a legal value
        rules[key] = rules[key].model_copy(
            update={"value": freeze(value), "legal_reference": legal_reference}
        )
    return pack.model_copy(
        update={
            "rules": freeze(rules),
            "status": "unapproved",
            "approved_by": None,
            "approved_at": None,
        }
    )
