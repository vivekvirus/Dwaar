"""Retention rule lookup (PRIV-06, PRD Appendix B, D-16)."""

from __future__ import annotations

from functools import cache

from .errors import RuleNotFound
from .loader import load_typed
from .models import RetentionPack, RetentionRule
from .paths import legal_packs_dir


@cache
def default_retention_pack() -> RetentionPack:
    return load_typed(legal_packs_dir() / "retention" / "retention-classes.yaml", RetentionPack)


def retention_rule(record_class: str, pack: RetentionPack | None = None) -> RetentionRule:
    """Rule for a record class code such as ``VIS``; unknown classes raise RuleNotFound."""
    pack = pack or default_retention_pack()
    try:
        return pack.classes[record_class]
    except KeyError:
        raise RuleNotFound(f"unknown retention class {record_class!r}") from None


def operational_days(
    rule: RetentionRule, *, extension_days: int | None = None, justification: str | None = None
) -> int | None:
    """Operational visibility days. An extension needs a recorded justification and stays within the
    class's ``extendable_to_days`` (VIS: 30 -> up to 90, D-16)."""
    if extension_days is None:
        return rule.operational.days
    limit = rule.operational.extendable_to_days
    if limit is None or rule.operational.days is None:
        raise ValueError(f"class {rule.record_class} is not extendable")
    if rule.operational.extension_requires_justification and not (justification or "").strip():
        raise ValueError("extension requires a recorded justification")
    if not rule.operational.days <= extension_days <= limit:
        raise ValueError(f"extension must be between {rule.operational.days} and {limit} days")
    return extension_days
