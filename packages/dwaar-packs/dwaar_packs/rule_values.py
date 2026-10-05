"""Shape and range validation for secretary-configured rule values (GOV-01, INV-10).

REQ: GOV-01, INV-10.

This module encodes NO legal value: it only refuses values that cannot be a legal value at all (text where
a number belongs, NaN, negative days, a quorum cap of zero ...) so a typo in an override can never reach a
bill run or a vote as "law". Counsel approval remains a separate, external step.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

from pydantic import ValidationError

_MAX_DEPTH = 8
_MAX_ITEMS = 500


def is_number(value: object) -> bool:
    """A finite int/float/Decimal (never bool, never NaN or infinity)."""
    if isinstance(value, bool) or not isinstance(value, int | float | Decimal):
        return False
    return not (isinstance(value, float) and not math.isfinite(value)) and (
        not isinstance(value, Decimal) or value.is_finite()
    )


def _check_json(value: Any, key: str, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError(f"{key}: value is nested too deeply")
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int | float | Decimal):
        if not is_number(value):
            raise ValueError(f"{key}: numbers must be finite")
        return
    if isinstance(value, dict):
        if len(value) > _MAX_ITEMS:
            raise ValueError(f"{key}: too many entries")
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{key}: object keys must be strings")
            _check_json(v, key, depth + 1)
        return
    if isinstance(value, list | tuple):
        if len(value) > _MAX_ITEMS:
            raise ValueError(f"{key}: too many entries")
        for v in value:
            _check_json(v, key, depth + 1)
        return
    raise ValueError(f"{key}: unsupported value type {type(value).__name__}")


def _percent(value: Any, key: str, *, allow_zero: bool) -> None:
    if not is_number(value) or value < 0 or value > 100 or (value == 0 and not allow_zero):
        raise ValueError(f"{key}: must be a number {'>= 0' if allow_zero else '> 0'} and <= 100")


def _same_kind(new: Any, current: Any, key: str) -> None:
    if current is None:
        return
    pairs = (
        (dict, dict),
        (list, list),
        (str, str),
        (bool, bool),
    )
    for a, b in pairs:
        if isinstance(current, a):
            if not isinstance(new, b):
                raise ValueError(f"{key}: expected {a.__name__}, got {type(new).__name__}")
            return
    if is_number(current) and not is_number(new):
        raise ValueError(f"{key}: expected a number, got {type(new).__name__}")


def validate_rule_value(key: str, value: Any, current: Any = None) -> None:
    """Raise ValueError if ``value`` is not an acceptable configured value for rule ``key``."""
    if value is None:
        raise ValueError(f"{key}: use no override to leave a rule unconfigured")
    _check_json(value, key)
    if key.endswith("_clear_days"):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 366:
            raise ValueError(f"{key}: must be a whole number of days between 1 and 366")
        return
    if key == "interest.max_simple_pct_pa" or ".min_pct_" in key:
        _percent(value, key, allow_zero=True)
        return
    if key.startswith("quorum."):
        from .quorum import QuorumParams, check_quorum_params  # local: avoid an import cycle

        try:
            check_quorum_params(QuorumParams.model_validate(value))
        except ValidationError as exc:
            raise ValueError(
                f"{key}: not a valid quorum rule ({len(exc.errors())} problem(s))"
            ) from None
        return
    if key == "voting.basis":
        if not isinstance(value, dict):
            raise ValueError(f"{key}: must be an object")
        if "resolution_pct_of_members_present" in value:
            _percent(value["resolution_pct_of_members_present"], key, allow_zero=False)
        _same_kind(value, current, key)
        return
    if is_number(value) and value < 0:
        raise ValueError(f"{key}: numbers must not be negative")
    _same_kind(value, current, key)
