"""Integer rounding with an explicit mode (INV-02: money is integer paise; no floats).

One implementation: this module maps the pack-facing mode names onto ``dwaar_common.money.div_round``, so
the law packs and the money library can never round differently.
"""

from __future__ import annotations

from enum import StrEnum

from dwaar_common.money import RoundingMode as MoneyRoundingMode
from dwaar_common.money import div_round


class RoundingMode(StrEnum):
    HALF_UP = "half_up"
    HALF_EVEN = "half_even"
    UP = "up"  # towards +infinity (ceiling) for non-negative values
    DOWN = "down"  # floor


_MONEY_MODE: dict[RoundingMode, MoneyRoundingMode] = {
    RoundingMode.HALF_UP: "half_up",
    RoundingMode.HALF_EVEN: "half_even",
    RoundingMode.UP: "ceil",
    RoundingMode.DOWN: "floor",
}


def round_div(numerator: int, denominator: int, mode: RoundingMode) -> int:
    """Return numerator/denominator rounded to an integer. Both must be non-negative / positive."""
    if numerator < 0 or denominator <= 0:
        raise ValueError("round_div needs numerator >= 0 and denominator > 0")
    try:
        money_mode = _MONEY_MODE[RoundingMode(mode)]
    except ValueError:
        raise ValueError(f"unknown rounding mode {mode!r}") from None
    return div_round(numerator, denominator, money_mode)
