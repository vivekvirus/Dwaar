"""Money as integer paise. There are no floats anywhere in this module.

REQ: INV-02 (money = integer paise, journals balance, immutable), INV-10 (law is
configuration: rates, caps and rounding policies are always passed in, never defaulted
to a statutory value here).

`Paise` is a plain `int` alias: one rupee = 100 paise. Every public function validates
its inputs (rejecting `float` and `bool`) and range-guards results to the signed 64-bit
range so values always fit PostgreSQL `bigint`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from decimal import Decimal, localcontext
from typing import Final, Literal, TypeAlias

Paise: TypeAlias = int  # noqa: UP040 - plain alias: `Paise(5)` and isinstance stay valid

MAX_PAISE: Final = 2**63 - 1
MIN_PAISE: Final = -(2**63)
BP_DENOMINATOR: Final = 10_000
RUPEE_SYMBOL: Final = "₹"

RoundingMode = Literal["floor", "ceil", "half_up", "half_even", "down"]


class MoneyError(ValueError):
    """Invalid monetary input or arithmetic result."""


class MoneyRangeError(MoneyError):
    """Value outside the signed 64-bit paise range."""


def _require_int(value: object, what: str = "amount") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MoneyError(f"{what} must be an int number of paise, got {type(value).__name__}")
    return value


def ensure_paise(value: object, what: str = "amount") -> Paise:
    """Validate that `value` is an int within signed 64-bit range and return it."""
    number = _require_int(value, what)
    if not MIN_PAISE <= number <= MAX_PAISE:
        raise MoneyRangeError(f"{what} {number} outside signed 64-bit paise range")
    return number


def add(a: Paise, b: Paise) -> Paise:
    return ensure_paise(ensure_paise(a) + ensure_paise(b), "sum")


def sub(a: Paise, b: Paise) -> Paise:
    return ensure_paise(ensure_paise(a) - ensure_paise(b), "difference")


def neg(a: Paise) -> Paise:
    return ensure_paise(-ensure_paise(a), "negation")


def mul_int(a: Paise, factor: int) -> Paise:
    """Multiply by an integer quantity (e.g. units x per-unit amount)."""
    return ensure_paise(ensure_paise(a) * _require_int(factor, "factor"), "product")


def sum_paise(values: Iterable[Paise]) -> Paise:
    """Checked sum; every intermediate total is range-guarded."""
    total = 0
    for value in values:
        total = add(total, value)
    return total


# --------------------------------------------------------------------------- parsing

_PLAIN = r"\d+"
_WESTERN = r"\d{1,3}(?:,\d{3})+"
_INDIAN = r"\d{1,2}(?:,\d{2})*,\d{3}"
_DECIMAL_TEXT = re.compile(
    rf"^(?P<sign>[+-])?(?:{RUPEE_SYMBOL}|Rs\.?|INR)?\s*"
    rf"(?P<int>{_PLAIN}|{_WESTERN}|{_INDIAN})(?:\.(?P<frac>\d{{1,2}}))?$"
)


def parse_rupees(value: str | int | Decimal) -> Paise:
    """Parse a rupee amount into paise.

    Accepts `str` ("1234.50", "1,23,456.78", "₹500"), `int` (whole rupees) and `Decimal`.
    Rejects `float` and `bool` outright, more than two decimal places, non-finite
    Decimals, and malformed digit grouping.
    """
    if isinstance(value, bool | float):
        raise MoneyError("rupee amounts must not be float or bool; pass a str, int or Decimal")
    if isinstance(value, int):
        return ensure_paise(value * 100, "amount")
    if isinstance(value, Decimal):
        return _decimal_to_paise(value)
    if isinstance(value, str):
        match = _DECIMAL_TEXT.match(value.strip())
        if match is None:
            raise MoneyError("not a valid rupee amount (max 2 decimals, valid digit grouping)")
        whole = int(match.group("int").replace(",", ""))
        frac_text = (match.group("frac") or "").ljust(2, "0")
        paise = whole * 100 + int(frac_text)
        return ensure_paise(-paise if match.group("sign") == "-" else paise, "amount")
    raise MoneyError(f"cannot parse rupees from {type(value).__name__}")


def _decimal_to_paise(value: Decimal) -> Paise:
    if not value.is_finite():
        raise MoneyError("amount must be finite")
    with localcontext() as ctx:
        ctx.prec = 60
        scaled = value.scaleb(2)
        if scaled != scaled.to_integral_value():
            raise MoneyError("amount has more than two decimal places")
        return ensure_paise(int(scaled), "amount")


def paise_to_rupees_str(paise: Paise) -> str:
    """Plain decimal string with exactly two decimals, e.g. -1234 -> '-12.34'."""
    amount = ensure_paise(paise)
    sign = "-" if amount < 0 else ""
    rupees, rem = divmod(abs(amount), 100)
    return f"{sign}{rupees}.{rem:02d}"


# --------------------------------------------------------------------------- formatting


def group_indian(digits: str) -> str:
    """Indian digit grouping for a string of digits: '123456' -> '1,23,456'."""
    if not digits.isdigit():
        raise MoneyError("digits only")
    if len(digits) <= 3:
        return digits
    head, tail = digits[:-3], digits[-3:]
    parts: list[str] = []
    while len(head) > 2:
        parts.append(head[-2:])
        head = head[:-2]
    if head:
        parts.append(head)
    return ",".join(reversed(parts)) + "," + tail


def format_inr(paise: Paise, *, symbol: bool = True, show_paise: bool = True) -> str:
    """Format paise with Indian grouping, e.g. 12345678 -> '₹1,23,456.78'.

    Negative amounts render as '-₹1,00.00' style (sign before the symbol).
    `show_paise=False` drops the decimals only when they are zero; it never rounds.
    """
    amount = ensure_paise(paise)
    rupees, rem = divmod(abs(amount), 100)
    text = group_indian(str(rupees))
    if show_paise or rem:
        text += f".{rem:02d}"
    prefix = RUPEE_SYMBOL if symbol else ""
    return f"{'-' if amount < 0 else ''}{prefix}{text}"


# --------------------------------------------------------------------------- allocation


def allocate(total: Paise, weights: Sequence[int]) -> list[Paise]:
    """Split `total` paise across `weights`, exactly and deterministically.

    Largest-remainder method: every share is floor(total * w / W); the leftover paise go
    one each to the largest fractional remainders, ties broken by lower index. The result
    always sums to `total`. Zero-weight entries never receive paise. Negative totals are
    allocated symmetrically (the result for -t is the element-wise negation of that for t).
    """
    amount = ensure_paise(total, "total")
    if not weights:
        raise MoneyError("weights must not be empty")
    checked = [_require_int(w, "weight") for w in weights]
    if any(w < 0 for w in checked):
        raise MoneyError("weights must be non-negative")
    weight_sum = sum(checked)
    if weight_sum == 0:
        raise MoneyError("at least one weight must be positive")
    if amount < 0:
        return [-share for share in allocate(-amount, checked)]

    shares: list[int] = []
    remainders: list[tuple[int, int]] = []
    for index, weight in enumerate(checked):
        quotient, remainder = divmod(amount * weight, weight_sum)
        shares.append(quotient)
        remainders.append((remainder, index))
    leftover = amount - sum(shares)
    # Largest remainder first; equal remainders: lowest index first.
    for _, index in sorted(remainders, key=lambda item: (-item[0], item[1]))[:leftover]:
        shares[index] += 1
    return [ensure_paise(share, "share") for share in shares]


def allocate_equal(total: Paise, parts: int) -> list[Paise]:
    """Split `total` into `parts` near-equal shares (earlier shares absorb the remainder)."""
    count = _require_int(parts, "parts")
    if count <= 0:
        raise MoneyError("parts must be positive")
    return allocate(total, [1] * count)


# --------------------------------------------------------------------------- bp / percent


def _div_round(numerator: int, denominator: int, mode: RoundingMode) -> int:
    """Integer division with an explicit rounding mode (denominator > 0)."""
    quotient, remainder = divmod(numerator, denominator)  # floor semantics
    if remainder == 0:
        return quotient
    if mode == "floor":
        return quotient
    if mode == "ceil":
        return quotient + 1
    if mode == "down":  # toward zero
        return quotient + 1 if numerator < 0 else quotient
    twice = 2 * remainder
    if twice < denominator:
        return quotient
    if twice > denominator:
        return quotient + 1
    # exact tie
    if mode == "half_up":  # ties away from zero
        return quotient + 1 if numerator >= 0 else quotient
    if mode == "half_even":
        return quotient if quotient % 2 == 0 else quotient + 1
    raise MoneyError(f"unknown rounding mode {mode!r}")


def apply_bp(amount: Paise, bp: int, mode: RoundingMode) -> Paise:
    """`amount * bp / 10_000` in integer arithmetic with an explicit rounding mode.

    The rounding mode is mandatory: it is a configured policy, never a hidden default.
    """
    value = ensure_paise(amount)
    rate = _require_int(bp, "bp")
    return ensure_paise(_div_round(value * rate, BP_DENOMINATOR, mode), "result")


def percent_to_bp(percent: str | int | Decimal) -> int:
    """Convert a percentage ('12.5', 18, Decimal('0.25')) to basis points (at most 2 decimals)."""
    if isinstance(percent, bool | float):
        raise MoneyError("percent must not be float or bool; pass a str, int or Decimal")
    if isinstance(percent, str):
        text = percent.strip()
        if not re.fullmatch(r"[+-]?\d+(?:\.\d{1,2})?", text):
            raise MoneyError("percent must have at most two decimal places")
        decimal = Decimal(text)
    elif isinstance(percent, int):
        decimal = Decimal(percent)
    elif isinstance(percent, Decimal):
        decimal = percent
    else:
        raise MoneyError(f"cannot parse percent from {type(percent).__name__}")
    if not decimal.is_finite():
        raise MoneyError("percent must be finite")
    scaled = decimal.scaleb(2)
    if scaled != scaled.to_integral_value():
        raise MoneyError("percent must have at most two decimal places")
    return int(scaled)


def bp_to_percent_str(bp: int) -> str:
    """Basis points as a percent string: 1250 -> '12.5', 1800 -> '18', 5 -> '0.05'."""
    value = _require_int(bp, "bp")
    sign = "-" if value < 0 else ""
    whole, frac = divmod(abs(value), 100)
    frac_text = f"{frac:02d}".rstrip("0")
    return f"{sign}{whole}" + (f".{frac_text}" if frac_text else "")
