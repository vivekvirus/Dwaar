from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dwaar_common import money
from dwaar_common.money import (
    MAX_PAISE,
    MIN_PAISE,
    MoneyError,
    MoneyRangeError,
    allocate,
    allocate_equal,
    apply_bp,
    bp_to_percent_str,
    ensure_paise,
    format_inr,
    group_indian,
    paise_to_rupees_str,
    parse_rupees,
    percent_to_bp,
    sum_paise,
)

paise = st.integers(min_value=MIN_PAISE // 1000, max_value=MAX_PAISE // 1000)
amounts = st.integers(min_value=0, max_value=10**15)
weight_lists = st.lists(st.integers(min_value=0, max_value=10**9), min_size=1, max_size=40).filter(
    lambda ws: sum(ws) > 0
)


# ------------------------------------------------------------------ guards


def test_range_guard_boundaries() -> None:
    assert ensure_paise(MAX_PAISE) == MAX_PAISE
    assert ensure_paise(MIN_PAISE) == MIN_PAISE
    with pytest.raises(MoneyRangeError):
        ensure_paise(MAX_PAISE + 1)
    with pytest.raises(MoneyRangeError):
        ensure_paise(MIN_PAISE - 1)


@pytest.mark.parametrize("bad", [1.5, 1.0, True, False, "100", None, Decimal("1")])
def test_ensure_paise_rejects_non_int(bad: object) -> None:
    with pytest.raises(MoneyError):
        ensure_paise(bad)


def test_checked_arithmetic_overflows_loudly() -> None:
    with pytest.raises(MoneyRangeError):
        money.add(MAX_PAISE, 1)
    with pytest.raises(MoneyRangeError):
        money.sub(MIN_PAISE, 1)
    with pytest.raises(MoneyRangeError):
        money.neg(MIN_PAISE)
    with pytest.raises(MoneyRangeError):
        money.mul_int(MAX_PAISE, 2)
    assert money.add(2, 3) == 5
    assert money.mul_int(250, 12) == 3000
    assert sum_paise([1, 2, 3]) == 6
    with pytest.raises(MoneyRangeError):
        sum_paise([MAX_PAISE, 1])


# ------------------------------------------------------------------ parse_rupees


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", 0),
        ("1", 100),
        ("1.5", 150),
        ("1.50", 150),
        ("1234.56", 123_456),
        ("-12.34", -1234),
        ("+7", 700),
        ("1,23,456.78", 12_345_678),
        ("123,456.78", 12_345_678),
        ("1,000", 100_000),
        ("₹500", 50_000),
        ("₹ 1,00,000", 10_000_000),
        ("-₹2.05", -205),
        ("Rs. 10", 1000),
        ("  42  ", 4200),
    ],
)
def test_parse_rupees_text(text: str, expected: int) -> None:
    assert parse_rupees(text) == expected


@pytest.mark.parametrize(
    "bad",
    ["", "abc", "1.234", "1.", ".5", "1,2,3", "12,34", "1,23,4,567", "1e3", "--1", "1 000", "NaN"],
)
def test_parse_rupees_rejects_malformed_text(bad: str) -> None:
    with pytest.raises(MoneyError):
        parse_rupees(bad)


def test_parse_rupees_rejects_float_and_bool() -> None:
    with pytest.raises(MoneyError, match="float"):
        parse_rupees(1.5)  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        parse_rupees(True)


def test_parse_rupees_int_and_decimal() -> None:
    assert parse_rupees(5) == 500
    assert parse_rupees(Decimal("12.34")) == 1234
    assert parse_rupees(Decimal("1.500")) == 150  # numerically two decimals
    with pytest.raises(MoneyError, match="two decimal"):
        parse_rupees(Decimal("1.234"))
    with pytest.raises(MoneyError):
        parse_rupees(Decimal("NaN"))
    with pytest.raises(MoneyError):
        parse_rupees(Decimal("Infinity"))
    with pytest.raises(MoneyRangeError):
        parse_rupees(2**63)


@given(st.integers(min_value=-(10**15), max_value=10**15))
def test_parse_format_roundtrip(value: int) -> None:
    assert parse_rupees(paise_to_rupees_str(value)) == value
    assert parse_rupees(format_inr(value)) == value
    assert parse_rupees(format_inr(value, symbol=False)) == value


# ------------------------------------------------------------------ formatting


def test_format_inr_examples() -> None:
    assert format_inr(12_345_678) == "₹1,23,456.78"
    assert format_inr(0) == "₹0.00"
    assert format_inr(5) == "₹0.05"
    assert format_inr(99_999) == "₹999.99"
    assert format_inr(100_000) == "₹1,000.00"
    assert format_inr(10_000_000) == "₹1,00,000.00"
    assert format_inr(1_000_000_000) == "₹1,00,00,000.00"
    assert format_inr(-12_345_678) == "-₹1,23,456.78"
    assert format_inr(12_345_678, symbol=False) == "1,23,456.78"
    assert format_inr(50_000, show_paise=False) == "₹500"
    assert format_inr(50_001, show_paise=False) == "₹500.01"


def test_group_indian() -> None:
    assert group_indian("1") == "1"
    assert group_indian("999") == "999"
    assert group_indian("1000") == "1,000"
    assert group_indian("12345") == "12,345"
    assert group_indian("123456") == "1,23,456"
    assert group_indian("1234567") == "12,34,567"
    assert group_indian("123456789") == "12,34,56,789"
    with pytest.raises(MoneyError):
        group_indian("-1")


def test_paise_to_rupees_str() -> None:
    assert paise_to_rupees_str(-5) == "-0.05"
    assert paise_to_rupees_str(123_400) == "1234.00"


# ------------------------------------------------------------------ allocation


def test_allocate_examples() -> None:
    assert allocate(100, [1, 1, 1]) == [34, 33, 33]
    assert allocate(10, [1, 2, 3]) == [2, 3, 5]
    assert allocate(1, [1, 1]) == [1, 0]
    assert allocate(0, [3, 4]) == [0, 0]
    assert allocate(100, [0, 1, 0]) == [0, 100, 0]
    assert allocate_equal(1000, 3) == [334, 333, 333]
    assert allocate(-100, [1, 1, 1]) == [-34, -33, -33]


def test_allocate_tie_break_is_lowest_index_first() -> None:
    # equal remainders: lower index wins
    assert allocate(2, [1, 1, 1]) == [1, 1, 0]
    # a larger remainder beats a lower index
    assert allocate(5, [1, 3]) == [1, 4]  # exact 1.25 / 3.75 -> floor 1,3 -> +1 to idx 1


def test_allocate_rejects_bad_input() -> None:
    with pytest.raises(MoneyError):
        allocate(10, [])
    with pytest.raises(MoneyError):
        allocate(10, [0, 0])
    with pytest.raises(MoneyError):
        allocate(10, [1, -1])
    with pytest.raises(MoneyError):
        allocate(10, [1.5, 1])  # type: ignore[list-item]
    with pytest.raises(MoneyError):
        allocate(1.5, [1])  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        allocate_equal(10, 0)


@settings(max_examples=300)
@given(paise, weight_lists)
def test_allocate_conserves_total(total: int, weights: list[int]) -> None:
    shares = allocate(total, weights)
    assert sum(shares) == total
    assert len(shares) == len(weights)


@settings(max_examples=300)
@given(amounts, weight_lists)
def test_allocate_shares_are_within_one_paise_of_exact(total: int, weights: list[int]) -> None:
    shares = allocate(total, weights)
    weight_sum = sum(weights)
    for share, weight in zip(shares, weights, strict=True):
        exact_floor = total * weight // weight_sum
        assert exact_floor <= share <= exact_floor + 1
        assert share >= 0
        if weight == 0:
            assert share == 0


@settings(max_examples=200)
@given(amounts, weight_lists)
def test_allocate_is_deterministic_and_sign_symmetric(total: int, weights: list[int]) -> None:
    assert allocate(total, weights) == allocate(total, weights)
    assert allocate(-total, weights) == [-s for s in allocate(total, weights)]


@settings(max_examples=200)
@given(amounts, weight_lists, st.integers(min_value=1, max_value=1000))
def test_allocate_scale_invariant_in_weights(total: int, weights: list[int], k: int) -> None:
    assert allocate(total, weights) == allocate(total, [w * k for w in weights])


@given(amounts, st.integers(min_value=1, max_value=500))
def test_allocate_equal_spread_is_at_most_one_paise(total: int, parts: int) -> None:
    shares = allocate_equal(total, parts)
    assert sum(shares) == total
    assert max(shares) - min(shares) <= 1
    assert shares == sorted(shares, reverse=True)


# ------------------------------------------------------------------ bp / percent


def test_apply_bp_rounding_modes() -> None:
    # 1250 bp of 1 paise... exact tie cases: 5 paise * 1000bp = 0.5 paise
    assert apply_bp(5, 1000, "floor") == 0
    assert apply_bp(5, 1000, "ceil") == 1
    assert apply_bp(5, 1000, "half_up") == 1
    assert apply_bp(5, 1000, "half_even") == 0
    assert apply_bp(15, 1000, "half_even") == 2
    assert apply_bp(-5, 1000, "half_up") == -1
    assert apply_bp(-5, 1000, "floor") == -1
    assert apply_bp(-5, 1000, "ceil") == 0
    assert apply_bp(-5, 1000, "down") == 0
    assert apply_bp(5, 1000, "down") == 0
    assert apply_bp(10_000, 1800, "half_up") == 1800
    assert apply_bp(123_456, 0, "floor") == 0
    assert apply_bp(7, 5000, "half_up") == 4  # 3.5 -> 4


def test_apply_bp_rejects_floats_and_unknown_mode() -> None:
    with pytest.raises(MoneyError):
        apply_bp(100, 12.5, "floor")  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        apply_bp(100.0, 1250, "floor")  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        apply_bp(1, 5000, "bogus")  # type: ignore[arg-type]


@given(paise, st.integers(min_value=0, max_value=100_000))
def test_apply_bp_modes_are_ordered(amount: int, bp: int) -> None:
    floor = apply_bp(amount, bp, "floor")
    ceil = apply_bp(amount, bp, "ceil")
    assert 0 <= ceil - floor <= 1
    for mode in ("half_up", "half_even", "down"):
        assert floor <= apply_bp(amount, bp, mode) <= ceil
    exact_num = amount * bp
    assert floor * 10_000 <= exact_num <= ceil * 10_000


@given(amounts, st.integers(min_value=0, max_value=10_000))
def test_apply_bp_never_exceeds_amount_up_to_100_percent(amount: int, bp: int) -> None:
    assert 0 <= apply_bp(amount, bp, "ceil") <= amount


def test_percent_conversions() -> None:
    assert percent_to_bp("18") == 1800
    assert percent_to_bp("12.5") == 1250
    assert percent_to_bp("0.05") == 5
    assert percent_to_bp(18) == 1800
    assert percent_to_bp(Decimal("0.25")) == 25
    assert bp_to_percent_str(1250) == "12.5"
    assert bp_to_percent_str(1800) == "18"
    assert bp_to_percent_str(5) == "0.05"
    assert bp_to_percent_str(0) == "0"
    assert bp_to_percent_str(-250) == "-2.5"
    with pytest.raises(MoneyError):
        percent_to_bp("12.345")
    with pytest.raises(MoneyError):
        percent_to_bp(12.5)  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        percent_to_bp(Decimal("1.234"))
    with pytest.raises(MoneyError):
        percent_to_bp(Decimal("NaN"))


@given(st.integers(min_value=-1_000_000, max_value=1_000_000))
def test_percent_roundtrip(bp: int) -> None:
    assert percent_to_bp(bp_to_percent_str(bp)) == bp


def test_module_contains_no_float_arithmetic() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(money))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            assert not isinstance(node.value, float), f"float literal at line {node.lineno}"
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, ast.Div), f"true division at line {node.lineno}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"float", "round"}, f"{node.func.id}() at line {node.lineno}"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id != "math", f"math.{node.attr} at line {node.lineno}"
