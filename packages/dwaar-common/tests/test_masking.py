from hypothesis import given
from hypothesis import strategies as st

from dwaar_common.masking import mask_aadhaar, mask_bank, mask_phone


def test_mask_phone() -> None:
    assert mask_phone("+91 99999 00123") == "********0123"
    assert mask_phone("9999900123") == "******0123"
    assert mask_phone("123") == "****"
    assert mask_phone(None) == ""
    assert mask_phone("") == ""


def test_mask_aadhaar() -> None:
    assert mask_aadhaar("1234 5678 9012") == "XXXX XXXX 9012"
    assert mask_aadhaar("123456789012") == "XXXX XXXX 9012"
    assert mask_aadhaar("1234-5678-9012") == "XXXX XXXX 9012"
    assert mask_aadhaar("12345") == "****"  # not 12 digits: fail closed
    assert mask_aadhaar(None) == ""


def test_mask_bank() -> None:
    assert mask_bank("123456789012") == "********9012"
    assert mask_bank("1234") == "****"
    assert mask_bank("0012 3456 7890") == "********7890"
    assert mask_bank(None) == ""


@given(st.text(alphabet="0123456789 -+", min_size=5, max_size=20))
def test_masks_never_reveal_more_than_last_four_digits(raw: str) -> None:
    digits = "".join(c for c in raw if c.isdigit())
    for out in (mask_phone(raw), mask_bank(raw), mask_aadhaar(raw)):
        revealed = [c for c in out if c.isdigit()]
        assert len(revealed) <= 4
        if revealed:
            assert "".join(revealed) == digits[-len(revealed) :]
