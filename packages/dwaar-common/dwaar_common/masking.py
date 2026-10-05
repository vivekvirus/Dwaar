"""Masking helpers for display, audit diffs and logs: keep only the last four digits.

REQ: OBS-01 / PRD privacy rules (masked values in audit and logs), data minimisation.
These helpers never raise on odd input: unknown shapes are fully masked (fail closed).
"""

from __future__ import annotations

import re

_FULL_MASK = "****"
_NON_DIGIT = re.compile(r"\D")


def _digits(value: object) -> str:
    return _NON_DIGIT.sub("", str(value))


def _keep_last4(digits: str) -> str:
    if len(digits) <= 4:
        return _FULL_MASK
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_phone(value: str | None) -> str:
    """'+91 99999 00123' -> '********0123' (digits only; separators and prefix dropped)."""
    if not value:
        return ""
    return _keep_last4(_digits(value))


def mask_aadhaar(value: str | None) -> str:
    """12-digit Aadhaar -> 'XXXX XXXX 1234'; anything else is fully masked."""
    if not value:
        return ""
    digits = _digits(value)
    if len(digits) != 12:
        return _FULL_MASK
    return f"XXXX XXXX {digits[-4:]}"


def mask_bank(value: str | None) -> str:
    """Bank account number -> stars plus last four digits; <=4 digits fully masked."""
    if not value:
        return ""
    return _keep_last4(_digits(value))
