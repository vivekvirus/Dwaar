"""Format validation and masking of PAN, TAN and GSTIN (SOC-01).

REQ: SOC-01 (PAN/TAN/GSTIN optional, stored encrypted, never returned unmasked), PRD 7.4 (field-level envelope
encryption for ID numbers).

Only the shape of the identifier is checked here (no registry lookup, no checksum claim). The masked form keeps the
last four characters and is stored beside the ciphertext, so an API read never has to decrypt.
"""

from __future__ import annotations

import re
from typing import Final

PAN_RE: Final = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]\Z")
TAN_RE: Final = re.compile(r"^[A-Z]{4}[0-9]{5}[A-Z]\Z")
GSTIN_RE: Final = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\Z")


def normalise(value: str) -> str:
    return value.strip().upper()


def mask(value: str) -> str:
    """``ABCDE1234F`` -> ``******234F`` (last four characters only)."""
    return "*" * (len(value) - 4) + value[-4:]
