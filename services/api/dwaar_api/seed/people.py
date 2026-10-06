"""Every seeded person, in one place, and the synthetic TOTP secret of the MFA enrolment.

REQ: IAM-03 (MFA for elevated roles), PRD 5.1, BUILD_BRIEF 7 (invented identities, reserved test numbers, demo logins only
in synthetic development).
"""

from __future__ import annotations

import base64
import hashlib

import pyotp

from .dataset import (
    BULK,
    DOMESTIC_STAFF_PEOPLE,
    OPERATOR,
    RESIDENT_PEOPLE,
    STAFF_PEOPLE,
    Person,
    bulk_people,
)


def all_people() -> list[Person]:
    people = [OPERATOR, *STAFF_PEOPLE, *DOMESTIC_STAFF_PEOPLE, *RESIDENT_PEOPLE]
    for spec in BULK:
        people.extend(bulk_people(spec))
    numbers = [p.n for p in people]
    keys = [p.key for p in people]
    if len(set(numbers)) != len(numbers) or len(set(keys)) != len(keys):
        raise ValueError("seed people must have unique keys and unique phone indexes")
    return people


def by_key() -> dict[str, Person]:
    return {p.key: p for p in all_people()}


def totp_secret(e164: str) -> str:
    """The synthetic, DOCUMENTED TOTP secret of a seeded elevated-role holder (base32).

    A pure function of the fictional phone number, so the local demo (README "Local demo") can type a valid code with
    ``python -m dwaar_api.seed totp <phone>``. It protects nothing: the person, the number and the database are synthetic
    and the seed refuses to run outside ``DWAAR_ENV=local``.
    """
    digest = hashlib.sha256(b"dwaar-seed-totp-v1|" + e164.encode()).digest()[:20]
    return base64.b32encode(digest).decode().rstrip("=")


def current_totp(e164: str) -> str:
    return pyotp.TOTP(totp_secret(e164)).now()
