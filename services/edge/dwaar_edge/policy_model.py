"""Signed policy snapshot models (shared contract with the cloud edge module).

REQ: EDGE-04 (sequence, issue time, validity, issuer key ID and a data-minimisation manifest),
GATE-06 / GATE-14 (resident credentials, invitations, standing rules evaluated locally).

Every model forbids unknown fields: the manifest is the data-minimisation contract, so a snapshot that
carries a field this gateway does not know (for example a phone number or a name) is REJECTED, not stored.
"""

# REQ: EDGE-04, GATE-06, GATE-14

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from dwaar_common.timeutil import ensure_utc

SUPPORTED_SCHEMA_VERSIONS: Final = frozenset({1})

# Lowest defaults, also Appendix C. Policy may only make the gateway stricter than the hard caps.
HARD_GUEST_OFFLINE_MAX_S: Final = 2 * 3600  # PRD 9.2 / D-13: maximum 2 hours
HARD_RESIDENT_OFFLINE_MAX_S: Final = 72 * 3600
HARD_CLOCK_UNCERTAINTY_MAX_MS: Final = 60_000  # EDGE-05

Ref = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Aware = datetime


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Gate(_M):
    id: uuid.UUID
    kind: str = Field(max_length=40)


class Lane(_M):
    id: uuid.UUID
    gate_id: uuid.UUID
    direction: Literal[
        "in", "out", "entry", "exit", "both"
    ]  # the cloud sends in|out|both; entry/exit accepted too

    @property
    def is_exit(self) -> bool:
        return self.direction in ("out", "exit")


class DeviceEntry(_M):
    id: uuid.UUID
    kind: str = Field(max_length=40)
    gate_id: uuid.UUID | None = None
    status: str = Field(max_length=40)


class Resident(_M):
    credential_ref: Ref
    person_ref: Ref
    unit_id: uuid.UUID
    status: Literal["active", "suspended", "revoked"]
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    revocation_version: int = Field(ge=0)


class Window(_M):
    start: datetime
    end: datetime


class Invitation(_M):
    id: uuid.UUID
    gate_id: uuid.UUID | None = None
    window_start: datetime
    window_end: datetime
    windows: list[Window] = Field(
        default_factory=list
    )  # explicit windows; the outer bounds alone would be too wide
    max_uses: int = Field(ge=1, le=10_000)
    uses_remaining: int = Field(ge=0)
    revoked_version: int | None = Field(default=None, ge=0)
    nonce: str = Field(min_length=8, max_length=128)
    kind: str = Field(max_length=40)
    visitor_alias: str | None = Field(default=None, max_length=80)

    @property
    def cloud_used(self) -> int:
        """Uses the cloud has counted. A REVOKED pass is published with ``uses_remaining = 0`` whatever it used (ADR-0019), so that number
        says nothing about use and must not turn a legitimate earlier entry into a "pass reused" conflict."""
        if (self.revoked_version or 0) > 0:
            return 0
        return self.max_uses - self.uses_remaining


class StandingRule(_M):
    unit_id: uuid.UUID
    rule_kind: str = Field(max_length=40)
    params: dict[str, Any] = Field(default_factory=dict)
    effective_from: date | datetime | None = None  # the cloud sends dates (YYYY-MM-DD)
    effective_to: date | datetime | None = None


class Timing(_M):
    approval_expiry_s: int = Field(ge=1, le=3600)
    cascade_steps: list[Any] = Field(default_factory=list)
    guest_offline_max_s: int = Field(ge=0)
    resident_offline_validity_s: int = Field(ge=0)
    clock_uncertainty_limit_ms: int = Field(ge=0)
    policy_age_limit_s: int = Field(ge=0)


class Revocation(_M):
    ref: Ref
    version: int = Field(ge=0)


class Manifest(_M):
    gates: list[Gate] = Field(default_factory=list)
    lanes: list[Lane] = Field(default_factory=list)
    devices: list[DeviceEntry] = Field(default_factory=list)
    residents: list[Resident] = Field(default_factory=list)
    invitations: list[Invitation] = Field(default_factory=list)
    standing_rules: list[StandingRule] = Field(default_factory=list)
    timing: Timing
    revocations: list[Revocation] = Field(default_factory=list)


class Snapshot(_M):
    schema_version: int
    society_id: uuid.UUID
    seq: int = Field(ge=1)
    issued_at: datetime
    valid_until: datetime
    issuer_key_id: str = Field(min_length=1, max_length=64)
    manifest: Manifest
    signature: str

    @field_validator("issued_at", "valid_until")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)


# ---- data minimisation (EDGE-04) ---------------------------------------------------------------
# Free-form members (standing rule params, aliases) must not smuggle personal data past the typed
# fields. Keys that name personal data are refused; string values that look like a phone number,
# e-mail address or government ID are refused.
FORBIDDEN_KEYS: Final = frozenset(
    {
        "phone",
        "mobile",
        "msisdn",
        "contact",
        "name",
        "full_name",
        "first_name",
        "last_name",
        "surname",
        "email",
        "address",
        "aadhaar",
        "aadhar",
        "pan",
        "dob",
        "birth_date",
        "photo",
        "image",
        "face",
        "id_number",
        "vehicle_plate",
        "plate",
    }
)
_PHONE_LIKE = re.compile(
    r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)|(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)"
)
_DIGIT_GAP = re.compile(r"(?<=\d)[\s().-]+(?=\d)")
_UUID_TEXT = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_EMAIL_LIKE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def minimisation_violations(value: Any, path: str = "$") -> list[str]:
    """Paths in a raw (untyped) value that hold personal data. Empty means the value is minimal."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}.{key}"
            if isinstance(key, str) and key.lower() in FORBIDDEN_KEYS:
                found.append(here)
            found.extend(minimisation_violations(item, here))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(minimisation_violations(item, f"{path}[{index}]"))
    elif (
        isinstance(value, str)
        and not _UUID_TEXT.fullmatch(value)
        and (_PHONE_LIKE.search(_DIGIT_GAP.sub("", value)) or _EMAIL_LIKE.search(value))
    ):
        found.append(path)
    return found
