"""Request models of the parcels API (PRD 9.5).

REQ: PAR-01 (brand + time window pre-approval), PAR-02 (states and the record of a receipt), PAR-03 (consent, token, supervised
alternate proof, delegated family pickup), PAR-04 (courier claims are external observations), PAR-05 (custody report), PAR-08
(an order screenshot is never proof of entitlement), INV-01 (no model has a society_id input).

``extra="forbid"`` everywhere: a smuggled ``society_id``, ``screenshot`` or ``image`` field is a 400, not silently ignored.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Version = Annotated[int, Field(ge=1, le=2_000_000_000)]
Brand = Annotated[str, Field(min_length=1, max_length=60)]
_BIN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}\Z")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


def _aware(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
    return value.astimezone(dt.UTC)


class ExpectationCreate(Strict):
    """A resident's pre-approval: brand and time window (PAR-01). ``source`` is ``manual`` only: reading an order screenshot is AI-R04
    (M2) and, even then, a screenshot is never proof of entitlement (PAR-08)."""

    unit_id: uuid.UUID
    brand: Brand
    expected_from: dt.datetime
    expected_until: dt.datetime
    carrier: Annotated[str, Field(min_length=1, max_length=60)] | None = None
    leave_at_gate_consent: bool = False
    source: Literal["manual", "order_screenshot"] = "manual"

    @field_validator("brand", "carrier")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean(value)

    @field_validator("expected_from", "expected_until")
    @classmethod
    def _tz(cls, value: dt.datetime) -> dt.datetime:
        return _aware(value)

    @model_validator(mode="after")
    def _window(self) -> ExpectationCreate:
        if self.expected_until <= self.expected_from:
            raise ValueError("window_end_must_follow_start")
        if self.expected_until - self.expected_from > dt.timedelta(days=14):
            raise ValueError("window_longer_than_14_days")
        return self


class ParcelReceive(Strict):
    """The guard records a parcel at the gate (PAR-02). ``expected_parcel_id`` links a pre-approval; without it the service looks for an
    open pre-approval of the same unit and brand whose window contains now."""

    unit_id: uuid.UUID
    gate_id: uuid.UUID
    brand: Brand
    carrier: Annotated[str, Field(min_length=1, max_length=60)] | None = None
    carrier_ref: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    photo_ref: Annotated[str, Field(max_length=300)] | None = None
    expected_parcel_id: uuid.UUID | None = None
    leave_at_gate: bool = False

    @field_validator("brand", "carrier", "carrier_ref", "photo_ref")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean(value)


class ParcelStore(Strict):
    bin_code: Annotated[str, Field(min_length=1, max_length=20)]
    expected_version: Version

    @field_validator("bin_code")
    @classmethod
    def _bin_ok(cls, value: str) -> str:
        if not _BIN.match(value):
            raise ValueError("invalid_bin_code")
        return value


class ConsentPut(Strict):
    """Explicit and revocable until the guard takes custody (PAR-03)."""

    granted: bool
    expected_version: Version


class PickupTokenIssue(Strict):
    expected_version: Version


class Collector(Strict):
    kind: Literal["recipient", "family"]
    person_id: uuid.UUID | None = None


class AlternateProof(Strict):
    """Supervised alternate proof (PAR-03). An order screenshot is NEVER proof (PAR-08): it is refused by name, with a clear code."""

    kind: str = Field(min_length=3, max_length=40)
    note: Annotated[str, Field(min_length=5, max_length=300)]

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, value: str) -> str:
        return value.strip().lower()


class ParcelCollect(Strict):
    method: Literal["token", "alternate_proof"]
    token: Annotated[str, Field(min_length=20, max_length=200)] | None = None
    collector: Collector
    alternate_proof: AlternateProof | None = None


class ParcelResolve(Strict):
    outcome: Literal["refused", "returned", "lost_exception"]
    note: Annotated[str, Field(min_length=5, max_length=500)]
    expected_version: Version


class CourierClaim(Strict):
    source: Literal["courier_app", "courier_sms", "courier_call", "rider_statement", "other"]
    claim: Literal["out_for_delivery", "attempted", "delivered"]
    claimed_at: dt.datetime
    external_ref: Annotated[str, Field(max_length=100)] | None = None

    @field_validator("claimed_at")
    @classmethod
    def _tz(cls, value: dt.datetime) -> dt.datetime:
        return _aware(value)


class CustodyReportCreate(Strict):
    """The guard's physical count (PAR-05). ``bin_counts`` is optional per-bin detail; a discrepancy is reported, never auto-resolved."""

    gate_id: uuid.UUID | None = None
    physical_count: Annotated[int, Field(ge=0, le=100_000)]
    bin_counts: dict[
        Annotated[str, Field(min_length=1, max_length=20)], Annotated[int, Field(ge=0, le=100_000)]
    ] = Field(default_factory=dict, max_length=500)
    note: Annotated[str, Field(max_length=500)] | None = None
