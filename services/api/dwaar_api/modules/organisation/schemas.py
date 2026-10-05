"""Request and response models of the organisation API.

REQ: SOC-01, SOC-02, INV-02 (areas are decimals serialised as strings, money is integer paise, no floats),
INV-01 (no model has a society_id input field: the society comes from the validated path/grant, never the body).
"""

from __future__ import annotations

import uuid
import zoneinfo
from decimal import Decimal
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import masking

ENTITY_TYPES: Final = ("chs", "apartment_assoc", "society_reg", "company")
EntityType = Literal["chs", "apartment_assoc", "society_reg", "company"]
_MAX_SETTINGS_DEPTH: Final = 6


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _no_control(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


Name = Annotated[str, Field(min_length=1, max_length=200)]
Area = Annotated[Decimal, Field(gt=0, max_digits=12, decimal_places=2)]
Interest = Annotated[Decimal, Field(ge=0, le=100, max_digits=9, decimal_places=6)]
Paise = Annotated[int, Field(ge=0, le=10**15)]


def _check_json(value: Any, depth: int = 0) -> None:
    """Settings are JSON without floats (a float would break the canonical idempotent response, INV-02)."""
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("too_deep")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non_string_key")
            _check_json(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _check_json(item, depth + 1)
        return
    raise ValueError("unsupported_value")


class LegalEntityIn(Strict):
    name: Name
    entity_type: EntityType
    registration_no: Annotated[str, Field(min_length=1, max_length=100)]
    pan: str | None = None
    tan: str | None = None
    gstin: str | None = None
    gst_registered: bool | None = None

    @field_validator("name", "registration_no")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)

    @field_validator("pan", "tan", "gstin", mode="before")
    @classmethod
    def _blank_to_none(cls, value: Any) -> Any:
        if isinstance(value, str):
            cleaned = masking.normalise(value)
            return cleaned or None
        return value

    @field_validator("pan")
    @classmethod
    def _pan(cls, value: str | None) -> str | None:
        if value is not None and not masking.PAN_RE.match(value):
            raise ValueError("invalid_pan")
        return value

    @field_validator("tan")
    @classmethod
    def _tan(cls, value: str | None) -> str | None:
        if value is not None and not masking.TAN_RE.match(value):
            raise ValueError("invalid_tan")
        return value

    @field_validator("gstin")
    @classmethod
    def _gstin(cls, value: str | None) -> str | None:
        if value is not None and not masking.GSTIN_RE.match(value):
            raise ValueError("invalid_gstin")
        return value

    @model_validator(mode="after")
    def _gst_flag(self) -> LegalEntityIn:
        if self.gstin is not None and self.gst_registered is False:
            raise ValueError("gstin_requires_gst_registered")
        return self


class SocietyCreate(Strict):
    name: Name
    org_id: uuid.UUID | None = None
    legal_entity: LegalEntityIn
    legal_pack_id: uuid.UUID
    tax_pack_id: uuid.UUID | None = None
    city: Annotated[str, Field(min_length=1, max_length=100)]
    state: Annotated[str, Field(min_length=1, max_length=100)]
    timezone: Annotated[str, Field(max_length=64)] = "Asia/Kolkata"
    settings: dict[str, Any] = Field(default_factory=dict)
    ai_budget_paise: Paise = 0

    @field_validator("name", "city", "state")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        return _valid_timezone(value)

    @field_validator("settings")
    @classmethod
    def _settings(cls, value: dict[str, Any]) -> dict[str, Any]:
        _check_json(value)
        return value


def _valid_timezone(value: str) -> str:
    try:
        zoneinfo.ZoneInfo(value)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError("invalid_timezone") from None
    return value


class SocietyPatch(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    name: Name | None = None
    city: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    state: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    timezone: Annotated[str, Field(max_length=64)] | None = None
    settings: dict[str, Any] | None = None
    ai_budget_paise: Paise | None = None
    legal_pack_id: uuid.UUID | None = None
    tax_pack_id: uuid.UUID | None = None

    @field_validator("name", "city", "state")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else _no_control(value)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return None if value is None else _valid_timezone(value)

    @field_validator("settings")
    @classmethod
    def _settings(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            _check_json(value)
        return value


class BlockCreate(Strict):
    name: Annotated[str, Field(min_length=1, max_length=100)]
    floors: Annotated[int, Field(ge=0, le=300)]
    has_lift: bool = False

    @field_validator("name")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)


class BlockPatch(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    name: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    floors: Annotated[int, Field(ge=0, le=300)] | None = None
    has_lift: bool | None = None

    @field_validator("name")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else _no_control(value)


def _areas_consistent(carpet: Decimal | None, builtup: Decimal | None) -> None:
    if carpet is not None and builtup is not None and builtup < carpet:
        raise ValueError("builtup_area_below_carpet_area")


class UnitCreate(Strict):
    block_id: uuid.UUID
    label: Annotated[str, Field(min_length=1, max_length=40)]
    floor: Annotated[int, Field(ge=-10, le=300)]
    carpet_area_sqft: Area | None = None
    builtup_area_sqft: Area | None = None
    undivided_interest_pct: Interest | None = None
    construction_cost_paise: Paise | None = None

    @field_validator("label")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _no_control(value)

    @model_validator(mode="after")
    def _areas(self) -> UnitCreate:
        _areas_consistent(self.carpet_area_sqft, self.builtup_area_sqft)
        return self


class UnitPatch(Strict):
    expected_version: Annotated[int, Field(ge=1)]
    label: Annotated[str, Field(min_length=1, max_length=40)] | None = None
    floor: Annotated[int, Field(ge=-10, le=300)] | None = None
    carpet_area_sqft: Area | None = None
    builtup_area_sqft: Area | None = None
    undivided_interest_pct: Interest | None = None
    construction_cost_paise: Paise | None = None

    @field_validator("label")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else _no_control(value)


class FlagPut(Strict):
    enabled: bool
    expected_version: Annotated[int, Field(ge=1)] | None = None


class QuotasPut(Strict):
    expected_version: Annotated[int, Field(ge=1)] | None = None
    rate_per_minute: Annotated[int, Field(ge=1, le=100000)] | None = None
    rate_burst: Annotated[int, Field(ge=1, le=100000)] | None = None
    queue_quota: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    ai_requests_per_day: Annotated[int, Field(ge=0, le=1_000_000)] | None = None
