"""Request models of the notifications API (``extra='forbid'``: a smuggled ``society_id`` is a 400; INV-01).

REQ: INV-01, NOTIF-05, NOTIF-06, NOTIF-09, CALL-01, CALL-02.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal[
    "security_approval", "emergency", "finance", "service_ticket", "community_digest"
]
Channel = Literal["push", "ivr_call", "sms", "whatsapp"]
Language = Literal["en", "hi", "mr"]
Permission = Literal["granted", "denied", "unknown"]
Version = Annotated[int, Field(ge=1, le=2_147_483_647)]
_SHORT: Final = Annotated[str, Field(min_length=1, max_length=80)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("control_characters")
    return value


class PushTokenIn(Strict):
    platform: Literal["fcm", "apns"]
    token: Annotated[str, Field(min_length=16, max_length=4096)]
    device_label: Annotated[str, Field(max_length=80)] | None = None
    device_model: Annotated[str, Field(max_length=80)] | None = None
    manufacturer: Annotated[str, Field(max_length=40)] | None = None
    os_name: Annotated[str, Field(max_length=40)] | None = None
    os_version: Annotated[str, Field(max_length=40)] | None = None
    app_version: Annotated[str, Field(max_length=40)] | None = None
    notification_permission: Permission = "unknown"
    simulation: bool = True

    @field_validator(
        "token",
        "device_label",
        "device_model",
        "manufacturer",
        "os_name",
        "os_version",
        "app_version",
    )
    @classmethod
    def _no_control(cls, value: str | None) -> str | None:
        return _clean(value)


class DiagnosticIn(Strict):
    token_id: uuid.UUID | None = None
    manufacturer: Annotated[str, Field(min_length=1, max_length=40)]
    device_model: Annotated[str, Field(max_length=80)] | None = None
    os_name: Annotated[str, Field(max_length=40)] | None = None
    os_version: Annotated[str, Field(max_length=40)] | None = None
    notification_permission: Permission
    battery_optimisation: Literal["unrestricted", "optimised", "unknown"] = "unknown"
    focus_mode_blocks: Literal["yes", "no", "unknown"] = "unknown"
    test_push: Literal["received", "not_received", "not_run"] = "not_run"
    simulation: bool = False

    @field_validator("manufacturer", "device_model", "os_name", "os_version")
    @classmethod
    def _no_control(cls, value: str | None) -> str | None:
        return _clean(value)


class PreferencesIn(Strict):
    show_identity_on_lockscreen: bool
    whatsapp_opt_in: bool
    sms_opt_in: bool
    language: Language = "en"


class ReceiptIn(Strict):
    event: Literal["app_received", "displayed"]
    observed_at: dt.datetime | None = None


class ActionIn(Strict):
    action: Literal["approve", "deny"]
    client_action_id: uuid.UUID
    expected_version: Version | None = None


class UnitSettingsIn(Strict):
    primary_person_id: uuid.UUID | None = None
    approver_person_ids: Annotated[list[uuid.UUID], Field(max_length=6)] = Field(
        default_factory=list
    )
    alternate_person_id: uuid.UUID | None = None
    fallback_mode: Literal["call", "intercom"] = "call"
    expected_version: Annotated[int, Field(ge=0, le=2_147_483_647)] | None = None


class ProxyCallIn(Strict):
    target: Literal["primary", "alternate"] = "primary"
    gate_id: uuid.UUID | None = None


class AttemptIn(Strict):
    reason: Annotated[str, Field(min_length=3, max_length=500)]

    @field_validator("reason")
    @classmethod
    def _no_control(cls, value: str) -> str:
        return _clean(value) or value


class BudgetIn(Strict):
    monthly_notification_cap: Annotated[int, Field(ge=0, le=10_000_000)]
    monthly_call_cap: Annotated[int, Field(ge=0, le=1_000_000)]
    monthly_sms_cap: Annotated[int, Field(ge=0, le=1_000_000)]
    expected_version: Annotated[int, Field(ge=0, le=2_147_483_647)] | None = None


class TemplateIn(Strict):
    template_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]{1,80}$")]
    category: Category
    channel: Channel
    language: Language
    content_class: Literal["transactional", "service", "promotional"] = "transactional"
    body_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]{1,100}$")]
    dlt_header: Annotated[str, Field(pattern=r"^[A-Z]{6}$")] | None = None
    dlt_template_id: Annotated[str, Field(pattern=r"^[0-9]{8,30}$")] | None = None
    whitelisted_url: Annotated[str, Field(max_length=200)] | None = None


class DltIn(Strict):
    dlt_header: Annotated[str, Field(pattern=r"^[A-Z]{6}$")]
    dlt_template_id: Annotated[str, Field(pattern=r"^[0-9]{8,30}$")]
    expected_version: Version | None = None
