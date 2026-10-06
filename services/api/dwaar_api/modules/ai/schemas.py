"""Request bodies of the AI module. Every body forbids unknown members; a society id in a body is never read (INV-01)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposalCreate(_Body):
    feature_id: str = Field(min_length=1, max_length=80)
    inputs: dict[str, Any] = Field(default_factory=dict)
    language: Literal["en", "hi", "mr"] = "en"


class ConfirmBody(_Body):
    """Confirmation is bound to the payload hash the user was shown. ``edits`` are the user's own validated corrections
    (outcome 'edited'); they can change content fields and, for a complaint, the place among the caller's OWN units, never the command."""

    payload_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_target_versions: list[int] | None = Field(default=None, max_length=50)
    edits: dict[str, Any] | None = None


class FeedbackBody(_Body):
    run_id: str = Field(min_length=36, max_length=36)
    outcome: Literal["accepted", "edited", "rejected"]
    correction: str | None = Field(default=None, max_length=2000)


class FeatureControl(_Body):
    state: Literal["enabled", "disabled"] | None = None
    prompt_version_pin: str | None = Field(default=None, pattern=r"^v[0-9]{1,4}$")
    clear_prompt_version_pin: bool = False
    daily_limit: int | None = Field(default=None, ge=0, le=1_000_000)
    clear_daily_limit: bool = False


class ControlsPut(_Body):
    kill_switch: bool | None = None
    reason: str | None = Field(default=None, max_length=300)
    features: dict[str, FeatureControl] = Field(default_factory=dict, max_length=40)
