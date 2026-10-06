"""Gateway configuration (environment driven, fail closed).

REQ: AI-SYS-01, AI-SYS-06 (15 s timeout), D-18 (model ids), G11/PRIV-15 (no training on customer data, sub-processors disclosed),
PRIV-14. The ONLY switch for a real provider is ``DWAAR_AI_ANTHROPIC_API_KEY``; it is never read in local/test unless explicitly
allowed, and it never appears in ``repr`` or in any API response.

Deliberately absent: any setting that could enable an excluded AI capability (PRD 11.5). ``tests/integration/ai`` scans this
model's JSON schema for such words.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

#: PRD D-18 / 10.5 model ids (exact strings)
MODEL_HAIKU: Final = "claude-haiku-4-5-20251001"
MODEL_SONNET: Final = "claude-sonnet-5-5"
MODEL_OPUS: Final = "claude-opus-5-5"

MODEL_TIMEOUT_SECONDS: Final = 15.0  # AI-SYS-06, NFR-13
MAX_INPUT_CHARS: Final = 20_000  # per untrusted segment (size limits, AI-SYS-03)
MAX_SEGMENTS: Final = 12
MAX_OUTPUT_TOKENS: Final = 1_500
MAX_AUDIO_SECONDS: Final = 60  # PRD 11.2 AI-R02
MAX_AUDIO_BYTES: Final = 2_000_000

#: sub-processors disclosed per G11/PRIV-14; the simulator has none. Approval status is NOT claimed here.
SUBPROCESSORS: Final = (
    {
        "name": "Anthropic",
        "purpose": "language model inference (drafting, extraction, translation)",
        "enabled_by": "DWAAR_AI_ANTHROPIC_API_KEY",
        "training_on_customer_data": False,
        "status": "[VERIFY] model, region, retention and training terms must be approved by the privacy owner (D-18)",
    },
)


@dataclass(frozen=True)
class GatewayConfig:
    environment: str = "local"
    anthropic_api_key: str | None = field(default=None, repr=False)
    provider: str = "simulator"  # simulator | anthropic ; selectable per environment
    timeout_seconds: float = MODEL_TIMEOUT_SECONDS
    max_input_chars: int = MAX_INPUT_CHARS
    max_segments: int = MAX_SEGMENTS
    escalation_features: frozenset[str] = (
        frozenset()
    )  # Opus only where Sonnet failed evaluation; empty by default
    hosts_allowed: tuple[str, ...] = ()  # URLs a model output may contain; empty = none
    usd_inr: float = (
        85.0  # ASSUMED planning rate for cost_paise ([VERIFY] with finance); DWAAR_AI_USD_INR
    )

    @property
    def simulators_allowed(self) -> bool:
        return self.environment in {"local", "test"}

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GatewayConfig:
        e = env if env is not None else os.environ
        environment = e.get("DWAAR_ENV", "local")
        key = (e.get("DWAAR_AI_ANTHROPIC_API_KEY") or "").strip() or None
        wanted = (e.get("DWAAR_AI_PROVIDER") or "").strip().lower()
        provider = wanted or (
            "anthropic" if key and environment not in {"local", "test"} else "simulator"
        )
        try:
            rate = float((e.get("DWAAR_AI_USD_INR") or "85").strip())
        except ValueError:
            rate = 85.0
        return cls(
            environment=environment,
            anthropic_api_key=key,
            provider=provider,
            usd_inr=rate if 1.0 <= rate <= 1000.0 else 85.0,
        )

    def public_view(self) -> dict[str, object]:
        """Safe summary for authorised admins: never the key, only whether one is present."""
        return {
            "environment": self.environment,
            "selected_provider": self.provider,
            "anthropic_key_present": self.anthropic_api_key is not None,
            "timeout_seconds": self.timeout_seconds,
        }
