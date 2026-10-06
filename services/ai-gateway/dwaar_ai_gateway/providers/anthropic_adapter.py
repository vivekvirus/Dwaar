"""Anthropic provider adapter (official ``anthropic`` SDK). DISABLED unless ``DWAAR_AI_ANTHROPIC_API_KEY`` is set.

REQ: AI-SYS-01, D-18 (claude-haiku-4-5-20251001 for high-volume extraction, claude-sonnet-5-5 for drafting and reasoning,
claude-opus-5-5 only where Sonnet fails evaluation), AI-SYS-06 (15 s timeout), G11/PRIV-15.

NOT VERIFIED AGAINST THE LIVE API: no key and no network exist in this environment. The adapter is unit-tested ONLY against a
mocked client object (``tests/unit/test_anthropic_adapter.py``); the request shape follows the SDK documentation (messages.create,
``output_config.format`` json_schema, no sampling parameters, no ``thinking`` field, no prefill). Real-world behaviour
(structured-output acceptance of every schema keyword, refusals, latency, cost) is an open item for the first staging run.

Deliberate choices:
* no server-side model ``fallbacks``: sending a declined request to a DIFFERENT model is a data-processing decision the privacy
  owner has not approved (D-18); a refusal returns ``ProviderError('refused')`` and the user gets the ordinary form;
* ``max_retries=0``: the gateway owns the 15 s budget; a retry would blow it. The caller falls back instead;
* the system prompt goes in ``system``; ALL data goes in the user turn inside ``<untrusted_data>`` blocks; no tools are declared
  (the model has no tools, credentials, URLs or SQL at the boundary);
* the request carries no personal identifiers: the pipeline redacts first (AI-SYS-05).
"""

from __future__ import annotations

import json
import math
from typing import Any, Final

from ..config import MODEL_HAIKU, MODEL_OPUS, MODEL_SONNET
from ..injection import render_untrusted
from ..types import ProviderRequest, ProviderResponse, Tier, ToolCall
from .base import ProviderError

#: USD per million tokens (input, output), from the SDK reference cached 2026-09-25. A PLANNING assumption, not a bill.
PRICES_USD_PER_MTOK: Final[dict[str, tuple[float, float]]] = {
    MODEL_HAIKU: (1.0, 5.0),
    MODEL_SONNET: (2.0, 10.0),
    MODEL_OPUS: (4.0, 20.0),
}
DEFAULT_USD_INR: Final = (
    85.0  # assumed planning rate; set DWAAR_AI_USD_INR to change. [VERIFY] with finance.
)


def model_for(tier: Tier, feature_id: str, escalation_features: frozenset[str]) -> str:
    if tier is Tier.COMPLEX or feature_id in escalation_features:
        return MODEL_OPUS
    if tier is Tier.DRAFT:
        return MODEL_SONNET
    return MODEL_HAIKU


def cost_paise(
    model_id: str, input_tokens: int, output_tokens: int, usd_inr: float = DEFAULT_USD_INR
) -> int:
    pin, pout = PRICES_USD_PER_MTOK.get(model_id, (0.0, 0.0))
    usd = (input_tokens * pin + output_tokens * pout) / 1_000_000
    return math.ceil(usd * usd_inr * 100)


def missing_dependency() -> str | None:
    try:
        import anthropic  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
    except ImportError:
        return "python package 'anthropic' is not installed (uv sync --extra anthropic)"
    return None


class AnthropicProvider:
    name = "anthropic"
    simulation = False

    def __init__(
        self,
        api_key: str,
        *,
        client: Any = None,
        timeout_seconds: float = 15.0,
        usd_inr: float = DEFAULT_USD_INR,
    ) -> None:
        if client is None:
            import anthropic  # type: ignore[import-not-found,unused-ignore]

            client = anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds, max_retries=0)
        self._client = client
        self._usd_inr = usd_inr
        self._timeout = timeout_seconds

    def _call(self, request: ProviderRequest) -> Any:
        user = json.dumps(
            {"task": dict(request.task), "language": request.language}, ensure_ascii=False
        )
        user += "\n\n" + render_untrusted(list(request.untrusted), request.request_nonce)
        output_config: dict[str, Any] = {
            "format": {"type": "json_schema", "schema": dict(request.schema)}
        }
        if request.model_id != MODEL_HAIKU:  # effort is not accepted on Haiku 4.5
            output_config["effort"] = "medium"
        return self._client.messages.create(
            model=request.model_id,
            max_tokens=request.max_output_tokens,
            system=[{"type": "text", "text": request.system}],
            messages=[{"role": "user", "content": user}],
            output_config=output_config,
            timeout=self._timeout,
        )

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        try:
            message = self._call(request)
        except ProviderError:
            raise
        except (
            Exception
        ) as exc:  # classify by SDK class name without importing the SDK at module load
            raise ProviderError(_classify(exc)) from None
        if getattr(message, "stop_reason", None) == "refusal":
            raise ProviderError("refused")
        if getattr(message, "stop_reason", None) == "max_tokens":
            raise ProviderError("error", "truncated")
        text = next((b.text for b in message.content if getattr(b, "type", "") == "text"), "")
        usage = getattr(message, "usage", None)
        return ProviderResponse(
            raw_text=text,
            tool_calls=tuple(
                ToolCall(b.name, dict(b.input))
                for b in message.content
                if getattr(b, "type", "") == "tool_use"
            ),
            model_id=str(getattr(message, "model", request.model_id)),
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            simulation=False,
            provider=self.name,
        )

    def cost_paise(self, model_id: str, input_tokens: int, output_tokens: int) -> int:
        return cost_paise(model_id, input_tokens, output_tokens, self._usd_inr)


def _classify(exc: Exception) -> str:
    names = {c.__name__ for c in type(exc).__mro__}
    if "APITimeoutError" in names or isinstance(exc, TimeoutError):
        return "timeout"
    if "RateLimitError" in names:
        return "rate_limited"
    if "APIConnectionError" in names:
        return "outage"
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and status >= 500:
        return "outage"
    return "error"
