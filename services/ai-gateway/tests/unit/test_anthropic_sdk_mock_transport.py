"""The Anthropic adapter against the REAL ``anthropic`` SDK with a MOCKED HTTP transport (no network, no key).

Skipped unless the optional extra is installed (``uv sync --extra anthropic`` in services/ai-gateway); the default environment and CI do not
install it, so this is a manual / opt-in check. It was run once against anthropic 1.11.0 with httpx2.MockTransport (see the slice report).
It proves the request shape and the error mapping against the SDK's own classes. It proves NOTHING about the live API.
"""

from __future__ import annotations

import json

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from dwaar_ai_gateway.providers import AnthropicProvider, ProviderError  # noqa: E402
from dwaar_ai_gateway.types import ProviderRequest, Tier, UntrustedSegment  # noqa: E402

pytestmark = pytest.mark.req("AI-SYS-01")


def request() -> ProviderRequest:
    schema = {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
        "additionalProperties": False,
    }
    return ProviderRequest(
        "AI-R07",
        Tier.EXTRACT,
        "claude-haiku-4-5-20251001",
        "SYS",
        {"target_language": "hi"},
        [UntrustedSegment("text", "notice", "hello")],
        schema,
        (),
        "en",
        500,
        "n1",
    )


def client_for(handler) -> object:  # type: ignore[no-untyped-def]
    return anthropic.Anthropic(
        api_key="sk-test",
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
        max_retries=0,
    )


def test_request_and_response_round_trip_through_the_real_sdk() -> None:
    seen: dict = {}  # type: ignore[type-arg]

    def handler(req):  # type: ignore[no-untyped-def]
        seen.update(
            url=str(req.url), key=req.headers.get("x-api-key"), body=json.loads(req.content)
        )
        return httpx2.Response(
            200, headers={"request-id": "req_1"},
            json={"id": "m", "type": "message", "role": "assistant", "model": "claude-haiku-4-5-20251001", "content": [{"type": "text", "text": '{"x": "ok"}'}], "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 12, "output_tokens": 5}},
        )  # fmt: skip

    out = AnthropicProvider("sk-test", client=client_for(handler)).complete(request())
    assert (
        json.loads(out.raw_text) == {"x": "ok"}
        and out.input_tokens == 12
        and out.output_tokens == 5
        and out.simulation is False
    )
    assert seen["url"] == "https://api.anthropic.com/v1/messages" and seen["key"] == "sk-test"
    body = seen["body"]
    assert (
        body["model"] == "claude-haiku-4-5-20251001"
        and body["system"] == [{"type": "text", "text": "SYS"}]
        and body["output_config"]["format"]["type"] == "json_schema"
    )
    assert not {"temperature", "thinking", "tools", "tool_choice", "betas", "fallbacks"} & set(body)
    assert '<untrusted_data id="text" kind="notice" request="n1">' in body["messages"][0]["content"]


@pytest.mark.parametrize(
    ("status", "kind"),
    [(500, "outage"), (529, "outage"), (429, "rate_limited"), (400, "error"), (401, "error")],
)
def test_http_errors_map_to_provider_errors(status: int, kind: str) -> None:
    def handler(req):  # type: ignore[no-untyped-def]
        return httpx2.Response(
            status,
            json={"type": "error", "error": {"type": "api_error", "message": "secret detail"}},
        )

    with pytest.raises(ProviderError) as exc:
        AnthropicProvider("sk-test", client=client_for(handler)).complete(request())
    assert exc.value.kind == kind and "secret detail" not in str(exc.value)


def test_transport_failures_map_to_timeout_and_outage() -> None:
    def timeout(req):  # type: ignore[no-untyped-def]
        raise httpx2.ReadTimeout("slow", request=req)

    def refused(req):  # type: ignore[no-untyped-def]
        raise httpx2.ConnectError("down", request=req)

    with pytest.raises(ProviderError) as t:
        AnthropicProvider("sk-test", client=client_for(timeout)).complete(request())
    with pytest.raises(ProviderError) as c:
        AnthropicProvider("sk-test", client=client_for(refused)).complete(request())
    assert (t.value.kind, c.value.kind) == ("timeout", "outage")
