"""Request-id + structured access logging + safe response headers (pure ASGI, no BaseHTTPMiddleware).

REQ: OBS-01 (structured logs with correlation id, society token, route, latency, status and safe error
code; never OTPs, phones, pass secrets, images or bank credentials), PRD 12 (``request_id`` in every response).

* Each request gets a UUIDv7 ``request_id`` (an inbound ``X-Request-ID`` is honoured only if it is a
  valid UUID, so clients cannot inject arbitrary text into logs/audit rows).
* The access log records the ROUTE TEMPLATE, never the raw path or query string (those may contain
  identifiers or secrets), plus method, status, latency and the stable error code.
* The society token is a non-reversible hash (``dwaar_common.logging.society_log_token``); the raw
  society id is not logged.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Final

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from dwaar_common.errors import InvalidSchema
from dwaar_common.ids import uuid7
from dwaar_common.logging import bind_log_context

REQUEST_ID_HEADER: Final = "X-Request-ID"
access_log = logging.getLogger("dwaar_api.access")


def _inbound_request_id(scope: Scope) -> uuid.UUID:
    for key, value in scope.get("headers", []):
        if key == b"x-request-id":
            try:
                return uuid.UUID(value.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                break
    return uuid7()


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _inbound_request_id(scope)
        state: dict[str, Any] = scope.setdefault("state", {})
        state["request_id"] = str(request_id)
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = str(request_id)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("Cache-Control", "no-store")
            await send(message)

        with bind_log_context(correlation_id=request_id):
            try:
                await self.app(scope, receive, send_wrapper)
            finally:
                route = scope.get("route")
                extra: dict[str, Any] = {
                    "method": scope.get("method"),
                    "route": getattr(route, "path", None) or "unmatched",
                    "status": status,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                    "error_code": state.get("error_code"),
                }
                token = state.get("society_token")
                if token:
                    extra["society_token"] = token
                access_log.info("request", extra=extra)


class BodySizeLimitMiddleware:
    """Refuse request bodies above a limit with 413 BEFORE they are buffered, hashed or validated.

    REQ: ARCH-05 (abuse protection), DoS hygiene. ``Content-Length`` above the limit is answered at once;
    bodies without a length (chunked) are counted while streaming and cut off at the limit. The default
    comes from ``Settings.max_request_body_bytes``; a module that really needs more registers
    ``app.state.body_limits["/v1/some/prefix"] = n_bytes`` (longest matching prefix wins). The reverse
    proxy must enforce its own, equal or smaller, limit as well.
    """

    def __init__(self, app: ASGIApp, default_limit: int = 1_048_576) -> None:
        self.app = app
        self.default_limit = default_limit

    def _limit_for(self, scope: Scope) -> int:
        overrides: dict[str, int] = (
            getattr(scope["app"].state, "body_limits", {}) if "app" in scope else {}
        )
        path = scope.get("path", "")
        best = ""
        for prefix in overrides:
            if path.startswith(prefix) and len(prefix) > len(best):
                best = prefix
        return overrides[best] if best else self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(scope)
        declared = next((v for k, v in scope.get("headers", []) if k == b"content-length"), None)
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True  # a malformed length is refused like an oversized one
            if too_big:
                await self._refuse(scope, receive, send, limit)
                return
        seen = 0
        started = False
        refused = False

        async def counting_receive() -> Message:
            nonlocal seen, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # Answer 413 right here: raising from ``receive`` would be re-wrapped as a 400 by
                    # FastAPI's body parsing. The app then sees a disconnect and its own reply is dropped.
                    refused = True
                    if not started:
                        await self._refuse(scope, receive, send, limit)
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if refused:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, counting_receive, tracking_send)

    @staticmethod
    async def _refuse(scope: Scope, receive: Receive, send: Send, limit: int) -> None:
        state: dict[str, Any] = scope.setdefault("state", {})
        state["error_code"] = InvalidSchema.code
        rid = str(state.get("request_id") or "00000000-0000-0000-0000-000000000000")
        error = InvalidSchema(details={"reason": "payload_too_large", "max_bytes": limit})
        payload = json.dumps(error.to_body(rid), separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})
