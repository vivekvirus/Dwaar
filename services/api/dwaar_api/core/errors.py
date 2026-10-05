"""Exception handlers that produce the PRD 12.2 error body.

REQ: PRD 12.2 (every error has ``request_id``, a stable ``code``, a user-safe ``message`` and field
details), PRD 12 (raw database errors are never exposed), IAM/privacy rule (error differences must not
reveal membership: forbidden-to-reveal cases are ``404 not_found``).

Body: ``{request_id, code, message, message_key, details}``. Nothing from a driver, SQL statement,
constraint/table name, stack trace or user-supplied input value is ever copied into a response.
"""

from __future__ import annotations

import logging
from typing import Any, Final

import psycopg
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from dwaar_common.errors import (
    DependencyUnavailable,
    DwaarError,
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    RateLimited,
    StaleVersion,
    Unauthenticated,
    internal_error_body,
)

log = logging.getLogger("dwaar_api.errors")

REQUEST_ID_HEADER: Final = "X-Request-ID"
_NO_REQUEST_ID: Final = "00000000-0000-0000-0000-000000000000"

# Unique constraints whose key is scoped to ONE society (e.g. unit number within a society). Only a
# collision on one of these may say ``already_exists``: the caller is a member of that society, so
# the answer reveals nothing outside it. A collision on any other unique key (globally unique
# identifiers such as persons.phone_token) must not become an existence oracle for people who may
# belong to another society, so it is answered with the generic 409 ``stale_version`` instead.
_SOCIETY_SCOPED_UNIQUES: set[str] = set()


def register_society_scoped_unique(*constraint_names: str) -> None:
    """Declare unique constraints (by name) that are safe to report as ``already_exists``."""
    _SOCIETY_SCOPED_UNIQUES.update(constraint_names)


def _constraint_name(original: BaseException | None) -> str | None:
    diag = getattr(original, "diag", None)
    name = getattr(diag, "constraint_name", None)
    return name if isinstance(name, str) else None


class ErrorBody(BaseModel):
    """OpenAPI schema of every error response (PRD 12.2)."""

    request_id: str
    code: str
    message: str
    message_key: str
    details: dict[str, Any] = {}


ERROR_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    status: {"model": ErrorBody, "description": description}
    for status, description in {
        400: "invalid_schema",
        401: "unauthenticated",
        403: "not_authorised",
        404: "not_found",
        409: "stale_version, duplicate_payload_mismatch, already_decided, request_expired",
        422: "policy_violation, missing_tax_config, legal_pack_not_approved",
        429: "rate_limited (Retry-After header)",
        503: "dependency_unavailable (Retry-After header)",
    }.items()
}


def request_id_of(request: Request) -> str:
    value = request.scope.get("state", {}).get("request_id")
    return str(value) if value else _NO_REQUEST_ID


def error_response(request: Request, exc: DwaarError) -> JSONResponse:
    request.scope.setdefault("state", {})["error_code"] = exc.code
    rid = request_id_of(request)
    headers = {**exc.headers, REQUEST_ID_HEADER: rid}
    if exc.status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(status_code=exc.status, content=exc.to_body(rid), headers=headers)


def map_db_error(exc: BaseException) -> DwaarError | None:
    """Translate a database/driver exception into a safe error, or ``None`` if it is a server fault.

    Only the five-character SQLSTATE class decides the outcome. The message, constraint and table
    names are never forwarded.
    """
    original: BaseException | None = exc.orig if isinstance(exc, DBAPIError) else exc
    sqlstate: str | None = getattr(original, "sqlstate", None)
    if isinstance(exc, SQLAlchemyError) and not isinstance(exc, DBAPIError):
        # Pool exhausted / timeouts and other driver-independent failures: capacity, not a bug in the request.
        return DependencyUnavailable(retry_after=2)
    if sqlstate is None:
        if isinstance(original, psycopg.OperationalError | psycopg.InterfaceError):
            return DependencyUnavailable(retry_after=2)
        if isinstance(original, psycopg.DataError):
            # raised by the DRIVER before the statement is sent, e.g. a NUL (0x00) in a text value: bad input
            return InvalidSchema()
        return None
    if sqlstate in {"40001", "40P01"}:  # serialization failure, deadlock detected
        return DependencyUnavailable(retry_after=1)
    if sqlstate in {"55P03", "57014"} or sqlstate.startswith(("08", "53", "57P")):
        return DependencyUnavailable(retry_after=2)
    if (
        sqlstate == "42501"
    ):  # insufficient_privilege incl. row-level-security rejections: reveal nothing
        return NotFound()
    if sqlstate == "23503":  # a referenced row is missing: same answer as any unknown object
        return NotFound()
    if sqlstate == "23505":
        if _constraint_name(original) in _SOCIETY_SCOPED_UNIQUES:
            return PolicyViolation(details={"reason": "already_exists"})
        return StaleVersion()  # generic conflict; never confirms that an identifier exists
    if sqlstate.startswith("23"):
        kind = {
            "23502": "required_value_missing",
            "23514": "value_not_allowed",
        }.get(sqlstate, "constraint")
        return PolicyViolation(details={"reason": kind})
    if sqlstate.startswith("22"):  # data exception: malformed uuid, out-of-range number, ...
        return InvalidSchema()
    return None


def _field_path(loc: tuple[Any, ...]) -> str:
    parts = [str(p) for p in loc if p not in ("body", "query", "path", "header", "cookie")]
    return ".".join(parts) or "request"


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DwaarError)
    async def _dwaar(request: Request, exc: DwaarError) -> Response:  # noqa: RUF029
        if exc.status >= 500:
            log.warning("service error", extra={"error_code": exc.code})
        return error_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> Response:
        # Field path + pydantic error type only: the submitted VALUE is never echoed (it may be PII).
        fields = [(_field_path(tuple(e["loc"])), str(e["type"])) for e in exc.errors()]
        return error_response(request, InvalidSchema.for_fields(fields[:20]))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        status = exc.status_code
        if status == 401:
            mapped: DwaarError = Unauthenticated()
        elif status == 403:
            mapped = NotAuthorised()
        elif status == 404:
            mapped = NotFound()
        elif status == 429:
            mapped = RateLimited(retry_after=1)
        elif status == 405:
            response = error_response(
                request, InvalidSchema(details={"reason": "method_not_allowed"})
            )
            response.status_code = 405
            allow = (exc.headers or {}).get("Allow")
            if allow:
                response.headers["Allow"] = allow
            return response
        elif status >= 500:
            mapped = DependencyUnavailable(retry_after=5)
        else:
            mapped = InvalidSchema()
        return error_response(request, mapped)

    @app.exception_handler(SQLAlchemyError)
    async def _sqlalchemy(request: Request, exc: SQLAlchemyError) -> Response:
        return _db_failure(request, exc)

    @app.exception_handler(psycopg.Error)
    async def _psycopg(request: Request, exc: psycopg.Error) -> Response:
        return _db_failure(request, exc)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> Response:
        return _internal(request, exc)


def _db_failure(request: Request, exc: BaseException) -> Response:
    mapped = map_db_error(exc)
    if mapped is None:
        return _internal(
            request, exc
        )  # full (scrubbed) detail goes to the log, never to the client
    original = exc.orig if isinstance(exc, DBAPIError) else exc
    log.warning(
        "database error",
        extra={
            "exc_type": type(original).__name__,
            "sqlstate": getattr(original, "sqlstate", None),
            "error_code": mapped.code,
        },
    )
    return error_response(request, mapped)


def _internal(request: Request, exc: BaseException) -> Response:
    request.scope.setdefault("state", {})["error_code"] = "internal_error"
    rid = request_id_of(request)
    log.error("unhandled exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content=internal_error_body(rid),
        # The generic Exception handler runs in Starlette's outer ServerErrorMiddleware, OUTSIDE the
        # RequestContextMiddleware send wrapper that adds these to every other response: add them here.
        headers={
            REQUEST_ID_HEADER: rid,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
