"""Error hierarchy mapped exactly to PRD section 12.2.

REQ: PRD 12.2 (codes and statuses), IAM/privacy rule that error differences must not
reveal whether a person is a member (use NotFound where existence would leak).

Every error carries a stable `code`, an HTTP `status`, a safe i18n `message_key`, an
English `message` fallback and JSON-safe `details`. `to_body(request_id)` yields the
canonical response body ``{request_id, code, message, message_key, details}``.
Raw database/driver errors must never be put into `message` or `details`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar, Final

INTERNAL_ERROR_CODE: Final = "internal_error"
# `internal_error` is not a PRD 12.2 code: its user-facing text is the catalog's generic
# `errors.unknown`. Every other code resolves to `errors.<code>` in packages/i18n/locales/*/errors.json.
_CATALOG_KEY_BY_CODE: Final[dict[str, str]] = {INTERNAL_ERROR_CODE: "errors.unknown"}


def message_key_for(code: str) -> str:
    """i18n catalog key for an error code (namespace `errors`, see packages/i18n)."""
    return _CATALOG_KEY_BY_CODE.get(code, f"errors.{code}")


class DwaarError(Exception):
    code: ClassVar[str] = "internal_error"
    status: ClassVar[int] = 500
    default_message: ClassVar[str] = "Something went wrong."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: Mapping[str, Any] | None = None,
        message_key: str | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.message_key = message_key or message_key_for(self.code)
        self.details: dict[str, Any] = dict(details or {})
        super().__init__(self.message)

    @property
    def headers(self) -> dict[str, str]:
        return {}

    def to_body(self, request_id: str) -> dict[str, Any]:
        return {
            "request_id": request_id,
            "code": self.code,
            "message": self.message,
            "message_key": self.message_key,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, status={self.status})"


class InvalidSchema(DwaarError):
    code = "invalid_schema"
    status = 400
    default_message = "The request is not valid."

    @classmethod
    def for_fields(cls, fields: Sequence[tuple[str, str]]) -> InvalidSchema:
        """`fields` = (field path, short issue code), e.g. ('visitor.phone', 'invalid_phone')."""
        return cls(details={"fields": [{"field": f, "issue": i} for f, i in fields]})


class Unauthenticated(DwaarError):
    code = "unauthenticated"
    status = 401
    default_message = "Please sign in to continue."


class NotAuthorised(DwaarError):
    code = "not_authorised"
    status = 403
    default_message = "You are not allowed to do this."


class NotFound(DwaarError):
    """Also used where revealing existence would leak membership or another society's data."""

    code = "not_found"
    status = 404
    default_message = "We could not find that."


class Conflict(DwaarError):
    status = 409


class StaleVersion(Conflict):
    code = "stale_version"
    default_message = "This item changed since you opened it. Refresh and try again."


class DuplicatePayloadMismatch(Conflict):
    code = "duplicate_payload_mismatch"
    default_message = "This request key was already used with different content."


class AlreadyDecided(Conflict):
    code = "already_decided"
    default_message = "A decision has already been recorded."


class RequestExpired(Conflict):
    code = "request_expired"
    default_message = "This request has expired."


class Unprocessable(DwaarError):
    status = 422


class PolicyViolation(Unprocessable):
    code = "policy_violation"
    default_message = "This action is not allowed by the current policy."


class MissingTaxConfig(Unprocessable):
    code = "missing_tax_config"
    default_message = "Tax configuration is missing for this operation."


class LegalPackNotApproved(Unprocessable):
    code = "legal_pack_not_approved"
    default_message = "The legal pack for this feature has not been approved."


class RateLimited(DwaarError):
    code = "rate_limited"
    status = 429
    default_message = "Too many attempts. Please wait and try again."

    def __init__(
        self,
        message: str | None = None,
        *,
        retry_after: int,
        details: Mapping[str, Any] | None = None,
        message_key: str | None = None,
    ) -> None:
        if isinstance(retry_after, bool) or not isinstance(retry_after, int) or retry_after < 1:
            raise ValueError("retry_after must be a positive int number of seconds")
        self.retry_after = retry_after
        merged = {**(details or {}), "retry_after_seconds": retry_after}
        super().__init__(message, details=merged, message_key=message_key)

    @property
    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)}


class DependencyUnavailable(DwaarError):
    code = "dependency_unavailable"
    status = 503
    default_message = "A required service is temporarily unavailable. Please try again shortly."

    def __init__(
        self,
        message: str | None = None,
        *,
        retry_after: int | None = None,
        details: Mapping[str, Any] | None = None,
        message_key: str | None = None,
    ) -> None:
        if retry_after is not None and (
            isinstance(retry_after, bool) or not isinstance(retry_after, int) or retry_after < 1
        ):
            raise ValueError("retry_after must be a positive int number of seconds")
        self.retry_after = retry_after
        merged = dict(details or {})
        if retry_after is not None:
            merged["retry_after_seconds"] = retry_after
        super().__init__(message, details=merged, message_key=message_key)

    @property
    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)} if self.retry_after else {}


ERROR_CLASSES: Final[tuple[type[DwaarError], ...]] = (
    InvalidSchema,
    Unauthenticated,
    NotAuthorised,
    NotFound,
    StaleVersion,
    DuplicatePayloadMismatch,
    AlreadyDecided,
    RequestExpired,
    PolicyViolation,
    MissingTaxConfig,
    LegalPackNotApproved,
    RateLimited,
    DependencyUnavailable,
)

#: PRD 12.2 table: code -> HTTP status.
STATUS_BY_CODE: Final[dict[str, int]] = {cls.code: cls.status for cls in ERROR_CLASSES}
ERROR_BY_CODE: Final[dict[str, type[DwaarError]]] = {cls.code: cls for cls in ERROR_CLASSES}


def internal_error_body(request_id: str) -> dict[str, Any]:
    """Body for an unexpected 500. `internal_error` is not a PRD 12.2 code; it only
    exists so unhandled faults never leak driver or stack details to clients."""
    return {
        "request_id": request_id,
        "code": INTERNAL_ERROR_CODE,
        "message": DwaarError.default_message,
        "message_key": message_key_for(INTERNAL_ERROR_CODE),
        "details": {},
    }
