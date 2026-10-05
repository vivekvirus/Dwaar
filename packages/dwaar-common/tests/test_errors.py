import json

import pytest

from dwaar_common import errors
from dwaar_common.errors import (
    ERROR_BY_CODE,
    STATUS_BY_CODE,
    AlreadyDecided,
    DependencyUnavailable,
    DuplicatePayloadMismatch,
    DwaarError,
    InvalidSchema,
    LegalPackNotApproved,
    MissingTaxConfig,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    RateLimited,
    RequestExpired,
    StaleVersion,
    Unauthenticated,
    internal_error_body,
)

# PRD 12.2 table, verbatim as data.
PRD_TABLE = {
    "invalid_schema": 400,
    "unauthenticated": 401,
    "not_authorised": 403,
    "not_found": 404,
    "stale_version": 409,
    "duplicate_payload_mismatch": 409,
    "already_decided": 409,
    "request_expired": 409,
    "policy_violation": 422,
    "missing_tax_config": 422,
    "legal_pack_not_approved": 422,
    "rate_limited": 429,
    "dependency_unavailable": 503,
}


def test_codes_and_statuses_match_prd_12_2_exactly() -> None:
    assert STATUS_BY_CODE == PRD_TABLE
    assert set(ERROR_BY_CODE) == set(PRD_TABLE)


@pytest.mark.parametrize(
    ("cls", "code", "status"),
    [
        (InvalidSchema, "invalid_schema", 400),
        (Unauthenticated, "unauthenticated", 401),
        (NotAuthorised, "not_authorised", 403),
        (NotFound, "not_found", 404),
        (StaleVersion, "stale_version", 409),
        (DuplicatePayloadMismatch, "duplicate_payload_mismatch", 409),
        (AlreadyDecided, "already_decided", 409),
        (RequestExpired, "request_expired", 409),
        (PolicyViolation, "policy_violation", 422),
        (MissingTaxConfig, "missing_tax_config", 422),
        (LegalPackNotApproved, "legal_pack_not_approved", 422),
    ],
)
def test_each_error_class(cls: type[DwaarError], code: str, status: int) -> None:
    exc = cls(details={"field": "x"})
    assert (exc.code, exc.status) == (code, status)
    assert exc.message_key == f"error.{code}"
    assert exc.message
    body = exc.to_body("req-1")
    assert body == {
        "request_id": "req-1",
        "code": code,
        "message": exc.message,
        "message_key": f"error.{code}",
        "details": {"field": "x"},
    }
    json.dumps(body)  # JSON-safe
    assert exc.headers == {}
    assert isinstance(exc, DwaarError)


def test_rate_limited_requires_retry_info_and_sets_header() -> None:
    exc = RateLimited(retry_after=30)
    assert exc.status == 429
    assert exc.headers == {"Retry-After": "30"}
    assert exc.details["retry_after_seconds"] == 30
    assert exc.to_body("r")["details"] == {"retry_after_seconds": 30}
    with pytest.raises(TypeError):
        RateLimited()  # type: ignore[call-arg]
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="retry_after"):
            RateLimited(retry_after=bad)  # type: ignore[arg-type]


def test_dependency_unavailable_optional_retry() -> None:
    assert DependencyUnavailable().headers == {}
    exc = DependencyUnavailable(retry_after=5, details={"dependency": "payments"})
    assert exc.status == 503
    assert exc.headers == {"Retry-After": "5"}
    assert exc.details == {"dependency": "payments", "retry_after_seconds": 5}
    with pytest.raises(ValueError, match="retry_after"):
        DependencyUnavailable(retry_after=0)


def test_invalid_schema_field_details() -> None:
    exc = InvalidSchema.for_fields([("visitor.phone", "invalid_phone"), ("purpose", "required")])
    assert exc.details == {
        "fields": [
            {"field": "visitor.phone", "issue": "invalid_phone"},
            {"field": "purpose", "issue": "required"},
        ]
    }


def test_custom_message_and_key_override() -> None:
    exc = NotFound("Visit not found", message_key="visit.not_found")
    assert str(exc) == "Visit not found"
    assert exc.message_key == "visit.not_found"


def test_not_found_and_not_authorised_do_not_leak_membership() -> None:
    # default messages are generic and identical regardless of why the lookup failed
    assert NotFound().to_body("r") == NotFound(details={}).to_body("r")
    assert "member" not in NotFound().message.lower()
    assert "society" not in NotFound().message.lower()


def test_details_are_copied_not_aliased() -> None:
    source = {"a": 1}
    exc = PolicyViolation(details=source)
    source["a"] = 2
    assert exc.details == {"a": 1}


def test_internal_error_body_is_not_a_prd_code() -> None:
    body = internal_error_body("r")
    assert body["code"] == "internal_error"
    assert "internal_error" not in PRD_TABLE
    assert body["details"] == {}
    assert errors.INTERNAL_ERROR_CODE == "internal_error"
