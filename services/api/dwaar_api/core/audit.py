"""Audit rows, domain events and the atomic ``mutation`` helper.

REQ: PRD 12.4 (domain mutation, audit row and outbox row in ONE transaction; audit stores actor and
effective role, operation, object and version, masked before/after diff, reason, approver, timestamp,
request id; audit text never copies personal data unnecessarily), DB-02 (append-only), INV-01, INV-02 plumbing.

Use :func:`mutation` for every write: it runs your domain function, then writes the audit row and the
outbox row on the SAME connection inside a SAVEPOINT. If any of the three steps raises, all three are
rolled back, even if the caller catches the exception and keeps using the transaction.
"""

from __future__ import annotations

import datetime as dt
import decimal
import json
import logging
import re
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema
from dwaar_common.events import DomainEvent, canonical_json
from dwaar_common.ids import uuid7
from dwaar_common.keynames import is_identifier_key, is_quantity_key, is_sensitive_key
from dwaar_common.logging import REDACTED, scrub_text

from .db import RequestContext

log = logging.getLogger("dwaar_api.audit")
_SYSTEM_ROLE: Final = "system"
_ENCRYPTED_SUFFIXES: Final = ("_enc", "_vault", "_ciphertext", "_hash", "_token", "_secret")


class AuditError(Exception):
    """The audit/outbox write is not possible (bad context); the caller's transaction must roll back."""


# Identity / bank / contact fields that never belong in an audit diff or an event payload, whatever
# the caller remembers to pass in ``redact=``. Judged per whole word of the key (snake or camel case).
_PII_KEY_WORDS: Final = frozenset(
    {
        "email", "mail", "pan", "upi", "vpa", "ifsc", "gstin", "dob", "birthdate", "birth",
        "address", "plate", "licence", "license", "passport", "voter", "ssn", "iban", "swift",
    }
)  # fmt: skip
# `name` alone is an object label (society, unit, vendor) and stays visible; person-name compounds
# (visitor_name, full_name, ...) are masked.
_PERSON_NAME_PREFIXES: Final = frozenset(
    {
        "first", "last", "middle", "full", "display", "visitor", "guest", "resident", "owner",
        "tenant", "member", "person", "driver", "nominee", "holder", "contact", "emergency",
        "father", "mother", "spouse", "legal", "staff", "guard", "employee", "payer", "payee",
    }
)  # fmt: skip
_KEY_SPLIT: Final = re.compile(r"[^a-z0-9]+")
_KEY_CAMEL: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _is_pii_key(key: str) -> bool:
    words = [w for w in _KEY_SPLIT.split(_KEY_CAMEL.sub("_", key).lower()) if w]
    if set(words) & _PII_KEY_WORDS:
        return True
    return any(
        w == "name" and i > 0 and words[i - 1] in _PERSON_NAME_PREFIXES for i, w in enumerate(words)
    )


def _is_masked_key(key: str, extra: frozenset[str]) -> bool:
    lowered = key.lower()
    return (
        lowered in extra
        or lowered.endswith(_ENCRYPTED_SUFFIXES)
        or is_sensitive_key(key)
        or _is_pii_key(key)
    )


def _clean_text(value: str) -> str:
    """A string that cannot be encoded as UTF-8 (a lone surrogate from a hostile client) is bad INPUT: a controlled
    400, not a UnicodeEncodeError (500) while the audit/outbox row is being written."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidSchema(details={"reason": "invalid_unicode"}) from None
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, str):
        return _clean_text(value)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, Mapping):
        return {_clean_text(str(k)): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    return _clean_text(str(value))


# A decimal quantity ("2500000.00", "-12.5"): a point and a short fraction. No identifier looks like this.
_DECIMAL_QUANTITY: Final = re.compile(r"^[+-]?[0-9]{1,30}\.[0-9]{1,6}\Z")
_DIGITS_ONLY: Final = re.compile(r"^[+-]?[0-9]{1,40}\Z")
_LONG_NUMBER: Final = (
    9  # digits at which a number under an identifier-like key is treated as an identifier
)


def _mask_number(key: str, value: int | float) -> Any:
    """Numbers are DATA unless the key says they are identifiers.

    Money must survive the audit diff and the outbox payload (INV-02): Rs 10 lakh is 100_000_000 paise, nine
    digits, which looks exactly like a phone or account number. Digit count therefore never decides. The key
    does: a number under a phone/account/card/contact/reference name is masked, a number under anything else is
    kept. (Personal data is masked by key class in ``_is_masked_key`` before a value is looked at.)
    """
    if is_quantity_key(key):
        return value
    if is_identifier_key(key) and sum(ch.isdigit() for ch in str(value)) >= _LONG_NUMBER:
        return REDACTED
    return value


def _mask_text(key: str, value: str) -> str:
    """Strings are content-scrubbed (phone, Aadhaar, OTP ...), except values that are plainly quantities."""
    if _DECIMAL_QUANTITY.match(value):  # a decimal amount carries a point; a phone number does not
        return value
    if _DIGITS_ONLY.match(value) and is_quantity_key(key):  # "250000000" under amount/credit/...
        return value
    return scrub_text(value)


def _mask(key: str, value: Any, extra: frozenset[str]) -> Any:
    """Mask a value found under ``key``: by key name first, then (for strings) by content.

    Nested mappings and lists of any depth are walked. Numbers are masked by KEY only (see ``_mask_number``).
    """
    if value is None:
        return None
    if _is_masked_key(key, extra):
        return REDACTED
    value = _jsonable(value)
    if isinstance(value, Mapping):
        return {str(k): _mask(str(k), v, extra) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask(key, v, extra) for v in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return _mask_number(key, value)
    if isinstance(value, str):
        return _mask_text(key, value)
    return scrub_text(str(value))


def mask_payload(value: Mapping[str, Any], *, redact: Iterable[str] = ()) -> dict[str, Any]:
    """Apply the audit masking rules to an arbitrary JSON-like mapping (keys and leaf content)."""
    extra = frozenset(r.lower() for r in redact)
    masked = _mask("payload", dict(value), extra)
    return dict(masked) if isinstance(masked, Mapping) else {}


def _leak_paths(original: Any, masked: Any, path: str = "") -> list[str]:
    """Key paths (never values) at which ``masked`` differs from ``original``."""
    if isinstance(original, Mapping) and isinstance(masked, Mapping):
        out: list[str] = []
        for k, v in original.items():
            out += _leak_paths(v, masked.get(str(k)), f"{path}.{k}" if path else str(k))
        return out
    if isinstance(original, list) and isinstance(masked, list) and len(original) == len(masked):
        return [
            leak for i, (a, b) in enumerate(zip(original, masked, strict=True))
            for leak in _leak_paths(a, b, f"{path}[{i}]")
        ]  # fmt: skip
    return [] if original == masked else [path or "payload"]


def masked_diff(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    *,
    redact: Iterable[str] = (),
) -> dict[str, Any]:
    """Field-level diff with every sensitive value replaced by ``[REDACTED]``.

    ``{"op": "create"|"update"|"delete", "changed": {field: {"before": .., "after": ..}}}``.
    A changed sensitive field is listed (so reviewers see THAT it changed) but its values are masked.
    Unchanged fields are omitted (data minimisation). ``redact`` adds field names to mask by name.
    """
    extra = frozenset(r.lower() for r in redact)
    old = dict(before or {})
    new = dict(after or {})
    op = "create" if before is None else ("delete" if after is None else "update")
    changed: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        a, b = _jsonable(old.get(key)), _jsonable(new.get(key))
        if before is not None and after is not None and a == b:
            continue
        changed[key] = {
            "before": _mask(key, old.get(key), extra) if key in old else None,
            "after": _mask(key, new.get(key), extra) if key in new else None,
        }
    return {"op": op, "changed": changed}


def _require_society(ctx: RequestContext) -> uuid.UUID:
    if ctx.society_id is None:
        raise AuditError("this operation needs a society context")
    return ctx.society_id


def record_audit(
    conn: Connection,
    ctx: RequestContext,
    *,
    operation: str,
    object_type: str,
    object_id: uuid.UUID | None = None,
    object_version: int | None = None,
    before: Mapping[str, Any] | None = None,
    after: Mapping[str, Any] | None = None,
    diff: Mapping[str, Any] | None = None,
    reason: str | None = None,
    approver_id: uuid.UUID | None = None,
    redact: Iterable[str] = (),
    platform_level: bool = False,
) -> uuid.UUID:
    """Insert one ``audit_log`` row on ``conn`` (the caller owns the transaction).

    ``platform_level=True`` records an event with no society (sign-in failures, society creation).
    Otherwise ``ctx.society_id`` is required and must equal the transaction's RLS context.
    """
    society_id = None if platform_level else _require_society(ctx)
    audit_id = uuid7()
    # An explicit ``diff=`` goes through the same masker as before/after: the masking guarantee must
    # not depend on which call style a handler happens to use.
    payload = (
        mask_payload(diff, redact=redact)
        if diff is not None
        else masked_diff(before, after, redact=redact)
    )
    conn.execute(
        text(
            "INSERT INTO audit_log (id, society_id, actor_id, effective_role, operation, object_type,"
            " object_id, object_version, diff_masked, reason, approver_id, request_id)"
            " VALUES (:id, :society_id, :actor_id, :role, :operation, :object_type, :object_id,"
            " :object_version, CAST(:diff AS jsonb), :reason, :approver_id, :request_id)"
        ),
        {
            "id": audit_id,
            "society_id": society_id,
            "actor_id": ctx.person_id,
            "role": ctx.actor_role or _SYSTEM_ROLE,
            "operation": operation,
            "object_type": object_type,
            "object_id": object_id,
            "object_version": object_version,
            "diff": json.dumps(_jsonable(payload), separators=(",", ":"), sort_keys=True),
            "reason": scrub_text(reason) if reason else None,
            "approver_id": approver_id,
            "request_id": ctx.request_id,
        },
    )
    return audit_id


def emit_event(
    conn: Connection,
    ctx: RequestContext,
    *,
    aggregate_type: str,
    aggregate_id: uuid.UUID,
    aggregate_version: int,
    event_type: str,
    payload: Mapping[str, Any] | None = None,
    causation_id: uuid.UUID | None = None,
    schema_version: int = 1,
) -> DomainEvent:
    """Insert one ``outbox`` row (PRD 12.4 contract) on ``conn``. The payload must be minimal and float-free; personal data and secrets are masked."""
    society_id = _require_society(ctx)
    raw_payload = _jsonable(dict(payload or {}))
    clean_payload = mask_payload(raw_payload)
    leaks = _leak_paths(raw_payload, clean_payload)
    if leaks:
        # Events are relayed to other services and stored for years: they carry ids and state, never
        # personal data or secrets. Mask rather than block the business write, and tell the developer
        # (paths only, never values) so the call site gets fixed.
        log.warning(
            "event payload carried personal data or secrets; masked",
            extra={"event_type": event_type, "paths": leaks[:20]},
        )
    event = DomainEvent.new(
        society_id=society_id,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        aggregate_version=aggregate_version,
        event_type=event_type,
        actor_ref=ctx.actor_ref,
        correlation_id=ctx.request_id or uuid7(),
        causation_id=causation_id,
        payload=dict(clean_payload),
        schema_version=schema_version,
    )
    conn.execute(
        text(
            "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id,"
            " aggregate_version, event_type, occurred_at, actor_ref, correlation_id, causation_id,"
            " payload, payload_hash)"
            " VALUES (:event_id, :schema_version, :society_id, :aggregate_type, :aggregate_id,"
            " :aggregate_version, :event_type, :occurred_at, :actor_ref, :correlation_id, :causation_id,"
            " CAST(:payload AS jsonb), :payload_hash)"
        ),
        {
            "event_id": event.event_id,
            "schema_version": event.schema_version,
            "society_id": event.society_id,
            "aggregate_type": event.aggregate_type,
            "aggregate_id": event.aggregate_id,
            "aggregate_version": event.aggregate_version,
            "event_type": event.event_type,
            "occurred_at": event.occurred_at,
            "actor_ref": event.actor_ref,
            "correlation_id": event.correlation_id,
            "causation_id": event.causation_id,
            "payload": canonical_json(event.payload).decode("utf-8"),
            "payload_hash": event.payload_hash(),
        },
    )
    return event


@dataclass(frozen=True)
class MutationResult:
    """What a domain function reports back to :func:`mutation`.

    ``before``/``after`` feed the masked audit diff; ``event_payload`` is the MINIMAL outbox payload
    (ids and state, not personal data). ``value`` is returned to the caller unchanged.
    """

    object_id: uuid.UUID
    object_version: int
    before: Mapping[str, Any] | None = None
    after: Mapping[str, Any] | None = None
    event_payload: Mapping[str, Any] = field(default_factory=dict)
    value: Any = None


@dataclass(frozen=True)
class MutationOutcome:
    result: MutationResult
    audit_id: uuid.UUID
    event: DomainEvent


def mutation(
    conn: Connection,
    ctx: RequestContext,
    *,
    operation: str,
    object_type: str,
    event_type: str,
    apply: Callable[[Connection], MutationResult],
    aggregate_type: str | None = None,
    reason: str | None = None,
    approver_id: uuid.UUID | None = None,
    redact: Iterable[str] = (),
    causation_id: uuid.UUID | None = None,
) -> MutationOutcome:
    """Domain change + audit row + outbox row, all-or-nothing, on ``conn``.

    Runs inside a SAVEPOINT: an exception from ``apply``, the audit insert or the outbox insert rolls
    back all of them and is re-raised. The caller's outer transaction (and anything else it did) is
    untouched, so it may handle the error and continue.
    """
    with conn.begin_nested():
        result = apply(conn)
        audit_id = record_audit(
            conn,
            ctx,
            operation=operation,
            object_type=object_type,
            object_id=result.object_id,
            object_version=result.object_version,
            before=result.before,
            after=result.after,
            reason=reason,
            approver_id=approver_id,
            redact=redact,
        )
        event = emit_event(
            conn,
            ctx,
            aggregate_type=aggregate_type or object_type,
            aggregate_id=result.object_id,
            aggregate_version=result.object_version,
            event_type=event_type,
            payload=result.event_payload,
            causation_id=causation_id,
        )
    return MutationOutcome(result, audit_id, event)
