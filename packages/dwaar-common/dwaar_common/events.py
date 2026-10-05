"""Event envelopes and canonical JSON.

REQ: EDGE-02 / PRD 12.3 (edge event envelope), PRD 12.4 (domain event contract),
EDGE-03 (event IDs are never regenerated on retry: `event_id` is part of the signed bytes).

Canonical JSON = keys sorted by UTF-16 code unit (RFC 8785), no insignificant whitespace, UTF-8, no floats. Floats are
rejected on purpose: they have no stable canonical text, so quantities travel as ints or
strings (paise, Wh, litres as fixed-decimal strings).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dwaar_common.ids import uuid7
from dwaar_common.timeutil import assert_utc, ensure_utc, format_iso_utc, utc_now

PAYLOAD_HASH_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}\Z")  # \Z: `$` would accept a trailing newline

# Domain event names listed in PRD 12.4. Modules may add more; this is a reference set.
KNOWN_EVENT_TYPES: Final = frozenset(
    {
        "MembershipVerified",
        "RoleGranted",
        "RoleExpired",
        "PolicyPublished",
        "InvitationRevoked",
        "ApprovalRequested",
        "ApprovalEscalated",
        "ApprovalDecided",
        "EntryObserved",
        "ExitObserved",
        "ParcelCollected",
        "InvoicePosted",
        "PaymentConfirmed",
        "SettlementMatched",
        "JournalReversed",
        "WorkOrderCompleted",
        "DocumentPublished",
        "RightsRequestResolved",
        "DataErased",
        "AIProposalConfirmed",
        "TelemetryAnomaly",
    }
)


class CanonicalJsonError(TypeError):
    """Value cannot be represented in canonical JSON."""


MAX_CANONICAL_DEPTH: Final = 64
_INT_BITS: Final = 64  # money is bigint paise; anything wider is not a quantity this platform produces


def _canonical(value: Any, path: str, depth: int) -> Any:
    """Validate ``value`` and return an equivalent structure whose mappings are in canonical key order.

    One bounded pass (no recursion beyond ``MAX_CANONICAL_DEPTH``), so hostile input raises a
    ``CanonicalJsonError`` instead of a ``RecursionError``/``UnicodeEncodeError``/digit-limit ``ValueError``.
    """
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalJsonError(f"nesting deeper than {MAX_CANONICAL_DEPTH} at {path}")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise CanonicalJsonError(f"float at {path}: use int or string, floats are not canonical")
    if isinstance(value, int):
        if value.bit_length() > _INT_BITS:
            raise CanonicalJsonError(f"integer at {path} is wider than {_INT_BITS} bits")
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise CanonicalJsonError(f"string at {path} is not valid Unicode (lone surrogate)") from None
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return format_iso_utc(value)
    if isinstance(value, Mapping):
        items: list[tuple[bytes, str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string key at {path}")
            try:
                # RFC 8785 (JCS): members sort by UTF-16 code units; big-endian UTF-16 bytes compare the same.
                sort_key = key.encode("utf-16-be")
            except UnicodeEncodeError:
                raise CanonicalJsonError(f"key at {path} is not valid Unicode") from None
            items.append((sort_key, key, _canonical(item, f"{path}.{key}", depth + 1)))
        items.sort(key=lambda entry: entry[0])
        return dict((key, item) for _sort, key, item in items)
    if isinstance(value, list | tuple):
        return [_canonical(item, f"{path}[{i}]", depth + 1) for i, item in enumerate(value)]
    raise CanonicalJsonError(f"type {type(value).__name__} is not canonical-JSON serialisable")


def canonical_json(value: Any) -> bytes:
    """Deterministic UTF-8 JSON bytes (RFC 8785 member order), `,` and `:` separators, no floats."""
    return json.dumps(
        _canonical(value, "$", 0),
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def payload_hash(payload: Mapping[str, Any]) -> str:
    """`sha256:<hex>` of the canonical JSON of `payload`."""
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


class _Envelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    @field_validator("occurred_at", check_fields=False)
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class EdgeEvent(_Envelope):
    """Edge sync event (PRD EDGE-02 / 12.3).

    `signature` is `None` until signed. The signed bytes are the canonical JSON of the
    wire form without the `signature` field (see `signing.sign_edge_event`).
    """

    event_id: uuid.UUID
    society_id: uuid.UUID
    device_id: uuid.UUID
    seq: int = Field(ge=0)
    entity_id: uuid.UUID
    entity_version: int = Field(ge=0)
    type: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z][A-Za-z0-9_.]*$")
    policy_version: int = Field(ge=0)
    occurred_at: datetime
    clock_uncertainty_ms: int = Field(ge=0)
    payload_hash: str
    payload: dict[str, Any]
    signature: str | None = None

    @field_validator("occurred_at")
    @classmethod
    def _millisecond_precision(cls, value: datetime) -> datetime:
        """The signed wire form carries milliseconds; the stored value must be exactly that."""
        return value.replace(microsecond=value.microsecond // 1000 * 1000)

    def has_signable_timestamp(self) -> bool:
        """False if ``occurred_at`` has sub-millisecond precision the signature cannot cover."""
        return self.occurred_at.microsecond % 1000 == 0

    @field_validator("payload_hash")
    @classmethod
    def _hash_format(cls, value: str) -> str:
        if not PAYLOAD_HASH_PATTERN.match(value):
            raise ValueError("payload_hash must be 'sha256:<64 hex>'")
        return value

    @classmethod
    def build(
        cls,
        *,
        society_id: uuid.UUID,
        device_id: uuid.UUID,
        seq: int,
        entity_id: uuid.UUID,
        entity_version: int,
        type: str,
        policy_version: int,
        payload: dict[str, Any],
        occurred_at: datetime | None = None,
        clock_uncertainty_ms: int = 0,
        event_id: uuid.UUID | None = None,
    ) -> Self:
        """Create an unsigned event, computing `payload_hash` and a fresh UUIDv7 `event_id`."""
        return cls(
            event_id=event_id or uuid7(),
            society_id=society_id,
            device_id=device_id,
            seq=seq,
            entity_id=entity_id,
            entity_version=entity_version,
            type=type,
            policy_version=policy_version,
            occurred_at=occurred_at or utc_now(),
            clock_uncertainty_ms=clock_uncertainty_ms,
            payload_hash=payload_hash(payload),
            payload=payload,
        )

    def payload_hash_matches(self) -> bool:
        """True if `payload_hash` equals the hash of `payload` (tamper / corruption check)."""
        return self.payload_hash == payload_hash(self.payload)

    def to_wire(self) -> dict[str, Any]:
        """JSON-ready dict (UUIDs as strings, timestamps as UTC ms `Z`)."""
        return {
            "event_id": str(self.event_id),
            "society_id": str(self.society_id),
            "device_id": str(self.device_id),
            "seq": self.seq,
            "entity_id": str(self.entity_id),
            "entity_version": self.entity_version,
            "type": self.type,
            "policy_version": self.policy_version,
            "occurred_at": format_iso_utc(assert_utc(self.occurred_at)),
            "clock_uncertainty_ms": self.clock_uncertainty_ms,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
            "signature": self.signature,
        }

    def signing_bytes(self) -> bytes:
        """Canonical JSON of the envelope minus `signature`: exactly what is signed."""
        wire = self.to_wire()
        del wire["signature"]
        return canonical_json(wire)

    def canonical_bytes(self) -> bytes:
        """Canonical JSON of the full wire form (including signature, if any)."""
        return canonical_json(self.to_wire())

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> Self:
        return cls.model_validate(dict(data))

    def with_signature(self, signature: str) -> Self:
        return self.model_copy(update={"signature": signature})


class DomainEvent(_Envelope):
    """Domain event contract (PRD 12.4), written to the outbox in the mutating transaction."""

    event_id: uuid.UUID
    schema_version: int = Field(ge=1)
    society_id: uuid.UUID
    aggregate_type: str = Field(min_length=1, max_length=100)
    aggregate_id: uuid.UUID
    aggregate_version: int = Field(ge=0)
    event_type: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z][A-Za-z0-9_.]*$")
    occurred_at: datetime
    actor_ref: str = Field(min_length=1, max_length=200)
    correlation_id: uuid.UUID
    causation_id: uuid.UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def new(
        cls,
        *,
        society_id: uuid.UUID,
        aggregate_type: str,
        aggregate_id: uuid.UUID,
        aggregate_version: int,
        event_type: str,
        actor_ref: str,
        correlation_id: uuid.UUID,
        payload: dict[str, Any] | None = None,
        causation_id: uuid.UUID | None = None,
        schema_version: int = 1,
        occurred_at: datetime | None = None,
        event_id: uuid.UUID | None = None,
    ) -> Self:
        return cls(
            event_id=event_id or uuid7(),
            schema_version=schema_version,
            society_id=society_id,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            aggregate_version=aggregate_version,
            event_type=event_type,
            occurred_at=occurred_at or utc_now(),
            actor_ref=actor_ref,
            correlation_id=correlation_id,
            causation_id=causation_id,
            payload=payload or {},
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "schema_version": self.schema_version,
            "society_id": str(self.society_id),
            "aggregate_type": self.aggregate_type,
            "aggregate_id": str(self.aggregate_id),
            "aggregate_version": self.aggregate_version,
            "event_type": self.event_type,
            "occurred_at": format_iso_utc(assert_utc(self.occurred_at)),
            "actor_ref": self.actor_ref,
            "correlation_id": str(self.correlation_id),
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "payload": self.payload,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_wire())

    def payload_hash(self) -> str:
        return payload_hash(self.payload)

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> Self:
        return cls.model_validate(dict(data))
