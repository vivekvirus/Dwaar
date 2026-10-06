"""Policy snapshot verification and the in-memory policy bundle used by the decision engine.

REQ: EDGE-04 (verify signature against PROVISIONED issuer keys, schema version, society, validity;
reject rollback; keep last good policy), EDGE-05 (policy age from trusted time), INV-03.

The issuer public keys come from commissioning configuration, never from the snapshot itself.
"""

# REQ: EDGE-04, EDGE-05, INV-03

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from dwaar_common.events import canonical_json
from dwaar_common.signing import verify_bytes

from .errors import PolicyRejected
from .policy_model import (
    HARD_CLOCK_UNCERTAINTY_MAX_MS,
    HARD_GUEST_OFFLINE_MAX_S,
    HARD_RESIDENT_OFFLINE_MAX_S,
    SUPPORTED_SCHEMA_VERSIONS,
    Gate,
    Invitation,
    Lane,
    Resident,
    Snapshot,
    StandingRule,
    Timing,
    minimisation_violations,
)

MAX_SNAPSHOT_FUTURE_SKEW: Final = timedelta(minutes=10)


@dataclass(frozen=True)
class EffectiveLimits:
    """Timing limits after the hard PRD caps are applied: policy can only tighten them."""

    guest_offline_max_s: int
    resident_offline_validity_s: int
    clock_uncertainty_limit_ms: int
    approval_expiry_s: int

    @classmethod
    def from_timing(cls, timing: Timing) -> EffectiveLimits:
        guest = min(timing.guest_offline_max_s, timing.policy_age_limit_s, HARD_GUEST_OFFLINE_MAX_S)
        resident = min(
            timing.resident_offline_validity_s,
            timing.policy_age_limit_s,
            HARD_RESIDENT_OFFLINE_MAX_S,
        )
        return cls(
            guest_offline_max_s=guest,
            resident_offline_validity_s=resident,
            clock_uncertainty_limit_ms=min(
                timing.clock_uncertainty_limit_ms, HARD_CLOCK_UNCERTAINTY_MAX_MS
            ),
            approval_expiry_s=timing.approval_expiry_s,
        )


@dataclass(frozen=True)
class PolicyBundle:
    """A verified snapshot with lookup indexes. Immutable; replaced as a whole on apply."""

    snapshot: Snapshot
    raw: Mapping[str, Any] = field(repr=False)
    gates: Mapping[uuid.UUID, Gate]
    lanes: Mapping[uuid.UUID, Lane]
    residents: Mapping[str, Resident]
    invitations: Mapping[uuid.UUID, Invitation]
    rules_by_unit: Mapping[uuid.UUID, tuple[StandingRule, ...]]
    revocations: Mapping[str, int]
    limits: EffectiveLimits
    confirmed_at: datetime | None = None  # last authenticated "you are up to date" from the cloud

    @classmethod
    def build(
        cls,
        snapshot: Snapshot,
        raw: Mapping[str, Any],
        extra_revocations: Mapping[str, int] | None = None,
        confirmed_at: datetime | None = None,
    ) -> PolicyBundle:
        m = snapshot.manifest
        rules: dict[uuid.UUID, list[StandingRule]] = {}
        for rule in m.standing_rules:
            rules.setdefault(rule.unit_id, []).append(rule)
        revs: dict[str, int] = dict(extra_revocations or {})
        for rev in m.revocations:  # newest known deny wins: versions only ever go up
            revs[rev.ref] = max(rev.version, revs.get(rev.ref, -1))
        return cls(
            snapshot=snapshot,
            raw=raw,
            gates={g.id: g for g in m.gates},
            lanes={ln.id: ln for ln in m.lanes},
            residents={r.credential_ref: r for r in m.residents},
            invitations={i.id: i for i in m.invitations},
            rules_by_unit={k: tuple(v) for k, v in rules.items()},
            revocations=revs,
            limits=EffectiveLimits.from_timing(m.timing),
            confirmed_at=confirmed_at,
        )

    @property
    def seq(self) -> int:
        return self.snapshot.seq

    @property
    def valid_until(self) -> datetime:
        return self.snapshot.valid_until

    def with_confirmation(self, at: datetime) -> PolicyBundle:
        if self.confirmed_at is not None and at <= self.confirmed_at:
            return self
        return replace(self, confirmed_at=at)

    def freshness_anchor(self) -> datetime:
        """Moment from which policy age is counted: issue time or the last authenticated confirmation."""
        issued = self.snapshot.issued_at
        if self.confirmed_at is not None and self.confirmed_at > issued:
            return self.confirmed_at
        return issued

    def age(self, now: datetime) -> timedelta:
        return max(timedelta(0), now - self.freshness_anchor())


def verify_snapshot(
    raw: Mapping[str, Any],
    *,
    issuer_keys: Mapping[str, Ed25519PublicKey],
    society_id: uuid.UUID,
    now: datetime | None,
    current_seq: int,
) -> Snapshot:
    """Verify a raw snapshot. Raises ``PolicyRejected`` with a stable code; never returns a half-checked one.

    Order: well-formed envelope -> provisioned issuer key -> signature over canonical JSON of the snapshot
    minus ``signature`` -> schema version -> typed parse (unknown fields refused) -> society -> data
    minimisation -> validity window -> rollback. Nothing in the snapshot is trusted before the signature.
    """
    if not isinstance(raw, Mapping):
        raise PolicyRejected("snapshot is not an object", code="malformed")
    key_id = raw.get("issuer_key_id")
    signature = raw.get("signature")
    if not isinstance(key_id, str) or not isinstance(signature, str):
        raise PolicyRejected("missing issuer_key_id or signature", code="malformed")
    key = issuer_keys.get(key_id)
    if key is None:
        raise PolicyRejected("issuer key is not provisioned on this gateway", code="unknown_issuer")
    try:
        body = canonical_json({k: v for k, v in raw.items() if k != "signature"})
    except TypeError as exc:
        raise PolicyRejected("snapshot is not canonical JSON", code="malformed") from exc
    if not verify_bytes(key, body, signature):
        raise PolicyRejected("signature does not verify", code="bad_signature")
    if raw.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise PolicyRejected("unsupported schema_version", code="unsupported_schema")
    try:
        snapshot = Snapshot.model_validate(dict(raw))
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"][:3]) for e in exc.errors()})
        raise PolicyRejected(
            f"snapshot fields invalid or not allowed: {fields[:5]}", code="schema_invalid"
        ) from exc
    if snapshot.society_id != society_id:
        raise PolicyRejected("snapshot is for another society", code="wrong_society")
    manifest_raw = raw.get("manifest")
    # Only the FREE-FORM members are scanned for personal data: rule params and visitor aliases. Identifiers (ids, refs,
    # nonces) are opaque by construction and a random id can contain a digit run that merely looks like a phone number.
    free_form: list[Any] = []
    if isinstance(manifest_raw, Mapping):
        free_form.extend(
            r.get("params")
            for r in manifest_raw.get("standing_rules", [])
            if isinstance(r, Mapping)
        )
        free_form.extend(
            {"visitor_alias": i.get("visitor_alias")}
            for i in manifest_raw.get("invitations", [])
            if isinstance(i, Mapping)
        )
    bad = minimisation_violations(free_form)
    if bad:
        raise PolicyRejected(
            f"personal data in snapshot at {bad[0]}", code="minimisation_violation"
        )
    if snapshot.valid_until <= snapshot.issued_at:
        raise PolicyRejected("valid_until is not after issued_at", code="schema_invalid")
    if now is not None:
        if snapshot.valid_until <= now:
            raise PolicyRejected("snapshot already expired", code="expired")
        if snapshot.issued_at > now + MAX_SNAPSHOT_FUTURE_SKEW:
            raise PolicyRejected("snapshot issued in the future", code="issued_in_future")
    if snapshot.seq <= current_seq:
        code = "duplicate" if snapshot.seq == current_seq else "rollback"
        raise PolicyRejected(f"snapshot seq {snapshot.seq} <= applied {current_seq}", code=code)
    return snapshot
