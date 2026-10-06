"""Confirmation bound to the payload hash, and the pure re-validation rules applied at confirmation time.

REQ: AI-SYS-04 ('confirmation binds to the payload hash; execution re-checks role, target version, budget and idempotency'), AT-26
(a proposal confirmed after the user's role or the target version changed MUST fail revalidation and require a NEW proposal),
PRD 10.1 (explicit confirmation bound to payload hash, re-check of role and target version), INV-06.

What the hash covers: command, risk class, payload, target ids, target versions, actor, society and the expiry. Editing a proposal
before confirming is a separate, validated step in the API module (the edit produces ``outcome=edited`` and its own receipt); it can
never be used to swap the command or the targets, because those are not editable and are inside the hash.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from dwaar_common.events import canonical_json

from .types import ProposalState


def compute_hash(
    *, society_id: uuid.UUID, actor_id: uuid.UUID, command: str, risk_class: str, payload: Mapping[str, Any],
    target_ids: Sequence[uuid.UUID], target_versions: Sequence[int], expires_at: dt.datetime,
) -> str:  # fmt: skip
    body = {
        "society_id": str(society_id), "actor_id": str(actor_id), "command": command, "risk_class": risk_class,
        "payload": dict(payload), "target_ids": [str(t) for t in target_ids], "target_versions": list(target_versions),
        "expires_at": expires_at.astimezone(dt.UTC).isoformat(),
    }  # fmt: skip
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


class ConfirmationRejected(Exception):
    """``code`` is one of: hash_mismatch, expired, already_decided, wrong_actor, role_changed, role_not_allowed, target_changed,
    approver_required, version_count_mismatch."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class StoredProposal:
    society_id: uuid.UUID
    actor_id: uuid.UUID
    actor_role: str
    command: str
    risk_class: str
    payload: Mapping[str, Any]
    target_ids: Sequence[uuid.UUID]
    target_versions: Sequence[int]
    expires_at: dt.datetime
    state: str
    payload_hash: str


def verify_confirmation(
    stored: StoredProposal,
    *,
    presented_hash: str,
    now: dt.datetime,
    confirmer_id: uuid.UUID,
    confirmer_role: str,  # role derived NOW from the database, never from the proposal
    allowed_roles: frozenset[str],
    approver_roles: frozenset[str],
    current_target_versions: Sequence[int],
) -> None:
    """Raise ConfirmationRejected unless every re-check passes. Order matters: cheap and identity checks first."""
    if stored.state != ProposalState.PROPOSED:
        raise ConfirmationRejected("already_decided")
    if now >= stored.expires_at:
        raise ConfirmationRejected("expired")
    recomputed = compute_hash(
        society_id=stored.society_id, actor_id=stored.actor_id, command=stored.command, risk_class=stored.risk_class,
        payload=stored.payload, target_ids=stored.target_ids, target_versions=stored.target_versions, expires_at=stored.expires_at,
    )  # fmt: skip
    if recomputed != stored.payload_hash:  # the stored row itself was tampered with
        raise ConfirmationRejected("hash_mismatch")
    if presented_hash != stored.payload_hash:
        raise ConfirmationRejected("hash_mismatch")
    if stored.risk_class == "C":
        if confirmer_id == stored.actor_id or confirmer_role not in approver_roles:
            raise ConfirmationRejected("approver_required")
    else:
        if confirmer_id != stored.actor_id:
            raise ConfirmationRejected("wrong_actor")
        if confirmer_role != stored.actor_role:
            raise ConfirmationRejected(
                "role_changed"
            )  # AT-26: the role the proposal was made under is not the role held now
    if confirmer_role not in allowed_roles and stored.risk_class != "C":
        raise ConfirmationRejected("role_not_allowed")
    if len(current_target_versions) != len(stored.target_versions):
        raise ConfirmationRejected("target_changed")
    if list(current_target_versions) != list(stored.target_versions):
        raise ConfirmationRejected(
            "target_changed"
        )  # AT-26: the target moved on since the proposal was drafted
