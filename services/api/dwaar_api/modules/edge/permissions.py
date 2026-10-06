"""Permission declarations of the edge module (society-facing actions; the edge's own endpoints use device signatures).

REQ: GATE-14 (standing rules per household), EDGE-04 (publishing), OBS-02 (status), INV-01. Role sets reuse the visits module's.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..visits.permissions import GATE_READERS, GUARD_SUP, HOUSEHOLD, SECRETARY

permissions: Final = (
    Permission(
        "edge.policy.publish",
        frozenset({SECRETARY, GUARD_SUP}),
        description="Publish a signed policy snapshot now (idempotent: unchanged content returns the existing snapshot)",
        sensitive=True,
    ),
    Permission(
        "edge.status.read",
        GATE_READERS | {GUARD_SUP},
        description="Edge sync status: sync age, policy age, backlog, latest snapshot metadata and the quarantine (OBS-02)",
    ),
    Permission(
        "gate.standing_rule.manage",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Create and end standing rules of the own household (GATE-14); only members who may decide for the household",
    ),
    Permission(
        "gate.standing_rule.read",
        HOUSEHOLD | GATE_READERS | {GUARD_SUP},
        scope=ScopeKind.UNIT,
        description="Read the standing rules of the own household; society roles read every unit's",
    ),
)
