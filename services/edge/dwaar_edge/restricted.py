"""Restricted standalone terminal model (gateway lost / LAN split).

REQ: EDGE-06 (terminals run restricted standalone for at least 24 h using signed cached entitlements only),
PRD 9.3 (LAN split: gate-bound passes only; multi-use quota only via per-gate escrow), AT-05, AT-07, INV-03.

This is the LOGIC a terminal runs when it cannot reach its gateway. It uses the SAME pure decision engine with
``mode=RESTRICTED_STANDALONE``, verifies the cached snapshot signature itself against the provisioned issuer
keys, keeps a local single-use ledger scoped to this gate, and queues observations with its own sequence for
``Gateway.reconcile_standalone``. The Android UI is a later slice; this is the tested core it will mirror.
It cannot guarantee global single-use: a pass that is not bound to this gate goes to a supervisor.
"""

# REQ: EDGE-06, INV-03

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dwaar_common.ids import uuid7
from dwaar_common.timeutil import format_iso_utc, parse_iso_utc

from .clock import ClockModel
from .decision import (
    Credential,
    Decision,
    DecisionRequest,
    GuestPass,
    LedgerView,
    OperatingMode,
    Outcome,
    decide,
)
from .errors import InvalidRequest
from .policy import PolicyBundle, verify_snapshot


@dataclass
class StandaloneTerminal:
    device_id: uuid.UUID
    gate_id: uuid.UUID
    society_id: uuid.UUID
    issuer_keys: Mapping[str, Ed25519PublicKey]
    clock: ClockModel
    bundle: PolicyBundle | None = None
    escrow: dict[uuid.UUID, int] = field(default_factory=dict)
    _used: dict[uuid.UUID, int] = field(default_factory=dict)  # local consumed count per invitation
    _tseq: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)

    mode: OperatingMode = OperatingMode.RESTRICTED_STANDALONE

    def load_cache(self, cache: Mapping[str, Any]) -> None:
        """Load the gateway's exported cache. The snapshot is verified here; the terminal trusts no one."""
        snap = verify_snapshot(
            cache["policy"],
            issuer_keys=self.issuer_keys,
            society_id=self.society_id,
            now=None,
            current_seq=0,
        )
        confirmed = cache.get("confirmed_at")
        self.bundle = PolicyBundle.build(
            snap, cache["policy"], None, parse_iso_utc(confirmed) if confirmed else None
        )
        self.escrow = {uuid.UUID(k): int(v) for k, v in cache.get("escrow", {}).items()}

    @property
    def banner(self) -> str:
        """What the terminal UI must show: truthful, never pretending to be connected."""
        return "restricted_standalone"

    def evaluate(self, credential: Credential, lane_id: uuid.UUID) -> Decision:
        state = self.clock.assess()
        used = 0
        if isinstance(credential, GuestPass):
            used = self._used.get(credential.invitation_id, 0)
        ledger = LedgerView(
            used_total=used,
            used_at_gate=used,
            escrow_allocated=(
                self.escrow.get(credential.invitation_id)
                if isinstance(credential, GuestPass)
                else None
            ),
        )
        return decide(
            self.bundle,
            DecisionRequest(
                credential, self.gate_id, lane_id, OperatingMode.RESTRICTED_STANDALONE, ledger
            ),
            state,
        )

    def record_entry(
        self,
        decision: Decision,
        credential: Credential,
        lane_id: uuid.UUID,
        *,
        authorised_by: str = "cached_policy",
        alias: str | None = None,
    ) -> dict[str, Any]:
        """Record an observed entry. Needs an allow decision or an explicit manual authorisation
        (``authorised_by`` guard_assisted / supervisor_override after a needs_* outcome)."""
        if decision.outcome is not Outcome.ALLOW and authorised_by == "cached_policy":
            raise InvalidRequest(
                "entry needs an allow decision or an explicit manual authorisation",
                code="no_authorising_decision",
            )
        invitation = credential.invitation_id if isinstance(credential, GuestPass) else None
        if invitation is not None:
            self._used[invitation] = self._used.get(invitation, 0) + 1
        return self._queue("entry", lane_id, invitation, authorised_by, alias)

    def record_exit(
        self, lane_id: uuid.UUID, observation_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        return self._queue("exit", lane_id, None, "guard_assisted", None, observation_id)

    def _queue(
        self,
        kind: str,
        lane_id: uuid.UUID,
        invitation: uuid.UUID | None,
        source: str,
        alias: str | None,
        observation_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        self._tseq += 1
        state = self.clock.assess()
        ob: dict[str, Any] = {
            "tseq": self._tseq,
            "observation_id": str(observation_id or uuid7()),
            "kind": kind,
            "gate_id": str(self.gate_id),
            "lane_id": str(lane_id),
            "credential_kind": "qr" if invitation else "guard_assisted",
            "decision_source": source,
            "occurred_at": format_iso_utc(state.now),
            "clock_uncertainty_ms": state.uncertainty_ms,
        }
        if invitation is not None:
            ob["invitation_id"] = str(invitation)
            known = None if self.bundle is None else self.bundle.invitations.get(invitation)
            if known is not None:
                ob["max_uses"] = (
                    known.max_uses
                )  # the gateway may no longer hold the pass when this is reconciled (expired passes leave the policy)
        if alias:
            ob["alias"] = alias
        self.observations.append(ob)
        return ob

    def drain(self) -> list[dict[str, Any]]:
        out, self.observations = self.observations, []
        return out


def now_iso(moment: datetime) -> str:  # tiny helper for tests
    return format_iso_utc(moment)
