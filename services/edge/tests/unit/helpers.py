"""Builders shared by the edge unit tests (pure objects, no database)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from dwaar_edge.clock import ClockState
from dwaar_edge.decision import DecisionRequest, LedgerView, OperatingMode
from dwaar_edge.policy import PolicyBundle, verify_snapshot
from tests.integration.edge_gateway.support import START, World


def bundle(
    w: World,
    manifest: dict[str, Any],
    *,
    issued_at: datetime = START,
    valid_for: timedelta = timedelta(hours=96),
    confirmed_at: datetime | None = None,
    seq: int = 1,
) -> PolicyBundle:
    raw = w.snapshot(seq=seq, issued_at=issued_at, manifest=manifest, valid_for=valid_for)
    snap = verify_snapshot(
        raw,
        issuer_keys={w.issuer.key_id: w.issuer.public_key},
        society_id=w.society_id,
        now=None,
        current_seq=0,
    )
    return PolicyBundle.build(snap, raw, None, confirmed_at)


def clock(
    now: datetime,
    *,
    unc: int = 50,
    trusted: bool = True,
    back: bool = False,
    fwd: bool = False,
) -> ClockState:
    return ClockState(
        now=now,
        uncertainty_ms=unc,
        trusted=trusted,
        wall_jumped_backwards=back,
        wall_jumped_forwards=fwd,
        restarted_without_trusted_time=not trusted,
    )


def req(
    cred: Any,
    gate: uuid.UUID,
    lane: uuid.UUID,
    *,
    mode: OperatingMode = OperatingMode.NORMAL,
    ledger: LedgerView | None = None,
) -> DecisionRequest:
    return DecisionRequest(cred, gate, lane, mode, ledger or LedgerView())
