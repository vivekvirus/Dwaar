"""Small helpers shared by the real-cloud tests: one gateway action, written the way a terminal performs it."""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import uuid
from typing import Any

from tests.integration.edge_e2e._cloud import Site


def evaluate(
    s: Site,
    cred: dict[str, Any],
    *,
    gate: uuid.UUID | None = None,
    lane: uuid.UUID | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    gate = gate or s.gate_a
    lane = lane or (s.lane_a_in if gate == s.gate_a else s.lane_b_in)
    return s.gw.evaluate(actor or s.actor(), gate_id=gate, lane_id=lane, credential=cred)


def enter(
    s: Site,
    cred: dict[str, Any],
    *,
    gate: uuid.UUID | None = None,
    lane: uuid.UUID | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    """Evaluate (must ALLOW) and record the observed entry. Returns the gateway's entry result."""
    gate = gate or s.gate_a
    lane = lane or (s.lane_a_in if gate == s.gate_a else s.lane_b_in)
    actor = actor or s.actor()
    ev = s.gw.evaluate(actor, gate_id=gate, lane_id=lane, credential=cred)
    assert ev["decision"]["outcome"] == "allow", ev["decision"]
    return s.gw.record_entry(actor, gate_id=gate, lane_id=lane, evaluation_id=ev["evaluation_id"])


def leave(
    s: Site,
    movement: str,
    *,
    gate: uuid.UUID | None = None,
    lane: uuid.UUID | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    return s.gw.record_exit(
        actor or s.actor(),
        gate_id=gate or s.gate_a,
        lane_id=lane or s.lane_a_out,
        movement_id=uuid.UUID(movement),
    )


def statuses(s: Site) -> list[tuple[int, str, str, str | None]]:
    """(seq, type, status, reason) of every event the cloud holds for this gateway."""
    return [(int(r[1]), str(r[2]), str(r[3]), r[4]) for r in s.cloud_events()]


def exceptions(s: Site, kind: str | None = None) -> list[tuple[Any, ...]]:
    return s.ew.exceptions(kind)
