"""Duplicate PROPOSALS (OPS-02) and the hook for AI-F01 grouping.

REQ: OPS-02 (duplicate detection proposes links but NEVER exposes another household's private complaint; common-area tickets
show status to all residents to reduce duplicates), AI-F01 (grouping is built later by the ai-gateway work: this module only
exposes the interface), INV-06 (a model proposes, deterministic services execute: a proposal is a row a person accepts by
merging).

The rule is structural, not a filter on output:

* candidates are SELECTED from the tickets of the SAME scope; a private ticket is only ever compared with tickets of the same
  household unit, a block ticket with tickets of the same block (the default proposer queries exactly that);
* every proposal from ANY proposer (including a future model-backed one registered with ``register_proposer``) passes
  ``enforce_same_audience`` before it is stored or returned, so a buggy hook cannot leak across households;
* the database refuses a link across scope or household (trigger ``ticket_links_same_scope``);
* category ``support_privacy`` tickets are never candidates and never get proposals.

A hook receives ``TicketRef`` (ids and the scope fields) and returns ``Proposal`` rows (ids, score, method). It cannot return
ticket text: text never leaves ``similar_by_text`` below.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from sqlalchemy import Connection, text

MAX_PROPOSALS: Final = 5
_OPEN_OR_RECENT: Final = (
    "(t.state IN ('submitted', 'triaged', 'assigned', 'in_progress', 'awaiting_material', 'awaiting_resident', 'resolved')"
    " OR (t.state = 'closed' AND t.closed_basis <> 'merged' AND t.closed_at > now() - interval '14 days'))"
)


@dataclass(frozen=True)
class TicketRef:
    id: uuid.UUID
    scope: str
    unit_id: uuid.UUID | None
    block_id: uuid.UUID | None
    category: str
    text: str  # title + description: input to a proposer, never returned from one


@dataclass(frozen=True)
class Proposal:
    ticket_id: uuid.UUID
    similarity: float
    method: str  # 'trigram' | 'ai_grouping'


class DuplicateProposer(Protocol):
    """The seam for AI-F01 grouping. ``propose`` returns candidate ids and scores only."""

    method: str

    def propose(
        self, conn: Connection, ticket: TicketRef, *, threshold: float, limit: int
    ) -> Sequence[Proposal]: ...


class TrigramProposer:
    """Deterministic similarity over title + description with pg_trgm, restricted to the same audience."""

    method = "trigram"

    def propose(
        self, conn: Connection, ticket: TicketRef, *, threshold: float, limit: int
    ) -> Sequence[Proposal]:
        if not ticket.text.strip():
            return []
        # the operator % uses pg_trgm.similarity_threshold: set it for this transaction only
        conn.execute(
            text("SELECT set_config('pg_trgm.similarity_threshold', :t, true)"),
            {"t": str(threshold)},
        )
        sql = (
            "SELECT t.id, similarity(lower(t.title || ' ' || t.description), lower(:txt)) AS sim FROM tickets t"
            " WHERE t.id <> :id AND t.scope = :scope AND t.category <> 'support_privacy'"
            " AND (CAST(:unit AS uuid) IS NULL OR t.unit_id = CAST(:unit AS uuid))"
            " AND (CAST(:block AS uuid) IS NULL OR t.block_id = CAST(:block AS uuid))"
            " AND __OPEN_OR_RECENT__"
            " AND lower(t.title || ' ' || t.description) % lower(:txt)"
            " ORDER BY sim DESC, t.id LIMIT :lim"
        ).replace("__OPEN_OR_RECENT__", _OPEN_OR_RECENT)
        rows = conn.execute(
            text(sql),
            {
                "txt": ticket.text, "id": ticket.id, "scope": ticket.scope, "unit": ticket.unit_id,
                "block": ticket.block_id, "lim": limit,
            },
        ).all()  # fmt: skip
        return [Proposal(r[0], round(float(r[1]), 3), self.method) for r in rows]


_PROPOSERS: list[DuplicateProposer] = [TrigramProposer()]


def register_proposer(proposer: DuplicateProposer) -> None:
    """Add a proposer (the ai-gateway grouping hook). Its output is still filtered by ``enforce_same_audience``."""
    if all(p.method != proposer.method for p in _PROPOSERS):
        _PROPOSERS.append(proposer)


def proposers() -> tuple[DuplicateProposer, ...]:
    return tuple(_PROPOSERS)


def enforce_same_audience(
    conn: Connection, ticket: TicketRef, proposals: Sequence[Proposal]
) -> list[Proposal]:
    """Drop every proposal whose ticket is not in the same scope / household / block, or is a privacy ticket."""
    if not proposals:
        return []
    ids = [p.ticket_id for p in proposals]
    rows = conn.execute(
        text(
            "SELECT id FROM tickets WHERE id = ANY(:ids) AND id <> :me AND scope = :scope AND category <> 'support_privacy'"
            " AND unit_id IS NOT DISTINCT FROM CAST(:unit AS uuid) AND block_id IS NOT DISTINCT FROM CAST(:block AS uuid)"
        ),
        {
            "ids": ids,
            "me": ticket.id,
            "scope": ticket.scope,
            "unit": ticket.unit_id,
            "block": ticket.block_id,
        },
    ).all()
    allowed = {r[0] for r in rows}
    return [p for p in proposals if p.ticket_id in allowed]


def propose(conn: Connection, ticket: TicketRef, *, threshold: float) -> list[Proposal]:
    """All proposals, best first, deduplicated by ticket, already restricted to the ticket's own audience."""
    best: dict[uuid.UUID, Proposal] = {}
    for proposer in _PROPOSERS:
        for p in enforce_same_audience(
            conn, ticket, proposer.propose(conn, ticket, threshold=threshold, limit=MAX_PROPOSALS)
        ):
            if p.ticket_id not in best or p.similarity > best[p.ticket_id].similarity:
                best[p.ticket_id] = p
    return sorted(best.values(), key=lambda p: (-p.similarity, str(p.ticket_id)))[:MAX_PROPOSALS]


def store_proposals(
    conn: Connection, society_id: uuid.UUID, ticket_id: uuid.UUID, proposals: Sequence[Proposal]
) -> list[dict[str, Any]]:
    """Persist as ``proposed`` links (idempotent) and return the safe view: id, number, title, state, score."""
    out: list[dict[str, Any]] = []
    for p in proposals:
        conn.execute(
            text(
                "INSERT INTO ticket_links (society_id, ticket_id, linked_ticket_id, similarity, method)"
                " VALUES (:s, :t, :l, :sim, :m) ON CONFLICT (society_id, ticket_id, linked_ticket_id) DO NOTHING"
            ),
            {"s": society_id, "t": ticket_id, "l": p.ticket_id, "sim": p.similarity, "m": p.method},
        )
        row = conn.execute(
            text("SELECT id, ticket_no, title, state, scope FROM tickets WHERE id = :id"), {"id": p.ticket_id}
        ).mappings().first()  # fmt: skip
        if row is not None:
            out.append({**dict(row), "similarity": f"{p.similarity:.3f}", "method": p.method})
    return out
