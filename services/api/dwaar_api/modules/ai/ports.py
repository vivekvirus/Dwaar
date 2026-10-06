"""Command ports and the AI runtime held on ``app.state.ai``.

REQ: INV-06 (AI proposes, deterministic services execute), AI-F01, AI-G08, AI-R02, AI-C01 (the ticket, shift and notice modules are built by
other teams: consumed ONLY through these narrow interfaces).

A ``CommandPort`` is the DETERMINISTIC executor of one command. It is called inside the confirmation transaction with the caller's scoped
connection, so a real module writes its row, its audit row and its outbox row atomically with the proposal's own confirmation. It must be
idempotent on ``external_key`` (stable per proposal). A port that is not registered means the module does not exist yet: the confirmation
answers 503 ``dependency_unavailable`` and the proposal stays open.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import Connection

from dwaar_ai_gateway.pipeline import Gateway
from dwaar_ai_gateway.ports import AsrAdapter

from ...core.db import RequestContext


@runtime_checkable
class CommandPort(Protocol):
    def execute(
        self,
        conn: Connection,
        ctx: RequestContext,
        payload: Mapping[str, Any],
        *,
        proposal_id: uuid.UUID,
        external_key: str,
    ) -> Mapping[str, Any]: ...


@dataclass
class AiRuntime:
    gateway: Gateway
    sources: dict[str, Any] = field(
        default_factory=dict
    )  # feature id -> TicketSource / ShiftSource
    ports: dict[str, CommandPort] = field(
        default_factory=dict
    )  # ticket_create, ticket_triage, notice_draft, shift_handover
    asr: AsrAdapter | None = None
    clock: Any = None  # callable returning an aware datetime; tests inject

    def now(self) -> datetime:
        from datetime import UTC

        return self.clock() if self.clock else datetime.now(UTC)
