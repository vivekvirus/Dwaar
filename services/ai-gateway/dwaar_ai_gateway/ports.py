"""Narrow interfaces to modules that do not exist yet (tickets, shifts, ledger) and to speech recognition.

REQ: AI-F01, AI-G08, AI-C05 (interfaces only), AI-R02 (ASR adapter interface). The data modules are built by other teams; the AI layer
consumes them ONLY through these protocols, always as the CALLER (the implementation must apply the caller's society, role and unit
scope; the gateway then re-checks every returned document in ``policy.authorise_sources``). Tests use fakes.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .types import Caller, SourceDoc


@runtime_checkable
class TicketSource(Protocol):
    """AI-F01 input: tickets the CALLER may see. ``SourceDoc.text`` is the ticket text (untrusted); ``unit_id`` its unit;
    ``version`` the ticket version; ``meta`` may carry ``category``/``created_at``."""

    def tickets(self, caller: Caller, ticket_ids: Sequence[str]) -> Sequence[SourceDoc]: ...


@runtime_checkable
class ShiftSource(Protocol):
    """AI-G08 input: events of one shift the CALLER may see. ``SourceDoc.meta`` carries ``kind``, ``critical`` (bool), ``resolved`` (bool)
    and optionally ``occurred_at``; ``text`` is the guard's free-text note (untrusted)."""

    def events(self, caller: Caller, shift_id: str) -> Sequence[SourceDoc]: ...


@dataclass(frozen=True)
class BillRunPreview:
    """AI-C05 input (INTERFACE ONLY: the ledger slice does not exist). Deterministic checks and preset violations block by themselves;
    a model may only explain flagged units."""

    run_id: uuid.UUID
    society_id: uuid.UUID
    lines: Sequence[tuple[uuid.UUID, int, int]]  # (unit_id, amount_paise, previous_amount_paise)


@runtime_checkable
class BillRunSource(Protocol):
    def preview(self, caller: Caller, run_id: uuid.UUID) -> BillRunPreview | None: ...


@dataclass(frozen=True)
class Transcript:
    text: str
    language: str
    confidence: float
    simulation: bool


class AsrError(Exception):
    pass


@runtime_checkable
class AsrAdapter(Protocol):
    """Speech-to-text adapter. D-19 names self-hosted faster-whisper (India region); that adapter is NOT built here (no GPU, no
    model weights): the registry reports it as not configured and only the labelled simulator exists."""

    name: str
    simulation: bool

    def transcribe(self, audio: bytes, language: str, duration_seconds: float) -> Transcript: ...
