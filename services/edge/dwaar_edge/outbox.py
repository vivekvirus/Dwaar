"""Durable event outbox: monotonic device sequence, signed events, batches, acknowledgements.

REQ: EDGE-02 (event envelope; persisted atomically with the local projection before success is shown),
EDGE-03 (monotonic device seq never reused; batches of at most 500 events / 1 MB; event ids never regenerated;
acknowledgement handling with gaps), NFR-09 (72 h / 60,000+ events buffer), PRD 7.4 (offline ordering).
"""

# REQ: EDGE-02, EDGE-03, NFR-09

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from dwaar_common.events import EdgeEvent, canonical_json
from dwaar_common.signing import Signer

from .errors import InvalidRequest
from .store import EdgeStore, iso

MAX_BATCH_EVENTS: Final = 500
MAX_BATCH_BYTES: Final = 1_000_000  # "1 MB": the decimal megabyte, the stricter reading
MAX_PAYLOAD_BYTES: Final = (
    2_000  # the cloud quarantines payloads above 2,048 bytes of canonical JSON
)


@dataclass(frozen=True)
class OutboxRow:
    seq: int
    event_id: uuid.UUID
    wire: dict[str, Any]
    size_bytes: int
    attempts: int


class Outbox:
    def __init__(
        self, store: EdgeStore, signer: Signer, society_id: uuid.UUID, device_id: uuid.UUID
    ) -> None:
        self.store = store
        self.signer = signer
        self.society_id = society_id
        self.device_id = device_id

    # ---- append (call inside the caller's transaction) ------------------------------------------
    def append(
        self,
        *,
        type: str,
        entity_id: uuid.UUID,
        entity_version: int,
        payload: dict[str, Any],
        occurred_at: datetime,
        clock_uncertainty_ms: int,
        policy_version: int,
        event_id: uuid.UUID | None = None,
    ) -> EdgeEvent:
        if len(canonical_json(payload)) > MAX_PAYLOAD_BYTES:
            raise InvalidRequest("event payload too large", code="payload_too_large")
        with self.store.transaction() as conn:
            row = conn.execute(
                "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key='last_seq' RETURNING value"
            ).fetchone()
            seq = int(row[0])
            event = EdgeEvent.build(
                society_id=self.society_id,
                device_id=self.device_id,
                seq=seq,
                entity_id=entity_id,
                entity_version=entity_version,
                type=type,
                policy_version=policy_version,
                payload=payload,
                occurred_at=occurred_at,
                clock_uncertainty_ms=min(max(clock_uncertainty_ms, 0), 86_400_000),
                event_id=event_id,
            )
            signed = self.signer.sign_event(event)
            wire = signed.to_wire()
            wire_text = json.dumps(wire, separators=(",", ":"), sort_keys=True)
            conn.execute(
                "INSERT INTO outbox (seq, event_id, type, entity_id, entity_version, occurred_at, policy_version,"
                " wire_enc, size_bytes, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (
                    seq,
                    str(signed.event_id),
                    type,
                    str(entity_id),
                    entity_version,
                    iso(signed.occurred_at),
                    policy_version,
                    self.store.cipher.seal("outbox", "wire", seq, wire_text),
                    len(wire_text.encode()),
                ),
            )
            self.store.crash_point("after_outbox_insert")
            return signed

    # ---- reading for sync -----------------------------------------------------------------------
    def pending_batch(
        self, *, max_events: int = MAX_BATCH_EVENTS, max_bytes: int = MAX_BATCH_BYTES
    ) -> list[OutboxRow]:
        """Oldest pending events, at most ``max_events`` and ``max_bytes`` of event JSON (overhead reserved)."""
        budget = max_bytes - 600  # envelope: device id, cursor, brackets
        rows = self.store.all(
            "SELECT seq, event_id, wire_enc, size_bytes, attempts FROM outbox WHERE state='pending'"
            " ORDER BY seq LIMIT ?",
            (max_events,),
        )
        out: list[OutboxRow] = []
        used = 0
        for r in rows:
            size = int(r["size_bytes"]) + 1  # comma
            if out and used + size > budget:
                break
            wire = json.loads(self.store.cipher.open("outbox", "wire", r["seq"], r["wire_enc"]))
            out.append(
                OutboxRow(int(r["seq"]), uuid.UUID(r["event_id"]), wire, size, int(r["attempts"]))
            )
            used += size
        return out

    def note_attempt(self, seqs: list[int], at: datetime) -> None:
        if not seqs:
            return
        with self.store.transaction() as c:
            c.executemany(
                "UPDATE outbox SET attempts = attempts + 1, last_attempt_at = ? WHERE seq = ?",
                [(iso(at), s) for s in seqs],
            )

    def apply_outcomes(
        self,
        outcomes: list[tuple[str, str, str | None]],
        gaps: list[tuple[int, int]],
        at: datetime,
    ) -> dict[str, int]:
        """Record per-event outcomes and re-queue gaps, atomically. Returns counts per resulting state."""
        counts = {"acked": 0, "quarantined": 0, "rejected": 0, "requeued": 0}
        with self.store.transaction() as c:
            for event_id, status, reason in outcomes:
                if status in ("accepted", "duplicate"):
                    cur = c.execute(
                        "UPDATE outbox SET state='acked', acked_at=?, reason=NULL WHERE event_id=?"
                        " AND state IN ('pending', 'acked')",
                        (iso(at), event_id),
                    )
                    counts["acked"] += cur.rowcount
                elif status == "quarantined":
                    cur = c.execute(
                        "UPDATE outbox SET state='quarantined', reason=? WHERE event_id=? AND state='pending'",
                        (reason or "quarantined", event_id),
                    )
                    counts["quarantined"] += cur.rowcount
                elif status == "rejected_transition":
                    cur = c.execute(
                        "UPDATE outbox SET state='rejected', reason=? WHERE event_id=? AND state='pending'",
                        (reason or "rejected_transition", event_id),
                    )
                    counts["rejected"] += cur.rowcount
            for lo, hi in gaps:
                cur = c.execute(
                    "UPDATE outbox SET state='pending', acked_at=NULL WHERE seq BETWEEN ? AND ? AND state='acked'",
                    (lo, hi),
                )
                counts["requeued"] += cur.rowcount
        return counts

    def stats(self) -> dict[str, Any]:
        rows = self.store.all("SELECT state, COUNT(*) AS n FROM outbox GROUP BY state")
        by_state = {str(r["state"]): int(r["n"]) for r in rows}
        head = self.store.one("SELECT MIN(seq) AS lo FROM outbox WHERE state='pending'")
        last = self.store.get_meta("last_seq", "0")
        oldest = self.store.one("SELECT MIN(occurred_at) AS t FROM outbox WHERE state='pending'")
        return {
            "pending": by_state.get("pending", 0),
            "acked": by_state.get("acked", 0),
            "quarantined": by_state.get("quarantined", 0),
            "rejected": by_state.get("rejected", 0),
            "last_seq": int(last or 0),
            "oldest_pending_seq": None if head is None or head["lo"] is None else int(head["lo"]),
            "oldest_pending_at": None
            if oldest is None or oldest["t"] is None
            else str(oldest["t"]),
        }

    def prune_acked(self, keep_last: int = 1000) -> int:
        """Delete old acknowledged rows (the sequence counter lives in ``meta``, so seq is never reused)."""
        with self.store.transaction() as c:
            cur = c.execute(
                "DELETE FROM outbox WHERE state='acked' AND seq <= (SELECT COALESCE(MAX(seq), 0) FROM outbox) - ?",
                (keep_last,),
            )
            return cur.rowcount
