"""Edge sync ingestion: the EDGE-07 conflict algorithm, quarantine, clock flags and the acknowledgement cursor.

REQ: EDGE-03 (per-event outcome, highest contiguous acknowledged sequence, gaps, policy cursor; a bad event is quarantined without
blocking later events; event ids never regenerated), EDGE-05 (clock uncertainty recorded, implausible timestamps flagged, never rewritten),
EDGE-07 (verify signature -> reject wrong society or schema -> deduplicate (device_id, seq) and event_id -> enforce the permitted
transition -> commit record, audit and outbox atomically -> acknowledge -> propagate; invalid transitions go to the exception queue and a
physical entry is NEVER silently discarded), INV-03 / INV-07 (an observation never creates permission), INV-01, PRD 9.3 (append-only;
preserve both observations on a conflict).

One batch = one database transaction (acknowledgement happens after the commit), one SAVEPOINT per event, so a failing event rolls back
only itself. Concurrent batches of the same device serialise on a transaction-scoped advisory lock; a deadlock between two devices that
touch the same visit is retried (the whole batch is idempotent).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from dwaar_common.events import CanonicalJsonError, EdgeEvent, canonical_json
from dwaar_common.ids import uuid7
from dwaar_common.signing import public_key_from_b64, verify_edge_event
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mask_payload, mutation
from ...core.db import Database, RequestContext
from ..visits import exceptions as visit_exceptions
from ..visits.policy import json_text
from . import clock
from .auth import EdgeDevice
from .config import EdgeConfig
from .metrics import EdgeMetrics
from .snapshot import limits

log = logging.getLogger("dwaar_api.edge.sync")

ACTOR_ROLE: Final = "edge_device"
MAX_SEQ: Final = 2**62
DECISION_SOURCES: Final = frozenset(
    {
        "cached_policy",
        "resident_app",
        "ivr",
        "guard_assisted",
        "supervisor_override",
        "rfid",
        "anpr",
    }
)
CREDENTIAL_KINDS: Final = frozenset(
    {"qr", "code", "guard_assisted", "resident_app", "rfid", "anpr", "none"}
)
EXIT_BASES: Final = frozenset({"scanned", "observed", "reconciled_unknown"})
#: namespace of the visit ids derived for edge-local pass entries (ADR-0019): the gateway-minted movement id is NOT used as a primary key
EDGE_VISIT_NAMESPACE: Final = uuid.UUID("b3a0c2d4-5e6f-4a81-9c27-0d4e6f8a1b3c")
OBSERVATION_TYPES: Final = frozenset({"EntryObserved", "ExitObserved"})
#: words that must never appear as a payload key: data minimisation (EDGE-04) mirrored on the way in
FORBIDDEN_PAYLOAD_WORDS: Final = frozenset(
    {
        "phone", "mobile", "msisdn", "otp", "aadhaar", "aadhar", "email", "dob", "address", "passport",
        "pan", "upi", "vpa", "ifsc", "iban", "account", "password", "secret", "name", "surname",
        "amount", "paise", "balance", "salary",
    }
)  # fmt: skip
_KEY_SPLIT: Final = re.compile(r"[^a-z0-9]+")
_KEY_CAMEL: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_OPERATIONAL_SQLSTATES: Final = ("08", "40", "53", "55", "57")


# ------------------------------------------------------------------------------------------ results
@dataclass
class Outcome:
    index: int
    event_id: uuid.UUID | None
    seq: int | None
    status: str
    reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    stored: bool = False  # a NEW ledger or quarantine row was written for this event
    quarantined: bool = False

    def to_wire(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "index": self.index,
            "event_id": str(self.event_id) if self.event_id else None,
            "seq": self.seq,
            "status": self.status,
        }
        if self.reason:
            body["reason"] = self.reason
        for key, value in self.extra.items():
            body[key] = str(value) if isinstance(value, uuid.UUID) else value
        return body


@dataclass(frozen=True)
class BatchResult:
    outcomes: list[Outcome]
    highest_contiguous_seq: int
    gaps: list[list[int]]
    latest_policy_seq: int

    def to_wire(self) -> dict[str, Any]:
        return {
            "outcomes": [o.to_wire() for o in self.outcomes],
            "highest_contiguous_seq": self.highest_contiguous_seq,
            "gaps": self.gaps,
            "policy_cursor": {"latest_seq": self.latest_policy_seq},
        }


@dataclass(frozen=True)
class Transition:
    changed: bool
    note: str
    status: str  # accepted | rejected_transition
    exception: tuple[str, str, bool | None] | None = None  # kind, reason, entry_happened
    project: bool = False  # an edge-local PASS entry the cloud knows: project it onto a visit and the pass use (ADR-0019)


@dataclass
class _Ledger:
    """What the batch already knows: stored events and quarantined raw hashes (updated as the batch proceeds)."""

    by_event: dict[uuid.UUID, Mapping[str, Any]] = field(default_factory=dict)
    by_seq: dict[int, Mapping[str, Any]] = field(default_factory=dict)  # this device's seqs
    quarantined: dict[str, Mapping[str, Any]] = field(default_factory=dict)  # raw_sha256 -> row


# ------------------------------------------------------------------------------------------ helpers
def _raw_digest(raw: Any) -> str:
    try:
        data = canonical_json(raw)
    except (CanonicalJsonError, TypeError, ValueError, RecursionError):
        data = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=True).encode(
            "ascii", "replace"
        )
    return hashlib.sha256(data).hexdigest()


def edge_visit_id(society_id: uuid.UUID, movement_id: uuid.UUID) -> uuid.UUID:
    """The cloud visit that represents an edge-local pass movement. Derived, so an exit finds it again and a device can never pick (or probe)
    the primary key of another society's visit."""
    return uuid.uuid5(EDGE_VISIT_NAMESPACE, f"{society_id}:{movement_id}")


def _safe_seq(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SEQ:
        return None
    return value


def _safe_uuid(value: Any) -> uuid.UUID | None:
    if not isinstance(value, str):
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _bounded_raw(raw: Any, digest: str) -> dict[str, Any]:
    """A masked, size-bounded copy of what the device sent (evidence for a reviewer; never a phone or a secret)."""
    if not isinstance(raw, Mapping):
        return {"non_object": type(raw).__name__, "sha256": digest}
    try:
        masked = mask_payload(raw)
        encoded = json.dumps(masked, default=str, separators=(",", ":"))
    except Exception:
        return {"unserialisable": True, "sha256": digest, "keys": sorted(str(k) for k in raw)[:30]}
    if len(encoded) > 6000:
        return {"truncated": True, "sha256": digest, "keys": sorted(str(k) for k in raw)[:30]}
    return json.loads(encoded)  # type: ignore[no-any-return]


def _forbidden_key(payload: Any, depth: int = 0) -> bool:
    if depth > 8:
        return True
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            words = {w for w in _KEY_SPLIT.split(_KEY_CAMEL.sub("_", str(key)).lower()) if w}
            if words & FORBIDDEN_PAYLOAD_WORDS or _forbidden_key(value, depth + 1):
                return True
    elif isinstance(payload, list):
        return any(_forbidden_key(v, depth + 1) for v in payload)
    return False


def _operational(exc: BaseException) -> bool:
    """A failure of the database or the connection (deadlock, timeout, serialisation): the WHOLE batch must be retried, not one event quarantined."""
    original = exc.orig if isinstance(exc, DBAPIError) else exc
    state = getattr(original, "sqlstate", None)
    return isinstance(state, str) and state.startswith(_OPERATIONAL_SQLSTATES)


# ------------------------------------------------------------------------------------------ the transition table
def decide_transition(
    visit: Mapping[str, Any],
    *,
    event_type: str,
    occurred_at: dt.datetime,
    clock_uncertainty_ms: int,
    uncertainty_limit_ms: int,
    exit_basis: str,
) -> Transition:
    """The permitted transition for one observation. Pure: no I/O, so it is unit-testable and is the ONLY place the rule lives.

    Never creates permission: it only ever moves a visit that was ALREADY authorised (INV-07). The stated clock uncertainty widens the
    permission window by at most the policy limit; above the limit an entry is recorded but not applied (EDGE-05, AT-08).
    """
    if event_type == "EntryObserved":
        state = visit["state"]
        if state == "inside":
            return Transition(False, "duplicate_entry", "accepted")
        if state == "authorised":
            if clock_uncertainty_ms > uncertainty_limit_ms:
                return Transition(
                    False, "clock_uncertain_review", "rejected_transition",
                    ("clock_implausible", "Entry observed while the device clock was uncertain: the authorisation was not applied, please review", True),
                )  # fmt: skip
            until = visit["authorised_until"]
            tolerance = dt.timedelta(milliseconds=min(clock_uncertainty_ms, uncertainty_limit_ms))
            if until is None or occurred_at <= until + tolerance:
                return Transition(True, "entered", "accepted")
            return Transition(
                False, "entry_without_authorisation", "rejected_transition",
                ("unauthorised_entry", "Entry observed by an edge device after the permission expired (permission_expired)", True),
            )  # fmt: skip
        return Transition(
            False, "entry_without_authorisation", "rejected_transition",
            ("unauthorised_entry", f"Entry observed by an edge device without a valid authorisation (visit_{state})", True),
        )  # fmt: skip
    # exit: essential egress is never gated (GATE-07)
    state = visit["state"]
    if state == "exited":
        return Transition(False, "duplicate_exit", "accepted")
    if state in ("inside", "authorised"):
        if exit_basis == "reconciled_unknown":
            return Transition(
                True, "exit_reconciled_unknown", "accepted",
                ("exit_unknown", "Exit reconciled as unknown: the real exit time was not observed", True),
            )  # fmt: skip
        if state == "authorised":
            return Transition(
                True, "exit_without_observed_entry", "accepted",
                ("exit_without_entry", "Exit observed for a visit whose entry was never observed", None),
            )  # fmt: skip
        return Transition(True, "exited", "accepted")
    return Transition(
        False, "exit_without_entry", "rejected_transition",
        ("exit_without_entry", f"Exit observed for a visit in state {state}", None),
    )  # fmt: skip


#: decisions the GATEWAY took itself from its cached signed policy (resident credential, pass, standing rule, RFID/ANPR reader)
LOCAL_DECISION_SOURCES: Final = frozenset({"cached_policy", "rfid", "anpr"})
#: sentinel: the event names an invitation the cloud does not know
UNKNOWN_INVITATION: Final = object()


def decide_unmatched(
    *,
    event_type: str,
    decision_source: str,
    invitation: Mapping[str, Any] | object | None,
    prior_entry: bool,
    occurred_at: dt.datetime,
    clock_uncertainty_ms: int,
    uncertainty_limit_ms: int,
    conflict: str | None,
) -> Transition:
    """An observation whose ``entity_id`` is not a cloud visit: an edge-local MOVEMENT (a resident, a pass, a standing rule, an override).

    The gateway keeps its own movements (it mints their ids) and the cloud has no visit for them, so there is nothing to transition. The
    observation is recorded and judged by what the payload says (INV-07: it creates no permission and no visit):

    * a decision the gateway took from its own cached policy is recorded as it is; a pass that the cloud knows was REVOKED before the entry
      (by more than the stated, capped clock uncertainty) or does not know at all is flagged for review;
    * a supervisor override always leaves a ``manual_entry`` exception (GATE-07: no invisible bypass);
    * a remote decision (resident app, IVR) can only be verified against a cloud visit: without one it is flagged;
    * an exit matches an earlier observed entry of the same movement, otherwise it says so (essential egress is still recorded).
    """
    if event_type == "ExitObserved":
        if prior_entry:
            return Transition(False, "edge_movement_exit", "accepted")
        return Transition(
            False, "exit_without_entry", "rejected_transition",
            ("exit_without_entry", "Exit observed by an edge device with no matching observed entry", None),
        )  # fmt: skip
    if (
        decision_source not in LOCAL_DECISION_SOURCES
        and decision_source != "supervisor_override"
        and decision_source != "guard_assisted"
    ):
        return Transition(
            False, "entry_unknown_visit", "rejected_transition",
            ("unauthorised_entry", f"Entry observed ({decision_source}) for a visit the cloud does not know", True),
        )  # fmt: skip
    if invitation is UNKNOWN_INVITATION:
        return Transition(
            False, "entry_unknown_invitation", "rejected_transition",
            ("unauthorised_entry", "Entry observed with a pass the cloud does not know", True),
        )  # fmt: skip
    if (
        isinstance(invitation, Mapping)
        and invitation["state"] == "revoked"
        and invitation["revoked_at"] is not None
    ):
        tolerance = dt.timedelta(milliseconds=min(clock_uncertainty_ms, uncertainty_limit_ms))
        if invitation["revoked_at"] + tolerance < occurred_at:
            return Transition(
                False, "entry_after_revocation", "rejected_transition",
                ("unauthorised_entry", "Entry observed with a pass that was revoked before the entry (the gateway policy was stale)", True),
            )  # fmt: skip
    known_pass = isinstance(invitation, Mapping)
    if decision_source == "supervisor_override":
        return Transition(
            False, "override_entry_recorded", "accepted",
            ("manual_entry", "Entry recorded by the gateway under a supervisor override: review the override", True),
            project=known_pass,
        )  # fmt: skip
    if conflict:
        return Transition(
            False, "edge_conflict_recorded", "accepted",
            ("other", f"The gateway flagged this entry ({conflict[:80]}): review", True),
            project=known_pass,
        )  # fmt: skip
    return Transition(False, "edge_entry_recorded", "accepted", project=known_pass)


# ------------------------------------------------------------------------------------------ the processor
class BatchProcessor:
    """Processes ONE batch for ONE authenticated device inside an open transaction (``conn`` has the society context set)."""

    def __init__(
        self,
        conn: Connection,
        device: EdgeDevice,
        cfg: EdgeConfig,
        request_id: uuid.UUID,
        *,
        metrics: EdgeMetrics | None = None,
    ) -> None:
        self.conn = conn
        self.device = device
        self.cfg = cfg
        self.ctx = RequestContext(device.society_id, None, ACTOR_ROLE, request_id)
        self.key = public_key_from_b64(device.public_key)
        self.uncertainty_limit_ms, self.max_age_s = limits(
            conn
        )  # approved pack + society policy (INV-10)
        self.metrics = metrics
        self.received = utc_now()
        self.outage_s = 0
        self.ledger = _Ledger()

    # ------------------------------------------------------------------ batch
    def run(self, raw_events: Sequence[Any]) -> BatchResult:
        conn, device = self.conn, self.device
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"edge-sync:{device.id}"},
        )
        conn.execute(
            text(
                "INSERT INTO edge_device_state (id, society_id, device_id) VALUES (:id, :s, :d)"
                " ON CONFLICT (society_id, device_id) DO NOTHING"
            ),
            {"id": uuid7(), "s": device.society_id, "d": device.id},
        )
        state = conn.execute(
            text(
                "SELECT highest_contiguous_seq, max_seq_seen, last_sync_at FROM edge_device_state WHERE device_id = :d"
            ),
            {"d": device.id},
        ).one()
        # a gateway that was cut off for longer than the policy age limit legitimately uploads events older than that limit (NFR-09: 72 h and
        # more are buffered): the time since its LAST batch explains their age, so only an age beyond the outage itself is a clock problem
        self.outage_s = (
            0 if state[2] is None else max(0, int((self.received - state[2]).total_seconds()))
        )
        self._preload(raw_events)
        outcomes = [self._process(i, raw) for i, raw in enumerate(raw_events)]
        high_seen = max(
            [int(state[1]), *[o.seq for o in outcomes if o.seq is not None and o.seq > 0]]
        )
        highest, gaps = self._contiguity(int(state[0]), high_seen)
        stored = sum(1 for o in outcomes if o.stored and not o.quarantined)
        quarantined = sum(1 for o in outcomes if o.stored and o.quarantined)
        conn.execute(
            text(
                "UPDATE edge_device_state SET highest_contiguous_seq = :hc, max_seq_seen = :ms, last_batch_at = :now,"
                " last_sync_at = :now, batches_total = batches_total + 1, events_total = events_total + :n,"
                " quarantined_total = quarantined_total + :q WHERE device_id = :d"
            ),
            {
                "hc": highest,
                "ms": high_seen,
                "now": self.received,
                "n": stored,
                "q": quarantined,
                "d": device.id,
            },
        )
        latest = conn.execute(
            text("SELECT coalesce(max(seq), 0) FROM policy_snapshots")
        ).scalar_one()
        return BatchResult(outcomes, highest, gaps, int(latest))

    def _preload(self, raw_events: Sequence[Any]) -> None:
        seqs: list[int] = []
        ids: list[uuid.UUID] = []
        hashes: list[str] = []
        for raw in raw_events:
            hashes.append(_raw_digest(raw))
            if isinstance(raw, Mapping):
                seq = _safe_seq(raw.get("seq"))
                eid = _safe_uuid(raw.get("event_id"))
                if seq is not None:
                    seqs.append(seq)
                if eid is not None:
                    ids.append(eid)
        if seqs or ids:
            rows = self.conn.execute(
                text(
                    "SELECT device_id, seq, event_id, status, reason, payload_hash, access_event_id, exception_id"
                    " FROM edge_events WHERE (device_id = :d AND seq = ANY(:seqs)) OR event_id = ANY(:ids)"
                ),
                {"d": self.device.id, "seqs": seqs, "ids": ids},
            ).mappings()
            for row in rows:
                self.ledger.by_event[row["event_id"]] = dict(row)
                if row["device_id"] == self.device.id:
                    self.ledger.by_seq[row["seq"]] = dict(row)
        if hashes:
            for row in self.conn.execute(
                text(
                    "SELECT raw_sha256, reason, seq, event_id, exception_id FROM edge_quarantine"
                    " WHERE device_id = :d AND raw_sha256 = ANY(:h)"
                ),
                {"d": self.device.id, "h": hashes},
            ).mappings():
                self.ledger.quarantined[row["raw_sha256"]] = dict(row)

    def _contiguity(self, highest: int, high_seen: int) -> tuple[int, list[list[int]]]:
        """Advance the cursor over the disposed seqs and list the gaps below the highest seq seen (SQL twin of ``contiguity.compute``)."""
        conn = self.conn
        disposed = (
            "SELECT seq FROM edge_events WHERE device_id = :d AND seq > :hc"
            " UNION SELECT seq FROM edge_quarantine WHERE device_id = :d AND seq IS NOT NULL AND seq > :hc"
        )
        row = conn.execute(
            text(
                f"WITH s AS ({disposed}), g AS (SELECT seq, seq - row_number() OVER (ORDER BY seq) AS grp FROM s)"  # noqa: S608
                " SELECT (SELECT min(seq) FROM g),"
                " (SELECT max(seq) FROM g WHERE grp = (SELECT grp FROM g ORDER BY seq LIMIT 1))"
            ),
            {"d": self.device.id, "hc": highest},
        ).one()
        if row[0] is not None and int(row[0]) == highest + 1:
            highest = int(row[1])
        gap_rows = conn.execute(
            text(
                "SELECT prev + 1, seq - 1 FROM (SELECT seq, lag(seq) OVER (ORDER BY seq) AS prev FROM"  # noqa: S608
                f" (SELECT CAST(:hc AS bigint) AS seq UNION {disposed}) t) u"
                " WHERE seq - prev > 1 ORDER BY seq LIMIT :n"
            ),
            {"d": self.device.id, "hc": highest, "n": self.cfg.max_gaps},
        ).all()
        return highest, [[int(a), int(b)] for a, b in gap_rows]

    # ------------------------------------------------------------------ one event
    def _process(self, index: int, raw: Any) -> Outcome:
        digest = _raw_digest(raw)
        seq0 = _safe_seq(raw.get("seq")) if isinstance(raw, Mapping) else None
        eid0 = _safe_uuid(raw.get("event_id")) if isinstance(raw, Mapping) else None
        known = self.ledger.quarantined.get(digest)
        if known is not None:  # the same event again: quarantine is stable, never a second row
            self._count("events_total", status="quarantined")
            return Outcome(
                index, known["event_id"] or eid0, known["seq"] if known["seq"] is not None else seq0,
                "quarantined", known["reason"], {"replayed": True, "exception_id": known["exception_id"]},
            )  # fmt: skip
        try:
            with self.conn.begin_nested():
                outcome = self._decide(index, raw, digest)
        except IntegrityError as exc:
            if _operational(exc):
                raise
            reason = _conflict_reason(exc)
            outcome = self._quarantine_safely(index, raw, digest, reason, seq0, eid0)
        except Exception as exc:
            if isinstance(exc, DBAPIError) and _operational(exc):
                raise
            log.warning(
                "edge event processing failed",
                extra={"exc_type": type(exc).__name__, "index": index},
            )
            outcome = self._quarantine_safely(index, raw, digest, "processing_error", seq0, eid0)
        self._count("events_total", status=outcome.status)
        return outcome

    def _count(self, name: str, **labels: str) -> None:
        if self.metrics is not None:
            self.metrics.inc_labels(name, {"device": str(self.device.id), **labels})

    def _quarantine_safely(
        self, index: int, raw: Any, digest: str, reason: str, seq: int | None, eid: uuid.UUID | None
    ) -> Outcome:
        with self.conn.begin_nested():
            return self._quarantine(index, raw, digest, reason, seq, eid)

    def _decide(self, index: int, raw: Any, digest: str) -> Outcome:
        device = self.device
        seq0 = _safe_seq(raw.get("seq")) if isinstance(raw, Mapping) else None
        eid0 = _safe_uuid(raw.get("event_id")) if isinstance(raw, Mapping) else None
        # 1. schema
        if not isinstance(raw, Mapping):
            return self._quarantine(index, raw, digest, "schema_invalid", None, None)
        if "schema_version" in raw and raw.get("schema_version") != 1:
            return self._quarantine(index, raw, digest, "schema_version_mismatch", seq0, eid0)
        try:
            event = EdgeEvent.from_wire(raw)
        except (ValidationError, ValueError, TypeError):
            return self._quarantine(index, raw, digest, "schema_invalid", seq0, eid0)
        if event.seq > MAX_SEQ:
            return self._quarantine(index, raw, digest, "schema_invalid", None, event.event_id)
        # 2. signature (the authenticated device's registered key)
        if not verify_edge_event(self.key, event):
            return self._quarantine(index, raw, digest, "bad_signature", event.seq, event.event_id)
        # 3. society and device
        if event.society_id != device.society_id:
            return self._quarantine(
                index, raw, digest, "wrong_society", event.seq, event.event_id,
                claimed_society=event.society_id,
            )  # fmt: skip
        if event.device_id != device.id:
            return self._quarantine(index, raw, digest, "wrong_device", event.seq, event.event_id)
        # 4. deduplicate (device_id, seq) and event_id; conflicts keep BOTH observations
        by_event = self.ledger.by_event.get(event.event_id)
        if by_event is not None:
            if (
                by_event["device_id"] == device.id
                and by_event["seq"] == event.seq
                and by_event["payload_hash"] == event.payload_hash
            ):
                return self._duplicate(index, event, by_event)
            reason = (
                "payload_mismatch"
                if by_event["device_id"] == device.id and by_event["seq"] == event.seq
                else "event_id_conflict"
            )
            return self._quarantine(index, raw, digest, reason, event.seq, event.event_id)
        if event.seq in self.ledger.by_seq:
            return self._quarantine(index, raw, digest, "seq_conflict", event.seq, event.event_id)
        # 5. payload hygiene
        try:
            size = len(canonical_json(event.payload))
        except CanonicalJsonError:
            return self._quarantine(index, raw, digest, "schema_invalid", event.seq, event.event_id)
        if size > self.cfg.max_payload_bytes:
            return self._quarantine(
                index, raw, digest, "payload_too_large", event.seq, event.event_id
            )
        if _forbidden_key(event.payload):
            return self._quarantine(index, raw, digest, "pii_in_payload", event.seq, event.event_id)
        # 6. transition, record, audit, outbox
        return self._apply(index, event, raw, digest)

    def _duplicate(self, index: int, event: EdgeEvent, row: Mapping[str, Any]) -> Outcome:
        original = str(row["status"])
        extra: dict[str, Any] = {"original_status": original, "replayed": True}
        if row["reason"]:
            extra["original_reason"] = row["reason"]
        if row["exception_id"]:
            extra["exception_id"] = row["exception_id"]
        if row["access_event_id"]:
            extra["access_event_recorded"] = True
        # a stored `accepted` event answers "duplicate"; any other original status is repeated unchanged (it carries more information)
        status = "duplicate" if original == "accepted" else original
        return Outcome(index, event.event_id, event.seq, status, row["reason"], extra)

    # ------------------------------------------------------------------ quarantine
    def _quarantine(
        self,
        index: int,
        raw: Any,
        digest: str,
        reason: str,
        seq: int | None,
        eid: uuid.UUID | None,
        *,
        claimed_society: uuid.UUID | None = None,
    ) -> Outcome:
        conn, ctx = self.conn, self.ctx
        etype = raw.get("type") if isinstance(raw, Mapping) else None
        exception_id = self._flag_exception(
            "edge_quarantine",
            f"Edge event quarantined ({reason}); a supervisor should review the device",
            {"device_id": str(self.device.id), "reason": reason},
        )
        row_id = uuid7()

        def apply(c: Connection) -> MutationResult:
            c.execute(
                text(
                    "INSERT INTO edge_quarantine (id, society_id, device_id, seq, event_id, event_type, reason,"
                    " claimed_society_id, raw, raw_sha256, received_at, exception_id)"
                    " VALUES (:id, :s, :d, :seq, :eid, :et, :why, :cs, CAST(:raw AS jsonb), :h, :rcv, :ex)"
                ),
                {
                    "id": row_id, "s": self.device.society_id, "d": self.device.id, "seq": seq, "eid": eid,
                    "et": etype[:100] if isinstance(etype, str) else None, "why": reason, "cs": claimed_society,
                    "raw": json_text(_bounded_raw(raw, digest)), "h": digest, "rcv": self.received, "ex": exception_id,
                },
            )  # fmt: skip
            return MutationResult(
                row_id, 1,
                after={"device_id": self.device.id, "reason": reason, "seq": seq},
                event_payload={"device_id": self.device.id, "reason": reason, "seq": seq, "event_id": eid},
            )  # fmt: skip

        mutation(
            conn, ctx, operation="edge.event_quarantined", object_type="edge_quarantine",
            event_type="EdgeEventQuarantined", apply=apply, reason=f"quarantined: {reason}",
        )  # fmt: skip
        self.ledger.quarantined[digest] = {
            "reason": reason,
            "seq": seq,
            "event_id": eid,
            "exception_id": exception_id,
        }
        self._count("quarantined_total", reason=reason)
        extra: dict[str, Any] = {}
        if exception_id:
            extra["exception_id"] = exception_id
        return Outcome(index, eid, seq, "quarantined", reason, extra, stored=True, quarantined=True)

    def _flag_exception(
        self,
        kind: str,
        reason: str,
        key: Mapping[str, str],
        *,
        visit_id: uuid.UUID | None = None,
        evidence: Mapping[str, Any] | None = None,
        dedupe: bool = True,
    ) -> uuid.UUID:
        """Open an exception for a supervisor; while one with the same key is still open, reuse it (a bad clock must not flood the queue)."""
        conn = self.conn
        if dedupe:
            found = conn.execute(
                text(
                    "SELECT id FROM exceptions WHERE kind = :k AND state IN ('open', 'supervisor_review')"
                    " AND evidence @> CAST(:ev AS jsonb) ORDER BY created_at DESC LIMIT 1"
                ),
                {"k": kind, "ev": json_text(key)},
            ).first()
            if found is not None:
                return uuid.UUID(str(found[0]))
        return visit_exceptions.open_exception(
            conn, self.ctx, kind=kind, reason=reason, visit_id=visit_id, entry_happened=None,
            evidence={**(evidence or {}), **key}, system=True,
        )  # fmt: skip

    # ------------------------------------------------------------------ apply
    def _apply(self, index: int, event: EdgeEvent, raw: Mapping[str, Any], digest: str) -> Outcome:
        flag = clock.assess(
            occurred_at=event.occurred_at, received_at=self.received,
            clock_uncertainty_ms=event.clock_uncertainty_ms, uncertainty_limit_ms=self.uncertainty_limit_ms,
            max_age_s=max(self.max_age_s, self.outage_s), future_grace_ms=self.cfg.future_grace_ms,
        )  # fmt: skip
        flag_exception: uuid.UUID | None = None
        if flag is not None and event.type not in OBSERVATION_TYPES:
            flag_exception = self._clock_exception(event, flag)
        if event.type not in OBSERVATION_TYPES:
            return self._record_only(index, event, flag, flag_exception)
        return self._apply_observation(index, event, flag, raw, digest)

    def _clock_exception(self, event: EdgeEvent, flag: str) -> uuid.UUID:
        return self._flag_exception(
            "clock_implausible",
            f"Edge device clock looks implausible ({flag}): timestamps were recorded as stated and not corrected",
            {"device_id": str(self.device.id), "flag": flag},
            evidence={"example_event_id": str(event.event_id), "clock_uncertainty_ms": event.clock_uncertainty_ms},
        )  # fmt: skip

    def _ledger_insert(
        self,
        c: Connection,
        event: EdgeEvent,
        *,
        status: str,
        reason: str | None,
        projected: bool,
        flag: str | None,
        access_event_id: uuid.UUID | None,
        exception_id: uuid.UUID | None,
    ) -> uuid.UUID:
        row_id = uuid7()
        c.execute(
            text(
                "INSERT INTO edge_events (id, society_id, device_id, seq, event_id, event_type, entity_id, entity_version,"
                " policy_version, status, reason, projected, occurred_at, received_at, clock_uncertainty_ms, clock_flag,"
                " payload_hash, access_event_id, exception_id) VALUES (:id, :s, :d, :seq, :eid, :et, :ent, :ev, :pv, :st,"
                " :why, :proj, :occ, :rcv, :unc, :flag, :hash, :ae, :ex)"
            ),
            {
                "id": row_id, "s": self.device.society_id, "d": self.device.id, "seq": event.seq, "eid": event.event_id,
                "et": event.type, "ent": event.entity_id, "ev": min(event.entity_version, 2**31 - 1),
                "pv": event.policy_version, "st": status, "why": reason, "proj": projected, "occ": event.occurred_at,
                "rcv": self.received, "unc": min(event.clock_uncertainty_ms, 86_400_000), "flag": flag,
                "hash": event.payload_hash, "ae": access_event_id, "ex": exception_id,
            },
        )  # fmt: skip
        self.ledger.by_event[event.event_id] = {
            "device_id": self.device.id, "seq": event.seq, "event_id": event.event_id, "status": status,
            "reason": reason, "payload_hash": event.payload_hash, "access_event_id": access_event_id,
            "exception_id": exception_id,
        }  # fmt: skip
        self.ledger.by_seq[event.seq] = self.ledger.by_event[event.event_id]
        return row_id

    def _record_only(
        self, index: int, event: EdgeEvent, flag: str | None, exception_id: uuid.UUID | None
    ) -> Outcome:
        """An event type the cloud does not interpret: stored durably in the ledger, audited, outboxed. Nothing is projected."""
        holder: dict[str, uuid.UUID] = {}

        def apply(c: Connection) -> MutationResult:
            row_id = self._ledger_insert(
                c, event, status="accepted", reason="recorded_not_projected", projected=False, flag=flag,
                access_event_id=None, exception_id=exception_id,
            )  # fmt: skip
            holder["id"] = row_id
            return MutationResult(
                row_id, 1,
                after={"type": event.type, "device_id": self.device.id, "seq": event.seq, "projected": False},
                event_payload={
                    "event_id": event.event_id, "device_id": self.device.id, "seq": event.seq, "type": event.type,
                    "clock_flag": flag,
                },
            )  # fmt: skip

        mutation(
            self.conn, self.ctx, operation="edge.event_recorded", object_type="edge_event",
            event_type="EdgeEventRecorded", apply=apply,
        )  # fmt: skip
        extra: dict[str, Any] = {}
        if exception_id:
            extra["exception_id"] = exception_id
        if flag:
            extra["clock_flag"] = flag
        return Outcome(
            index,
            event.event_id,
            event.seq,
            "accepted",
            "recorded_not_projected",
            extra,
            stored=True,
        )

    def _apply_observation(
        self, index: int, event: EdgeEvent, flag: str | None, raw: Mapping[str, Any], digest: str
    ) -> Outcome:
        conn, device = self.conn, self.device
        payload = event.payload
        self._invitation = None
        problem = self._observation_problem(event)
        if problem is not None:
            return self._quarantine(index, raw, digest, problem, event.seq, event.event_id)
        gate_id, lane_id = self._resolved_place  # set by _observation_problem
        decision_source = str(payload.get("decision_source", "cached_policy"))
        credential_kind = str(payload.get("credential_kind", "none"))
        exit_basis = str(payload.get("exit_basis", "observed"))
        derived = edge_visit_id(device.society_id, event.entity_id)
        visit = (
            conn.execute(
                text(
                    "SELECT id, state, authorised_until, version FROM visits WHERE id = ANY(:ids)"
                    " ORDER BY (id = :id) DESC LIMIT 1 FOR UPDATE"
                ),
                {"ids": [event.entity_id, derived], "id": event.entity_id},
            )
            .mappings()
            .first()
        )
        if visit is not None:
            transition = decide_transition(
                dict(visit), event_type=event.type, occurred_at=event.occurred_at,
                clock_uncertainty_ms=event.clock_uncertainty_ms, uncertainty_limit_ms=self.uncertainty_limit_ms,
                exit_basis=exit_basis,
            )  # fmt: skip
        else:
            transition = self._unmatched(event, decision_source)
        visit_id = visit["id"] if visit is not None else None
        projected = False
        if (
            transition.project and event.type == "EntryObserved"
        ):  # project is only ever set for a pass the cloud knows
            transition, visit_id = self._project_pass_entry(
                event, transition, derived, gate_id, decision_source
            )
            projected = True
        exception_id: uuid.UUID | None = None
        if transition.exception is not None:
            kind, reason, happened = transition.exception
            exception_id = visit_exceptions.open_exception(
                conn, self.ctx, kind=kind, reason=reason, visit_id=visit_id, entry_happened=happened,
                evidence={"event_id": str(event.event_id), "device_id": str(device.id), "gate_id": str(gate_id)},
                system=True,
            )  # fmt: skip
        if flag is not None and exception_id is None:
            exception_id = self._clock_exception(event, flag)
        elif (
            flag is not None and (transition.exception or ("", "", None))[0] != "clock_implausible"
        ):
            self._clock_exception(
                event, flag
            )  # the observation's own exception stays the primary link
        access_id = uuid7()

        def apply(c: Connection) -> MutationResult:
            c.execute(
                text(
                    "INSERT INTO access_events (id, society_id, device_id, seq, event_id, event_type, gate_id, lane_id,"
                    " visit_id, credential_kind, decision_source, policy_version, occurred_at, received_at,"
                    " clock_uncertainty_ms, payload_hash, signature, payload)"
                    " VALUES (:id, :s, :dev, :seq, :eid, :et, :g, :lane, :v, :ck, :ds, :pv, :occ, :rcv, :unc, :hash, :sig,"
                    " CAST(:payload AS jsonb))"
                ),
                {
                    "id": access_id, "s": device.society_id, "dev": device.id, "seq": event.seq, "eid": event.event_id,
                    "et": event.type, "g": gate_id, "lane": lane_id, "v": visit_id, "ck": credential_kind,
                    "ds": decision_source, "pv": event.policy_version, "occ": event.occurred_at, "rcv": self.received,
                    "unc": min(event.clock_uncertainty_ms, 86_400_000), "hash": event.payload_hash,
                    "sig": event.signature, "payload": json_text(payload),
                },
            )  # fmt: skip
            if transition.changed and event.type == "EntryObserved":
                row = c.execute(
                    text(
                        "UPDATE visits SET state = 'inside', entered_at = :occ, confidence_inside = 'observed',"
                        " version = version + 1 WHERE id = :id AND state = 'authorised' RETURNING version"
                    ),
                    {"occ": event.occurred_at, "id": visit_id},
                ).first()
                if row is None:  # pragma: no cover (locked above)
                    raise RuntimeError("visit changed under lock")
            elif transition.changed:
                reconciled = exit_basis == "reconciled_unknown"
                row = c.execute(
                    text(
                        "UPDATE visits SET state = 'exited', exit_basis = :basis,"
                        " exited_at = CASE WHEN :rec THEN NULL ELSE CAST(:occ AS timestamptz) END,"
                        " exit_reconciled_at = CASE WHEN :rec THEN CAST(:occ AS timestamptz) END,"
                        " confidence_inside = CASE WHEN :rec THEN 'unknown' ELSE 'none' END, version = version + 1"
                        " WHERE id = :id AND state IN ('inside', 'authorised') RETURNING version"
                    ),
                    {
                        "basis": exit_basis,
                        "rec": reconciled,
                        "occ": event.occurred_at,
                        "id": visit_id,
                    },
                ).first()
                if row is None:  # pragma: no cover
                    raise RuntimeError("visit changed under lock")
            self._ledger_insert(
                c, event, status=transition.status, reason=transition.note, projected=transition.changed or projected, flag=flag,
                access_event_id=access_id, exception_id=exception_id,
            )  # fmt: skip
            return MutationResult(
                access_id, 1,
                after={
                    "visit_id": visit_id, "type": event.type, "outcome": transition.note, "gate_id": gate_id,
                    "device_id": device.id, "seq": event.seq, "visit_state_before": visit["state"] if visit else None,
                    "permission_created": False, "visit_projected": projected,
                },
                event_payload={
                    "event_id": event.event_id, "visit_id": visit_id, "gate_id": gate_id, "device_id": device.id,
                    "seq": event.seq, "outcome": transition.note, "occurred_at": event.occurred_at,
                    "clock_uncertainty_ms": event.clock_uncertainty_ms, "clock_flag": flag,
                },
            )  # fmt: skip

        mutation(
            conn, self.ctx, operation=f"edge.{'entry' if event.type == 'EntryObserved' else 'exit'}_observed",
            object_type="access_event", event_type=event.type, apply=apply,
        )  # fmt: skip
        extra: dict[str, Any] = {"access_event_recorded": True, "outcome": transition.note}
        if exception_id:
            extra["exception_id"] = exception_id
        if flag:
            extra["clock_flag"] = flag
        outcome_reason: str | None = (
            transition.note if (transition.status != "accepted" or transition.exception) else None
        )
        return Outcome(
            index, event.event_id, event.seq, transition.status, outcome_reason, extra, stored=True
        )

    def _unmatched(self, event: EdgeEvent, decision_source: str) -> Transition:
        """Judge an observation of an edge-local movement (no cloud visit with that id); see :func:`decide_unmatched`."""
        conn = self.conn
        invitation: Mapping[str, Any] | object | None = None
        raw_invitation = event.payload.get("invitation_id")
        if raw_invitation is not None:
            invitation_id = _safe_uuid(raw_invitation)
            found = (
                conn.execute(
                    text(
                        "SELECT id, state, revoked_at, unit_id, kind, visitor_alias, people_count, max_uses, uses, created_by"
                        " FROM invitations WHERE id = :id FOR UPDATE"
                    ),
                    {"id": invitation_id},
                )
                .mappings()
                .first()
                if invitation_id is not None
                else None
            )
            invitation = dict(found) if found is not None else UNKNOWN_INVITATION
            self._invitation = dict(found) if found is not None else None
        else:
            self._invitation = None
        prior = (
            event.type == "ExitObserved"
            and conn.execute(
                text(
                    "SELECT 1 FROM edge_events WHERE entity_id = :e AND event_type = 'EntryObserved' LIMIT 1"
                ),
                {"e": event.entity_id},
            ).first()
            is not None
        )
        conflict = event.payload.get("conflict")
        return decide_unmatched(
            event_type=event.type, decision_source=decision_source, invitation=invitation, prior_entry=prior,
            occurred_at=event.occurred_at, clock_uncertainty_ms=event.clock_uncertainty_ms,
            uncertainty_limit_ms=self.uncertainty_limit_ms, conflict=conflict if isinstance(conflict, str) else None,
        )  # fmt: skip

    def _observation_problem(self, event: EdgeEvent) -> str | None:
        """Validate what an observation needs (place, vocabulary). ``None`` = fine; the resolved (gate, lane) is kept on ``self``."""
        conn, device = self.conn, self.device
        payload = event.payload
        lane_raw, gate_raw = payload.get("lane_id"), payload.get("gate_id")
        lane_id = _safe_uuid(lane_raw) if lane_raw is not None else None
        gate_id = _safe_uuid(gate_raw) if gate_raw is not None else None
        if (lane_raw is not None and lane_id is None) or (gate_raw is not None and gate_id is None):
            return "invalid_payload"
        if str(payload.get("decision_source", "cached_policy")) not in DECISION_SOURCES:
            return "invalid_payload"
        if str(payload.get("credential_kind", "none")) not in CREDENTIAL_KINDS:
            return "invalid_payload"
        if (
            event.type == "ExitObserved"
            and str(payload.get("exit_basis", "observed")) not in EXIT_BASES
        ):
            return "invalid_payload"
        if event.type == "EntryObserved" and "exit_basis" in payload:
            return "invalid_payload"
        if lane_id is not None:
            lane = conn.execute(
                text("SELECT gate_id FROM lanes WHERE id = :id AND status = 'active'"),
                {"id": lane_id},
            ).first()
            if lane is None:
                return "unknown_lane"
            if gate_id is not None and lane[0] != gate_id:
                return "gate_lane_mismatch"
            gate_id = lane[0]
        if gate_id is None:
            gate_id = device.gate_id
        if gate_id is None:
            return "gate_unresolved"
        if device.gate_id is not None and gate_id != device.gate_id:
            return "device_wrong_gate"
        if (
            conn.execute(text("SELECT 1 FROM gates WHERE id = :id"), {"id": gate_id}).first()
            is None
        ):
            return "unknown_gate"
        self._resolved_place = (gate_id, lane_id)
        return None

    _resolved_place: tuple[uuid.UUID, uuid.UUID | None]
    _invitation: dict[str, Any] | None = None

    def _project_pass_entry(
        self,
        event: EdgeEvent,
        transition: Transition,
        visit_id: uuid.UUID,
        gate_id: uuid.UUID,
        decision_source: str,
    ) -> tuple[Transition, uuid.UUID]:
        """Project an accepted edge pass entry onto the cloud: a visit that is ``inside`` and one more use of the pass (ADR-0019).

        The gateway decided from its signed policy and the gate saw the person walk in, so this records facts: it creates NO permission
        (INV-07; the visit says ``authorised_until = entered_at``, the permission was consumed by the entry itself). A pass whose allowed uses
        the cloud had already counted (for example redeemed online meanwhile) still gets its visit, so the person inside is visible, plus a
        supervisor exception. A late entry whose exit was already recorded becomes an ``exited`` visit.
        """
        conn, device = self.conn, self.device
        inv = self._invitation
        assert inv is not None  # noqa: S101
        movement = event.entity_id
        used_up = int(inv["uses"]) >= int(inv["max_uses"])
        if used_up:
            why = "Pass used more often than allowed: the cloud had already counted every permitted use"
            current = transition.exception
            transition = dataclasses.replace(
                transition,
                note=transition.note if current else "edge_entry_pass_overused",
                exception=(current[0], f"{current[1]}; {why}", True)
                if current
                else ("unauthorised_entry", why, True),
            )
        later_exit = conn.execute(
            text(
                "SELECT occurred_at FROM edge_events WHERE entity_id = :e AND event_type = 'ExitObserved' ORDER BY seq LIMIT 1"
            ),
            {"e": movement},
        ).first()
        source = "supervisor_override" if decision_source == "supervisor_override" else "invitation"

        def apply(c: Connection) -> MutationResult:
            uses = None
            if not used_up:
                row = c.execute(
                    text(
                        "UPDATE invitations SET uses = uses + 1,"
                        " state = CASE WHEN state = 'active' AND uses + 1 >= max_uses THEN 'consumed' ELSE state END,"
                        " version = version + 1 WHERE id = :id AND state IN ('active', 'expired') AND uses < max_uses"
                        " RETURNING uses"
                    ),
                    {"id": inv["id"]},
                ).first()
                uses = None if row is None else int(row[0])
            exited = later_exit is not None
            c.execute(
                text(
                    "INSERT INTO visits (id, society_id, kind, state, visitor_alias, invitation_id, gate_id, people_count,"
                    " authorisation_source, authorised_at, authorised_until, entered_at, exited_at, exit_basis,"
                    " confidence_inside, consent_recorded, created_by)"
                    " VALUES (:id, :s, :kind, :state, :alias, :inv, :g, :n, :src, :occ, :occ, :occ, :xat, :xb, :conf, false, :by)"
                ),
                {
                    "id": visit_id, "s": device.society_id, "kind": inv["kind"], "state": "exited" if exited else "inside",
                    "alias": inv["visitor_alias"] or "Guest", "inv": inv["id"], "g": gate_id,
                    "n": inv["people_count"], "src": source, "occ": event.occurred_at,
                    "xat": later_exit[0] if later_exit else None, "xb": "observed" if exited else None,
                    "conf": "none" if exited else "observed", "by": inv["created_by"],
                },
            )  # fmt: skip
            c.execute(
                text(
                    "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq, authorised, state)"
                    " VALUES (:id, :s, :v, :u, 1, true, 'authorised')"
                ),
                {"id": uuid7(), "s": device.society_id, "v": visit_id, "u": inv["unit_id"]},
            )
            return MutationResult(
                visit_id, 1,
                after={
                    "state": "exited" if exited else "inside", "source": source, "invitation_id": inv["id"],
                    "invitation_uses": uses, "gate_id": gate_id, "projected_from_edge": True, "permission_created": False,
                },
                event_payload={
                    "visit_id": visit_id, "unit_id": inv["unit_id"], "source": source, "invitation_id": inv["id"],
                    "device_id": device.id, "seq": event.seq,
                },
            )  # fmt: skip

        mutation(
            conn, self.ctx, operation="edge.pass_entry_projected", object_type="visit",
            event_type="VisitEntered", apply=apply,
        )  # fmt: skip
        return transition, visit_id


def _conflict_reason(exc: IntegrityError) -> str:
    text_ = str(exc.orig)
    if "access_events_device_seq_uq" in text_ or "edge_events_device_seq_uq" in text_:
        return "seq_conflict"
    if "access_events_event_uq" in text_ or "edge_events_event_uq" in text_:
        return "event_id_conflict"
    return "processing_error"


# ------------------------------------------------------------------------------------------ entry point
def ingest_batch(
    db: Database,
    device: EdgeDevice,
    cfg: EdgeConfig,
    request_id: uuid.UUID,
    raw_events: Sequence[Any],
    *,
    metrics: EdgeMetrics | None = None,
) -> BatchResult:
    """Process one batch in ONE transaction (commit before the caller answers). Retries the whole batch on a deadlock."""
    ctx = RequestContext(device.society_id, None, ACTOR_ROLE, request_id)
    last: Exception | None = None
    for _attempt in range(3):
        try:
            with db.app_tx(ctx) as conn:
                result = BatchProcessor(conn, device, cfg, request_id, metrics=metrics).run(
                    raw_events
                )
            return result
        except DBAPIError as exc:
            sqlstate = getattr(exc.orig, "sqlstate", None)
            if sqlstate not in {"40P01", "40001"}:
                raise
            last = exc
    assert last is not None  # noqa: S101
    raise last
