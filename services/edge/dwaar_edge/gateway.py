"""The gateway service core: policy, decisions, observations, guard/supervisor flows, status, LAN feed.

REQ: EDGE-01..EDGE-07, EDGE-10, GATE-05, GATE-06, GATE-07, GATE-14, INV-03, INV-07, NFR-02, NFR-04,
PRD 9.3 (authority split: cloud owns identity/passes/revocations; the gate owns physical observations),
Appendix C (supervisor override until shift end; guard-assisted options; never auto-allow).

Every mutating operation is ONE SQLite transaction holding the domain change (projection / ledger), the signed
outbox event, the LAN feed row, the audit row and the idempotency record. The caller sees success only after the
transaction committed (``synchronous=FULL``), so an acknowledged observation survives ``kill -9``.

There is no actuator code here: a decision is information. ``barrier`` is a simulation-only stub that nothing in
this module ever calls (HW-03 groundwork).
"""

# REQ: EDGE-01, EDGE-02, EDGE-05, EDGE-06, EDGE-07, EDGE-10, GATE-05, GATE-06, GATE-07, GATE-14, INV-03, INV-07, NFR-02, NFR-04

from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal

from dwaar_common.events import canonical_json
from dwaar_common.ids import uuid7
from dwaar_common.signing import Signer
from dwaar_common.timeutil import parse_iso_utc

from .actuator import BarrierAdapter, SimulatedBarrier
from .clock import ClockModel, ClockState
from .config import EdgeConfig
from .decision import (
    Credential,
    Decision,
    DecisionRequest,
    GuestPass,
    InvalidCredential,
    LedgerView,
    OperatingMode,
    Outcome,
    ResidentCredential,
    StandingVisitor,
    UnknownCredential,
    decide,
)
from .errors import (
    ConflictError,
    InvalidRequest,
    NotAuthorisedError,
    PolicyRejected,
    TombstonesRequired,
)
from .outbox import Outbox
from .policy import PolicyBundle, verify_snapshot
from .qr import parse_qr
from .store import EdgeStore, iso
from .tokens import Role, TokenClaims, mint, parse

GUARD_RESOLUTIONS: Final = ("admit", "hold", "leave_at_gate", "lobby_only", "intercom", "deny")
DEFAULT_APPROVAL_EXPIRY_S: Final = 90  # PRD 9.2 / D-14
MIN_REASON_LEN: Final = 3
MAX_REASON_LEN: Final = 200
KEEP_SNAPSHOTS: Final = 3


@dataclass(frozen=True)
class Actor:
    """An authenticated terminal call."""

    device_id: uuid.UUID
    role: Role
    token_id: uuid.UUID | None = None

    @property
    def label(self) -> str:
        return f"{self.role}:{self.device_id}"


@dataclass
class _EvalRecord:
    decision: Decision
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    credential_kind: str
    invitation_id: uuid.UUID | None
    reservation_id: str | None
    unit_id: uuid.UUID | None
    expires: datetime
    used: bool = False


def _clean_reason(reason: str) -> str:
    text = " ".join(str(reason).split())
    if len(text) < MIN_REASON_LEN:
        raise InvalidRequest("a reason is required", code="reason_required")
    return text[:MAX_REASON_LEN]


class Gateway:
    """Owns the store, the clock, the in-memory policy bundle and every operation terminals can ask for."""

    def __init__(
        self,
        config: EdgeConfig,
        *,
        clock: ClockModel | None = None,
        barrier: BarrierAdapter | None = None,
    ) -> None:
        self.config = config
        self.clock = clock or ClockModel()
        self.barrier: BarrierAdapter = barrier or SimulatedBarrier()
        self.store = EdgeStore(
            config.db_path,
            keyring=config.keyring,
            society_id=config.society_id,
            device_id=config.device_id,
            full_integrity_on_open=config.full_integrity_on_open,
        )
        self.signer = Signer(config.device_key_id, config.device_key)
        self.outbox = Outbox(self.store, self.signer, config.society_id, config.device_id)
        self._bundle: PolicyBundle | None = None
        self._evals: dict[str, _EvalRecord] = {}
        self._cond = threading.Condition()
        self._anomaly_reported: set[str] = set()
        self._last_cloud_ok_mono: float | None = None
        self._last_touch: dict[uuid.UUID, float] = {}
        self.sync_info: dict[str, Any] = {}

    # ---- lifecycle ---------------------------------------------------------------------------
    def start(self) -> Gateway:
        """Open the store, load the last good policy. Issues NO command to anything (HW-03)."""
        self.store.open()
        hw = self.store.get_meta("high_water")
        if hw:
            self.clock.high_water = parse_iso_utc(hw)
        self._load_policy()
        clock = self.clock.assess()
        with self.store.transaction():
            self.store.audit(
                "gateway",
                "gateway_started",
                None,
                {
                    "policy_seq": None if self._bundle is None else self._bundle.seq,
                    "clock_trusted": clock.trusted,
                },
                clock.now,
            )
            self._persist_high_water(clock.now)
        return self

    def stop(self) -> None:
        self.store.close()

    def __enter__(self) -> Gateway:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def policy(self) -> PolicyBundle | None:
        return self._bundle

    # ---- clock helpers -----------------------------------------------------------------------
    def clock_state(self) -> ClockState:
        state = self.clock.assess()
        self._report_clock_anomalies(state)
        return state

    def note_trusted_time(self, utc: datetime, uncertainty_ms: int) -> None:
        self.clock.sync(utc, uncertainty_ms)
        self._anomaly_reported.clear()

    def _persist_high_water(self, now: datetime) -> None:
        self.store.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('high_water', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (iso(now),),
        )

    def _report_clock_anomalies(self, clock: ClockState) -> None:
        """AT-08: a backwards (or forwards) wall clock step is recorded once as an event and a review item."""
        for flag, active in (
            ("clock_jumped_backwards", clock.wall_jumped_backwards),
            ("clock_jumped_forwards", clock.wall_jumped_forwards),
        ):
            if not active or flag in self._anomaly_reported:
                continue
            self._anomaly_reported.add(flag)
            policy_seq = 0 if self._bundle is None else self._bundle.seq
            with self.store.transaction() as c:
                rid = str(uuid7())
                c.execute(
                    "INSERT INTO review_items (id, kind, entity_id, detail_enc, created_at) VALUES (?, ?, NULL, ?, ?)",
                    (
                        rid,
                        flag,
                        self.store.cipher.seal_json(
                            "review_items", "detail_enc", rid, {"flag": flag}
                        ),
                        iso(clock.now),
                    ),
                )
                self.outbox.append(
                    type="ClockAnomalyDetected",
                    entity_id=uuid.UUID(rid),
                    entity_version=1,
                    payload={"flag": flag, "automatic_guest_approval": "disabled"},
                    occurred_at=clock.now,
                    clock_uncertainty_ms=clock.uncertainty_ms,
                    policy_version=policy_seq,
                )
                self.store.audit("gateway", flag, rid, {}, clock.now)
                self._feed(c, "clock_anomaly", None, {"flag": flag}, clock.now)
            self._notify()

    # ---- policy ------------------------------------------------------------------------------
    def _load_policy(self) -> None:
        rows = self.store.all("SELECT seq, blob_enc FROM policy_snapshots ORDER BY seq DESC")
        known = {
            str(r["ref"]): int(r["version"])
            for r in self.store.all("SELECT ref, version FROM known_revocations")
        }
        confirmed = self.store.get_meta("policy_confirmed_at")
        for row in (
            rows
        ):  # newest verifiable snapshot wins; a corrupt/unverifiable one falls back to the previous
            try:
                raw = self.store.cipher.open_json(
                    "policy_snapshots", "blob_enc", row["seq"], row["blob_enc"]
                )
                snap = verify_snapshot(
                    raw,
                    issuer_keys=self.config.issuer_keys,
                    society_id=self.config.society_id,
                    now=None,
                    current_seq=0,
                )
            except Exception as exc:
                self.store.conn.execute(
                    "INSERT INTO audit_log (at, actor, action, object, detail) VALUES (?, 'gateway', 'policy_load_failed', ?, ?)",
                    (
                        iso(datetime.now(UTC)),
                        str(row["seq"]),
                        json.dumps({"error": type(exc).__name__}),
                    ),
                )
                continue
            self._bundle = PolicyBundle.build(
                snap, raw, known, parse_iso_utc(confirmed) if confirmed else None
            )
            return

    def apply_policy(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        """Verify and apply a signed snapshot atomically. Raises ``PolicyRejected``; the last good policy stays."""
        clock = self.clock.assess()
        current = int(self.store.get_meta("policy_seq", "0") or 0)
        try:
            snap = verify_snapshot(
                raw,
                issuer_keys=self.config.issuer_keys,
                society_id=self.config.society_id,
                now=clock.now,
                current_seq=current,
            )
        except PolicyRejected as exc:
            with self.store.transaction():
                self.store.audit(
                    "gateway",
                    "policy_rejected",
                    None,
                    {"code": exc.code, "applied_seq": current},
                    clock.now,
                )
            raise
        raw_dict = dict(raw)
        with self.store.transaction() as c:
            c.execute(
                "INSERT INTO policy_snapshots (seq, issued_at, valid_until, received_at, issuer_key_id, blob_enc)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    snap.seq,
                    iso(snap.issued_at),
                    iso(snap.valid_until),
                    iso(clock.now),
                    snap.issuer_key_id,
                    self.store.cipher.seal_json("policy_snapshots", "blob_enc", snap.seq, raw_dict),
                ),
            )
            self.store.crash_point("after_policy_insert")
            known = {
                str(r[0]): int(r[1])
                for r in c.execute("SELECT ref, version FROM known_revocations")
            }
            new_tombstones = 0
            for rev in snap.manifest.revocations:
                if rev.version > known.get(rev.ref, -1):
                    known[rev.ref] = rev.version
                    c.execute(
                        "INSERT INTO known_revocations (ref, version) VALUES (?, ?)"
                        " ON CONFLICT(ref) DO UPDATE SET version=excluded.version",
                        (rev.ref, rev.version),
                    )
                    c.execute(
                        "INSERT INTO revocation_log (policy_seq, ref, version) VALUES (?, ?, ?)",
                        (snap.seq, rev.ref, rev.version),
                    )
                    new_tombstones += 1
            c.execute(
                "DELETE FROM policy_snapshots WHERE seq NOT IN (SELECT seq FROM policy_snapshots ORDER BY seq DESC LIMIT ?)",
                (KEEP_SNAPSHOTS,),
            )
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('policy_seq', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(snap.seq),),
            )
            self.store.audit(
                "gateway",
                "policy_applied",
                str(snap.seq),
                {"issuer": snap.issuer_key_id, "tombstones": new_tombstones},
                clock.now,
            )
            self._feed(c, "policy_applied", None, {"seq": snap.seq}, clock.now)
            self._persist_high_water(clock.now)
        confirmed = self.store.get_meta("policy_confirmed_at")
        self._bundle = PolicyBundle.build(
            snap, raw_dict, known, parse_iso_utc(confirmed) if confirmed else None
        )
        self._notify()
        return {"applied_seq": snap.seq, "tombstones": new_tombstones}

    def confirm_policy_current(self) -> None:
        """Authenticated cloud contact (200 applied / 204 up to date) refreshes policy age. Only a trusted,
        un-jumped clock may do this: a wrong clock must not be able to make a stale policy look fresh."""
        clock = self.clock.assess()
        self._last_cloud_ok_mono = self.clock.mono()
        if (
            self._bundle is None
            or not clock.trusted
            or clock.wall_jumped_backwards
            or clock.wall_jumped_forwards
        ):
            return
        with self.store.transaction() as c:
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('policy_confirmed_at', ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (iso(clock.now),),
            )
        self._bundle = self._bundle.with_confirmation(clock.now)

    def note_cloud_contact(self) -> None:
        self._last_cloud_ok_mono = self.clock.mono()

    def policy_seq(self) -> int:
        return int(self.store.get_meta("policy_seq", "0") or 0)

    # ---- feed (LAN propagation) ----------------------------------------------------------------
    def _feed(
        self,
        conn: Any,
        kind: str,
        gate_id: uuid.UUID | str | None,
        body: dict[str, Any],
        at: datetime,
    ) -> int:
        cur = conn.execute(
            "INSERT INTO lan_feed (at, kind, gate_id, body) VALUES (?, ?, ?, ?)",
            (
                iso(at),
                kind,
                None if gate_id is None else str(gate_id),
                json.dumps(body, sort_keys=True, separators=(",", ":")),
            ),
        )
        return int(cur.lastrowid)

    def _notify(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def feed_after(self, after_id: int, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.store.all(
            "SELECT id, at, kind, gate_id, body FROM lan_feed WHERE id > ? ORDER BY id LIMIT ?",
            (after_id, limit),
        )
        return [
            {
                "id": int(r["id"]),
                "at": r["at"],
                "kind": r["kind"],
                "gate_id": r["gate_id"],
                "body": json.loads(r["body"]),
            }
            for r in rows
        ]

    def wait_feed(self, after_id: int, timeout_s: float, limit: int = 100) -> list[dict[str, Any]]:
        """Long poll: return as soon as something newer than ``after_id`` exists, or [] at the timeout."""
        deadline = time.monotonic() + timeout_s
        while True:
            items = self.feed_after(after_id, limit)
            if items:
                return items
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []
            with self._cond:
                self._cond.wait(min(remaining, 0.25))

    # ---- identity of callers ---------------------------------------------------------------------
    def issue_terminal_token(
        self, device_id: uuid.UUID, role: Role, *, valid_for: timedelta = timedelta(days=30)
    ) -> str:
        """Commissioning: a signed token bound to one device and role."""
        clock = self.clock.assess()
        jti = uuid7()
        expires = clock.now + valid_for
        with self.store.transaction() as c:
            c.execute(
                "INSERT INTO terminal_tokens (jti, device_id, role, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (str(jti), str(device_id), role, iso(clock.now), iso(expires)),
            )
            self.store.audit(
                "gateway",
                "terminal_token_issued",
                str(device_id),
                {"role": role, "jti": str(jti)},
                clock.now,
            )
        return mint(
            self.config.token_key,
            society_id=self.config.society_id,
            device_id=device_id,
            role=role,
            jti=jti,
            issued_at=clock.now,
            expires_at=expires,
        )

    def revoke_terminal_token(self, jti: uuid.UUID) -> None:
        clock = self.clock.assess()
        with self.store.transaction() as c:
            c.execute(
                "UPDATE terminal_tokens SET revoked_at=? WHERE jti=? AND revoked_at IS NULL",
                (iso(clock.now), str(jti)),
            )
            self.store.audit("gateway", "terminal_token_revoked", str(jti), {}, clock.now)

    def authenticate(self, token: str) -> Actor | None:
        claims: TokenClaims | None = parse(token, self.config.token_key)
        if claims is None or claims.society_id != self.config.society_id:
            return None
        clock = self.clock.assess()
        if clock.now >= claims.expires_at:
            return None
        row = self.store.one(
            "SELECT revoked_at FROM terminal_tokens WHERE jti=? AND device_id=?",
            (str(claims.jti), str(claims.device_id)),
        )
        if row is None or row["revoked_at"] is not None:
            return None
        bundle = self._bundle
        if bundle is not None:
            for dev in bundle.snapshot.manifest.devices:
                if dev.id == claims.device_id and dev.status != "active":
                    return None  # the cloud has retired or blocked this device
        self._touch_terminal(claims.device_id, clock.now)
        return Actor(claims.device_id, claims.role, claims.jti)

    def _touch_terminal(self, device_id: uuid.UUID, now: datetime) -> None:
        mono = self.clock.mono()
        if mono - self._last_touch.get(device_id, -1e9) < 30:
            return
        self._last_touch[device_id] = mono
        with self.store.transaction() as c:
            c.execute(
                "INSERT INTO terminal_state (device_id, last_seen) VALUES (?, ?)"
                " ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen",
                (str(device_id), iso(now)),
            )

    # ---- credential parsing ---------------------------------------------------------------------
    def _parse_credential(self, raw: Mapping[str, Any]) -> tuple[Credential, str, uuid.UUID | None]:
        """(credential, credential_kind for the event schema, unit id if any)."""
        kind = raw.get("kind")
        try:
            if kind == "resident":
                return (
                    ResidentCredential(
                        str(raw["credential_ref"]), int(raw.get("revocation_version", 0))
                    ),
                    "resident_app",
                    None,
                )
            if kind == "qr":
                parsed = parse_qr(str(raw["text"]), self.config.pass_keys, self.config.society_id)
                if parsed is None:
                    return InvalidCredential("qr_unreadable_or_wrong_society"), "qr", None
                return parsed[0], "qr", None
            if kind == "guest_pass":
                return (
                    GuestPass(uuid.UUID(str(raw["invitation_id"])), str(raw["nonce"])),
                    "qr",
                    None,
                )
            if kind == "standing":
                unit = uuid.UUID(str(raw["unit_id"]))
                cat, vk = raw.get("category"), raw.get("visit_kind")
                if cat is None and vk is None:
                    raise KeyError("category or visit_kind")
                return (
                    StandingVisitor(
                        unit, None if cat is None else str(cat), None if vk is None else str(vk)
                    ),
                    "none",
                    unit,
                )
            if kind in ("none", None):
                return UnknownCredential(), "none", None
        except (KeyError, ValueError, TypeError):
            return InvalidCredential("malformed_credential"), "none", None
        return InvalidCredential("unknown_credential_kind"), "none", None

    # ---- ledger ------------------------------------------------------------------------------------
    def _ledger_view(
        self,
        conn: Any,
        invitation_id: uuid.UUID,
        gate_id: uuid.UUID,
        device_id: uuid.UUID,
        now: datetime,
    ) -> LedgerView:
        conn.execute(
            "UPDATE pass_uses SET state='released' WHERE state='held' AND invitation_id=? AND expires_at <= ?",
            (str(invitation_id), iso(now)),
        )
        used = at_gate = 0
        own_hold = other_hold = False
        for r in conn.execute(
            "SELECT state, gate_id, device_id FROM pass_uses WHERE invitation_id=? AND state IN ('held', 'consumed')",
            (str(invitation_id),),
        ):
            if r["state"] == "held" and r["device_id"] == str(device_id):
                own_hold = True
                continue
            if r["state"] == "held":
                other_hold = True
            used += 1
            if r["gate_id"] == str(gate_id):
                at_gate += 1
        esc = conn.execute(
            "SELECT allocated FROM quota_escrow WHERE invitation_id=? AND gate_id=?",
            (str(invitation_id), str(gate_id)),
        ).fetchone()
        return LedgerView(used, own_hold, other_hold, at_gate, None if esc is None else int(esc[0]))

    # ---- evaluation ---------------------------------------------------------------------------------
    def evaluate(
        self,
        actor: Actor,
        *,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID,
        credential: Mapping[str, Any],
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Decide locally. An allow on a pass reserves a use; nothing here is a command or an observed entry."""
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        clock = self.clock_state()
        cred, cred_kind, unit_id = self._parse_credential(credential)
        bundle = self._bundle
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            ledger = LedgerView()
            if isinstance(cred, GuestPass):
                ledger = self._ledger_view(
                    c, cred.invitation_id, gate_id, actor.device_id, clock.now
                )
            decision = decide(
                bundle, DecisionRequest(cred, gate_id, lane_id, OperatingMode.NORMAL, ledger), clock
            )
            reservation_id: str | None = None
            invitation_id = cred.invitation_id if isinstance(cred, GuestPass) else None
            if decision.consumes_pass and invitation_id is not None:
                reservation_id = self._reserve(
                    c, invitation_id, gate_id, actor.device_id, ledger, clock.now
                )
            evaluation_id = uuid7()
            c.execute(
                "INSERT INTO decision_log (at, device_id, gate_id, lane_id, credential_kind, outcome, reason_code,"
                " policy_seq, clock_uncertainty_ms, review, evidence_enc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    iso(clock.now),
                    str(actor.device_id),
                    str(gate_id),
                    str(lane_id),
                    cred_kind,
                    decision.outcome.value,
                    decision.reason_code,
                    None if bundle is None else bundle.seq,
                    clock.uncertainty_ms,
                    int(decision.review_required),
                    self.store.cipher.seal_json(
                        "decision_log", "evidence_enc", str(evaluation_id), decision.evidence
                    ),
                ),
            )
            pending_id: str | None = None
            if decision.outcome in (Outcome.NEEDS_GUARD, Outcome.NEEDS_SUPERVISOR):
                pending_id = self._create_pending(
                    c,
                    decision,
                    gate_id,
                    lane_id,
                    cred_kind,
                    invitation_id,
                    unit_id,
                    clock.now,
                    bundle.limits.approval_expiry_s if bundle else DEFAULT_APPROVAL_EXPIRY_S,
                )
            self._feed(
                c,
                "decision",
                gate_id,
                {
                    "outcome": decision.outcome.value,
                    "reason": decision.reason_code,
                    "pending_id": pending_id,
                },
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {
                "evaluation_id": str(evaluation_id),
                "decision": decision.to_json(),
                "pending_id": pending_id,
                "reservation_id": reservation_id,
                "policy_seq": None if bundle is None else bundle.seq,
                "decision_source": "cached_policy",
                "entry_observed": False,  # INV-07: a decision is not an entry
            }
            self._remember(c, client_action_id, actor, result, clock.now)
        self._evals[str(evaluation_id)] = _EvalRecord(
            decision,
            gate_id,
            lane_id,
            cred_kind,
            invitation_id,
            reservation_id,
            unit_id,
            clock.now + timedelta(seconds=self.config.hold_ttl_s),
        )
        if len(self._evals) > 5000:
            self._prune_evals(clock.now)
        self._notify()
        return result

    def evaluate_decision_only(
        self, *, gate_id: uuid.UUID, lane_id: uuid.UUID, credential: Mapping[str, Any]
    ) -> Decision:
        """Pure decision with no ledger or log writes (used by benchmarks to separate engine time from I/O time)."""
        clock = self.clock.assess()
        cred, _kind, _unit = self._parse_credential(credential)
        return decide(self._bundle, DecisionRequest(cred, gate_id, lane_id), clock)

    def _prune_evals(self, now: datetime) -> None:
        for key in [k for k, v in self._evals.items() if v.expires < now or v.used]:
            del self._evals[key]

    def _reserve(
        self,
        conn: Any,
        invitation_id: uuid.UUID,
        gate_id: uuid.UUID,
        device_id: uuid.UUID,
        ledger: LedgerView,
        now: datetime,
    ) -> str:
        if ledger.held_by_requester:
            row = conn.execute(
                "SELECT id FROM pass_uses WHERE invitation_id=? AND device_id=? AND state='held'",
                (str(invitation_id), str(device_id)),
            ).fetchone()
            if row is not None:
                return str(row[0])
        rid = str(uuid7())
        conn.execute(
            "INSERT INTO pass_uses (id, invitation_id, gate_id, device_id, state, created_at, expires_at)"
            " VALUES (?, ?, ?, ?, 'held', ?, ?)",
            (
                rid,
                str(invitation_id),
                str(gate_id),
                str(device_id),
                iso(now),
                iso(now + timedelta(seconds=self.config.hold_ttl_s)),
            ),
        )
        return rid

    def _create_pending(
        self,
        conn: Any,
        decision: Decision,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID,
        cred_kind: str,
        invitation_id: uuid.UUID | None,
        unit_id: uuid.UUID | None,
        now: datetime,
        expiry_s: int,
    ) -> str:
        pid = str(uuid7())
        role = "supervisor" if decision.outcome is Outcome.NEEDS_SUPERVISOR else "guard"
        detail = {
            "credential_kind": cred_kind,
            "invitation_id": None if invitation_id is None else str(invitation_id),
            "unit_id": None if unit_id is None else str(unit_id),
            "options": list(decision.fallback_options),
        }
        conn.execute(
            "INSERT INTO pending_items (id, kind, state, gate_id, lane_id, reason_code, requires_role, detail_enc,"
            " created_at, expires_at) VALUES (?, 'entry_decision', 'pending', ?, ?, ?, ?, ?, ?, ?)",
            (
                pid,
                str(gate_id),
                str(lane_id),
                decision.reason_code,
                role,
                self.store.cipher.seal_json("pending_items", "detail_enc", pid, detail),
                iso(now),
                iso(now + timedelta(seconds=expiry_s)),
            ),
        )
        return pid

    # ---- idempotency (terminal retries over the LAN) -------------------------------------------------
    def _replayed(self, client_action_id: uuid.UUID | None, actor: Actor) -> dict[str, Any] | None:
        if client_action_id is None:
            return None
        row = self.store.one(
            "SELECT device_id, result_json FROM client_actions WHERE client_action_id=?",
            (str(client_action_id),),
        )
        if row is None:
            return None
        if row["device_id"] != str(actor.device_id):
            raise ConflictError(
                "client_action_id belongs to another device", code="duplicate_payload_mismatch"
            )
        out: dict[str, Any] = json.loads(row["result_json"])
        out["replayed"] = True
        return out

    def _remember(
        self,
        conn: Any,
        client_action_id: uuid.UUID | None,
        actor: Actor,
        result: dict[str, Any],
        now: datetime,
    ) -> None:
        if client_action_id is not None:
            conn.execute(
                "INSERT INTO client_actions (client_action_id, device_id, result_json, created_at) VALUES (?, ?, ?, ?)",
                (
                    str(client_action_id),
                    str(actor.device_id),
                    json.dumps(result, sort_keys=True),
                    iso(now),
                ),
            )

    # ---- observations ---------------------------------------------------------------------------------
    def record_entry(
        self,
        actor: Actor,
        *,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID,
        evaluation_id: str | None = None,
        pending_id: str | None = None,
        alias: str | None = None,
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Record a PHYSICALLY OBSERVED entry (EntryObserved). It needs an authorising basis: an allow
        evaluation (cached policy) or a resolved guard/supervisor admission. Event, movement projection, ledger,
        feed and audit commit together; only then does the caller get a success."""
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        if (evaluation_id is None) == (pending_id is None):
            raise InvalidRequest(
                "give exactly one of evaluation_id or pending_id", code="authority_required"
            )
        clock = self.clock_state()
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        movement_id = uuid7()
        invitation_id: uuid.UUID | None = None
        cred_kind = "none"
        reservation_id: str | None = None
        reason_code = ""
        source = "cached_policy"
        review = False
        override_id: str | None = None
        ev_rec: _EvalRecord | None = None
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            if evaluation_id is not None:
                ev_rec = self._evals.get(evaluation_id)
                if ev_rec is None or ev_rec.used or ev_rec.expires < clock.now:
                    raise ConflictError(
                        "evaluation unknown, used or expired: evaluate again",
                        code="no_authorising_decision",
                    )
                if ev_rec.decision.outcome is not Outcome.ALLOW:
                    raise ConflictError(
                        "the evaluation did not allow entry", code="no_authorising_decision"
                    )
                if (ev_rec.gate_id, ev_rec.lane_id) != (gate_id, lane_id):
                    raise ConflictError(
                        "evaluation belongs to another gate or lane", code="no_authorising_decision"
                    )
                invitation_id, cred_kind, reservation_id = (
                    ev_rec.invitation_id,
                    ev_rec.credential_kind,
                    ev_rec.reservation_id,
                )
                reason_code, review = ev_rec.decision.reason_code, ev_rec.decision.review_required
            else:
                row = c.execute("SELECT * FROM pending_items WHERE id=?", (pending_id,)).fetchone()
                if row is None or not str(row["resolution"] or "").startswith("admit_"):
                    raise ConflictError(
                        "no admission recorded for this item", code="no_authorising_decision"
                    )
                if str(row["gate_id"]) != str(gate_id):
                    raise ConflictError(
                        "admission belongs to another gate", code="no_authorising_decision"
                    )
                resolved_at = parse_iso_utc(row["resolved_at"]) if row["resolved_at"] else None
                if resolved_at is None or clock.now - resolved_at > timedelta(
                    seconds=self.config.admission_valid_s
                ):
                    raise ConflictError(
                        "the admission expired: decide again", code="admission_expired"
                    )
                detail = self.store.cipher.open_json(
                    "pending_items", "detail_enc", pending_id, row["detail_enc"]
                )
                cred_kind = "guard_assisted"
                reason_code = row["reason_code"]
                source = (
                    "supervisor_override"
                    if row["resolution"] in ("admit_supervisor", "admit_override")
                    else "guard_assisted"
                )
                override_id = (
                    self._active_override_id(c, gate_id, clock.now)
                    if row["resolution"] == "admit_override"
                    else None
                )
                if detail.get("invitation_id"):
                    invitation_id = uuid.UUID(detail["invitation_id"])
                review = True
                c.execute(
                    "UPDATE pending_items SET resolution = 'entered:' || resolution WHERE id=?",
                    (pending_id,),
                )
            alias_clean = None if alias is None else alias.strip()[:80] or None
            self._insert_entry(
                c,
                movement_id,
                gate_id,
                lane_id,
                cred_kind,
                source,
                invitation_id,
                alias_clean,
                clock,
                review,
            )
            conflict = self._consume_pass(
                c, invitation_id, reservation_id, gate_id, actor.device_id, movement_id, clock.now
            )
            if conflict:
                self._review(
                    c,
                    "single_use_conflict",
                    movement_id,
                    {"invitation_id": str(invitation_id)},
                    clock.now,
                )
            self.store.crash_point("after_projection")
            payload: dict[str, Any] = {
                "gate_id": str(gate_id),
                "lane_id": str(lane_id),
                "credential_kind": cred_kind,
                "decision_source": source,
                "reason_code": reason_code,
            }
            if invitation_id is not None:
                payload["invitation_id"] = str(invitation_id)
            if override_id is not None:
                payload["override_id"] = override_id
            if review:
                payload["review"] = True
            if conflict:
                payload["conflict"] = "single_use_pass_reused"
            event = self.outbox.append(
                type="EntryObserved",
                entity_id=movement_id,
                entity_version=1,
                payload=payload,
                occurred_at=clock.now,
                clock_uncertainty_ms=clock.uncertainty_ms,
                policy_version=policy_seq,
            )
            self.store.crash_point("after_event")
            self.store.audit(
                actor.label,
                "entry_observed",
                str(movement_id),
                {"source": source, "seq": event.seq},
                clock.now,
            )
            self._feed(
                c,
                "entry_observed",
                gate_id,
                {"movement_id": str(movement_id), "seq": event.seq},
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {
                "movement_id": str(movement_id),
                "event_id": str(event.event_id),
                "seq": event.seq,
                "state": "inside",
                "decision_source": source,
                "conflict": conflict,
                "entry_observed": True,
            }
            self._remember(c, client_action_id, actor, result, clock.now)
            if ev_rec is not None:
                ev_rec.used = True
        # committed: only now may the terminal show success
        self._notify()
        return result

    def _insert_entry(
        self,
        c: Any,
        movement_id: uuid.UUID,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID | None,
        cred_kind: str,
        source: str,
        invitation_id: uuid.UUID | None,
        alias: str | None,
        clock: ClockState,
        review: bool,
    ) -> None:
        mid = str(movement_id)
        c.execute(
            "INSERT INTO movements (entity_id, state, gate_id, lane_id, credential_kind, decision_source, invitation_id,"
            " alias_enc, entered_at, entered_uncertainty_ms, version, review) VALUES (?, 'inside', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (
                mid,
                str(gate_id),
                None if lane_id is None else str(lane_id),
                cred_kind,
                source,
                None if invitation_id is None else str(invitation_id),
                None
                if alias is None
                else self.store.cipher.seal("movements", "alias_enc", mid, alias),
                iso(clock.now),
                clock.uncertainty_ms,
                int(review),
            ),
        )

    def _consume_pass(
        self,
        c: Any,
        invitation_id: uuid.UUID | None,
        reservation_id: str | None,
        gate_id: uuid.UUID,
        device_id: uuid.UUID,
        movement_id: uuid.UUID,
        now: datetime,
    ) -> bool:
        """Turn a reservation (or a guard-confirmed entry) into a consumed use. True if it exceeds the pass."""
        if invitation_id is None:
            return False
        if reservation_id is not None:
            cur = c.execute(
                "UPDATE pass_uses SET state='consumed', movement_id=? WHERE id=? AND state IN ('held', 'released')",
                (str(movement_id), reservation_id),
            )
            if cur.rowcount == 1:
                return False
        bundle = self._bundle
        inv = None if bundle is None else bundle.invitations.get(invitation_id)
        used = c.execute(
            "SELECT COUNT(*) FROM pass_uses WHERE invitation_id=? AND state IN ('held', 'consumed')",
            (str(invitation_id),),
        ).fetchone()[0]
        c.execute(
            "INSERT INTO pass_uses (id, invitation_id, gate_id, device_id, state, created_at, expires_at, movement_id)"
            " VALUES (?, ?, ?, ?, 'consumed', ?, ?, ?)",
            (
                str(uuid7()),
                str(invitation_id),
                str(gate_id),
                str(device_id),
                iso(now),
                iso(now),
                str(movement_id),
            ),
        )
        max_uses = 1 if inv is None else inv.max_uses
        cloud_used = 0 if inv is None else inv.max_uses - inv.uses_remaining
        return bool(max(used, cloud_used) >= max_uses)

    def _review(
        self,
        c: Any,
        kind: str,
        entity_id: uuid.UUID | str | None,
        detail: dict[str, Any],
        now: datetime,
    ) -> str:
        rid = str(uuid7())
        c.execute(
            "INSERT INTO review_items (id, kind, entity_id, detail_enc, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                rid,
                kind,
                None if entity_id is None else str(entity_id),
                self.store.cipher.seal_json("review_items", "detail_enc", rid, detail),
                iso(now),
            ),
        )
        return rid

    def record_exit(
        self,
        actor: Actor,
        *,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID,
        movement_id: uuid.UUID | None = None,
        invitation_id: uuid.UUID | None = None,
        basis: Literal["scanned", "observed"] = "observed",
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Record an observed exit (ExitObserved) at the REAL observation time (GATE-05: never an invented exit
        time). An exit with no matching inside record is kept as an unmatched observation and flagged."""
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        clock = self.clock_state()
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            row = None
            if movement_id is not None:
                row = c.execute(
                    "SELECT * FROM movements WHERE entity_id=?", (str(movement_id),)
                ).fetchone()
            elif invitation_id is not None:
                row = c.execute(
                    "SELECT * FROM movements WHERE invitation_id=? AND state='inside' ORDER BY entered_at DESC LIMIT 1",
                    (str(invitation_id),),
                ).fetchone()
            flagged: str | None = None
            if row is None:
                entity = uuid7()
                version = 1
                flagged = "exit_without_entry"
                self._insert_entry(
                    c,
                    entity,
                    gate_id,
                    lane_id,
                    "none",
                    "guard_assisted",
                    invitation_id,
                    None,
                    clock,
                    True,
                )
                c.execute(
                    "UPDATE movements SET state='exited', entered_at=NULL, entered_uncertainty_ms=NULL, exited_at=?,"
                    " exit_basis='unmatched', version=1 WHERE entity_id=?",
                    (iso(clock.now), str(entity)),
                )
            elif row["state"] == "exited":
                entity = uuid.UUID(row["entity_id"])
                version = int(row["version"]) + 1
                flagged = "duplicate_exit"
                c.execute(
                    "UPDATE movements SET version=?, review=1 WHERE entity_id=?",
                    (version, row["entity_id"]),
                )
            else:
                entity = uuid.UUID(row["entity_id"])
                version = int(row["version"]) + 1
                c.execute(
                    "UPDATE movements SET state='exited', exited_at=?, exit_basis=?, version=? WHERE entity_id=?",
                    (iso(clock.now), basis, version, row["entity_id"]),
                )
            if flagged:
                self._review(c, flagged, entity, {}, clock.now)
            payload: dict[str, Any] = {
                "gate_id": str(gate_id),
                "lane_id": str(lane_id),
                "credential_kind": "qr" if basis == "scanned" else "guard_assisted",
                "decision_source": "cached_policy" if basis == "scanned" else "guard_assisted",
                "exit_basis": basis,  # cloud vocabulary: scanned | observed | reconciled_unknown
            }
            if flagged:
                payload["flag"] = flagged
            event = self.outbox.append(
                type="ExitObserved",
                entity_id=entity,
                entity_version=version,
                payload=payload,
                occurred_at=clock.now,
                clock_uncertainty_ms=clock.uncertainty_ms,
                policy_version=policy_seq,
            )
            self.store.crash_point("after_event")
            self.store.audit(
                actor.label,
                "exit_observed",
                str(entity),
                {"seq": event.seq, "flag": flagged},
                clock.now,
            )
            self._feed(
                c,
                "exit_observed",
                gate_id,
                {"movement_id": str(entity), "seq": event.seq},
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {
                "movement_id": str(entity),
                "event_id": str(event.event_id),
                "seq": event.seq,
                "state": "exited",
                "flag": flagged,
                "exit_basis": payload["exit_basis"],
            }
            self._remember(c, client_action_id, actor, result, clock.now)
        self._notify()
        return result

    # ---- guard / supervisor flows -----------------------------------------------------------------------
    def _expire_pending(self, c: Any, now: datetime) -> int:
        """Expiry never admits anyone (INV-03): an expired item is closed and the guard must decide afresh."""
        cur = c.execute(
            "UPDATE pending_items SET state='expired', resolved_at=?, resolution='expired' WHERE state='pending' AND expires_at <= ?",
            (iso(now), iso(now)),
        )
        return int(cur.rowcount)

    def list_pending(self, gate_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
        clock = self.clock.assess()
        with self.store.transaction() as c:
            self._expire_pending(c, clock.now)
            rows = c.execute(
                "SELECT id, kind, gate_id, lane_id, reason_code, requires_role, created_at, expires_at FROM pending_items"
                " WHERE state='pending' ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows if gate_id is None or r["gate_id"] == str(gate_id)]

    def start_fresh_approval(
        self,
        actor: Actor,
        *,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID,
        unit_id: uuid.UUID | None,
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """A fresh remote approval cannot be obtained from this gateway: the cloud/household path is not
        reachable from here, so the response is the EXPLICIT FALLBACK (intercom, guard-assisted options). It
        never allows, and the pending item expires at the approval expiry without admitting anyone."""
        clock = self.clock_state()
        bundle = self._bundle
        expiry = bundle.limits.approval_expiry_s if bundle else DEFAULT_APPROVAL_EXPIRY_S
        decision = Decision(
            Outcome.NEEDS_GUARD,
            "remote_approval_unavailable_offline",
            {"wan": self.operating_mode().value, "clock_uncertainty_ms": clock.uncertainty_ms},
            fallback_options=("intercom", "hold", "leave_at_gate", "lobby_only", "deny"),
        )
        with self.store.transaction() as c:
            pid = self._create_pending(
                c, decision, gate_id, lane_id, "none", None, unit_id, clock.now, expiry
            )
            self._feed(c, "pending_created", gate_id, {"pending_id": pid}, clock.now)
            self._persist_high_water(clock.now)
        self._notify()
        return {
            "status": "fallback_required",
            "pending_id": pid,
            "fallback_options": list(decision.fallback_options),
            "auto_allow_on_timeout": False,
            "expires_in_s": expiry,
        }

    def guard_decision(
        self,
        actor: Actor,
        *,
        pending_id: str,
        resolution: str,
        note: str | None = None,
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Guard-assisted decision on a pending item. ``admit`` records PERMISSION to enter, not an entry.
        Items that need a supervisor are admitted only by a supervisor or under an active override."""
        if resolution not in GUARD_RESOLUTIONS:
            raise InvalidRequest("unknown resolution", code="invalid_resolution")
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        clock = self.clock_state()
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            self._expire_pending(c, clock.now)
            row = c.execute("SELECT * FROM pending_items WHERE id=?", (pending_id,)).fetchone()
            if row is None:
                raise InvalidRequest("unknown pending item", code="not_found")
            if row["state"] == "expired":
                raise ConflictError(
                    "the request expired; nothing was allowed", code="request_expired"
                )
            if row["state"] != "pending":
                raise ConflictError("already decided", code="already_decided")
            gate_id = uuid.UUID(row["gate_id"])
            via = "guard"
            if resolution == "admit" and row["requires_role"] == "supervisor":
                if actor.role in ("supervisor", "admin"):
                    via = "supervisor"
                elif self._active_override_id(c, gate_id, clock.now) is not None:
                    via = "override"
                else:
                    raise NotAuthorisedError(
                        "supervisor assistance is required for this entry",
                        code="supervisor_required",
                    )
            stored = f"admit_{via}" if resolution == "admit" else resolution
            c.execute(
                "UPDATE pending_items SET state='resolved', resolved_at=?, resolution=? WHERE id=?",
                (iso(clock.now), stored, pending_id),
            )
            payload: dict[str, Any] = {
                "gate_id": str(gate_id),
                "resolution": resolution,
                "reason_code": row["reason_code"],
                "decided_via": via if resolution == "admit" else actor.role,
                "entry_observed": False,
            }
            if note:
                payload["note"] = " ".join(note.split())[:MAX_REASON_LEN]
            event = self.outbox.append(
                type="GuardDecisionRecorded",
                entity_id=uuid.UUID(pending_id),
                entity_version=1,
                payload=payload,
                occurred_at=clock.now,
                clock_uncertainty_ms=clock.uncertainty_ms,
                policy_version=policy_seq,
            )
            self.store.audit(
                actor.label,
                "guard_decision",
                pending_id,
                {"resolution": resolution, "via": via},
                clock.now,
            )
            self._feed(
                c,
                "pending_resolved",
                gate_id,
                {"pending_id": pending_id, "resolution": resolution},
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {
                "pending_id": pending_id,
                "resolution": resolution,
                "decided_via": via,
                "seq": event.seq,
                "entry_observed": False,
            }
            self._remember(c, client_action_id, actor, result, clock.now)
        self._notify()
        return result

    def _active_override_id(self, c: Any, gate_id: uuid.UUID, now: datetime) -> str | None:
        row = c.execute(
            "SELECT id FROM overrides WHERE revoked_at IS NULL AND expires_at > ? AND (gate_id IS NULL OR gate_id = ?)"
            " ORDER BY expires_at DESC LIMIT 1",
            (iso(now), str(gate_id)),
        ).fetchone()
        return None if row is None else str(row[0])

    def record_override(
        self,
        actor: Actor,
        *,
        supervisor_ref: str,
        reason: str,
        shift_end: datetime,
        gate_id: uuid.UUID | None = None,
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Supervisor override with a reason, expiring at shift end or earlier (Appendix C)."""
        if actor.role not in ("supervisor", "admin"):
            raise NotAuthorisedError(
                "only a supervisor may record an override", code="supervisor_required"
            )
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        text = _clean_reason(reason)
        clock = self.clock_state()
        if shift_end <= clock.now:
            raise InvalidRequest("shift end is in the past", code="invalid_shift_end")
        expires = min(shift_end, clock.now + timedelta(seconds=self.config.max_override_s))
        oid = uuid7()
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            c.execute(
                "INSERT INTO overrides (id, device_id, supervisor_ref, gate_id, reason_enc, granted_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(oid),
                    str(actor.device_id),
                    supervisor_ref[:100],
                    None if gate_id is None else str(gate_id),
                    self.store.cipher.seal("overrides", "reason_enc", str(oid), text),
                    iso(clock.now),
                    iso(expires),
                ),
            )
            event = self.outbox.append(
                type="SupervisorOverrideRecorded",
                entity_id=oid,
                entity_version=1,
                payload={
                    "gate_id": None if gate_id is None else str(gate_id),
                    "reason": text,
                    "expires_at": iso(expires),
                    "supervisor_ref": supervisor_ref[:100],
                },
                occurred_at=clock.now,
                clock_uncertainty_ms=clock.uncertainty_ms,
                policy_version=policy_seq,
            )
            self.store.audit(
                actor.label, "override_recorded", str(oid), {"expires_at": iso(expires)}, clock.now
            )
            self._feed(
                c,
                "override_recorded",
                gate_id,
                {"override_id": str(oid), "expires_at": iso(expires)},
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {"override_id": str(oid), "expires_at": iso(expires), "seq": event.seq}
            self._remember(c, client_action_id, actor, result, clock.now)
        self._notify()
        return result

    def emergency_entry(
        self,
        actor: Actor,
        *,
        gate_id: uuid.UUID,
        lane_id: uuid.UUID | None,
        authority: str,
        reason: str,
        client_action_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """GATE-07: emergency/manual entry needs a DEFINED local authority and a reason, and is audited. It works
        with no cloud, no policy and no connectivity; it is an observed entry flagged for review, never invisible."""
        if authority not in self.config.local_authorities:
            raise NotAuthorisedError("not a defined local authority", code="authority_not_defined")
        replay = self._replayed(client_action_id, actor)
        if replay is not None:
            return replay
        text = _clean_reason(reason)
        clock = self.clock_state()
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        movement_id = uuid7()
        with self.store.transaction() as c:
            replay = self._replayed(client_action_id, actor)  # re-check under the writer lock
            if replay is not None:
                return replay
            self._insert_entry(
                c,
                movement_id,
                gate_id,
                lane_id,
                "none",
                "supervisor_override",
                None,
                None,
                clock,
                True,
            )
            event = self.outbox.append(
                type="EntryObserved",
                entity_id=movement_id,
                entity_version=1,
                payload={
                    "gate_id": str(gate_id),
                    "lane_id": None if lane_id is None else str(lane_id),
                    "credential_kind": "none",
                    "decision_source": "supervisor_override",
                    "emergency": True,
                    "authority": authority,
                    "reason": text,
                    "review": True,
                },
                occurred_at=clock.now,
                clock_uncertainty_ms=clock.uncertainty_ms,
                policy_version=policy_seq,
            )
            self._review(c, "emergency_entry", movement_id, {"authority": authority}, clock.now)
            self.store.audit(
                actor.label,
                "emergency_entry",
                str(movement_id),
                {"authority": authority, "seq": event.seq},
                clock.now,
            )
            self._feed(
                c,
                "entry_observed",
                gate_id,
                {"movement_id": str(movement_id), "seq": event.seq, "emergency": True},
                clock.now,
            )
            self._persist_high_water(clock.now)
            result = {
                "movement_id": str(movement_id),
                "seq": event.seq,
                "event_id": str(event.event_id),
                "state": "inside",
                "entry_observed": True,
            }
            self._remember(c, client_action_id, actor, result, clock.now)
        self._notify()
        return result

    # ---- reads for terminals -----------------------------------------------------------------------------
    def list_inside(self, gate_id: uuid.UUID | None = None) -> dict[str, Any]:
        """Who is inside, with a confidence indicator (GATE-05): ``observed`` entries are recent; ``stale`` ones
        are old enough that an exit was probably missed and needs reconciliation, never a guessed exit time."""
        clock = self.clock.assess()
        stale_before = clock.now - timedelta(seconds=self.config.inside_stale_after_s)
        rows = self.store.all("SELECT * FROM movements WHERE state='inside' ORDER BY entered_at")
        items = []
        for r in rows:
            entered = parse_iso_utc(r["entered_at"]) if r["entered_at"] else None
            items.append(
                {
                    "movement_id": r["entity_id"],
                    "gate_id": r["gate_id"],
                    "credential_kind": r["credential_kind"],
                    "decision_source": r["decision_source"],
                    "entered_at": r["entered_at"],
                    "confidence": "stale"
                    if entered is not None and entered < stale_before
                    else "observed",
                    "review": bool(r["review"]),
                }
            )
        if gate_id is not None:
            items = [i for i in items if i["gate_id"] == str(gate_id)]
        stale = sum(1 for i in items if i["confidence"] == "stale")
        return {
            "count": len(items),
            "stale_count": stale,
            "confidence": "observed" if stale == 0 else "stale",
            "items": items,
        }

    def operating_mode(self) -> OperatingMode:
        last = self._last_cloud_ok_mono
        if last is None or self.clock.mono() - last > self.config.wan_down_after_s:
            return OperatingMode.WAN_DOWN
        return OperatingMode.NORMAL

    def status(self) -> dict[str, Any]:
        """Truthful status for terminals (INV-07): what is cached, how old, what is degraded and why."""
        clock = self.clock.assess()
        bundle = self._bundle
        guest_block: str | None = None
        age: int | None = None
        stale_resident = False
        if bundle is not None:
            guest_block = clock.guest_block_reason(bundle.limits.clock_uncertainty_limit_ms)
            age = int(bundle.age(clock.now).total_seconds())
            stale_resident = age > bundle.limits.resident_offline_validity_s
        ob = self.outbox.stats()
        return {
            "mode": self.operating_mode().value,
            "simulation": self.config.simulation,
            "policy": None
            if bundle is None
            else {
                "seq": bundle.seq,
                "issued_at": iso(bundle.snapshot.issued_at),
                "valid_until": iso(bundle.valid_until),
                "age_s": age,
                "resident_offline_limit_s": bundle.limits.resident_offline_validity_s,
                "guest_offline_limit_s": bundle.limits.guest_offline_max_s,
                "resident_verification": "guard_assisted"
                if stale_resident or clock.now > bundle.valid_until
                else "automatic",
            },
            "clock": {
                "uncertainty_ms": clock.uncertainty_ms,
                "trusted": clock.trusted,
                "jumped_backwards": clock.wall_jumped_backwards,
                "jumped_forwards": clock.wall_jumped_forwards,
                "guest_automatic_approval": "disabled" if guest_block else "enabled",
                "guest_block_reason": guest_block,
            },
            "connectivity": {
                "wan": "down" if self.operating_mode() is OperatingMode.WAN_DOWN else "up",
                "gateway": "up",
                "last_cloud_contact_age_s": None
                if self._last_cloud_ok_mono is None
                else int(self.clock.mono() - self._last_cloud_ok_mono),
            },
            "outbox": ob,
            "sync": dict(self.sync_info),
            "essential_egress": "always_permitted",
            "pending_count": len(self.list_pending()),
            "inside_count": self.list_inside()["count"],
            "actuator": "none (simulation stub only)",
        }

    # ---- escrow, terminal cache, tombstones, reconciliation ---------------------------------------------
    def allocate_escrow(
        self, invitation_id: uuid.UUID, allocations: Mapping[uuid.UUID, int]
    ) -> dict[str, int]:
        """Optional per-gate pre-allocation of a multi-use pass (owner enables). Total may not exceed what is left."""
        bundle = self._bundle
        inv = None if bundle is None else bundle.invitations.get(invitation_id)
        if inv is None:
            raise InvalidRequest("unknown invitation", code="not_found")
        if any(n < 0 for n in allocations.values()) or any(
            g not in (bundle.gates if bundle else {}) for g in allocations
        ):
            raise InvalidRequest("bad allocation", code="invalid_allocation")
        clock = self.clock.assess()
        with self.store.transaction() as c:
            used = c.execute(
                "SELECT COUNT(*) FROM pass_uses WHERE invitation_id=? AND state IN ('held','consumed')",
                (str(invitation_id),),
            ).fetchone()[0]
            left = inv.max_uses - max(inv.max_uses - inv.uses_remaining, used)
            if sum(allocations.values()) > left:
                raise InvalidRequest("allocation exceeds remaining uses", code="invalid_allocation")
            c.execute("DELETE FROM quota_escrow WHERE invitation_id=?", (str(invitation_id),))
            for g, n in allocations.items():
                c.execute(
                    "INSERT INTO quota_escrow (invitation_id, gate_id, allocated) VALUES (?, ?, ?)",
                    (str(invitation_id), str(g), n),
                )
            self.store.audit(
                "gateway",
                "escrow_allocated",
                str(invitation_id),
                {str(g): n for g, n in allocations.items()},
                clock.now,
            )
        return {str(g): n for g, n in allocations.items()}

    def export_terminal_cache(self, gate_id: uuid.UUID) -> dict[str, Any]:
        """What a terminal keeps for restricted standalone mode: the SIGNED snapshot (the terminal verifies it
        itself) and this gate's escrow allocations. Nothing else (EDGE-06: signed cached entitlements only)."""
        bundle = self._bundle
        if bundle is None:
            raise InvalidRequest("no policy to cache", code="no_policy")
        rows = self.store.all(
            "SELECT invitation_id, allocated FROM quota_escrow WHERE gate_id=?", (str(gate_id),)
        )
        return {
            "gate_id": str(gate_id),
            "policy": dict(bundle.raw),
            "confirmed_at": None if bundle.confirmed_at is None else iso(bundle.confirmed_at),
            "escrow": {r["invitation_id"]: int(r["allocated"]) for r in rows},
        }

    def tombstones_since(self, seq: int) -> dict[str, Any]:
        rows = self.store.all(
            "SELECT policy_seq, ref, version FROM revocation_log WHERE policy_seq > ? ORDER BY id",
            (seq,),
        )
        return {
            "current_seq": self.policy_seq(),
            "tombstones": [{"ref": r["ref"], "version": int(r["version"])} for r in rows],
        }

    def ack_tombstones(self, actor: Actor, seq: int) -> dict[str, Any]:
        clock = self.clock.assess()
        with self.store.transaction() as c:
            c.execute(
                "INSERT INTO terminal_state (device_id, last_seen, acked_policy_seq) VALUES (?, ?, ?)"
                " ON CONFLICT(device_id) DO UPDATE SET acked_policy_seq = MAX(acked_policy_seq, excluded.acked_policy_seq),"
                " last_seen = excluded.last_seen",
                (str(actor.device_id), iso(clock.now), seq),
            )
        return {"acked_policy_seq": seq}

    def reconcile_standalone(
        self,
        actor: Actor,
        *,
        terminal_policy_seq: int,
        observations: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """A terminal that ran standalone uploads what it observed. EDGE-10: a stale terminal must first process
        tombstones (policy revocations newer than its cache) before cached personal records are accepted.
        Each observation keeps its own terminal sequence and REAL time; duplicates (device, tseq) are ignored;
        a single-use pass consumed twice keeps both observations and raises a review item (PRD 9.3)."""
        clock = self.clock_state()
        acked = self.store.one(
            "SELECT acked_policy_seq FROM terminal_state WHERE device_id=?", (str(actor.device_id),)
        )
        acked_seq = max(terminal_policy_seq, 0 if acked is None else int(acked[0]))
        pending_tombs = self.tombstones_since(acked_seq)["tombstones"]
        if pending_tombs:
            raise TombstonesRequired(f"{len(pending_tombs)} tombstones must be processed first")
        revoked = self._bundle.revocations if self._bundle else {}
        policy_seq = 0 if self._bundle is None else self._bundle.seq
        results: list[dict[str, Any]] = []
        with self.store.transaction() as c:
            for ob in observations:
                tseq = int(ob["tseq"])
                if c.execute(
                    "SELECT 1 FROM terminal_observations WHERE device_id=? AND tseq=?",
                    (str(actor.device_id), tseq),
                ).fetchone():
                    results.append({"tseq": tseq, "status": "duplicate"})
                    continue
                kind = str(ob["kind"])
                gate_id = uuid.UUID(str(ob["gate_id"]))
                lane_id = uuid.UUID(str(ob["lane_id"]))
                occurred = parse_iso_utc(str(ob["occurred_at"]))
                unc = int(ob.get("clock_uncertainty_ms", 0))
                inv = uuid.UUID(str(ob["invitation_id"])) if ob.get("invitation_id") else None
                alias = ob.get("alias")
                if inv is not None and str(inv) in revoked:
                    alias = None  # data minimisation: a tombstoned pass's cached personal record is not uploaded
                entity = uuid.UUID(str(ob["observation_id"]))
                conflict = False
                if kind == "entry":
                    fake = ClockState(occurred, unc, False)
                    self._insert_entry(
                        c,
                        entity,
                        gate_id,
                        lane_id,
                        str(ob.get("credential_kind", "qr")),
                        str(ob.get("decision_source", "cached_policy")),
                        inv,
                        alias,
                        fake,
                        True,
                    )
                    conflict = self._consume_pass(
                        c, inv, None, gate_id, actor.device_id, entity, clock.now
                    )
                    etype, version = "EntryObserved", 1
                elif kind == "exit":
                    row = c.execute(
                        "SELECT version FROM movements WHERE entity_id=?", (str(entity),)
                    ).fetchone()
                    version = 2 if row else 1
                    etype = "ExitObserved"
                else:
                    raise InvalidRequest("kind must be entry or exit", code="invalid_observation")
                payload: dict[str, Any] = {
                    "gate_id": str(gate_id),
                    "lane_id": str(lane_id),
                    "credential_kind": str(ob.get("credential_kind", "qr")),
                    "decision_source": str(ob.get("decision_source", "cached_policy")),
                    "via_terminal": str(actor.device_id),
                    "terminal_seq": tseq,
                    "restricted_standalone": True,
                }
                if inv is not None:
                    payload["invitation_id"] = str(inv)
                if conflict:
                    payload["conflict"] = "single_use_pass_reused"
                    self._review(
                        c,
                        "single_use_conflict",
                        entity,
                        {"invitation_id": str(inv), "terminal": str(actor.device_id)},
                        clock.now,
                    )
                event = self.outbox.append(
                    type=etype,
                    entity_id=entity,
                    entity_version=version,
                    payload=payload,
                    occurred_at=occurred,
                    clock_uncertainty_ms=unc,
                    policy_version=policy_seq,
                )
                c.execute(
                    "INSERT INTO terminal_observations (device_id, tseq, event_id) VALUES (?, ?, ?)",
                    (str(actor.device_id), tseq, str(event.event_id)),
                )
                results.append(
                    {
                        "tseq": tseq,
                        "status": "conflict_flagged" if conflict else "accepted",
                        "seq": event.seq,
                    }
                )
            self.store.audit(
                actor.label, "standalone_reconciled", None, {"count": len(observations)}, clock.now
            )
            self._persist_high_water(clock.now)
        self._notify()
        return {"results": results}

    # ---- misc reads --------------------------------------------------------------------------------------
    def review_items(self) -> list[dict[str, Any]]:
        return [
            {
                "id": r["id"],
                "kind": r["kind"],
                "entity_id": r["entity_id"],
                "created_at": r["created_at"],
                "state": r["state"],
            }
            for r in self.store.all(
                "SELECT id, kind, entity_id, created_at, state FROM review_items ORDER BY created_at"
            )
        ]

    def run_maintenance(self) -> dict[str, int]:
        """Bound the local tables (run from a timer). Observations and the outbox are NEVER pruned here: acknowledged
        outbox rows are pruned separately by ``outbox.prune_acked``, and ``audit_log`` is append-only."""
        now = self.clock.assess().now
        cfg = self.config
        cutoffs = {
            "decision_log": iso(now - timedelta(seconds=cfg.decision_log_keep_s)),
            "lan_feed": iso(now - timedelta(seconds=cfg.feed_keep_s)),
            "client_actions": iso(now - timedelta(seconds=cfg.client_action_keep_s)),
            "pass_uses": iso(now - timedelta(seconds=cfg.client_action_keep_s)),
        }
        removed: dict[str, int] = {}
        with self.store.transaction() as c:
            removed["decision_log"] = c.execute(
                "DELETE FROM decision_log WHERE at < ?", (cutoffs["decision_log"],)
            ).rowcount
            removed["lan_feed"] = c.execute(
                "DELETE FROM lan_feed WHERE at < ?", (cutoffs["lan_feed"],)
            ).rowcount
            removed["client_actions"] = c.execute(
                "DELETE FROM client_actions WHERE created_at < ?", (cutoffs["client_actions"],)
            ).rowcount
            # released holds are noise; consumed uses stay (they are the single-use ledger)
            removed["pass_uses"] = c.execute(
                "DELETE FROM pass_uses WHERE state='released' AND created_at < ?",
                (cutoffs["pass_uses"],),
            ).rowcount
            removed["pending_items"] = c.execute(
                "DELETE FROM pending_items WHERE state IN ('expired', 'resolved', 'cancelled') AND created_at < ?",
                (cutoffs["decision_log"],),
            ).rowcount
            self.store.audit("gateway", "maintenance", None, removed, now)
        self._prune_evals(now)
        return removed

    def backup(self, dest: Any) -> Any:
        return self.store.backup(dest)

    def backup_rotating(self, directory: Path, keep: int = 3) -> Path:
        """Timestamped backup copy; older copies beyond ``keep`` are removed. Run from a maintenance timer."""
        stamp = iso(self.clock.assess().now).replace(":", "").replace(".", "")
        dest = self.store.backup(Path(directory) / f"edge-{stamp}.sqlite3")
        old = sorted(Path(directory).glob("edge-*.sqlite3"))
        for stale in old[: max(0, len(old) - keep)]:
            stale.unlink(missing_ok=True)
        return dest


def canonical_size(value: Any) -> int:
    return len(canonical_json(value))
