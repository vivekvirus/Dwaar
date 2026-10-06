"""Local deterministic decision engine.

REQ: INV-03 (a deterministic local policy decides entry; no model, no timeout ever allows), GATE-06 (resident
credentials validate status, gate, time, policy age and revocation version locally), GATE-14 (standing rules
evaluated locally), EDGE-05 (72 h resident validity then guard-assisted verification, never automatic lockout;
clock model), D-13 (guest pass offline entitlement at most 2 h and bound to its assigned gate), EDGE-06,
PRD 9.3 (single-use consumption is serialised by the gateway; a partitioned gate cannot guarantee global
single-use, so such passes are gate-bound or need manual validation).

``decide`` is a PURE function: (policy, request, clock state) -> ``Decision``. It reads no clock, no database,
no network and has no side effects. There is no code path that turns a timeout into ``allow``: the only way to
get ``allow`` is for every check of the matching branch to pass.
"""

# REQ: INV-03, GATE-06, GATE-14, EDGE-05, EDGE-06

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .clock import ClockState
from .policy import PolicyBundle
from .policy_model import Invitation, Resident, StandingRule


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_GUARD = "needs_guard"
    NEEDS_SUPERVISOR = "needs_supervisor"


class OperatingMode(StrEnum):
    """What the deciding component can rely on (terminal-visible state, EDGE-06)."""

    NORMAL = "normal"  # gateway is the arbiter on the LAN (cloud may be down: cached policy)
    WAN_DOWN = "wan_down"  # reported by the gateway when the cloud has not been reached recently
    RESTRICTED_STANDALONE = (
        "restricted_standalone"  # terminal without its gateway: signed cache only
    )


# Appendix C: guard-assisted options when nothing can be decided automatically.
GUARD_OPTIONS: Final = ("hold", "leave_at_gate", "lobby_only", "intercom", "deny")


@dataclass(frozen=True)
class ResidentCredential:
    credential_ref: str
    revocation_version: int = 0
    kind: Literal["resident"] = "resident"


@dataclass(frozen=True)
class GuestPass:
    invitation_id: uuid.UUID
    nonce: str
    qr_signature_ok: bool | None = None  # None: not checked (no pass key provisioned)
    qr_expires: datetime | None = None
    qr_not_before: datetime | None = None
    kind: Literal["guest_pass"] = "guest_pass"


@dataclass(frozen=True)
class StandingVisitor:
    unit_id: uuid.UUID
    category: str | None = None  # e.g. food_delivery, milk_vendor (guard-selected visitor category)
    visit_kind: str | None = None  # guest | delivery | service | cab | vendor | staff
    kind: Literal["standing"] = "standing"


@dataclass(frozen=True)
class UnknownCredential:
    kind: Literal["unknown"] = "unknown"


@dataclass(frozen=True)
class InvalidCredential:
    """Presented text that does not parse or belongs to another society (never an entitlement)."""

    why: str = "malformed"
    kind: Literal["invalid"] = "invalid"


Credential = (
    ResidentCredential | GuestPass | StandingVisitor | UnknownCredential | InvalidCredential
)


@dataclass(frozen=True)
class LedgerView:
    """What the edge ledger says about the presented pass, computed by the caller inside its transaction."""

    used_total: int = (
        0  # consumed + held reservations (excluding a live hold of the requester itself)
    )
    held_by_requester: bool = False
    held_by_other: bool = False  # another terminal holds a reservation that is not yet consumed
    used_at_gate: int = 0  # consumed + held at THIS gate (escrow accounting)
    escrow_allocated: int | None = (
        None  # per-gate pre-allocation, None if the owner did not enable it
    )


@dataclass(frozen=True)
class DecisionRequest:
    credential: Credential
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    mode: OperatingMode = OperatingMode.NORMAL
    ledger: LedgerView = field(default_factory=LedgerView)


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason_code: str
    evidence: dict[str, Any]
    review_required: bool = False
    fallback_options: tuple[str, ...] = ()
    consumes_pass: bool = (
        False  # allow on a pass: the caller must reserve a use in the same transaction
    )
    automatic: bool = field(
        default=False
    )  # True only for allow decisions made with no human involved

    def to_json(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "evidence": self.evidence,
            "review_required": self.review_required,
            "fallback_options": list(self.fallback_options),
            "auto_allow_on_timeout": False,
        }


def _evidence(
    policy: PolicyBundle | None, clock: ClockState, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "clock_uncertainty_ms": clock.uncertainty_ms,
        "clock_trusted": clock.trusted,
    }
    if policy is not None:
        ev["policy_seq"] = policy.seq
        ev["policy_age_s"] = int(policy.age(clock.now).total_seconds())
    if extra:
        ev.update(extra)
    return ev


def _mk(
    outcome: Outcome,
    reason: str,
    policy: PolicyBundle | None,
    clock: ClockState,
    *,
    extra: dict[str, Any] | None = None,
    review: bool = False,
    consumes: bool = False,
) -> Decision:
    options = GUARD_OPTIONS if outcome in (Outcome.NEEDS_GUARD, Outcome.NEEDS_SUPERVISOR) else ()
    return Decision(
        outcome=outcome,
        reason_code=reason,
        evidence=_evidence(policy, clock, extra),
        review_required=review or outcome is Outcome.NEEDS_SUPERVISOR,
        fallback_options=options,
        consumes_pass=consumes,
        automatic=outcome is Outcome.ALLOW,
    )


def decide(policy: PolicyBundle | None, request: DecisionRequest, clock: ClockState) -> Decision:
    """The one entry point. See module docstring."""
    cred = request.credential
    if policy is None:
        return _mk(Outcome.NEEDS_GUARD, "no_policy", None, clock)

    lane = policy.lanes.get(request.lane_id)
    if lane is None or lane.gate_id != request.gate_id or request.gate_id not in policy.gates:
        return _mk(Outcome.DENY, "unknown_gate_or_lane", policy, clock)

    # GATE-07: essential egress never depends on cloud, policy age, clock or debt. An exit lane lets people
    # out; what is observed (and when) is recorded separately and never invented (GATE-05).
    if lane.is_exit:
        return _mk(Outcome.ALLOW, "egress_always_permitted", policy, clock)

    if isinstance(cred, InvalidCredential):
        return _mk(
            Outcome.DENY, "invalid_credential", policy, clock, extra={"why": cred.why}, review=True
        )

    now = clock.now
    flags = clock.flags(policy.limits.clock_uncertainty_limit_ms)
    review = bool(flags)
    if now > policy.valid_until:
        return _mk(
            Outcome.NEEDS_GUARD,
            "policy_expired",
            policy,
            clock,
            extra={"clock_flags": flags},
            review=review,
        )

    if isinstance(cred, ResidentCredential):
        return _decide_resident(policy, cred, request, clock, flags)
    if isinstance(cred, GuestPass):
        return _decide_guest(policy, cred, request, clock, flags)
    if isinstance(cred, StandingVisitor):
        return _decide_standing(policy, cred, request, clock, flags)
    return _mk(Outcome.NEEDS_GUARD, "no_local_entitlement", policy, clock, review=review)


# ---- resident ------------------------------------------------------------------------------------
def _margin(clock: ClockState) -> timedelta:
    """Boundary tolerance. Only a trusted estimate has a meaningful uncertainty; see clock.py."""
    return timedelta(milliseconds=clock.uncertainty_ms) if clock.trusted else timedelta(0)


def _decide_resident(
    policy: PolicyBundle,
    cred: ResidentCredential,
    request: DecisionRequest,
    clock: ClockState,
    flags: list[str],
) -> Decision:
    review = bool(flags)
    ref_ev = {"credential_ref_hash": _short(cred.credential_ref), "clock_flags": flags}
    res: Resident | None = policy.residents.get(cred.credential_ref)
    revoked_at = policy.revocations.get(cred.credential_ref)
    if revoked_at is not None and cred.revocation_version <= revoked_at:
        return _mk(Outcome.DENY, "credential_revoked", policy, clock, extra=ref_ev, review=review)
    if res is None:
        # Maybe issued after the last snapshot: a fresh remote approval is not possible offline.
        return _mk(
            Outcome.NEEDS_GUARD, "unknown_credential", policy, clock, extra=ref_ev, review=review
        )
    if res.status == "revoked":
        return _mk(Outcome.DENY, "credential_revoked", policy, clock, extra=ref_ev, review=review)
    if cred.revocation_version < res.revocation_version:
        return _mk(
            Outcome.DENY, "credential_superseded", policy, clock, extra=ref_ev, review=review
        )
    if res.status == "suspended":
        return _mk(
            Outcome.NEEDS_GUARD, "credential_suspended", policy, clock, extra=ref_ev, review=review
        )

    now, margin = clock.now, _margin(clock)
    lo, hi = now - margin, now + margin
    # time window: outside or ambiguous -> guard-assisted verification, never an automatic lockout
    if (res.valid_from is not None and hi < res.valid_from) or (
        res.valid_until is not None and lo > res.valid_until
    ):
        return _mk(
            Outcome.NEEDS_GUARD,
            "credential_window_invalid",
            policy,
            clock,
            extra=ref_ev,
            review=review,
        )
    if (res.valid_from is not None and lo < res.valid_from) or (
        res.valid_until is not None and hi > res.valid_until
    ):
        return _mk(
            Outcome.NEEDS_GUARD,
            "clock_boundary_uncertain",
            policy,
            clock,
            extra=ref_ev,
            review=True,
        )

    # EDGE-05: policy older than the resident offline validity -> guard-assisted verification
    limit = timedelta(seconds=policy.limits.resident_offline_validity_s)
    if policy.age(now) + margin > limit:
        return _mk(
            Outcome.NEEDS_GUARD, "policy_stale_resident", policy, clock, extra=ref_ev, review=review
        )
    return _mk(Outcome.ALLOW, "resident_valid", policy, clock, extra=ref_ev, review=review)


# ---- guest pass ----------------------------------------------------------------------------------
def _decide_guest(
    policy: PolicyBundle,
    cred: GuestPass,
    request: DecisionRequest,
    clock: ClockState,
    flags: list[str],
) -> Decision:
    ev: dict[str, Any] = {"invitation_id": str(cred.invitation_id), "clock_flags": flags}
    if cred.qr_signature_ok is False:
        return _mk(Outcome.DENY, "bad_signature", policy, clock, extra=ev, review=True)
    inv: Invitation | None = policy.invitations.get(cred.invitation_id)
    revoked_ref = policy.revocations.get(str(cred.invitation_id))
    if inv is None:
        # not in the cached policy: possibly created after the last snapshot -> explicit fallback path
        return _mk(Outcome.NEEDS_GUARD, "unknown_pass", policy, clock, extra=ev)
    if not hmac.compare_digest(inv.nonce.encode(), cred.nonce.encode()):
        return _mk(Outcome.DENY, "bad_nonce", policy, clock, extra=ev, review=True)
    if (inv.revoked_version is not None and inv.revoked_version > 0) or revoked_ref is not None:
        return _mk(Outcome.DENY, "pass_revoked", policy, clock, extra=ev)

    gate_id = request.gate_id
    # D-13 / PRD 9.3: bound to the assigned gate; a token at any other gate requires confirmation.
    if inv.gate_id is not None and inv.gate_id != gate_id:
        return _mk(
            Outcome.NEEDS_SUPERVISOR,
            "wrong_gate",
            policy,
            clock,
            extra={**ev, "assigned_gate_id": str(inv.gate_id), "presented_gate_id": str(gate_id)},
        )

    # EDGE-05: automatic time-sensitive guest approval needs a trustworthy clock.
    block = clock.guest_block_reason(policy.limits.clock_uncertainty_limit_ms)
    if block is not None:
        return _mk(Outcome.NEEDS_SUPERVISOR, block, policy, clock, extra=ev, review=True)

    now, margin = clock.now, _margin(clock)
    state = _window_state(now, margin, _guest_windows(inv, cred))
    if state == "outside":
        return _mk(Outcome.NEEDS_GUARD, "pass_window_invalid", policy, clock, extra=ev)
    if state == "ambiguous":
        return _mk(
            Outcome.NEEDS_GUARD, "clock_boundary_uncertain", policy, clock, extra=ev, review=True
        )

    # D-13: at most 2 hours of offline entitlement. Beyond it the pass needs confirmation.
    if policy.age(now) + margin > timedelta(seconds=policy.limits.guest_offline_max_s):
        return _mk(Outcome.NEEDS_GUARD, "policy_stale_guest", policy, clock, extra=ev)

    return _uses(policy, inv, request, clock, ev)


def _uses(
    policy: PolicyBundle,
    inv: Invitation,
    request: DecisionRequest,
    clock: ClockState,
    ev: dict[str, Any],
) -> Decision:
    led = request.ledger
    standalone = request.mode is OperatingMode.RESTRICTED_STANDALONE
    gate_bound_here = inv.gate_id is not None and inv.gate_id == request.gate_id
    cloud_used = inv.cloud_used
    used = max(cloud_used, led.used_total)
    remaining = inv.max_uses - used
    ev = {**ev, "max_uses": inv.max_uses, "uses_remaining_local": max(0, remaining)}

    if standalone and not gate_bound_here:
        # Gateway lost: this terminal cannot serialise a gate-agnostic pass against other gates.
        if led.escrow_allocated is None:
            reason = (
                "global_single_use_not_guaranteed" if inv.max_uses == 1 else "no_escrow_allocation"
            )
            return _mk(Outcome.NEEDS_SUPERVISOR, reason, policy, clock, extra=ev)
        escrow_left = led.escrow_allocated - led.used_at_gate
        ev["escrow_remaining"] = max(0, escrow_left)
        if escrow_left <= 0:
            return _mk(Outcome.DENY, "pass_quota_exhausted", policy, clock, extra=ev)
        return _mk(Outcome.ALLOW, "guest_pass_valid_escrow", policy, clock, extra=ev, consumes=True)

    if led.held_by_requester:
        return _mk(
            Outcome.ALLOW,
            "guest_pass_valid",
            policy,
            clock,
            extra={**ev, "hold": "own"},
            consumes=True,
        )
    if remaining <= 0:
        if led.held_by_other:
            return _mk(Outcome.DENY, "pass_in_use", policy, clock, extra=ev)
        reason = "pass_replay_consumed" if inv.max_uses == 1 else "pass_quota_exhausted"
        return _mk(Outcome.DENY, reason, policy, clock, extra=ev)
    return _mk(Outcome.ALLOW, "guest_pass_valid", policy, clock, extra=ev, consumes=True)


def _guest_windows(inv: Invitation, cred: GuestPass) -> list[tuple[datetime, datetime]]:
    """Explicit windows when the cloud sent them (recurring pass), else the outer bounds; clipped to the QR's own."""
    raw = [(w.start, w.end) for w in inv.windows] or [(inv.window_start, inv.window_end)]
    out: list[tuple[datetime, datetime]] = []
    for start, end in raw:
        if cred.qr_not_before is not None:
            start = max(start, cred.qr_not_before)
        if cred.qr_expires is not None:
            end = min(end, cred.qr_expires)
        if start <= end:
            out.append((start, end))
    return out


def _window_state(
    now: datetime, margin: timedelta, windows: list[tuple[datetime, datetime]]
) -> Literal["inside", "outside", "ambiguous"]:
    """inside: certainly in one window; outside: certainly in none; ambiguous: the clock uncertainty straddles an edge."""
    lo, hi = now - margin, now + margin
    possible = False
    for start, end in windows:
        if start <= lo and hi <= end:
            return "inside"
        if hi >= start and lo <= end:
            possible = True
    return "ambiguous" if possible else "outside"


# ---- standing rules (GATE-14) ----------------------------------------------------------------------
_TIME_FMT_LEN = 5
_ACTION_BY_KIND: Final = {
    "allow_window": "allow",
    "leave_at_gate": "leave_at_gate",
    "deny_category": "deny",
}
_ACTIONS: Final = frozenset({"allow", "leave_at_gate", "hold", "deny"})
_DEFAULT_TZ: Final = "Asia/Kolkata"


def _minutes(text: object) -> int | None:
    if not isinstance(text, str) or len(text) != _TIME_FMT_LEN or text[2] != ":":
        return None
    try:
        h, m = int(text[:2]), int(text[3:])
    except ValueError:
        return None
    return h * 60 + m if 0 <= h < 24 and 0 <= m < 60 else None


def _zone(name: object) -> ZoneInfo | None:
    try:
        return ZoneInfo(name if isinstance(name, str) else _DEFAULT_TZ)
    except (ZoneInfoNotFoundError, ValueError):
        return None


def _rule_date_ok(rule: StandingRule, now: datetime, tz: ZoneInfo) -> bool:
    """effective_from/to: dates are inclusive calendar days in the rule's zone; datetimes are instants."""
    start, end = rule.effective_from, rule.effective_to
    local_day = now.astimezone(tz).date()
    if isinstance(start, datetime):
        if now < start:
            return False
    elif start is not None and local_day < start:
        return False
    if isinstance(end, datetime):
        return now < end
    return end is None or local_day <= end


def _rule_matches(rule: StandingRule, cred: StandingVisitor, now: datetime) -> str | None:
    """The rule's action if it applies to this visitor now, else None. Anything malformed grants nothing."""
    p = rule.params
    tz = _zone(p.get("tz", _DEFAULT_TZ))
    visit_kind, category = p.get("visit_kind"), p.get("category")
    if tz is None or (visit_kind is None and category is None):
        return None
    if visit_kind is not None and visit_kind != cred.visit_kind:
        return None
    if category is not None and category != cred.category:
        return None
    if not _rule_date_ok(rule, now, tz):
        return None
    start, end = _minutes(p.get("start_local")), _minutes(p.get("end_local"))
    action = p.get("action") or _ACTION_BY_KIND.get(rule.rule_kind)
    if start is None or end is None or action not in _ACTIONS:
        return None
    local = now.astimezone(tz)
    minute = local.hour * 60 + local.minute
    in_window = start <= minute < end if start <= end else (minute >= start or minute < end)
    if not in_window:
        return None
    days = p.get("days")
    if isinstance(days, list) and days:
        # a window that wraps midnight belongs to the day it STARTED on
        day = local if start <= end or minute >= start else local - timedelta(days=1)
        if day.isoweekday() not in days:
            return None
    return str(action)


def _decide_standing(
    policy: PolicyBundle,
    cred: StandingVisitor,
    request: DecisionRequest,
    clock: ClockState,
    flags: list[str],
) -> Decision:
    ev: dict[str, Any] = {
        "unit_id": str(cred.unit_id),
        "visit_kind": cred.visit_kind,
        "category": cred.category,
        "clock_flags": flags,
    }
    rules = policy.rules_by_unit.get(cred.unit_id, ())
    if not rules:
        return _mk(Outcome.NEEDS_GUARD, "no_local_entitlement", policy, clock, extra=ev)
    block = clock.guest_block_reason(policy.limits.clock_uncertainty_limit_ms)
    if block is not None:
        return _mk(Outcome.NEEDS_SUPERVISOR, block, policy, clock, extra=ev, review=True)
    if policy.age(clock.now) > timedelta(seconds=policy.limits.guest_offline_max_s):
        return _mk(Outcome.NEEDS_GUARD, "policy_stale_guest", policy, clock, extra=ev)

    actions = {a for r in rules if (a := _rule_matches(r, cred, clock.now)) is not None}
    # precedence: deny > leave_at_gate > hold > allow
    if "deny" in actions:
        return _mk(Outcome.DENY, "standing_rule_deny", policy, clock, extra=ev)
    if "leave_at_gate" in actions:
        return _mk(
            Outcome.NEEDS_GUARD,
            "standing_rule_leave_at_gate",
            policy,
            clock,
            extra={**ev, "action": "leave_at_gate"},
        )
    if "hold" in actions:
        return _mk(
            Outcome.NEEDS_GUARD, "standing_rule_hold", policy, clock, extra={**ev, "action": "hold"}
        )
    if "allow" in actions:
        # A rule pre-authorises the category inside the window; the guard still confirms who is at the gate.
        return _mk(
            Outcome.ALLOW,
            "standing_rule_allow",
            policy,
            clock,
            extra={**ev, "guard_confirms_identity": True},
        )
    return _mk(Outcome.NEEDS_GUARD, "no_local_entitlement", policy, clock, extra=ev)


def _short(ref: str) -> str:
    """Stable short digest for evidence: the credential ref itself is not copied into audit text."""
    return hashlib.sha256(ref.encode()).hexdigest()[:12]
