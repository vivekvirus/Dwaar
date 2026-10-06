"""The deterministic cascade planner: a PURE function of (request time, policy, acknowledgements, already-issued actions, now).

REQ: NOTIF-03 / Appendix C / D-15 (t=0 push to the selected household approvers; t=10 s alternate configured adult without app acknowledgement;
t=20 s masked IVR to the primary; t=35 s WhatsApp utility template or SMS link to opted-in recipients; t=90 s expire and show the guard-assisted
options; at most ONE primary and ONE alternate call per request unless a supervisor starts a new attempt), AT-40, INV-03 (a timeout never
allows: the planner has no "allow" action at all), INV-07.

Properties this module guarantees (and ``tests/integration/notifications/test_planner_properties.py`` checks with Hypothesis):

* **never sends after expiry or after the request left ``pending``**: past ``expires_at`` the only action is ``expire``; for a decided,
  cancelled or expired request the only action is ``cancel``;
* **idempotent**: an action whose dedupe key is in ``done`` is never planned again, so running the executor twice (a restart, a duplicated
  event, two workers) adds nothing;
* **at most one primary call and one alternate call per attempt**: calls are planned only for those two roles, each once per attempt;
* **timings come from the stored plan** (the society policy as it was when the request was raised, validated to the approved bounds: at least
  10 s between steps, expiry 60-180 s), never from constants in this file, which are only the defaults of ``dwaar_packs`` repeated for the
  case the stored plan is incomplete;
* **no clock inside**: ``now`` is an argument. The worker passes an injectable clock.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

MIN_GAP_SECONDS: Final = 10
EXPIRY_BOUNDS: Final = (60, 180)
DEFAULT_GUARD_OPTIONS: Final = ("hold", "leave_at_gate", "lobby_only", "intercom", "deny")
#: an IVR outcome after which the alternate may be called (only when the policy enables an alternate call)
UNANSWERED: Final = frozenset({"no_answer", "busy", "failed", "rejected", "cancelled"})

PUSH: Final = "push"
IVR: Final = "ivr_call"
SMS: Final = "sms"
WHATSAPP: Final = "whatsapp"

STEP_PUSH: Final = 1
STEP_ALTERNATE: Final = 2
STEP_IVR: Final = 3
STEP_LINK: Final = 4
STEP_EXPIRE: Final = 5


@dataclass(frozen=True)
class Timings:
    """When each step is due, in seconds after the start of the attempt, validated to the approved bounds."""

    push_at: int = 0
    alternate_at: int = 10
    ivr_at: int = 20
    link_at: int = 35
    expiry_seconds: int = 90
    guard_options: tuple[str, ...] = DEFAULT_GUARD_OPTIONS
    alternate_call: bool = False

    @classmethod
    def from_plan(cls, plan: Mapping[str, Any] | None) -> Timings:
        """Read the plan stored on the approval request (``approval_requests.cascade``) and enforce the bounds: a stored value outside them
        is pulled to the nearest valid one, so a corrupt row can never yield a faster or slower cascade than the policy allows."""
        plan = plan or {}
        at: dict[int, int] = {}
        options: tuple[str, ...] = ()
        for raw in plan.get("steps") or []:
            if not isinstance(raw, Mapping):
                continue
            try:
                step, secs = int(raw["step"]), int(raw["at_seconds"])
            except (KeyError, TypeError, ValueError):
                continue
            if step in (1, 2, 3, 4, 5) and secs >= 0:
                at[step] = secs
            if step == STEP_EXPIRE and raw.get("guard_options"):
                options = tuple(str(o) for o in raw["guard_options"])
        try:
            expiry = int(plan.get("expiry_seconds") or at.get(STEP_EXPIRE) or 90)
        except (TypeError, ValueError):
            expiry = 90
        expiry = min(max(expiry, EXPIRY_BOUNDS[0]), EXPIRY_BOUNDS[1])
        alt = max(at.get(STEP_ALTERNATE, 10), MIN_GAP_SECONDS)
        ivr = max(at.get(STEP_IVR, 20), alt + MIN_GAP_SECONDS)
        link = max(at.get(STEP_LINK, 35), ivr + MIN_GAP_SECONDS)
        return cls(
            push_at=0,
            alternate_at=alt,
            ivr_at=ivr,
            link_at=link,
            expiry_seconds=expiry,
            guard_options=options or DEFAULT_GUARD_OPTIONS,
            alternate_call=bool(plan.get("alternate_call", False)),
        )


@dataclass(frozen=True)
class Household:
    """Who the cascade may reach, as resolved by the service from CURRENT memberships (never from a stale snapshot)."""

    approvers: tuple[uuid.UUID, ...]  # selected household approvers (t=0)
    primary: uuid.UUID | None = None
    alternate: uuid.UUID | None = None
    #: (person, channel) of residents who opted in to WhatsApp or SMS links (t=35)
    opted_in: tuple[tuple[uuid.UUID, str], ...] = ()
    fallback_mode: str = (
        "call"  # the household's configured fallback: a masked call, or the intercom
    )


@dataclass(frozen=True)
class Progress:
    request_id: uuid.UUID
    request_state: str
    started_at: dt.datetime
    expires_at: dt.datetime
    attempt_no: int = 1
    #: any app acknowledgement (app_received or later) of a push sent in THIS attempt
    acked: bool = False
    #: dedupe keys of everything already issued (created rows), whatever their outcome
    done: frozenset[str] = frozenset()
    #: dial outcome of the primary call, once known (lets a policy with ``alternate_call`` ring the alternate)
    primary_call_outcome: str | None = None


@dataclass(frozen=True)
class Action:
    kind: str  # push | ivr_call | sms | whatsapp | expire | cancel
    step: int
    role: str  # approver | primary | alternate | opted_in | system
    person_id: uuid.UUID | None
    due_at: dt.datetime
    dedupe_key: str

    @property
    def is_send(self) -> bool:
        return self.kind in (PUSH, IVR, SMS, WHATSAPP)

    @property
    def is_call(self) -> bool:
        return self.kind == IVR


def dedupe_key(
    request_id: uuid.UUID,
    attempt_no: int,
    step: int,
    channel: str,
    role: str,
    person: uuid.UUID | None,
) -> str:
    return f"{request_id}:{attempt_no}:{step}:{channel}:{role}:{person or '-'}"


def plan_cascade(
    timings: Timings, household: Household, progress: Progress, now: dt.datetime
) -> list[Action]:
    """The actions due at ``now`` that have not been issued yet, in cascade order. Pure."""
    rid, n = progress.request_id, progress.attempt_no
    if progress.request_state != "pending":
        # decided / denied / cancelled / expired elsewhere: stop everything, send nothing (NOTIF-04)
        return [Action("cancel", STEP_EXPIRE, "system", None, now, f"{rid}:{n}:cancel")]
    if now >= progress.expires_at:
        # t = expiry: guard-assisted options. There is no allow action and no further send (INV-03)
        return [
            Action("expire", STEP_EXPIRE, "system", None, progress.expires_at, f"{rid}:{n}:expire")
        ]
    elapsed = (now - progress.started_at).total_seconds()
    out: list[Action] = []

    def add(kind: str, step: int, role: str, person: uuid.UUID | None, at: int) -> None:
        key = dedupe_key(rid, n, step, kind, role, person)
        if key in progress.done:
            return
        due = progress.started_at + dt.timedelta(seconds=at)
        if due >= progress.expires_at:
            return  # a step that would fall on or after the expiry never happens
        out.append(Action(kind, step, role, person, due, key))

    seen: set[uuid.UUID] = set()
    if elapsed >= timings.push_at:
        for person in household.approvers:
            if person in seen:
                continue
            seen.add(person)
            role = "primary" if person == household.primary else "approver"
            add(PUSH, STEP_PUSH, role, person, timings.push_at)
    alt = household.alternate
    if (
        elapsed >= timings.alternate_at
        and alt is not None
        and alt not in household.approvers
        and alt != household.primary
        and not progress.acked  # "no app acknowledgement"
    ):
        add(PUSH, STEP_ALTERNATE, "alternate", alt, timings.alternate_at)
    if (
        elapsed >= timings.ivr_at
        and household.primary is not None
        and household.fallback_mode == "call"
    ):
        add(IVR, STEP_IVR, "primary", household.primary, timings.ivr_at)
    if (
        timings.alternate_call
        and household.fallback_mode == "call"
        and alt is not None
        and alt != household.primary
        and progress.primary_call_outcome in UNANSWERED
        and elapsed >= timings.ivr_at + MIN_GAP_SECONDS
    ):
        add(IVR, STEP_IVR, "alternate", alt, timings.ivr_at + MIN_GAP_SECONDS)
    if elapsed >= timings.link_at:
        done_people: set[tuple[uuid.UUID, str]] = set()
        for person, channel in household.opted_in:
            if channel not in (SMS, WHATSAPP) or (person, channel) in done_people:
                continue
            done_people.add((person, channel))
            add(channel, STEP_LINK, "opted_in", person, timings.link_at)
    return out


def calls_in(actions: Iterable[Action]) -> list[Action]:
    return [a for a in actions if a.is_call]


def due_steps(timings: Timings) -> Sequence[tuple[int, int]]:
    """``(step, seconds)`` of the five steps, for display and tests."""
    return (
        (STEP_PUSH, timings.push_at),
        (STEP_ALTERNATE, timings.alternate_at),
        (STEP_IVR, timings.ivr_at),
        (STEP_LINK, timings.link_at),
        (STEP_EXPIRE, timings.expiry_seconds),
    )
