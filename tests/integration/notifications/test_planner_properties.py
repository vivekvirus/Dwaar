"""The cascade planner as a pure function: unit tests of the PRD timings and Hypothesis properties over arbitrary schedules.

REQ: NOTIF-03 (t=0 / 10 / 20 / 35 / 90; at most ONE primary and ONE alternate call per attempt; min 10 s between steps, expiry 60-180 s from the
society policy), INV-03 (no schedule ever allows, and nothing is sent at or after expiry), AT-40 (the timings), NOTIF-04 (cancellation is idempotent).
No database: the planner takes ``now`` as an argument.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dwaar_api.modules.notifications.planner import (
    IVR,
    PUSH,
    SMS,
    WHATSAPP,
    Action,
    Household,
    Progress,
    Timings,
    plan_cascade,
)

pytestmark = [pytest.mark.req("NOTIF-03", "INV-03")]

T0 = dt.datetime(2026, 10, 6, 10, 0, 0, tzinfo=dt.UTC)
RID = uuid.UUID(int=7)
A, B, C, D = (uuid.UUID(int=n) for n in (101, 102, 103, 104))
DEFAULT_PLAN = {
    "expiry_seconds": 90,
    "steps": [
        {"step": 1, "at_seconds": 0}, {"step": 2, "at_seconds": 10}, {"step": 3, "at_seconds": 20},
        {"step": 4, "at_seconds": 35}, {"step": 5, "at_seconds": 90, "guard_options": ["hold", "leave_at_gate", "lobby_only", "intercom", "deny"]},
    ],
}  # fmt: skip


def _progress(expires: float = 90, *, state: str = "pending", acked: bool = False, done: frozenset[str] = frozenset(), n: int = 1,
              outcome: str | None = None) -> Progress:  # fmt: skip
    return Progress(RID, state, T0, T0 + dt.timedelta(seconds=expires), n, acked, done, outcome)


def _plan(
    at: float, household: Household, progress: Progress, timings: Timings | None = None
) -> list[Action]:
    return plan_cascade(
        timings or Timings.from_plan(DEFAULT_PLAN),
        household,
        progress,
        T0 + dt.timedelta(seconds=at),
    )


FULL = Household(
    approvers=(A,), primary=A, alternate=B, opted_in=((C, SMS), (D, WHATSAPP)), fallback_mode="call"
)


def test_the_pack_timings_are_the_defaults() -> None:
    t = Timings.from_plan(DEFAULT_PLAN)
    assert (t.push_at, t.alternate_at, t.ivr_at, t.link_at, t.expiry_seconds) == (0, 10, 20, 35, 90)
    assert (
        t.guard_options == ("hold", "leave_at_gate", "lobby_only", "intercom", "deny")
        and t.alternate_call is False
    )


def test_each_step_appears_at_its_time_and_not_before() -> None:
    def kinds(
        at: float, done: frozenset[str] = frozenset(), acked: bool = False
    ) -> list[tuple[str, str]]:
        return [(a.kind, a.role) for a in _plan(at, FULL, _progress(done=done, acked=acked))]

    assert kinds(0) == [(PUSH, "primary")]
    assert kinds(9.99) == [(PUSH, "primary")]
    assert (PUSH, "alternate") in kinds(10) and (IVR, "primary") not in kinds(10)
    assert (IVR, "primary") in kinds(20) and (SMS, "opted_in") not in kinds(20)
    k35 = kinds(35)
    assert (SMS, "opted_in") in k35 and (WHATSAPP, "opted_in") in k35
    assert kinds(89.9)[-1][0] == WHATSAPP
    assert [a.kind for a in _plan(90, FULL, _progress())] == ["expire"]


def test_no_alternate_when_an_app_acknowledged_but_the_call_still_follows() -> None:
    plan = _plan(25, FULL, _progress(acked=True))
    roles = [(a.kind, a.role) for a in plan]
    assert (PUSH, "alternate") not in roles and (
        IVR,
        "primary",
    ) in roles  # "still pending" is step 3's only condition


def test_the_intercom_household_gets_no_call() -> None:
    plan = _plan(60, Household((A,), A, B, (), "intercom"), _progress())
    assert IVR not in [a.kind for a in plan]


def test_already_issued_actions_are_never_planned_again() -> None:
    first = _plan(40, FULL, _progress())
    again = _plan(40, FULL, _progress(done=frozenset(a.dedupe_key for a in first)))
    assert again == []


def test_a_request_that_is_no_longer_pending_only_cancels() -> None:
    for state in ("approved", "denied", "cancelled", "expired"):
        plan = _plan(15, FULL, _progress(state=state))
        assert [a.kind for a in plan] == ["cancel"] and not any(a.is_send for a in plan)


def test_bounds_pull_a_corrupt_plan_back_to_the_approved_range() -> None:
    fast = Timings.from_plan(
        {
            "expiry_seconds": 5,
            "steps": [
                {"step": 2, "at_seconds": 1},
                {"step": 3, "at_seconds": 2},
                {"step": 4, "at_seconds": 3},
            ],
        }
    )
    assert (
        fast.expiry_seconds == 60
        and fast.alternate_at >= 10
        and fast.ivr_at - fast.alternate_at >= 10
        and fast.link_at - fast.ivr_at >= 10
    )
    slow = Timings.from_plan({"expiry_seconds": 10_000})
    assert slow.expiry_seconds == 180
    assert (
        Timings.from_plan(None).expiry_seconds == 90
        and Timings.from_plan({"steps": "nonsense"}).link_at == 35
    )


def test_a_step_that_would_fall_after_expiry_never_happens() -> None:
    plan = _plan(70, FULL, _progress(expires=60))  # past expiry
    assert [a.kind for a in plan] == ["expire"]
    t = Timings(alternate_at=10, ivr_at=20, link_at=35)
    near = plan_cascade(
        t,
        FULL,
        Progress(RID, "pending", T0, T0 + dt.timedelta(seconds=30)),
        T0 + dt.timedelta(seconds=29),
    )
    assert all(a.due_at < T0 + dt.timedelta(seconds=30) for a in near) and not any(
        a.kind in (SMS, WHATSAPP) for a in near
    )


def test_the_alternate_call_is_opt_in_policy_and_needs_an_unanswered_primary_call() -> None:
    t = Timings(alternate_call=True)
    h = Household((A,), A, B, (), "call")
    assert not any(
        a.role == "alternate" and a.kind == IVR
        for a in plan_cascade(t, h, _progress(outcome=None), T0 + dt.timedelta(seconds=40))
    )
    plan = plan_cascade(t, h, _progress(outcome="no_answer"), T0 + dt.timedelta(seconds=40))
    assert [a.role for a in plan if a.kind == IVR].count("alternate") == 1


# ------------------------------------------------------------------------------------------------------------ properties
ids = st.sampled_from([A, B, C, D])
households = st.builds(
    Household,
    approvers=st.lists(ids, max_size=3, unique=True).map(tuple),
    primary=st.one_of(st.none(), ids),
    alternate=st.one_of(st.none(), ids),
    opted_in=st.lists(
        st.tuples(ids, st.sampled_from([SMS, WHATSAPP, "push", "fax"])), max_size=4
    ).map(tuple),
    fallback_mode=st.sampled_from(["call", "intercom"]),
)
plans = st.fixed_dictionaries(
    {
        "expiry_seconds": st.integers(-10, 400),
        "alternate_call": st.booleans(),
        "steps": st.lists(
            st.fixed_dictionaries({"step": st.integers(0, 7), "at_seconds": st.integers(-5, 300)}),
            max_size=7,
        ),
    }
)
outcomes = st.sampled_from(
    [None, "answered", "no_answer", "busy", "failed", "rejected", "cancelled"]
)
SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _run(
    timings: Timings,
    household: Household,
    expires: float,
    offsets: list[float],
    flags: list[tuple[bool, str | None]],
    state_at: int | None,
):  # type: ignore[no-untyped-def]
    """Drive the planner like an executor: issue everything planned, remember it, move the clock, repeat. Yields (offset, progress, plan)."""
    done: frozenset[str] = frozenset()
    for i, off in enumerate(offsets):
        acked, outcome = flags[i % len(flags)]
        state = "pending" if state_at is None or i < state_at else "approved"
        progress = _progress(expires, state=state, acked=acked, done=done, outcome=outcome)
        plan = _plan(off, household, progress, timings)
        yield off, progress, plan
        done = done | frozenset(a.dedupe_key for a in plan if a.is_send)


@SETTINGS
@given(
    plans,
    households,
    st.integers(40, 180),
    st.lists(st.floats(0, 400, allow_nan=False), min_size=1, max_size=25),
    st.lists(st.tuples(st.booleans(), outcomes), min_size=1, max_size=4),
    st.one_of(st.none(), st.integers(0, 10)),
)
def test_property_at_most_one_primary_and_one_alternate_call_and_nothing_after_expiry(
    plan, household, expires, offsets, flags, state_at
):  # type: ignore[no-untyped-def]
    timings = Timings.from_plan(plan)
    offsets = sorted(offsets)
    calls: dict[str, int] = {}
    for off, progress, actions in _run(
        timings, household, float(expires), offsets, flags, state_at
    ):
        for a in actions:
            if a.is_send:
                assert progress.request_state == "pending"  # nothing is sent for a closed request
                assert off < expires  # nor at or after expiry
                assert a.due_at < progress.expires_at
            if a.is_call:
                assert a.role in ("primary", "alternate")
                calls[a.role] = calls.get(a.role, 0) + 1
            assert a.kind in {
                PUSH,
                IVR,
                SMS,
                WHATSAPP,
                "expire",
                "cancel",
            }  # there is no allow action to plan
    assert calls.get("primary", 0) <= 1 and calls.get("alternate", 0) <= 1


@SETTINGS
@given(plans, households, st.lists(st.floats(0, 200, allow_nan=False), min_size=1, max_size=10))
def test_property_replanning_after_issuing_is_empty_so_execution_is_idempotent(
    plan, household, offsets
):  # type: ignore[no-untyped-def]
    timings = Timings.from_plan(plan)
    for off in sorted(offsets):
        first = _plan(off, household, _progress(), timings)
        done = frozenset(a.dedupe_key for a in first)
        second = _plan(off, household, _progress(done=done), timings)
        assert [a for a in second if a.is_send] == []
        assert len({a.dedupe_key for a in first}) == len(first)  # no duplicate inside one plan


@SETTINGS
@given(
    plans,
    households,
    st.floats(0, 400, allow_nan=False),
    st.sampled_from(["approved", "denied", "cancelled", "expired"]),
    st.booleans(),
)
def test_property_cancellation_is_idempotent_and_never_sends(plan, household, at, state, acked):  # type: ignore[no-untyped-def]
    timings = Timings.from_plan(plan)
    p = _progress(state=state, acked=acked)
    once, twice = _plan(at, household, p, timings), _plan(at, household, p, timings)
    assert once == twice and [a.kind for a in once] == ["cancel"]


@SETTINGS
@given(plans, households, st.floats(0, 400, allow_nan=False))
def test_property_after_expiry_the_only_action_is_expire(plan, household, extra):  # type: ignore[no-untyped-def]
    timings = Timings.from_plan(plan)
    actions = plan_cascade(timings, household, _progress(90), T0 + dt.timedelta(seconds=90 + extra))
    assert [a.kind for a in actions] == ["expire"]


@SETTINGS
@given(plans)
def test_property_timings_always_respect_the_approved_bounds(plan):  # type: ignore[no-untyped-def]
    t = Timings.from_plan(plan)
    assert 60 <= t.expiry_seconds <= 180
    assert (
        t.alternate_at - t.push_at >= 10
        and t.ivr_at - t.alternate_at >= 10
        and t.link_at - t.ivr_at >= 10
    )
