"""The transition tables as pure functions (no database): every row of EDGE-07's "enforce the permitted transition".

REQ: EDGE-07, INV-07 (an observation never creates permission), GATE-05, GATE-07, EDGE-05.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from dwaar_api.modules.edge.sync import UNKNOWN_INVITATION, decide_transition, decide_unmatched

pytestmark = [pytest.mark.req("EDGE-07", "INV-07")]

NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
LIMIT = 60_000


def visit(state: str, until_minutes: int | None = 30) -> dict[str, Any]:
    return {
        "state": state,
        "authorised_until": None
        if until_minutes is None
        else NOW + dt.timedelta(minutes=until_minutes),
    }


def entry(state: str, **kw: Any) -> tuple[bool, str, str, str | None]:
    kw.setdefault("until_minutes", 30)
    t = decide_transition(
        visit(state, kw.pop("until_minutes")), event_type="EntryObserved", occurred_at=kw.pop("at", NOW),
        clock_uncertainty_ms=kw.pop("unc", 0), uncertainty_limit_ms=LIMIT, exit_basis="observed",
    )  # fmt: skip
    return t.changed, t.note, t.status, t.exception[0] if t.exception else None


def leave(state: str, basis: str = "observed") -> tuple[bool, str, str, str | None]:
    t = decide_transition(
        visit(state), event_type="ExitObserved", occurred_at=NOW, clock_uncertainty_ms=0, uncertainty_limit_ms=LIMIT, exit_basis=basis
    )  # fmt: skip
    return t.changed, t.note, t.status, t.exception[0] if t.exception else None


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("authorised", (True, "entered", "accepted", None)),
        ("inside", (False, "duplicate_entry", "accepted", None)),
        (
            "requested",
            (False, "entry_without_authorisation", "rejected_transition", "unauthorised_entry"),
        ),
        (
            "expired",
            (False, "entry_without_authorisation", "rejected_transition", "unauthorised_entry"),
        ),
        (
            "cancelled",
            (False, "entry_without_authorisation", "rejected_transition", "unauthorised_entry"),
        ),
        (
            "exited",
            (False, "entry_without_authorisation", "rejected_transition", "unauthorised_entry"),
        ),
    ],
)
def test_entry_for_a_cloud_visit_only_moves_an_authorised_visit(
    state: str, expected: tuple[bool, str, str, str | None]
) -> None:
    assert entry(state) == expected


def test_permission_window_and_clock_uncertainty() -> None:
    inside = dt.timedelta(minutes=29)
    assert entry("authorised", at=NOW + inside)[0] is True
    assert (
        entry("authorised", at=NOW + dt.timedelta(minutes=31))[1] == "entry_without_authorisation"
    )
    assert (
        entry("authorised", at=NOW + dt.timedelta(minutes=30, seconds=40), unc=45_000)[0] is True
    )  # widened by stated uncertainty
    assert (
        entry("authorised", at=NOW + dt.timedelta(minutes=30, seconds=90), unc=45_000)[0] is False
    )
    # the widening is capped at the policy limit: 10 minutes of claimed uncertainty buys at most 60 s
    assert entry("authorised", at=NOW + dt.timedelta(minutes=32), unc=59_000)[0] is False
    assert (
        entry("authorised", until_minutes=None, at=NOW + dt.timedelta(days=9))[0] is True
    )  # no window set: bounded elsewhere
    # above the limit the entry is recorded but NOT applied
    assert entry("authorised", unc=60_001) == (
        False,
        "clock_uncertain_review",
        "rejected_transition",
        "clock_implausible",
    )
    assert (
        entry("inside", unc=500_000)[1] == "duplicate_entry"
    )  # nothing to apply, nothing to review


@pytest.mark.parametrize(
    ("state", "basis", "expected"),
    [
        ("inside", "observed", (True, "exited", "accepted", None)),
        ("inside", "scanned", (True, "exited", "accepted", None)),
        (
            "inside",
            "reconciled_unknown",
            (True, "exit_reconciled_unknown", "accepted", "exit_unknown"),
        ),
        (
            "authorised",
            "observed",
            (True, "exit_without_observed_entry", "accepted", "exit_without_entry"),
        ),
        ("exited", "observed", (False, "duplicate_exit", "accepted", None)),
        (
            "requested",
            "observed",
            (False, "exit_without_entry", "rejected_transition", "exit_without_entry"),
        ),
        (
            "cancelled",
            "observed",
            (False, "exit_without_entry", "rejected_transition", "exit_without_entry"),
        ),
    ],
)
def test_exit_for_a_cloud_visit_is_never_gated(
    state: str, basis: str, expected: tuple[bool, str, str, str | None]
) -> None:
    assert leave(state, basis) == expected


def unmatched(
    event_type: str = "EntryObserved", source: str = "cached_policy", **kw: Any
) -> tuple[bool, str, str, str | None]:
    t = decide_unmatched(
        event_type=event_type, decision_source=source, invitation=kw.get("invitation"), prior_entry=kw.get("prior", False),
        occurred_at=NOW, clock_uncertainty_ms=kw.get("unc", 0), uncertainty_limit_ms=LIMIT, conflict=kw.get("conflict"),
    )  # fmt: skip
    assert t.changed is False  # an edge-local movement never changes a visit
    return t.changed, t.note, t.status, t.exception[0] if t.exception else None


def test_edge_local_movements_are_recorded_and_judged_by_their_payload() -> None:
    assert unmatched()[1:] == ("edge_entry_recorded", "accepted", None)
    assert unmatched(source="rfid")[1:] == ("edge_entry_recorded", "accepted", None)
    assert unmatched(source="guard_assisted")[1:] == ("edge_entry_recorded", "accepted", None)
    assert unmatched(source="supervisor_override")[1:] == (
        "override_entry_recorded",
        "accepted",
        "manual_entry",
    )
    assert unmatched(conflict="single_use_pass_reused")[1:] == (
        "edge_conflict_recorded",
        "accepted",
        "other",
    )
    for remote in ("resident_app", "ivr"):
        assert unmatched(source=remote)[1:] == (
            "entry_unknown_visit",
            "rejected_transition",
            "unauthorised_entry",
        )
    assert unmatched(invitation=UNKNOWN_INVITATION)[1:] == (
        "entry_unknown_invitation",
        "rejected_transition",
        "unauthorised_entry",
    )
    active = {"state": "active", "revoked_at": None}
    assert unmatched(invitation=active)[1:] == ("edge_entry_recorded", "accepted", None)


def test_a_revoked_pass_is_flagged_only_when_the_entry_came_after_the_revocation() -> None:
    def revoked(seconds_before: int, unc: int = 0) -> tuple[bool, str, str, str | None]:
        return unmatched(
            invitation={
                "state": "revoked",
                "revoked_at": NOW - dt.timedelta(seconds=seconds_before),
            },
            unc=unc,
        )

    assert revoked(300)[1:] == (
        "entry_after_revocation",
        "rejected_transition",
        "unauthorised_entry",
    )
    assert (
        revoked(30, unc=45_000)[1] == "edge_entry_recorded"
    )  # inside the stated uncertainty: not provable
    assert (
        revoked(100, unc=500_000)[1] == "entry_after_revocation"
    )  # the benefit of the doubt is capped at the limit
    later = unmatched(invitation={"state": "revoked", "revoked_at": NOW + dt.timedelta(minutes=5)})
    assert later[1] == "edge_entry_recorded"  # revoked AFTER the entry happened


def test_exit_of_an_edge_local_movement() -> None:
    assert unmatched("ExitObserved", prior=True)[1:] == ("edge_movement_exit", "accepted", None)
    assert unmatched("ExitObserved", prior=False)[1:] == (
        "exit_without_entry",
        "rejected_transition",
        "exit_without_entry",
    )
    assert (
        unmatched("ExitObserved", source="supervisor_override", prior=True)[1]
        == "edge_movement_exit"
    )
