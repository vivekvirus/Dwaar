"""Decision engine: deterministic, local, never an automatic allow on timeout (INV-03, GATE-06, GATE-14, EDGE-05)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dwaar_common.timeutil import format_iso_utc
from dwaar_edge.decision import (
    Decision,
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
from tests.integration.edge_gateway.support import START, World

from .helpers import bundle, clock, req

pytestmark = [pytest.mark.req("GATE-06", "INV-03")]

W = World()
H = timedelta(hours=1)


def resident_bundle(**res_kw: object) -> object:
    return bundle(W, W.manifest(residents=[W.resident(**res_kw)]))


def decide_res(
    b: object,
    now: datetime,
    *,
    ref: str = "cred-r1",
    ver: int = 1,
    **ck: object,
) -> Decision:
    return decide(b, req(ResidentCredential(ref, ver), W.gate_a, W.lane_a_in), clock(now, **ck))  # type: ignore[arg-type]


# ---- resident ------------------------------------------------------------------------------------
def test_resident_valid_is_allowed_locally() -> None:
    d = decide_res(resident_bundle(), START + H)
    assert d.outcome is Outcome.ALLOW and d.reason_code == "resident_valid" and d.automatic
    assert not d.review_required
    assert d.to_json()["auto_allow_on_timeout"] is False


def test_revoked_status_and_revocation_list_deny() -> None:
    assert decide_res(resident_bundle(status="revoked"), START).outcome is Outcome.DENY
    b = bundle(
        W, W.manifest(residents=[W.resident()], revocations=[{"ref": "cred-r1", "version": 1}])
    )
    d = decide_res(b, START, ver=1)
    assert d.outcome is Outcome.DENY and d.reason_code == "credential_revoked"
    # a re-issued credential with a higher revocation version is not caught by the older revocation
    assert decide_res(b, START, ver=2).outcome is Outcome.ALLOW


def test_superseded_version_is_denied() -> None:
    b = resident_bundle(revocation_version=3)
    d = decide_res(b, START, ver=2)
    assert d.outcome is Outcome.DENY and d.reason_code == "credential_superseded"


def test_suspended_needs_guard_unknown_needs_guard() -> None:
    assert decide_res(resident_bundle(status="suspended"), START).outcome is Outcome.NEEDS_GUARD
    d = decide_res(resident_bundle(), START, ref="nobody")
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "unknown_credential"


def test_credential_window_guard_assisted_not_lockout() -> None:
    b = resident_bundle(valid_until=format_iso_utc(START + H))
    assert decide_res(b, START + 2 * H).outcome is Outcome.NEEDS_GUARD
    b2 = resident_bundle(valid_from=format_iso_utc(START + 3 * H))
    assert decide_res(b2, START + H).outcome is Outcome.NEEDS_GUARD


def test_resident_72h_policy_age_boundary() -> None:
    b = resident_bundle()
    assert (
        decide_res(b, START + timedelta(hours=72), unc=0).outcome is Outcome.ALLOW
    )  # exactly at the limit
    assert (
        decide_res(b, START + timedelta(hours=72)).outcome is Outcome.NEEDS_GUARD
    )  # 50 ms of uncertainty tips it over
    d = decide_res(b, START + timedelta(hours=72, seconds=1), unc=0)
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "policy_stale_resident"
    assert d.fallback_options  # explicit guard-assisted options, never a silent lockout


def test_confirmation_resets_policy_age_but_not_beyond_valid_until() -> None:
    b = bundle(W, W.manifest(residents=[W.resident()]), confirmed_at=START + timedelta(hours=70))
    assert (
        decide_res(b, START + timedelta(hours=100)).outcome is Outcome.NEEDS_GUARD
    )  # 30 h old but valid_until (96 h) passed
    assert decide_res(b, START + timedelta(hours=95)).outcome is Outcome.ALLOW


def test_policy_expired_needs_guard() -> None:
    b = bundle(W, W.manifest(residents=[W.resident()]), valid_for=timedelta(hours=2))
    d = decide_res(b, START + 3 * H)
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "policy_expired"


def test_no_policy_never_allows_entry() -> None:
    d = decide(None, req(ResidentCredential("x", 1), W.gate_a, W.lane_a_in), clock(START))
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "no_policy"


def test_exit_lane_always_allows_even_without_clock_or_fresh_policy() -> None:
    b = resident_bundle()
    far = START + timedelta(days=30)
    d = decide(
        b,
        req(UnknownCredential(), W.gate_a, W.lane_a_out),
        clock(far, trusted=False, unc=86_400_000, back=True),
    )
    assert d.outcome is Outcome.ALLOW and d.reason_code == "egress_always_permitted"


def test_unknown_lane_or_gate_mismatch_denied() -> None:
    b = resident_bundle()
    assert (
        decide(
            b, req(ResidentCredential("cred-r1", 1), W.gate_b, W.lane_a_in), clock(START)
        ).outcome
        is Outcome.DENY
    )
    assert (
        decide(
            b, req(ResidentCredential("cred-r1", 1), W.gate_a, uuid.uuid4()), clock(START)
        ).outcome
        is Outcome.DENY
    )


def test_resident_with_untrusted_clock_flags_review_but_is_not_locked_out() -> None:
    d = decide_res(resident_bundle(), START + H, trusted=False, unc=86_400_000)
    assert d.outcome is Outcome.ALLOW and d.review_required
    assert "clock_untrusted" in d.evidence["clock_flags"]


def test_resident_boundary_ambiguity_with_trusted_uncertainty_goes_to_guard() -> None:
    b = resident_bundle(valid_until=format_iso_utc(START + H))
    d = decide_res(b, START + H - timedelta(seconds=10), unc=30_000)
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "clock_boundary_uncertain"


def test_invalid_credential_denied() -> None:
    d = decide(resident_bundle(), req(InvalidCredential("x"), W.gate_a, W.lane_a_in), clock(START))  # type: ignore[arg-type]
    assert d.outcome is Outcome.DENY and d.reason_code == "invalid_credential"


# ---- guest pass ------------------------------------------------------------------------------------
INV = uuid.uuid4()
NONCE = "nonce-abcdefgh"


def guest_bundle(
    *,
    gate: uuid.UUID | None = W.gate_a,
    start: datetime = START,
    end: datetime = START + 2 * H,
    max_uses: int = 1,
    uses_remaining: int | None = None,
    timing: dict[str, object] | None = None,
    **kw: object,
) -> object:
    inv = W.invitation(
        INV, gate=gate, start=start, end=end, max_uses=max_uses, uses_remaining=uses_remaining, **kw
    )
    return bundle(W, W.manifest(invitations=[inv], timing=W.timing(**(timing or {}))))


def decide_guest(
    b: object,
    now: datetime,
    *,
    gate: uuid.UUID | None = None,
    lane: uuid.UUID | None = None,
    nonce: str = NONCE,
    ledger: LedgerView | None = None,
    mode: OperatingMode = OperatingMode.NORMAL,
    **ck: object,
) -> Decision:
    g = gate or W.gate_a
    ln = lane or (W.lane_a_in if g == W.gate_a else W.lane_b_in)
    return decide(b, req(GuestPass(INV, nonce), g, ln, mode=mode, ledger=ledger), clock(now, **ck))  # type: ignore[arg-type]


def test_guest_valid_at_assigned_gate() -> None:
    d = decide_guest(guest_bundle(), START + timedelta(minutes=10))
    assert d.outcome is Outcome.ALLOW and d.consumes_pass


@pytest.mark.req("EDGE-05")
def test_guest_wrong_gate_requires_supervisor_confirmation() -> None:
    d = decide_guest(guest_bundle(gate=W.gate_a), START + timedelta(minutes=5), gate=W.gate_b)
    assert (
        d.outcome is Outcome.NEEDS_SUPERVISOR
        and d.reason_code == "wrong_gate"
        and d.review_required
    )


def test_guest_bad_nonce_and_revoked_denied() -> None:
    assert decide_guest(guest_bundle(), START, nonce="wrong-nonce-xx").reason_code == "bad_nonce"
    assert decide_guest(guest_bundle(revoked_version=2), START).reason_code == "pass_revoked"


def test_guest_window_expired_or_not_started_needs_confirmation() -> None:
    b = guest_bundle(start=START + H, end=START + 2 * H)
    assert decide_guest(b, START).outcome is Outcome.NEEDS_GUARD
    assert decide_guest(b, START + 3 * H).outcome is Outcome.NEEDS_GUARD
    assert decide_guest(b, START + 3 * H).reason_code == "pass_window_invalid"


@pytest.mark.req("EDGE-05")
def test_guest_offline_entitlement_max_two_hours_even_if_policy_says_more() -> None:
    b = guest_bundle(
        end=START + 10 * H, timing={"guest_offline_max_s": 86_400}
    )  # society asks for 24 h: capped at 2 h
    assert decide_guest(b, START + timedelta(hours=2), unc=0).outcome is Outcome.ALLOW
    d = decide_guest(b, START + timedelta(hours=2, seconds=1), unc=0)
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "policy_stale_guest"


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"back": True}, "clock_jumped_backwards"),
        ({"fwd": True}, "clock_jumped_forwards"),
        ({"unc": 60_001}, "clock_uncertainty_exceeded"),
        ({"trusted": False, "unc": 86_400_000}, "restart_without_trusted_time"),
    ],
)
def test_guest_clock_faults_disable_automatic_approval(kw: dict[str, object], reason: str) -> None:
    d = decide_guest(guest_bundle(), START + timedelta(minutes=5), **kw)
    assert d.outcome is Outcome.NEEDS_SUPERVISOR and d.reason_code == reason and d.review_required


def test_guest_uncertainty_at_exactly_60s_is_still_automatic() -> None:
    assert (
        decide_guest(guest_bundle(), START + timedelta(minutes=5), unc=60_000).outcome
        is Outcome.ALLOW
    )


def test_guest_uncertainty_limit_in_policy_can_only_tighten() -> None:
    b = guest_bundle(timing={"clock_uncertainty_limit_ms": 1_000_000})
    assert (
        decide_guest(b, START + timedelta(minutes=5), unc=61_000).outcome
        is Outcome.NEEDS_SUPERVISOR
    )
    b2 = guest_bundle(timing={"clock_uncertainty_limit_ms": 5_000})
    assert (
        decide_guest(b2, START + timedelta(minutes=5), unc=6_000).outcome
        is Outcome.NEEDS_SUPERVISOR
    )


def test_single_use_replay_denied_and_in_use_distinguished() -> None:
    b = guest_bundle()
    used = decide_guest(b, START + timedelta(minutes=5), ledger=LedgerView(used_total=1))
    assert used.outcome is Outcome.DENY and used.reason_code == "pass_replay_consumed"
    held = decide_guest(
        b, START + timedelta(minutes=5), ledger=LedgerView(used_total=1, held_by_other=True)
    )
    assert held.reason_code == "pass_in_use"
    again = decide_guest(
        b, START + timedelta(minutes=5), ledger=LedgerView(used_total=0, held_by_requester=True)
    )
    assert again.outcome is Outcome.ALLOW


def test_cloud_uses_remaining_zero_is_also_consumed() -> None:
    d = decide_guest(guest_bundle(uses_remaining=0), START + timedelta(minutes=5))
    assert d.outcome is Outcome.DENY and d.reason_code == "pass_replay_consumed"


def test_multi_use_quota() -> None:
    b = guest_bundle(max_uses=3)
    assert (
        decide_guest(b, START + timedelta(minutes=1), ledger=LedgerView(used_total=2)).outcome
        is Outcome.ALLOW
    )
    d = decide_guest(b, START + timedelta(minutes=1), ledger=LedgerView(used_total=3))
    assert d.outcome is Outcome.DENY and d.reason_code == "pass_quota_exhausted"


def test_qr_window_and_signature_flags() -> None:
    b = guest_bundle()
    r = req(GuestPass(INV, NONCE, qr_signature_ok=False), W.gate_a, W.lane_a_in)
    assert decide(b, r, clock(START)).reason_code == "bad_signature"  # type: ignore[arg-type]
    narrow = GuestPass(INV, NONCE, qr_signature_ok=True, qr_expires=START + timedelta(minutes=10))
    d = decide(b, req(narrow, W.gate_a, W.lane_a_in), clock(START + timedelta(minutes=20)))  # type: ignore[arg-type]
    assert d.reason_code == "pass_window_invalid"


def test_unknown_pass_needs_fallback_not_allow() -> None:
    d = decide(
        guest_bundle(), req(GuestPass(uuid.uuid4(), NONCE), W.gate_a, W.lane_a_in), clock(START)
    )  # type: ignore[arg-type]
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "unknown_pass"


# ---- restricted standalone (gateway lost / LAN split) -------------------------------------------------------
def test_standalone_gate_bound_single_use_is_local_and_consumed_once() -> None:
    b = guest_bundle(gate=W.gate_a)
    ok = decide_guest(b, START + timedelta(minutes=5), mode=OperatingMode.RESTRICTED_STANDALONE)
    assert ok.outcome is Outcome.ALLOW
    again = decide_guest(
        b,
        START + timedelta(minutes=6),
        mode=OperatingMode.RESTRICTED_STANDALONE,
        ledger=LedgerView(used_total=1, used_at_gate=1),
    )
    assert again.reason_code == "pass_replay_consumed"


def test_standalone_gate_agnostic_single_use_cannot_be_guaranteed() -> None:
    b = guest_bundle(gate=None)
    d = decide_guest(b, START + timedelta(minutes=5), mode=OperatingMode.RESTRICTED_STANDALONE)
    assert (
        d.outcome is Outcome.NEEDS_SUPERVISOR
        and d.reason_code == "global_single_use_not_guaranteed"
    )
    # while the gateway is the arbiter, the same pass is fine at any gate
    assert decide_guest(b, START + timedelta(minutes=5)).outcome is Outcome.ALLOW


def test_standalone_multi_use_needs_escrow() -> None:
    b = guest_bundle(gate=None, max_uses=4)
    t = START + timedelta(minutes=5)
    m = OperatingMode.RESTRICTED_STANDALONE
    assert decide_guest(b, t, mode=m).reason_code == "no_escrow_allocation"
    assert (
        decide_guest(b, t, mode=m, ledger=LedgerView(escrow_allocated=2, used_at_gate=1)).outcome
        is Outcome.ALLOW
    )
    d = decide_guest(b, t, mode=m, ledger=LedgerView(escrow_allocated=2, used_at_gate=2))
    assert d.outcome is Outcome.DENY and d.reason_code == "pass_quota_exhausted"


# ---- standing rules (GATE-14) --------------------------------------------------------------------------------
def rule(kind: str, category: str, start: str, end: str, **kw: object) -> dict[str, object]:
    return {
        "unit_id": str(W.unit_1),
        "rule_kind": kind,
        "params": {"category": category, "start_local": start, "end_local": end},
        "effective_from": None,
        "effective_to": None,
        **kw,
    }


def standing(
    rules: list[dict[str, object]], category: str, at_utc: datetime, **ck: object
) -> Decision:
    b = bundle(W, W.manifest(rules=rules), issued_at=at_utc - timedelta(minutes=1))
    return decide(
        b, req(StandingVisitor(W.unit_1, category), W.gate_a, W.lane_a_in), clock(at_utc, **ck)
    )  # type: ignore[arg-type]


IST_0630 = datetime(2026, 10, 5, 1, 0, tzinfo=UTC)  # 06:30 IST
IST_2230 = datetime(2026, 10, 5, 17, 0, tzinfo=UTC)  # 22:30 IST


@pytest.mark.req("GATE-14")
def test_milk_vendor_daily_6_to_7_allowed_only_in_window() -> None:
    rules = [rule("allow_window", "milk_vendor", "06:00", "07:00")]
    assert standing(rules, "milk_vendor", IST_0630).outcome is Outcome.ALLOW
    assert (
        standing(rules, "milk_vendor", IST_0630 + timedelta(hours=1)).outcome is Outcome.NEEDS_GUARD
    )
    assert standing(rules, "plumber", IST_0630).outcome is Outcome.NEEDS_GUARD


@pytest.mark.req("GATE-14")
def test_food_delivery_after_10pm_leave_at_gate_wraps_midnight() -> None:
    rules = [rule("leave_at_gate", "food_delivery", "22:00", "06:00")]
    d = standing(rules, "food_delivery", IST_2230)
    assert d.outcome is Outcome.NEEDS_GUARD and d.reason_code == "standing_rule_leave_at_gate"
    assert d.evidence["action"] == "leave_at_gate"
    assert (
        standing(rules, "food_delivery", IST_0630 + timedelta(hours=3)).reason_code
        == "no_local_entitlement"
    )


@pytest.mark.req("GATE-14")
def test_standing_deny_beats_allow_and_clock_fault_blocks_automatic_allow() -> None:
    rules = [
        rule("allow_window", "x", "00:00", "23:59"),
        rule("deny_category", "x", "00:00", "23:59"),
    ]
    assert standing(rules, "x", IST_0630).outcome is Outcome.DENY
    d = standing([rule("allow_window", "x", "00:00", "23:59")], "x", IST_0630, back=True)
    assert d.outcome is Outcome.NEEDS_SUPERVISOR


@pytest.mark.req("GATE-14")
def test_malformed_standing_rule_grants_nothing() -> None:
    bad = {
        "unit_id": str(W.unit_1),
        "rule_kind": "allow_window",
        "params": {"category": "x", "start_local": "6am", "end_local": "7am"},
        "effective_from": None,
        "effective_to": None,
    }
    assert standing([bad], "x", IST_0630).outcome is Outcome.NEEDS_GUARD


@pytest.mark.req("GATE-14")
def test_standing_rule_effective_window_respected() -> None:
    r = rule(
        "allow_window",
        "x",
        "00:00",
        "23:59",
        effective_to=format_iso_utc(IST_0630 - timedelta(days=1)),
    )
    assert standing([r], "x", IST_0630).outcome is Outcome.NEEDS_GUARD


# ---- property tests --------------------------------------------------------------------------------------------
SETTINGS = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
secs = st.integers(min_value=0, max_value=130 * 3600)


@SETTINGS
@given(
    status=st.sampled_from(["active", "suspended", "revoked"]),
    cred_ver=st.integers(0, 4),
    res_ver=st.integers(0, 4),
    revoked_at=st.one_of(st.none(), st.integers(0, 4)),
    vf=st.one_of(st.none(), st.integers(-50 * 3600, 50 * 3600)),
    vu=st.one_of(st.none(), st.integers(-50 * 3600, 50 * 3600)),
    policy_valid_h=st.integers(1, 120),
    age_s=secs,
    trusted=st.booleans(),
    unc=st.sampled_from([0, 50, 5_000, 59_999, 60_001, 86_400_000]),
    back=st.booleans(),
    fwd=st.booleans(),
    limit_h=st.integers(1, 100),
)
def test_property_resident_allow_implies_every_condition(**p: object) -> None:  # type: ignore[no-untyped-def]
    now = START + timedelta(seconds=int(p["age_s"]))  # type: ignore[arg-type]
    res = W.resident(
        status=p["status"],
        revocation_version=p["res_ver"],
        valid_from=None
        if p["vf"] is None
        else format_iso_utc(now + timedelta(seconds=int(p["vf"]))),  # type: ignore[arg-type]
        valid_until=None
        if p["vu"] is None
        else format_iso_utc(now + timedelta(seconds=int(p["vu"]))),  # type: ignore[arg-type]
    )
    revs = [] if p["revoked_at"] is None else [{"ref": "cred-r1", "version": p["revoked_at"]}]
    timing = W.timing(
        resident_offline_validity_s=int(p["limit_h"]) * 3600,
        policy_age_limit_s=int(p["limit_h"]) * 3600,
    )  # type: ignore[arg-type]
    b = bundle(
        W,
        W.manifest(residents=[res], revocations=revs, timing=timing),
        valid_for=timedelta(hours=int(p["policy_valid_h"])),
    )  # type: ignore[arg-type]
    ck = clock(
        now, unc=int(p["unc"]), trusted=bool(p["trusted"]), back=bool(p["back"]), fwd=bool(p["fwd"])
    )  # type: ignore[arg-type]
    d = decide(b, req(ResidentCredential("cred-r1", int(p["cred_ver"])), W.gate_a, W.lane_a_in), ck)  # type: ignore[arg-type]
    assert d == decide(
        b, req(ResidentCredential("cred-r1", int(p["cred_ver"])), W.gate_a, W.lane_a_in), ck
    )  # type: ignore[arg-type]  # deterministic
    if d.outcome is Outcome.ALLOW:
        assert p["status"] == "active"
        assert p["revoked_at"] is None or int(p["cred_ver"]) > int(p["revoked_at"])  # type: ignore[arg-type]
        assert int(p["cred_ver"]) >= int(p["res_ver"])  # type: ignore[arg-type]
        assert now <= b.valid_until  # type: ignore[attr-defined]
        assert b.age(now) <= timedelta(hours=int(p["limit_h"]))  # type: ignore[attr-defined]
        assert b.age(now) <= timedelta(hours=72)  # type: ignore[attr-defined]  # hard cap
        if p["vf"] is not None:
            assert int(p["vf"]) <= 0  # type: ignore[arg-type]
        if p["vu"] is not None:
            assert int(p["vu"]) >= 0  # type: ignore[arg-type]


@SETTINGS
@given(
    inv_gate=st.sampled_from(["a", "b", None]),
    at_gate=st.sampled_from(["a", "b"]),
    nonce_ok=st.booleans(),
    revoked=st.one_of(st.none(), st.integers(0, 3)),
    start_off=st.integers(-3 * 3600, 3 * 3600),
    dur=st.integers(60, 6 * 3600),
    age_s=st.integers(0, 4 * 3600),
    max_uses=st.integers(1, 4),
    used=st.integers(0, 5),
    cloud_remaining=st.integers(0, 4),
    trusted=st.booleans(),
    unc=st.sampled_from([0, 100, 60_000, 60_001, 300_000]),
    back=st.booleans(),
    fwd=st.booleans(),
    mode=st.sampled_from([OperatingMode.NORMAL, OperatingMode.RESTRICTED_STANDALONE]),
    escrow=st.one_of(st.none(), st.integers(0, 3)),
    policy_guest_s=st.integers(0, 86_400),
)
def test_property_guest_allow_implies_every_condition(**p: object) -> None:  # type: ignore[no-untyped-def]
    gates = {"a": W.gate_a, "b": W.gate_b, None: None}
    now = START + timedelta(seconds=int(p["age_s"]))  # type: ignore[arg-type]
    max_uses = int(p["max_uses"])  # type: ignore[arg-type]
    remaining = min(int(p["cloud_remaining"]), max_uses)  # type: ignore[arg-type]
    inv = W.invitation(
        INV,
        gate=gates[p["inv_gate"]],  # type: ignore[index]
        start=now + timedelta(seconds=int(p["start_off"])),  # type: ignore[arg-type]
        end=now + timedelta(seconds=int(p["start_off"]) + int(p["dur"])),  # type: ignore[arg-type]
        max_uses=max_uses,
        uses_remaining=remaining,
        revoked_version=p["revoked"],
    )
    b = bundle(
        W,
        W.manifest(
            invitations=[inv], timing=W.timing(guest_offline_max_s=int(p["policy_guest_s"]))
        ),
    )  # type: ignore[arg-type]
    gate = gates[p["at_gate"]]  # type: ignore[index]
    lane = W.lane_a_in if p["at_gate"] == "a" else W.lane_b_in
    nonce = NONCE if p["nonce_ok"] else "not-the-nonce"
    ledger = LedgerView(
        used_total=int(p["used"]), used_at_gate=int(p["used"]), escrow_allocated=p["escrow"]
    )  # type: ignore[arg-type]
    ck = clock(
        now, unc=int(p["unc"]), trusted=bool(p["trusted"]), back=bool(p["back"]), fwd=bool(p["fwd"])
    )  # type: ignore[arg-type]
    d = decide(b, req(GuestPass(INV, nonce), gate, lane, mode=p["mode"], ledger=ledger), ck)  # type: ignore[arg-type]
    if d.outcome is Outcome.ALLOW:
        assert p["nonce_ok"]
        assert p["revoked"] is None or int(p["revoked"]) == 0  # type: ignore[arg-type]
        assert p["inv_gate"] is None or p["inv_gate"] == p["at_gate"]  # never wrong-gate
        assert p["trusted"] and not p["back"] and not p["fwd"] and int(p["unc"]) <= 60_000  # type: ignore[arg-type]
        assert inv["window_start"] <= format_iso_utc(now) <= inv["window_end"]
        assert b.age(now) <= timedelta(seconds=min(int(p["policy_guest_s"]), 7200))  # type: ignore[attr-defined,arg-type]
        if p["mode"] is OperatingMode.RESTRICTED_STANDALONE and p["inv_gate"] is None:
            assert p["escrow"] is not None and int(p["escrow"]) > int(p["used"])  # type: ignore[arg-type]
        elif p["mode"] is OperatingMode.NORMAL or p["inv_gate"] is not None:
            assert max_uses - max(max_uses - remaining, int(p["used"])) >= 1  # type: ignore[arg-type]


@SETTINGS
@given(
    cred=st.sampled_from(["resident", "guest", "unknown", "standing"]),
    age_s=st.integers(0, 200 * 3600),
)
def test_property_nothing_allows_entry_without_a_policy(cred: str, age_s: int) -> None:
    c = {
        "resident": ResidentCredential("cred-r1", 1),
        "guest": GuestPass(INV, NONCE),
        "unknown": UnknownCredential(),
        "standing": StandingVisitor(W.unit_1, "x"),
    }[cred]
    d = decide(None, req(c, W.gate_a, W.lane_a_in), clock(START + timedelta(seconds=age_s)))  # type: ignore[arg-type]
    assert d.outcome is not Outcome.ALLOW


def test_engine_is_pure_no_clock_or_io() -> None:
    """The engine module must not import time, os, socket, sqlite3 or random: it cannot depend on a timeout."""
    import dwaar_edge.decision as mod

    src = open(mod.__file__).read()  # noqa: SIM115, PTH123
    for forbidden in (
        "import time",
        "import os",
        "import socket",
        "sqlite3",
        "import random",
        "datetime.now",
        "utcnow",
        "monotonic",
    ):
        assert forbidden not in src, forbidden
