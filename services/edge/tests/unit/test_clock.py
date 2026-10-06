"""Clock model: trusted sync + monotonic elapsed, uncertainty, jump detection (EDGE-05, AT-08, PRD 7.4)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from dwaar_edge.clock import UNKNOWN_UNCERTAINTY_MS, ClockModel
from tests.integration.edge_gateway.support import START, ManualTime

pytestmark = pytest.mark.req("EDGE-05")


def model(t: ManualTime, **kw: object) -> ClockModel:
    return ClockModel(wall=t.wall, mono=t.mono, **kw)  # type: ignore[arg-type]


def test_no_trusted_time_is_flagged_and_uncertainty_unknown() -> None:
    t = ManualTime()
    s = model(t).assess()
    assert not s.trusted and s.restarted_without_trusted_time
    assert s.uncertainty_ms == UNKNOWN_UNCERTAINTY_MS
    assert s.guest_block_reason(60_000) == "restart_without_trusted_time"


def test_trusted_anchor_plus_monotonic_elapsed() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 40)
    t.advance(3600)
    s = c.assess()
    assert s.trusted and s.now == START + timedelta(hours=1)
    assert 40 < s.uncertainty_ms < 1000  # sample uncertainty + 100 ppm drift over an hour (360 ms)
    assert s.guest_block_reason(60_000) is None


def test_uncertainty_grows_with_drift_until_it_disables_guests() -> None:
    t = ManualTime()
    c = model(t, drift_ppm=1000)  # a poor oscillator: 1 ms of uncertainty per 1000 s
    c.sync(START, 59_000)
    t.advance(500)
    assert c.assess().guest_block_reason(60_000) is None
    t.advance(1_600)
    s = c.assess()
    assert (
        s.uncertainty_ms > 60_000 and s.guest_block_reason(60_000) == "clock_uncertainty_exceeded"
    )


def test_72h_without_sync_at_default_drift_stays_below_60s() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 500)
    t.advance(72 * 3600)
    assert c.assess().uncertainty_ms < 60_000  # 500 ms + 72 h * 100 ppm = ~26 s


def test_wall_clock_moved_backwards_is_detected_and_does_not_move_estimate() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 50)
    t.advance(600)
    before = c.assess()
    t.step_wall(-3600)  # AT-08
    after = c.assess()
    assert after.wall_jumped_backwards
    assert after.now >= before.now  # the estimate comes from monotonic elapsed time, not the wall
    assert after.guest_block_reason(60_000) == "clock_jumped_backwards"


def test_backward_jump_latches_until_a_new_trusted_sync() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 50)
    t.step_wall(-120)
    assert c.assess().wall_jumped_backwards
    t.step_wall(
        +120
    )  # wall clock repaired by itself: the latch stays (it may have been abused meanwhile)
    assert c.assess().wall_jumped_backwards
    c.sync(t.wall_now, 50)
    assert not c.assess().wall_jumped_backwards


def test_forward_jump_also_disables_automatic_guest_decisions() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 50)
    t.step_wall(+7200)
    s = c.assess()
    assert s.wall_jumped_forwards and s.guest_block_reason(60_000) == "clock_jumped_forwards"


def test_small_wall_noise_is_not_a_jump() -> None:
    t = ManualTime()
    c = model(t)
    c.sync(START, 50)
    t.advance(10)
    t.step_wall(-1.0)  # within the 2 s tolerance
    assert not c.assess().wall_jumped_backwards


def test_untrusted_backward_wall_cannot_extend_windows_high_water_mark() -> None:
    t = ManualTime()
    hw = START + timedelta(hours=5)
    c = model(t, high_water=hw)  # persisted before a restart
    s = c.assess()
    assert s.now == hw  # never earlier than what was already observed
    assert s.wall_jumped_backwards and not s.trusted


def test_monotonic_across_assessments_without_anchor() -> None:
    t = ManualTime()
    c = model(t)
    seen = []
    for step in (10, 10, -500, 10):
        t.advance(10) if step > 0 else t.step_wall(step)
        seen.append(c.assess().now)
    assert seen == sorted(seen)
