"""Clock model: trusted sync time + monotonic elapsed time, with jump detection.

REQ: EDGE-05 (clock uncertainty above 60 s disables automatic time-sensitive guest approval; after a
restart without trusted time guest credentials need supervisor assistance), PRD 7.4 (offline ordering:
trusted sync time plus monotonic elapsed time; clock uncertainty recorded), AT-08.

The wall clock is NEVER trusted on its own. The estimate of "now" is

* with a trusted anchor (a sample from an authenticated cloud response or another trusted source):
  ``anchor_utc + (monotonic_now - anchor_monotonic)``; uncertainty = sample uncertainty + drift allowance;
* without an anchor (fresh process, no sync yet): ``max(wall, persisted high-water mark)``, flagged
  untrusted, uncertainty reported as "unknown" (24 h, the schema maximum).

A wall clock that disagrees with the estimate, or that steps relative to the monotonic clock, latches a
jump flag that only a new trusted sync clears. The estimate itself can never go backwards across a wall
clock step because it does not come from the wall clock once anchored, and before anchoring it is clamped
by the high-water mark, so a stepped-back wall clock cannot extend any validity window.
"""

# REQ: EDGE-05

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

UNKNOWN_UNCERTAINTY_MS: Final = 86_400_000  # schema maximum: "at least a day, treat as unknown"
DEFAULT_DRIFT_PPM: Final = 100  # allowance for oscillator drift between trusted syncs
DEFAULT_JUMP_TOLERANCE_MS: Final = 2_000


def system_wall() -> datetime:
    return datetime.now(UTC)


def system_mono() -> float:
    return time.monotonic()


@dataclass(frozen=True)
class ClockState:
    """Immutable view of the clock handed to the pure decision engine."""

    now: datetime
    uncertainty_ms: int
    trusted: bool
    wall_jumped_backwards: bool = False
    wall_jumped_forwards: bool = False
    restarted_without_trusted_time: bool = False

    def guest_block_reason(self, limit_ms: int) -> str | None:
        """Why automatic time-sensitive guest approval is disabled, or None if it may proceed."""
        if self.wall_jumped_backwards:
            return "clock_jumped_backwards"
        if self.wall_jumped_forwards:
            return "clock_jumped_forwards"
        if self.restarted_without_trusted_time or not self.trusted:
            return "restart_without_trusted_time"
        if self.uncertainty_ms > limit_ms:
            return "clock_uncertainty_exceeded"
        return None

    def flags(self, limit_ms: int) -> list[str]:
        out: list[str] = []
        if self.wall_jumped_backwards:
            out.append("clock_jumped_backwards")
        if self.wall_jumped_forwards:
            out.append("clock_jumped_forwards")
        if not self.trusted:
            out.append("clock_untrusted")
        elif self.uncertainty_ms > limit_ms:
            out.append("clock_uncertainty_exceeded")
        return out


@dataclass
class _Anchor:
    utc: datetime
    mono: float
    uncertainty_ms: int


@dataclass
class ClockModel:
    """Mutable clock owned by the gateway. All time sources are injectable (tests simulate 72 h)."""

    wall: Callable[[], datetime] = system_wall
    mono: Callable[[], float] = system_mono
    high_water: datetime | None = None
    drift_ppm: int = DEFAULT_DRIFT_PPM
    jump_tolerance_ms: int = DEFAULT_JUMP_TOLERANCE_MS
    _anchor: _Anchor | None = field(default=None, init=False, repr=False)
    _jump_back: bool = field(default=False, init=False)
    _jump_fwd: bool = field(default=False, init=False)
    _last_wall: datetime | None = field(default=None, init=False, repr=False)
    _last_mono: float | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    # -- trusted time ----------------------------------------------------------------------
    def sync(self, trusted_utc: datetime, uncertainty_ms: int) -> None:
        """Record a trusted time sample (``uncertainty_ms`` covers round trip and source resolution)."""
        if trusted_utc.tzinfo is None:
            raise ValueError("trusted time must be timezone-aware")
        with self._lock:
            self._anchor = _Anchor(trusted_utc.astimezone(UTC), self.mono(), max(0, uncertainty_ms))
            self._jump_back = False
            self._jump_fwd = False
            self._last_wall = self.wall()
            self._last_mono = self.mono()
            if self.high_water is None or trusted_utc > self.high_water:
                self.high_water = trusted_utc.astimezone(UTC)

    @property
    def has_trusted_time(self) -> bool:
        return self._anchor is not None

    # -- assessment ------------------------------------------------------------------------
    def assess(self) -> ClockState:
        """Best estimate of now plus every anomaly flag. Cheap; called on every decision and write."""
        with self._lock:
            wall = self.wall()
            mono = self.mono()
            tol = timedelta(milliseconds=self.jump_tolerance_ms)
            anchor = self._anchor
            # A step between two observations of (wall, monotonic): they must advance together.
            if self._last_wall is not None and self._last_mono is not None:
                wall_delta = wall - self._last_wall
                mono_delta = timedelta(seconds=mono - self._last_mono)
                step_tol = tol + mono_delta * self.drift_ppm // 1_000_000 * 2  # oscillator drift
                if wall_delta < mono_delta - step_tol:
                    self._jump_back = True
                elif wall_delta > mono_delta + step_tol:
                    self._jump_fwd = True
            self._last_wall, self._last_mono = wall, mono
            if anchor is not None:
                est = anchor.utc + timedelta(seconds=mono - anchor.mono)
                elapsed_s = max(0.0, mono - anchor.mono)
                unc = int(anchor.uncertainty_ms + elapsed_s * self.drift_ppm / 1000.0)
                wide = tol + timedelta(milliseconds=unc)
                if wall < est - wide:
                    self._jump_back = True
                elif wall > est + wide:
                    # the wall clock merely disagrees; the estimate does not use it, but it is worth a flag
                    self._jump_fwd = True
                trusted = True
            else:
                est = wall
                if self.high_water is not None and wall < self.high_water - tol:
                    self._jump_back = True
                if self.high_water is not None and est < self.high_water:
                    est = self.high_water  # never let a stepped-back wall clock extend a window
                unc = UNKNOWN_UNCERTAINTY_MS
                trusted = False
            if self.high_water is None or est > self.high_water:
                self.high_water = est
            return ClockState(
                now=est,
                uncertainty_ms=min(unc, UNKNOWN_UNCERTAINTY_MS),
                trusted=trusted,
                wall_jumped_backwards=self._jump_back,
                wall_jumped_forwards=self._jump_fwd,
                restarted_without_trusted_time=anchor is None,
            )
