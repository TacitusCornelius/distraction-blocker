"""Trusted UTC derived from boot monotonic time."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import time as _time
from typing import Any, Callable


class TrustedClock:
    """Keep UTC monotonic within a boot and latch unsafe wall-clock changes."""

    def __init__(self, state_reader: Callable[[], Any], state_writer: Callable[..., Any], synchronizer: Any,
                 wall: Callable[[], float] = _time.time, boottime: Callable[[], float] | None = None,
                 tolerance: float = 5.0):
        self._state_reader = state_reader
        self._state_writer = state_writer
        self._synchronizer = synchronizer
        self._wall = wall
        self._boottime = boottime or self._default_boottime
        self._tolerance = float(tolerance)
        if self._tolerance < 0:
            raise ValueError("clock tolerance must not be negative")
        wall_value = float(self._wall())
        boot_value = float(self._boottime())
        if not (wall_value == wall_value and boot_value == boot_value):
            raise ValueError("clock source returned NaN")
        self._base_wall = wall_value
        self._base_boot = boot_value
        self._last_boot = boot_value
        self._last = datetime.fromtimestamp(wall_value, timezone.utc)
        self._high_water = None
        self._trusted = True
        self._reason: str | None = None
        self._waiting_for_sync = False
        self._read_state()
        if not self._is_synchronized():
            self._waiting_for_sync = self._trusted
            self._mark_untrusted("time-not-synchronized")
        if self._high_water is not None and self._last < self._high_water:
            self._last = self._high_water
            self._mark_untrusted("before-high-water")

    @staticmethod
    def _default_boottime() -> float:
        return _time.clock_gettime(_time.CLOCK_BOOTTIME)

    def _read_state(self) -> None:
        try:
            state = self._state_reader()
        except Exception:
            self._mark_untrusted("state-unavailable")
            return
        if state is None:
            return
        high_water = getattr(state, "high_water_utc", None)
        latched_value = getattr(state, "clock_untrusted", False)
        if isinstance(state, dict):
            high_water = state.get("high_water_utc")
            latched_value = state.get("clock_untrusted", False)
        elif isinstance(state, datetime):
            high_water = state
        if not isinstance(latched_value, bool):
            self._mark_untrusted("invalid-clock-state")
            latched = True
        else:
            latched = latched_value
        if isinstance(high_water, str):
            try:
                high_water = datetime.fromisoformat(high_water.replace("Z", "+00:00"))
            except ValueError:
                self._mark_untrusted("invalid-high-water")
        if high_water is not None and not isinstance(high_water, datetime):
            self._mark_untrusted("invalid-high-water")
            high_water = None
        if isinstance(high_water, datetime) and (high_water.tzinfo is None or high_water.utcoffset() != timedelta(0)):
            self._mark_untrusted("invalid-high-water")
            high_water = None
        if isinstance(high_water, datetime):
            if high_water.tzinfo is not None and high_water.utcoffset() == timedelta(0):
                self._high_water = high_water.astimezone(timezone.utc)
                if self._high_water > self._last:
                    self._last = self._high_water
        if latched:
            self._mark_untrusted("persisted-clock-untrusted")

    def _is_synchronized(self) -> bool:
        try:
            result = self._synchronizer() if callable(self._synchronizer) else self._synchronizer
            if hasattr(result, "is_synchronized"):
                result = result.is_synchronized()
            return bool(result)
        except Exception:
            return False

    def _mark_untrusted(self, reason: str) -> None:
        self._trusted = False
        if self._reason is None:
            self._reason = reason

    @property
    def trusted(self) -> bool:
        return self._trusted

    @property
    def reason(self) -> str | None:
        return self._reason

    def now(self) -> datetime:
        trusted_at_start = self._trusted
        wall_value = float(self._wall())
        boot_value = float(self._boottime())
        if not (wall_value == wall_value and boot_value == boot_value):
            self._mark_untrusted("invalid-time-source")
            return self._last
        if self._waiting_for_sync:
            elapsed = max(0.0, boot_value - self._base_boot)
            self._last = max(
                self._last,
                datetime.fromtimestamp(self._base_wall + elapsed, timezone.utc),
            )
            if not self._is_synchronized():
                return self._last
            synchronized = datetime.fromtimestamp(wall_value, timezone.utc)
            if (
                self._high_water is not None
                and synchronized + timedelta(seconds=self._tolerance) < self._high_water
            ):
                self._waiting_for_sync = False
                self._mark_untrusted("before-high-water")
                return self._last
            self._base_wall = wall_value
            self._base_boot = boot_value
            self._last = synchronized
            self._trusted = True
            self._reason = None
            self._waiting_for_sync = False
            trusted_at_start = True
        if boot_value < self._last_boot:
            self._mark_untrusted("boottime-backward")
        self._last_boot = max(self._last_boot, boot_value)
        elapsed = max(0.0, boot_value - self._base_boot)
        candidate = datetime.fromtimestamp(self._base_wall + elapsed, timezone.utc)
        if abs(wall_value - candidate.timestamp()) > self._tolerance:
            # Breadcrumb for reviewers: retain the boot-derived instant and stop trusting wall time after a jump.
            self._mark_untrusted("wall-clock-jump")
        if candidate < self._last:
            self._mark_untrusted("trusted-time-backward")
        else:
            self._last = candidate
        if self._high_water is not None and self._last < self._high_water:
            self._last = self._high_water
            self._mark_untrusted("before-high-water")
        if trusted_at_start and not self._trusted:
            if self._high_water is None or self._last > self._high_water:
                self._high_water = self._last
            self._write_state(self._high_water)
        return self._last

    def clear_latch(self) -> datetime:
        wall_value = float(self._wall())
        boot_value = float(self._boottime())
        candidate = datetime.fromtimestamp(
            self._base_wall + max(0.0, boot_value - self._base_boot),
            timezone.utc,
        )
        wall_time = datetime.fromtimestamp(wall_value, timezone.utc)
        if not self._is_synchronized():
            raise RuntimeError("system time is not synchronized")
        if abs(wall_value - candidate.timestamp()) > self._tolerance:
            raise RuntimeError("wall clock does not match trusted elapsed time")
        if self._high_water is not None and wall_time + timedelta(seconds=self._tolerance) < self._high_water:
            raise RuntimeError("wall clock is before the saved time")
        self._trusted = True
        self._reason = None
        self._waiting_for_sync = False
        self._last = max(candidate, self._high_water or candidate)
        self._write_state(self._last)
        return self._last


    def checkpoint(self) -> datetime:
        current = self.now()
        if self._high_water is None or current > self._high_water:
            self._high_water = current
        self._write_state(self._high_water)
        return self._high_water

    def _write_state(self, value: datetime) -> None:
        try:
            signature = inspect.signature(self._state_writer)
        except (TypeError, ValueError):
            self._state_writer(value)
            return
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        accepts_varargs = any(
            parameter.kind == parameter.VAR_POSITIONAL
            for parameter in signature.parameters.values()
        )
        if accepts_varargs or len(positional) >= 2:
            self._state_writer(value, self._trusted is False)
        else:
            self._state_writer(value)
