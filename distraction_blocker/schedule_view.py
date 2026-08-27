"""Pure schedule projection shared by the GUI, the service, and the CLI.

This module owns the state-change and daily-overview arithmetic. It imports
only the policy model and the standard library, so the root service never
loads a GUI binding to answer a schedule request.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import os
from collections.abc import Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import MAX_POMODORO_CYCLES, MAX_WEEKLY_PERIODS, Rule

UTC = timezone.utc

MAX_DAILY_TRANSITIONS = max(MAX_WEEKLY_PERIODS * 2 + 2, MAX_POMODORO_CYCLES * 2)


class ScheduleViewError(ValueError):
    """A schedule projection input does not name a usable time or zone."""


@dataclass(frozen=True)
class StateChange:
    at_utc: datetime
    active_after: bool


@dataclass(frozen=True)
class DailyInterval:
    """One enabled rule interval in the selected local day."""

    rule_id: str
    rule_name: str
    start_local: datetime
    end_local: datetime


def system_timezone_name() -> str:
    """Get the IANA name of the Ubuntu local time zone."""
    configured = os.environ.get("TZ")
    if configured:
        try:
            ZoneInfo(configured)
        except ZoneInfoNotFoundError:
            pass
        else:
            return configured
    local_zone = datetime.now().astimezone().tzinfo
    key = getattr(local_zone, "key", None)
    if isinstance(key, str):
        return key
    # Breadcrumb for reviewers: Python does not expose the local IANA name on
    # all versions. Ubuntu links /etc/localtime into the zoneinfo database.
    resolved = os.path.realpath("/etc/localtime")
    marker = f"{os.sep}zoneinfo{os.sep}"
    if marker in resolved:
        candidate = resolved.split(marker, 1)[1]
        try:
            ZoneInfo(candidate)
        except ZoneInfoNotFoundError:
            pass
        else:
            return candidate
    raise ScheduleViewError("The system time zone is not an IANA time zone.")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ScheduleViewError("The rule has an invalid UTC date.") from error
    if parsed.tzinfo is None:
        raise ScheduleViewError("The rule has a UTC date without a time zone.")
    return parsed.astimezone(UTC)


def _weekly_events(rule: Rule, now_utc: datetime) -> list[StateChange]:
    schedule = rule.to_dict()["schedule"]
    zone = ZoneInfo(schedule["timezone"])
    local_now = now_utc.astimezone(zone)
    candidates: set[datetime] = set()
    first_date = local_now.date() - timedelta(days=2)
    for period in schedule["periods"]:
        start_time = time.fromisoformat(period["start"])
        end_time = time.fromisoformat(period["end"])
        weekdays = set(period["weekdays"])
        for offset in range(12):
            start_date = first_date + timedelta(days=offset)
            if start_date.weekday() not in weekdays:
                continue
            end_date = (
                start_date if end_time > start_time else start_date + timedelta(days=1)
            )
            for local_date, local_time in (
                (start_date, start_time),
                (end_date, end_time),
            ):
                local_value = datetime.combine(local_date, local_time, zone)
                candidates.add(local_value.replace(fold=0).astimezone(UTC))
                candidates.add(local_value.replace(fold=1).astimezone(UTC))

    # Breadcrumb for reviewers: a DST fold can change schedule state between
    # two nominal boundaries, so include each real UTC offset transition.
    cursor = (now_utc.astimezone(UTC) - timedelta(days=2)).replace(
        minute=0, second=0, microsecond=0
    )
    limit = now_utc.astimezone(UTC) + timedelta(days=10)
    previous_offset = cursor.astimezone(zone).utcoffset()
    while cursor < limit:
        following = cursor + timedelta(hours=1)
        following_offset = following.astimezone(zone).utcoffset()
        if following_offset != previous_offset:
            low, high = cursor, following
            while high - low > timedelta(seconds=1):
                middle = low + (high - low) / 2
                if middle.astimezone(zone).utcoffset() == previous_offset:
                    low = middle
                else:
                    high = middle
            candidates.add(high)
        cursor = following
        previous_offset = following_offset

    events: list[StateChange] = []
    for instant in sorted(candidates):
        active_before = rule.is_active(instant - timedelta(microseconds=1))
        active_after = rule.is_active(instant)
        if active_before != active_after:
            events.append(StateChange(instant, active_after))
    return events


def next_state_change(
    rule: Rule, now_utc: datetime, clock_trusted: bool = True
) -> StateChange | None:
    """Find the next automatic state change."""
    if now_utc.tzinfo is None:
        raise ScheduleViewError("The current UTC date needs a time zone.")
    data = rule.to_dict()
    if not data["enabled"] or not clock_trusted:
        return None
    schedule_data = data["schedule"]
    kind = schedule_data["kind"]
    if kind == "indefinite":
        return None
    schedule = rule.schedule
    if kind == "one_time":
        start = schedule.start_utc
        end = schedule.end_utc
        if now_utc < start:
            return StateChange(start, True)
        if now_utc < end:
            return StateChange(end, False)
        return None
    if kind == "pomodoro":
        start = schedule.start_utc
        work = timedelta(minutes=schedule.work_minutes)
        rest = timedelta(minutes=schedule.break_minutes)
        cycles = schedule.cycles
        end = schedule.pomodoro_end_utc()
        if now_utc < start:
            return StateChange(start, True)
        if now_utc >= end:
            return None
        cycle_span = work + rest
        cycle_index = (now_utc - start) // cycle_span
        work_end = start + cycle_index * cycle_span + work
        if now_utc < work_end:
            return StateChange(work_end, False)
        return StateChange(start + (cycle_index + 1) * cycle_span, True)
    current = rule.is_active(now_utc, clock_trusted=True)
    events = sorted(
        (item for item in _weekly_events(rule, now_utc) if item.at_utc > now_utc),
        key=lambda item: item.at_utc,
    )
    return next((item for item in events if item.active_after != current), None)


def project_daily_schedule(
    rules: Sequence[Rule],
    local_day: date,
    timezone_name: str,
    exhausted_rule_ids: frozenset[str] | None = None,
) -> tuple[DailyInterval, ...]:
    """Project enabled rule intervals into one local day.

    Breadcrumb (allowance seam): a rule whose daily start budget is used up
    blocks regardless of its schedule windows or exceptions until the
    budget resets. The service passes those rule ids here; this pure
    function then pins each of them to one full-day interval so every
    viewer (GUI overview, CLI) sees the same ACTIVE-BLOCKING projection.
    """
    exhausted = exhausted_rule_ids or frozenset()
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ScheduleViewError("Select a valid IANA time zone.") from error
    day_start = datetime.combine(local_day, time.min, zone)
    day_end = datetime.combine(local_day + timedelta(days=1), time.min, zone)
    start_utc = day_start.astimezone(UTC)
    end_utc = day_end.astimezone(UTC)
    intervals: list[DailyInterval] = []
    for rule in rules:
        if not rule.enabled:
            continue
        # Breadcrumb: exhaustion overrides schedule evaluation entirely,
        # including untrusted-clock handling, until the day resets.
        if rule.id in exhausted:
            intervals.append(
                DailyInterval(rule.id, rule.name, day_start, day_end)
            )
            continue
        active = rule.is_active(start_utc, clock_trusted=True)
        interval_start = start_utc if active else None
        cursor = start_utc - timedelta(microseconds=1)
        for _index in range(MAX_DAILY_TRANSITIONS):
            change = next_state_change(rule, cursor, clock_trusted=True)
            if change is None or change.at_utc >= end_utc:
                break
            if change.active_after:
                if interval_start is None:
                    interval_start = max(change.at_utc, start_utc)
            elif interval_start is not None:
                intervals.append(
                    DailyInterval(
                        rule.id,
                        rule.name,
                        interval_start.astimezone(zone),
                        change.at_utc.astimezone(zone),
                    )
                )
                interval_start = None
            cursor = change.at_utc
        if interval_start is not None:
            intervals.append(
                DailyInterval(
                    rule.id,
                    rule.name,
                    interval_start.astimezone(zone),
                    day_end,
                )
            )
    return tuple(
        sorted(
            intervals,
            key=lambda item: (item.start_local, item.end_local, item.rule_name),
        )
    )
