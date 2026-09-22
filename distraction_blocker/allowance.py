"""Pure elapsed-time allowance arithmetic for weekly URL rules.

The root service will own persistence and reporting.  This module deliberately
only answers three questions: which concrete weekly occurrence is active, what
fixed-window bucket contains it, and how much budget remains after already
observed usage intervals.
"""
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import math
from collections.abc import Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

from . import canonical
from .model import Rule, Schedule, TimeAllowance, WeeklyPeriod

UTC = timezone.utc
_DAY = timedelta(days=1)


class AllowanceError(ValueError):
    """An allowance calculation input is not usable."""


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AllowanceError(f"{label} must be an aware datetime")
    if value.utcoffset() is None:
        raise AllowanceError(f"{label} must be an aware datetime")
    return value.astimezone(UTC)


def _zone(schedule: Schedule) -> ZoneInfo:
    if schedule.kind != "weekly" or not schedule.timezone_name:
        raise AllowanceError("elapsed allowances require a weekly schedule")
    try:
        return ZoneInfo(schedule.timezone_name)
    except Exception as error:
        raise AllowanceError("schedule time zone is invalid") from error


def _resolve_local(value: datetime, zone: ZoneInfo) -> datetime:
    """Resolve one local wall time to a deterministic aware datetime.

    Ambiguous times use the earlier UTC occurrence.  Nonexistent times move
    forward through the DST gap to the first representable wall time at or
    after the requested value.  This makes both policy boundaries and local
    midnight resets deterministic without depending on host clock behavior.
    """
    naive = value.replace(tzinfo=None)
    candidates: list[datetime] = []
    projected: list[tuple[datetime, datetime]] = []
    for fold in (0, 1):
        candidate = naive.replace(tzinfo=zone, fold=fold)
        utc = candidate.astimezone(UTC)
        round_trip = utc.astimezone(zone).replace(tzinfo=None)
        if round_trip == naive:
            candidates.append(utc)
        else:
            projected.append((round_trip, utc))
    if candidates:
        return min(candidates).astimezone(zone)
    future = [item for item in projected if item[0] >= naive]
    if future:
        return min(future, key=lambda item: (item[0] - naive, item[1]))[1].astimezone(zone)
    return max(projected, key=lambda item: item[0])[1].astimezone(zone)


def _period_occurrence(
    period: WeeklyPeriod,
    period_index: int,
    occurrence_date: date,
    zone: ZoneInfo,
) -> "PeriodOccurrence":
    end_date = (
        occurrence_date
        if period.end_local > period.start_local
        else occurrence_date + _DAY
    )
    local_start = _resolve_local(
        datetime.combine(occurrence_date, period.start_local), zone
    )
    local_end = _resolve_local(datetime.combine(end_date, period.end_local), zone)
    start_utc = local_start.astimezone(UTC)
    end_utc = local_end.astimezone(UTC)
    if end_utc <= start_utc:
        raise AllowanceError("weekly period has no elapsed-time occurrence")
    return PeriodOccurrence(
        period_index,
        occurrence_date,
        local_start,
        local_end,
        start_utc,
        end_utc,
    )


@dataclass(frozen=True)
class UsageInterval:
    """One already validated interval of matching focused browser usage."""

    start_utc: datetime
    end_utc: datetime

    def __post_init__(self) -> None:
        start = _utc(self.start_utc, "usage start")
        end = _utc(self.end_utc, "usage end")
        if end <= start:
            raise AllowanceError("usage end must be after usage start")
        object.__setattr__(self, "start_utc", start)
        object.__setattr__(self, "end_utc", end)

@dataclass(frozen=True)
class AllowanceUsageReport:
    """One idempotent, service-accepted usage interval."""

    report_id: str
    rule_id: str
    start_utc: datetime
    end_utc: datetime

    def __post_init__(self) -> None:
        try:
            report_id = canonical.canonical_uuid(self.report_id)
            rule_id = canonical.canonical_uuid(self.rule_id)
        except canonical.CanonicalError as error:
            raise AllowanceError("usage report IDs must be canonical UUIDs") from error
        interval = UsageInterval(self.start_utc, self.end_utc)
        object.__setattr__(self, "report_id", report_id)
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "start_utc", interval.start_utc)
        object.__setattr__(self, "end_utc", interval.end_utc)

    def to_dict(self) -> dict[str, str]:
        return {
            "report_id": self.report_id,
            "rule_id": self.rule_id,
            "start_utc": canonical.format_utc(self.start_utc),
            "end_utc": canonical.format_utc(self.end_utc),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "AllowanceUsageReport":
        if not isinstance(data, Mapping) or set(data) != {
            "report_id", "rule_id", "start_utc", "end_utc",
        }:
            raise AllowanceError("usage report fields are invalid")
        try:
            start = canonical.parse_utc(data["start_utc"])
            end = canonical.parse_utc(data["end_utc"])
        except canonical.CanonicalError as error:
            raise AllowanceError("usage report times are invalid") from error
        return cls(data["report_id"], data["rule_id"], start, end)


MAX_USAGE_REPORTS = 4096


@dataclass(frozen=True)
class AllowanceUsageState:
    """Bounded, signed ledger of accepted elapsed-time reports."""

    items: tuple[AllowanceUsageReport, ...] = ()

    def __post_init__(self) -> None:
        if len(self.items) > MAX_USAGE_REPORTS:
            raise AllowanceError("allowance usage state is too large")
        if any(not isinstance(item, AllowanceUsageReport) for item in self.items):
            raise AllowanceError("allowance usage rows are invalid")
        ids = [item.report_id for item in self.items]
        if len(set(ids)) != len(ids):
            raise AllowanceError("allowance usage has duplicate report IDs")

    @classmethod
    def empty(cls) -> "AllowanceUsageState":
        return cls()

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "AllowanceUsageState":
        if not isinstance(data, Mapping) or set(data) != {"items"}:
            raise AllowanceError("allowance usage state has an invalid shape")
        raw_items = data["items"]
        if not isinstance(raw_items, list):
            raise AllowanceError("allowance usage items must be a list")
        if len(raw_items) > MAX_USAGE_REPORTS:
            raise AllowanceError("allowance usage state is too large")
        try:
            items = tuple(AllowanceUsageReport.from_dict(item) for item in raw_items)
        except (AllowanceError, TypeError, ValueError) as error:
            raise AllowanceError("allowance usage rows are invalid") from error
        return cls(items)

    def to_dict(self) -> dict[str, list[dict[str, str]]]:
        return {"items": [item.to_dict() for item in self.items]}

    def contains(self, report_id: str) -> bool:
        try:
            normalized = canonical.canonical_uuid(report_id)
        except canonical.CanonicalError:
            return False
        return any(item.report_id == normalized for item in self.items)

    def record(self, report: AllowanceUsageReport) -> "AllowanceUsageState":
        if not isinstance(report, AllowanceUsageReport):
            raise AllowanceError("usage report is invalid")
        if self.contains(report.report_id):
            return self
        if len(self.items) >= MAX_USAGE_REPORTS:
            raise AllowanceError("allowance usage state is full")
        return AllowanceUsageState((*self.items, report))

    def prune_before(self, before_utc: datetime) -> "AllowanceUsageState":
        before = _utc(before_utc, "usage retention boundary")
        kept = tuple(item for item in self.items if item.end_utc > before)
        return self if kept == self.items else AllowanceUsageState(kept)

    def for_rule(self, rule_id: str) -> tuple[UsageInterval, ...]:
        try:
            normalized = canonical.canonical_uuid(rule_id)
        except canonical.CanonicalError as error:
            raise AllowanceError("usage rule ID is invalid") from error
        return tuple(
            UsageInterval(item.start_utc, item.end_utc)
            for item in self.items
            if item.rule_id == normalized
        )

@dataclass(frozen=True)
class PeriodOccurrence:
    """One concrete weekly period occurrence on the UTC timeline."""

    period_index: int
    occurrence_date: date
    start_local: datetime
    end_local: datetime
    start_utc: datetime
    end_utc: datetime


@dataclass(frozen=True)
class AllowanceDecision:
    """Remaining budget for the active occurrence at one instant.

    ``remaining_seconds`` is the smaller of the current period/window budget
    and the local-day cap.  ``None`` means that no corresponding cap exists.
    A strict period has zero remaining time and is never allowed.
    """

    active: bool
    allowed: bool
    period_index: int | None
    occurrence_start_utc: datetime | None
    occurrence_end_utc: datetime | None
    window_start_utc: datetime | None
    window_end_utc: datetime | None
    period_budget_seconds: int | None
    period_used_seconds: int
    period_remaining_seconds: int | None
    daily_cap_seconds: int | None
    daily_used_seconds: int
    daily_remaining_seconds: int | None
    remaining_seconds: int | None


def occurrences_between(
    schedule: Schedule,
    start_utc: datetime,
    end_utc: datetime,
) -> tuple[PeriodOccurrence, ...]:
    """Return weekly occurrences intersecting a UTC half-open range."""
    start = _utc(start_utc, "range start")
    end = _utc(end_utc, "range end")
    if end <= start:
        raise AllowanceError("occurrence range end must be after its start")
    zone = _zone(schedule)
    if schedule.has_overlapping_periods():
        raise AllowanceError("elapsed allowances require non-overlapping periods")
    local_start = (start.astimezone(zone).date() - timedelta(days=2))
    local_end = end.astimezone(zone).date() + timedelta(days=2)
    result: list[PeriodOccurrence] = []
    cursor = local_start
    while cursor <= local_end:
        for index, period in enumerate(schedule.periods):
            if cursor.weekday() not in period.weekdays:
                continue
            occurrence = _period_occurrence(period, index, cursor, zone)
            if occurrence.start_utc < end and occurrence.end_utc > start:
                result.append(occurrence)
        cursor += _DAY
    return tuple(sorted(result, key=lambda item: (item.start_utc, item.period_index)))


def occurrence_at(
    schedule: Schedule,
    now_utc: datetime,
) -> PeriodOccurrence | None:
    """Return the active concrete weekly occurrence, if one exists."""
    now = _utc(now_utc, "current time")
    occurrences = occurrences_between(
        schedule,
        now - timedelta(days=2),
        now + timedelta(microseconds=1),
    )
    return next(
        (item for item in occurrences if item.start_utc <= now < item.end_utc),
        None,
    )


def _union_seconds(
    usage: Sequence[UsageInterval],
    windows: Sequence[tuple[datetime, datetime]],
) -> int:
    spans: list[tuple[datetime, datetime]] = []
    for interval in usage:
        for window_start, window_end in windows:
            start = max(interval.start_utc, window_start)
            end = min(interval.end_utc, window_end)
            if start < end:
                spans.append((start, end))
    if not spans:
        return 0
    spans.sort()
    total = timedelta(0)
    merged_start, merged_end = spans[0]
    for start, end in spans[1:]:
        if start <= merged_end:
            merged_end = max(merged_end, end)
        else:
            total += merged_end - merged_start
            merged_start, merged_end = start, end
    total += merged_end - merged_start
    # Rounding up prevents sub-second reports from granting extra budget.
    return math.ceil(total.total_seconds())

def _rolling_window_start(
    usage: Sequence[UsageInterval],
    occurrence: PeriodOccurrence,
    now: datetime,
    window: timedelta,
) -> datetime:
    """Find the current usage-anchored refill window.

    The first matching usage after a full-window idle gap starts a new
    window.  While usage remains within successive windows, the anchor
    advances in fixed-duration steps from that first usage instead of from
    the weekly period boundary.
    """
    relevant = sorted(
        (
            max(item.start_utc, occurrence.start_utc),
            min(item.end_utc, occurrence.end_utc, now),
        )
        for item in usage
        if item.start_utc < now and item.end_utc > occurrence.start_utc
    )
    relevant = [span for span in relevant if span[0] < span[1]]
    if not relevant:
        return now
    anchor = relevant[0][0]
    previous_end = relevant[0][1]
    for start, end in relevant[1:]:
        if start - previous_end >= window:
            anchor = start
        previous_end = max(previous_end, end)
    if now - previous_end >= window:
        return now
    candidate = anchor + ((now - anchor) // window) * window
    return candidate if candidate <= previous_end else now


def _daily_windows(
    schedule: Schedule,
    allowance: TimeAllowance,
    now: datetime,
) -> tuple[tuple[datetime, datetime], tuple[datetime, datetime]]:
    zone = _zone(schedule)
    local_day = now.astimezone(zone).date()
    day_start_local = _resolve_local(datetime.combine(local_day, time.min), zone)
    day_end_local = _resolve_local(datetime.combine(local_day + _DAY, time.min), zone)
    day_window = (
        day_start_local.astimezone(UTC),
        day_end_local.astimezone(UTC),
    )
    occurrences = occurrences_between(schedule, *day_window)
    enabled = tuple(
        (item.start_utc, item.end_utc)
        for item in occurrences
        if allowance.periods[item.period_index].mode != "strict"
    )
    return day_window, enabled


def allowance_decision(
    rule: Rule,
    now_utc: datetime,
    usage: Iterable[UsageInterval] = (),
) -> AllowanceDecision | None:
    """Evaluate one rule's elapsed allowance at ``now_utc``.

    ``usage`` is treated as a set of intervals: overlapping or repeated
    reports are counted once.  Intervals are clipped to the current occurrence
    and, independently, to the applicable local-day occurrences.
    """
    allowance = rule.time_allowance
    if allowance is None:
        return None
    if rule.schedule.kind != "weekly":
        raise AllowanceError("elapsed allowances require a weekly schedule")
    if len(allowance.periods) != len(rule.schedule.periods):
        raise AllowanceError("allowance periods do not match the schedule")
    now = _utc(now_utc, "current time")
    observed = tuple(usage)
    if any(not isinstance(item, UsageInterval) for item in observed):
        raise AllowanceError("usage must contain UsageInterval values")
    current = occurrence_at(rule.schedule, now)
    if current is None:
        return AllowanceDecision(
            False, False, None, None, None, None, None,
            None, 0, None, allowance.daily_cap_seconds, 0,
            allowance.daily_cap_seconds, None,
        )

    period = allowance.periods[current.period_index]
    if period.mode == "strict":
        return AllowanceDecision(
            True, False, current.period_index, current.start_utc, current.end_utc,
            None, None, 0, 0, 0, allowance.daily_cap_seconds, 0,
            allowance.daily_cap_seconds, 0,
        )
    window_start = current.start_utc
    window_end = current.end_utc
    if period.mode == "fixed_window":
        window = timedelta(seconds=period.window_seconds)
        window_start = _rolling_window_start(observed, current, now, window)
        window_end = min(window_start + window, current.end_utc)
    period_budget = period.quota_seconds
    period_used = _union_seconds(
        observed,
        ((window_start, min(window_end, now)),),
    )
    period_remaining = max(0, period_budget - period_used)

    daily_cap = allowance.daily_cap_seconds
    daily_used = 0
    daily_remaining: int | None = None
    if daily_cap is not None:
        day_window, enabled_windows = _daily_windows(rule.schedule, allowance, now)
        daily_used = _union_seconds(
            observed,
            tuple(
                (
                    max(day_window[0], start),
                    min(day_window[1], end, now),
                )
                for start, end in enabled_windows
                if start < min(day_window[1], now) and end > day_window[0]
            ),
        )
        daily_remaining = max(0, daily_cap - daily_used)
    remaining = period_remaining if daily_remaining is None else min(
        period_remaining, daily_remaining
    )
    return AllowanceDecision(
        True,
        remaining > 0,
        current.period_index,
        current.start_utc,
        current.end_utc,
        window_start,
        window_end,
        period_budget,
        period_used,
        period_remaining,
        daily_cap,
        daily_used,
        daily_remaining,
        remaining,
    )


__all__ = [
    "AllowanceDecision",
    "AllowanceError",
    "AllowanceUsageReport",
    "AllowanceUsageState",
    "MAX_USAGE_REPORTS",
    "PeriodOccurrence",
    "UsageInterval",
    "allowance_decision",
    "occurrence_at",
    "occurrences_between",
]
