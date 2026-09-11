"""Native GTK 4 client and pure rule-form helpers.

GTK stays behind :func:`load_gtk`. The service command and pure helper tests do
not need the optional desktop binding.
"""

from __future__ import annotations

import importlib
import os
import re
from pathlib import Path
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta, timezone
from enum import IntEnum
from types import ModuleType
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .categories import starter_categories
from .model import (
    MAX_POMODORO_CYCLES,
    MAX_TIME_ALLOWANCE_SECONDS,
    MAX_WEEKLY_PERIODS,
    NETWORK_CONTROLS,
    NOTIFICATION_CATEGORIES,
    TIME_ALLOWANCE_MODES,
    ManagedList,
    Policy,
    PolicyProjection,
    Rule,
    Schedule,
    Target,
    ValidationError,
)
from .canonical import CanonicalError, canonical_uuid, parse_utc
from .schedule_view import (
    MAX_DAILY_TRANSITIONS,
    DailyInterval,
    ScheduleViewError,
    StateChange,
    next_state_change,
    project_daily_schedule,
)
from .schedule_view import system_timezone_name as _view_timezone_name
from .preferences import THEMES, load_theme, save_theme
from .rpc import Client
from .transfer import (
    BlockListImportPreview,
    ImportPreview,
    TargetListPreview,
    TransferError,
    atomic_write_text,
    block_list_preview_text,
    domain_export_text,
    native_export_text,
    parse_block_list_export,
    parse_domain_text,
    parse_target_list_text,
    read_block_list_text,
    read_import_text,
    read_native_text,
    read_target_list_text,
    parse_native_export,
    statistics_export_text,
    target_list_export_text,
)
UTC = timezone.utc



class GtkUnavailableError(RuntimeError):
    """Report that the optional GTK runtime is not available."""


class FormError(ValueError):
    """Report invalid rule-form values."""


class Space(IntEnum):
    """Spacing tokens for the native interface."""

    COMPACT = 6
    SMALL = 12
    MEDIUM = 18
    LARGE = 24


WEEKDAY_LABELS = (
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
)
SCHEDULE_LABELS = ("One time", "Weekly", "Pomodoro", "Indefinite")
SCHEDULE_KINDS = ("one_time", "weekly", "pomodoro", "indefinite")
THEME_LABELS = ("System", "Light", "Dark")
RULE_FILTER_LABELS = ("All", "Active", "Inactive", "Enabled", "Disabled")
RULE_FILTERS = ("all", "active", "inactive", "enabled", "disabled")
RULE_SORT_LABELS = ("Most recent", "Alphabetical A-Z", "Alphabetical Z-A")
RULE_SORTS = ("recent", "name_asc", "name_desc")

NOTIFICATION_CATEGORY_OPTIONS = (
    (
        "state_changes",
        "Rule starts and ends",
        "Notify when this rule becomes active or inactive.",
    ),
    (
        "upcoming_changes",
        "Upcoming schedule changes",
        "Notify five minutes before this rule changes state.",
    ),
)
FOCUS_DURATIONS = (15, 30, 60, 120)
RPC_LIST_CHUNK_SIZE = 200
# Breadcrumb for reviewers: JSON ASCII escaping can triple the UTF-8 size.
# This bound keeps the full request below the fixed 65,536-byte RPC frame.
RPC_TEXT_CHUNK_BYTES = 16 * 1024
MAX_DENIAL_PATHS = 256
MAX_DENIAL_COUNT = (1 << 63) - 1



@dataclass(frozen=True)
class WeeklyPeriodForm:
    """Pure values from one weekly-period row."""

    weekdays: tuple[int, ...]
    start: str
    end: str
    allowance_mode: str = "strict"
    allowance_quota_minutes: int | None = None
    allowance_window_minutes: int | None = None


@dataclass(frozen=True)
class PeriodAllowanceForm:
    """Pure values from one weekly allowance row."""

    mode: str = "strict"
    quota_minutes: int | None = None
    window_minutes: int | None = None

@dataclass(frozen=True)
class ObservedRuleState:
    """The rule state that the GUI observed in one service poll."""

    name: str
    active: bool


@dataclass(frozen=True)
class RuleTransition:
    """A rule start or end that two GUI polls observed."""

    rule_id: str
    rule_name: str
    started: bool


@dataclass(frozen=True)
class ManagedListSummary:
    """Managed-list metadata that is safe for normal GUI responses."""

    id: str
    name: str
    source: str
    version: str
    license: str
    imported_utc: str
    domain_count: int

@dataclass(frozen=True)
class LockSummary:
    """Public rule-lock state returned by the service."""

    rule_id: str
    kind: str
    locked: bool
    until_utc: datetime | None
    retry_after_utc: datetime | None
    wait_seconds: int | None = None
    break_seconds: int | None = None
    pending_until_utc: datetime | None = None
    break_until_utc: datetime | None = None

@dataclass(frozen=True)
class DenialStatView:
    """One bounded application-denial row returned by the service."""

    path: str
    count: int
    first_utc: datetime
    last_utc: datetime
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class DenialStatistics:
    """One immutable denial-statistics response."""

    items: tuple[DenialStatView, ...]
    dropped: int


@dataclass(frozen=True)
class DenialStatDisplay:
    """Read-only text for one application-denial row."""

    path: str
    count: str
    first_utc: str
    last_utc: str
    rule_ids: str


@dataclass(frozen=True)
class WebsiteUsageView:
    """One bounded per-rule daily start-allowance row."""

    rule_id: str
    day: str
    count: int
    allowance_starts: int | None
    budget_exhausted: bool


@dataclass(frozen=True)
class AuthorizationChallenge:
    """One short-lived rule authorization challenge."""

    rule_id: str
    kind: str
    challenge_id: str
    prompt: str | None
    expires_in: int


@dataclass(frozen=True)
class AuthorizationGrant:
    """One short-lived weakening grant returned by the service."""

    rule_id: str
    authorized: bool
    expires_in: int


@dataclass(frozen=True)
class RpcCall:
    """One immutable RPC call plan for a worker thread."""

    command: str
    fields: Mapping[str, object]


@dataclass(frozen=True)
class GtkModules:
    Gtk: ModuleType
    Gio: ModuleType
    GLib: ModuleType


@dataclass(frozen=True)
class RuleForm:
    """Pure values from the rule editor."""

    name: str
    websites: tuple[str, ...]
    applications: tuple[str, ...]
    managed_list_ids: tuple[str, ...]
    schedule_kind: str
    timezone: str
    one_time_start: str = ""
    one_time_end: str = ""
    weekly_periods: tuple[WeeklyPeriodForm, ...] = ()
    pomodoro_start: str = ""
    pomodoro_work_minutes: int = 25
    pomodoro_break_minutes: int = 5
    pomodoro_cycles: int = 4
    # The editor presents website and URL targets in one pane while retaining
    # their exact model kinds for service and browser enforcement.
    target_entries: tuple[dict[str, str], ...] = ()
    url_targets: tuple[dict[str, str], ...] = ()
    url_exceptions: tuple[dict[str, str], ...] = ()
    # Breadcrumb: optional daily start budget; None means "no limit" and
    # round-trips through put_rule exactly like the other rule fields.
    allowance_starts: int | None = None
    # Timed allowances are enabled only for weekly URL-level rules. Each
    # allowance row corresponds by position to one weekly schedule period.
    time_allowance_enabled: bool = False
    time_allowance_periods: tuple[PeriodAllowanceForm, ...] = ()
    time_allowance_daily_cap_minutes: int | None = None
    configure_lock_after_save: bool = False
    # Breadcrumb: checked network controls; values are the exact network
    # target names and round-trip as kind "network" targets.
    # New-rule convenience: open the full lock configuration after saving.
    network_controls: tuple[str, ...] = ()
    notifications_enabled: bool = True
    notification_categories: tuple[str, ...] = NOTIFICATION_CATEGORIES


@dataclass(frozen=True)
class ServiceSnapshot:
    healthy: bool
    clock_trusted: bool
    clock_reason: str
    active_websites: int
    active_applications: int
    # Breadcrumb (network seam): count of distinct active network controls
    # (0..6) across active rules; mirrors list-rules network targets.
    active_network: int
    rules: tuple[Rule, ...]
    managed_lists: tuple[ManagedListSummary, ...]
    locks: tuple[LockSummary, ...]
    # Breadcrumb (allowance seam): ids of enabled rules whose daily start
    # budget is used up, mirrored from the list_rules projection.
    exhausted_rule_ids: frozenset[str] = frozenset()

def load_gtk(
    importer: Callable[[str], ModuleType] = importlib.import_module,
) -> GtkModules:
    """Load GTK 4 or give a clear error."""
    # Breadcrumb for reviewers: A runtime import keeps the service path
    # independent of the optional desktop binding.
    try:
        gi = importer("gi")
    except (ImportError, ModuleNotFoundError) as error:
        raise GtkUnavailableError(
            "GTK 4 Python bindings are not installed. "
            "Install python3-gi and gir1.2-gtk-4.0."
        ) from error
    try:
        gi.require_version("Gtk", "4.0")
        return GtkModules(
            importer("gi.repository.Gtk"),
            importer("gi.repository.Gio"),
            importer("gi.repository.GLib"),
        )
    except (AttributeError, ImportError, ValueError) as error:
        raise GtkUnavailableError(
            "GTK 4 is not available. Install gir1.2-gtk-4.0."
        ) from error


def system_timezone_name() -> str:
    """Get the IANA name of the Ubuntu local time zone."""
    # Breadcrumb: GUI callers catch FormError here, so the view error is
    # translated at this seam.
    try:
        return _view_timezone_name()
    except ScheduleViewError as error:
        raise FormError(str(error)) from error


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise FormError("The rule has an invalid UTC date.") from error
    if parsed.tzinfo is None:
        raise FormError("The rule has a UTC date without a time zone.")
    return parsed.astimezone(UTC)

def picker_text_to_datetime(value: str) -> datetime:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M")
    except ValueError as error:
        raise FormError("The selected date and time are invalid.") from error


def picker_datetime_text(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise FormError("The selected date and time are invalid.")
    return value.strftime("%Y-%m-%d %H:%M")


def default_one_time_window(now: datetime) -> tuple[str, str]:
    if not isinstance(now, datetime):
        raise FormError("The current date and time are invalid.")
    start = now.replace(second=0, microsecond=0)
    remainder = start.minute % 5
    if remainder or now.second or now.microsecond:
        start += timedelta(minutes=5 - remainder if remainder else 5)
    end = start + timedelta(hours=1)
    return picker_datetime_text(start), picker_datetime_text(end)




def _local_to_utc(value: str, timezone_name: str) -> datetime:
    local_value = picker_text_to_datetime(value)
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise FormError("Select a valid IANA time zone.") from error
    candidate = local_value.replace(tzinfo=zone, fold=0)
    round_trip = candidate.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
    if round_trip != local_value:
        raise FormError("This local time does not exist. Select a different time.")
    second = local_value.replace(tzinfo=zone, fold=1)
    if candidate.utcoffset() != second.utcoffset():
        raise FormError("This local time occurs twice. Select a different time.")
    return candidate.astimezone(UTC)


def _time_allowance_data(
    form: RuleForm,
    schedule: Schedule,
    targets: Sequence[Target],
) -> dict[str, object] | None:
    """Validate and serialize the optional weekly timed allowance."""
    if not form.time_allowance_enabled:
        return None
    if form.schedule_kind != "weekly" or schedule.kind != "weekly":
        raise FormError("Timed allowances require a weekly schedule.")
    if any(target.kind not in Target.URL_LIKE_KINDS for target in targets):
        raise FormError("Timed allowances require URL-level targets only.")
    if schedule.has_overlapping_periods():
        raise FormError(
            "Timed allowances require non-overlapping weekly periods."
        )
    if len(form.time_allowance_periods) != len(schedule.periods):
        raise FormError(
            "Add one timed allowance setting for each weekly period."
        )
    daily_minutes = form.time_allowance_daily_cap_minutes
    if daily_minutes is not None and (
        isinstance(daily_minutes, bool)
        or not isinstance(daily_minutes, int)
        or not 1 <= daily_minutes <= MAX_TIME_ALLOWANCE_SECONDS // 60
    ):
        raise FormError("The daily timed allowance must be 1 to 1440 minutes.")
    periods: list[dict[str, object]] = []
    for index, item in enumerate(form.time_allowance_periods, 1):
        if item.mode not in TIME_ALLOWANCE_MODES:
            raise FormError(f"Allowance mode for period {index} is invalid.")
        if item.mode == "strict":
            if item.quota_minutes is not None or item.window_minutes is not None:
                raise FormError(
                    f"Strict allowance period {index} cannot have durations."
                )
            periods.append({"mode": "strict"})
            continue
        quota = item.quota_minutes
        if (
            isinstance(quota, bool)
            or not isinstance(quota, int)
            or not 1 <= quota <= MAX_TIME_ALLOWANCE_SECONDS // 60
        ):
            raise FormError(
                f"Allowance quota for period {index} must be 1 to 1440 minutes."
            )
        if item.mode == "total":
            if item.window_minutes is not None:
                raise FormError(
                    f"Total allowance period {index} cannot have a window."
                )
            periods.append(
                {"mode": "total", "quota_seconds": quota * 60}
            )
            continue
        window = item.window_minutes
        if (
            isinstance(window, bool)
            or not isinstance(window, int)
            or not 1 <= window <= MAX_TIME_ALLOWANCE_SECONDS // 60
        ):
            raise FormError(
                f"Allowance window for period {index} must be 1 to 1440 minutes."
            )
        if quota > window:
            raise FormError(
                f"Allowance quota for period {index} exceeds its window."
            )
        periods.append(
            {
                "mode": "fixed_window",
                "quota_seconds": quota * 60,
                "window_seconds": window * 60,
            }
        )
    return {
        "periods": periods,
        "daily_cap_seconds": None if daily_minutes is None else daily_minutes * 60,
    }


def _normalize_clock(value: str) -> str:
    try:
        parsed = time.fromisoformat(value.strip())
    except ValueError as error:
        raise FormError("Use HH:MM for each weekly time.") from error
    if parsed.tzinfo is not None:
        raise FormError("A weekly time cannot contain a time zone.")
    return parsed.replace(second=0, microsecond=0).isoformat(timespec="minutes")


def form_to_rule(
    form: RuleForm,
    existing: Rule | None = None,
    id_factory: Callable[[], object] = uuid4,
) -> Rule:
    """Convert pure form values to a validated model rule."""
    name = form.name.strip()
    if not name:
        raise FormError("Enter a rule name.")
    targets: list[Target] = []
    if form.target_entries:
        for entry in form.target_entries:
            try:
                targets.append(Target.from_dict(entry))
            except ValidationError as error:
                raise FormError(error.message) from error
    else:
        for domain in form.websites:
            if domain.strip():
                try:
                    targets.append(Target.from_dict({
                        "kind": "website", "value": domain.strip()
                    }))
                except ValidationError as error:
                    raise FormError(
                        f"{domain.strip()} was rejected: websites accept bare"
                        " hostnames only."
                    ) from error
        for list_id in form.managed_list_ids:
            if list_id.strip():
                targets.append(
                    Target.from_dict({
                        "kind": "managed_list", "value": list_id.strip()
                    })
                )
        for entry in form.url_targets:
            if entry:
                targets.append(Target.from_dict(entry))
    for path in form.applications:
        if path.strip():
            targets.append(Target.from_dict({
                "kind": "application", "value": path.strip()
            }))
    exceptions: list[Target] = []
    for entry in form.url_exceptions:
        try:
            exception = Target.from_dict(entry)
        except ValidationError as error:
            raise FormError(error.message) from error
        if exception.kind not in Target.URL_LIKE_KINDS:
            raise FormError("Exceptions require URL-level targets.")
        exceptions.append(exception)
    for control in form.network_controls:
        if control not in NETWORK_CONTROLS:
            raise FormError(
                f"{control} is not a supported network control."
            )
        targets.append(
            Target.from_dict({"kind": "network", "value": control})
        )
    if not targets:
        raise FormError("Add at least one target.")

    if form.schedule_kind == "one_time":
        if not form.one_time_start.strip() or not form.one_time_end.strip():
            raise FormError("Enter the start and end date.")
        schedule_data: dict[str, object] = {
            "kind": "one_time",
            "start_utc": _utc_text(_local_to_utc(form.one_time_start, form.timezone)),
            "end_utc": _utc_text(_local_to_utc(form.one_time_end, form.timezone)),
        }
    elif form.schedule_kind == "weekly":
        if not form.weekly_periods:
            raise FormError("Add at least one weekly period.")
        if len(form.weekly_periods) > MAX_WEEKLY_PERIODS:
            raise FormError("A weekly schedule can have at most 16 periods.")
        try:
            ZoneInfo(form.timezone)
        except ZoneInfoNotFoundError as error:
            raise FormError("Select a valid IANA time zone.") from error
        periods: list[dict[str, object]] = []
        for item in form.weekly_periods:
            weekdays = sorted(set(item.weekdays))
            if not weekdays:
                raise FormError("Select at least one weekday in each period.")
            if any(
                not isinstance(day, int)
                or isinstance(day, bool)
                or day not in range(7)
                for day in weekdays
            ):
                raise FormError("Select valid weekdays.")
            periods.append(
                {
                    "weekdays": weekdays,
                    "start": _normalize_clock(item.start),
                    "end": _normalize_clock(item.end),
                }
            )
        schedule_data = {
            "kind": "weekly",
            "timezone": form.timezone,
            "periods": periods,
        }
    elif form.schedule_kind == "pomodoro":
        if not form.pomodoro_start.strip():
            raise FormError("Enter the Pomodoro start date.")
        values = (
            ("Work minutes", form.pomodoro_work_minutes, 1, 180),
            ("Break minutes", form.pomodoro_break_minutes, 1, 60),
            ("Cycles", form.pomodoro_cycles, 1, MAX_POMODORO_CYCLES),
        )
        for label, value, minimum, maximum in values:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise FormError(f"{label} must be from {minimum} to {maximum}.")
        schedule_data = {
            "kind": "pomodoro",
            "start_utc": _utc_text(
                _local_to_utc(form.pomodoro_start, form.timezone)
            ),
            "work_minutes": form.pomodoro_work_minutes,
            "break_minutes": form.pomodoro_break_minutes,
            "cycles": form.pomodoro_cycles,
        }
    elif form.schedule_kind == "indefinite":
        schedule_data = {"kind": "indefinite"}
    else:
        raise FormError("Select a valid schedule type.")

    schedule = Schedule.from_dict(schedule_data)
    if form.allowance_starts is not None and form.time_allowance_enabled:
        raise FormError(
            "Choose either a daily start allowance or a timed allowance."
        )
    time_allowance_data = _time_allowance_data(form, schedule, targets)
    if existing is None:
        rule_id, enabled, revision = str(id_factory()), True, 0
    else:
        current = existing.to_dict()
        rule_id = current["id"]
        enabled = current["enabled"]
        revision = current["revision"]
    rule_data = {
        "id": rule_id,
        "name": name,
        "enabled": enabled,
        "targets": [target.to_dict() for target in targets],
        "schedule": schedule.to_dict(),
        "revision": revision,
    }
    if exceptions:
        rule_data["exceptions"] = [target.to_dict() for target in exceptions]
    if form.allowance_starts is not None:
        if (
            isinstance(form.allowance_starts, bool)
            or not isinstance(form.allowance_starts, int)
            or form.allowance_starts < 1
        ):
            raise FormError(
                "The daily start allowance must be a whole number from 1 up."
            )
        if any(target.kind not in Target.URL_LIKE_KINDS for target in targets):
            raise FormError(
                "Daily start allowances require URL-level targets only."
            )
        rule_data["allowance_starts"] = form.allowance_starts
    if time_allowance_data is not None:
        rule_data["allowance_time"] = time_allowance_data
    if form.notifications_enabled and not form.notification_categories:
        raise FormError("Select at least one notification category.")
    if (
        not form.notifications_enabled
        or form.notification_categories != NOTIFICATION_CATEGORIES
    ):
        rule_data["notifications"] = {
            "enabled": form.notifications_enabled,
            "categories": list(form.notification_categories),
        }
    return Rule.from_dict(rule_data)


def form_to_request(
    form: RuleForm,
    existing: Rule | None = None,
    id_factory: Callable[[], object] = uuid4,
) -> dict[str, object]:
    """Build the exact fields for the ``put_rule`` RPC command."""
    return {"rule": form_to_rule(form, existing, id_factory).to_dict()}


def rule_to_form(rule: Rule, timezone_name: str) -> RuleForm:
    """Convert a model rule to editor values."""
    form = _rule_to_form_fields(rule, timezone_name)
    targets = rule.to_dict()["targets"]
    url_targets = tuple(
        {"kind": item["kind"], "value": item["value"]}
        for item in targets
        if item["kind"] in Target.URL_LIKE_KINDS
    )
    url_exceptions = tuple(
        {"kind": item.kind, "value": item.value}
        for item in rule.exceptions
    )
    network_controls = tuple(
        item["value"] for item in targets if item["kind"] == "network"
    )
    target_entries = tuple(
        {"kind": item["kind"], "value": item["value"]}
        for item in targets
        if item["kind"] not in {"application", "network"}
    )
    time_allowance = rule.time_allowance
    return replace(
        form,
        target_entries=target_entries,
        url_targets=url_targets,
        url_exceptions=url_exceptions,
        allowance_starts=rule.allowance_starts,
        time_allowance_enabled=time_allowance is not None,
        time_allowance_periods=(
            tuple(
                PeriodAllowanceForm(
                    period.mode,
                    None
                    if period.quota_seconds is None
                    else (period.quota_seconds + 59) // 60,
                    None
                    if period.window_seconds is None
                    else (period.window_seconds + 59) // 60,
                )
                for period in time_allowance.periods
            )
            if time_allowance is not None
            else ()
        ),
        time_allowance_daily_cap_minutes=(
            None
            if time_allowance is None or time_allowance.daily_cap_seconds is None
            else (time_allowance.daily_cap_seconds + 59) // 60
        ),
        network_controls=network_controls,
        notifications_enabled=rule.notifications_enabled,
        notification_categories=rule.notification_categories,
    )


def _rule_to_form_fields(rule: Rule, timezone_name: str) -> RuleForm:
    """Convert schedule and classic target fields to editor values."""
    data = rule.to_dict()
    websites = tuple(
        item["value"] for item in data["targets"] if item["kind"] == "website"
    )
    applications = tuple(
        item["value"] for item in data["targets"] if item["kind"] == "application"
    )
    managed_list_ids = tuple(
        item["value"] for item in data["targets"] if item["kind"] == "managed_list"
    )
    schedule = data["schedule"]
    kind = schedule["kind"]
    if kind == "one_time":
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as error:
            raise FormError("Select a valid IANA time zone.") from error
        start = _parse_utc(schedule["start_utc"]).astimezone(zone)
        end = _parse_utc(schedule["end_utc"]).astimezone(zone)
        return RuleForm(
            data["name"],
            websites,
            applications,
            managed_list_ids,
            kind,
            timezone_name,
            start.strftime("%Y-%m-%d %H:%M"),
            end.strftime("%Y-%m-%d %H:%M"),
        )
    if kind == "weekly":
        periods = tuple(
            WeeklyPeriodForm(
                tuple(item["weekdays"]),
                item["start"],
                item["end"],
            )
            for item in schedule["periods"]
        )
        return RuleForm(
            data["name"],
            websites,
            applications,
            managed_list_ids,
            kind,
            schedule["timezone"],
            weekly_periods=periods,
        )
    if kind == "pomodoro":
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as error:
            raise FormError("Select a valid IANA time zone.") from error
        start = _parse_utc(schedule["start_utc"]).astimezone(zone)
        return RuleForm(
            data["name"],
            websites,
            applications,
            managed_list_ids,
            kind,
            timezone_name,
            pomodoro_start=start.strftime("%Y-%m-%d %H:%M"),
            pomodoro_work_minutes=schedule["work_minutes"],
            pomodoro_break_minutes=schedule["break_minutes"],
            pomodoro_cycles=schedule["cycles"],
        )
    return RuleForm(
        data["name"],
        websites,
        applications,
        managed_list_ids,
        kind,
        timezone_name,
    )

def managed_list_summaries_from_results(
    items: Sequence[Mapping[str, object]],
) -> tuple[ManagedListSummary, ...]:
    """Parse list summaries without accepting domain data."""
    expected = {
        "id",
        "name",
        "source",
        "version",
        "license",
        "imported_utc",
        "domain_count",
    }
    summaries: list[ManagedListSummary] = []
    for item in items:
        # Breadcrumb for reviewers: rejecting extra fields prevents a normal
        # list response from moving managed domains into the GUI process.
        if set(item) != expected:
            raise FormError("The service returned an invalid managed-list summary.")
        strings = (
            item["id"],
            item["name"],
            item["source"],
            item["version"],
            item["license"],
            item["imported_utc"],
        )
        if any(not isinstance(value, str) or not value.strip() for value in strings):
            raise FormError("The service returned invalid managed-list metadata.")
        try:
            parsed_id = UUID(item["id"])
        except ValueError as error:
            raise FormError("The service returned an invalid managed-list ID.") from error
        if str(parsed_id) != item["id"]:
            raise FormError("The service returned an invalid managed-list ID.")
        count = item["domain_count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise FormError("The service returned an invalid managed-list count.")
        summaries.append(
            ManagedListSummary(
                item["id"],
                item["name"],
                item["source"],
                item["version"],
                item["license"],
                item["imported_utc"],
                count,
            )
        )
    return tuple(summaries)

def _canonical_uuid(value: object, message: str) -> str:
    try:
        return canonical_uuid(value)
    except CanonicalError:
        raise FormError(message)


def _optional_utc_result(value: object, message: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FormError(message)
    try:
        return parse_utc(value)
    except CanonicalError:
        raise FormError(message)


def lock_summaries_from_results(
    items: Sequence[Mapping[str, object]],
) -> tuple[LockSummary, ...]:
    """Parse only the public rule-lock summary contract."""
    base = {"rule_id", "kind", "locked", "until_utc", "retry_after_utc"}
    delay_fields = {
        "wait_seconds",
        "break_seconds",
        "pending_until_utc",
        "break_until_utc",
    }
    summaries: list[LockSummary] = []
    seen_rule_ids: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping) or not base.issubset(item):
            raise FormError("The service returned an invalid lock summary.")
        kind = item["kind"]
        expected = base | delay_fields if kind == "delay" else base
        if set(item) != expected:
            raise FormError("The service returned an invalid lock summary.")
        rule_id = _canonical_uuid(
            item["rule_id"], "The service returned an invalid lock rule ID."
        )
        if rule_id in seen_rule_ids:
            raise FormError("The service returned an invalid lock rule ID.")
        if kind not in {"timed", "schedule", "friction", "password", "delay"}:
            raise FormError("The service returned an unsupported lock kind.")
        if not isinstance(item["locked"], bool):
            raise FormError("The service returned an invalid lock state.")
        until_utc = _optional_utc_result(
            item["until_utc"], "The service returned an invalid lock expiry."
        )
        retry_after_utc = _optional_utc_result(
            item["retry_after_utc"],
            "The service returned invalid lock retry data.",
        )
        if (kind == "timed") != (until_utc is not None):
            raise FormError("The service returned an invalid lock expiry.")
        if kind != "password" and retry_after_utc is not None:
            raise FormError("The service returned invalid lock retry data.")
        wait_seconds = break_seconds = None
        pending_until_utc = break_until_utc = None
        if kind == "delay":
            wait_seconds = item["wait_seconds"]
            break_seconds = item["break_seconds"]
            if (
                isinstance(wait_seconds, bool)
                or not isinstance(wait_seconds, int)
                or not 1 <= wait_seconds <= 86400
                or isinstance(break_seconds, bool)
                or not isinstance(break_seconds, int)
                or not 60 <= break_seconds <= 86400
            ):
                raise FormError("The service returned invalid Delay settings.")
            pending_until_utc = _optional_utc_result(
                item["pending_until_utc"],
                "The service returned invalid Delay countdown data.",
            )
            break_until_utc = _optional_utc_result(
                item["break_until_utc"],
                "The service returned invalid Delay break data.",
            )
            if pending_until_utc is not None and break_until_utc is not None:
                raise FormError("The service returned invalid Delay state.")
        seen_rule_ids.add(rule_id)
        summaries.append(
            LockSummary(
                rule_id,
                kind,
                item["locked"],
                until_utc,
                retry_after_utc,
                wait_seconds,
                break_seconds,
                pending_until_utc,
                break_until_utc,
            )
        )
    return tuple(summaries)

def denial_statistics_from_result(result: Mapping[str, object]) -> DenialStatistics:
    """Parse the exact bounded denial-statistics RPC response."""
    if not isinstance(result, Mapping) or set(result) != {"items", "dropped"}:
        raise FormError("The service returned invalid denial statistics.")
    items = result["items"]
    dropped = result["dropped"]
    if not isinstance(items, list) or len(items) > MAX_DENIAL_PATHS:
        raise FormError("The service returned invalid denial statistics.")
    if (
        not isinstance(dropped, int)
        or isinstance(dropped, bool)
        or not 0 <= dropped <= MAX_DENIAL_COUNT
    ):
        raise FormError("The service returned an invalid dropped-event count.")

    expected = {"path", "count", "first_utc", "last_utc", "rule_ids"}
    parsed_items: list[DenialStatView] = []
    seen_paths: set[str] = set()
    for item in items:
        # Breadcrumb for reviewers: this fixed shape keeps the observational
        # view bounded and prevents protected service state from entering GTK.
        if not isinstance(item, Mapping) or set(item) != expected:
            raise FormError("The service returned an invalid denial-statistics row.")
        path = item["path"]
        if (
            not isinstance(path, str)
            or not path
            or "\x00" in path
            or not os.path.isabs(path)
            or path.startswith("//")
            or os.path.normpath(path) != path
            or path in seen_paths
        ):
            raise FormError("The service returned an invalid application path.")
        count = item["count"]
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= MAX_DENIAL_COUNT
        ):
            raise FormError("The service returned an invalid denial count.")
        first_utc = _optional_utc_result(
            item["first_utc"], "The service returned an invalid first denial time."
        )
        last_utc = _optional_utc_result(
            item["last_utc"], "The service returned an invalid last denial time."
        )
        if first_utc is None or last_utc is None or first_utc > last_utc:
            raise FormError("The service returned invalid denial times.")
        raw_rule_ids = item["rule_ids"]
        if not isinstance(raw_rule_ids, list):
            raise FormError("The service returned invalid denial rule IDs.")
        rule_ids = tuple(
            _canonical_uuid(value, "The service returned an invalid denial rule ID.")
            for value in raw_rule_ids
        )
        if rule_ids != tuple(sorted(set(rule_ids))):
            raise FormError("The service returned invalid denial rule IDs.")
        seen_paths.add(path)
        parsed_items.append(
            DenialStatView(path, count, first_utc, last_utc, rule_ids)
        )
    return DenialStatistics(tuple(parsed_items), dropped)


def denial_stat_display(stat: DenialStatView) -> DenialStatDisplay:
    """Format one denial row without GTK, I/O, or local-time ambiguity."""
    return DenialStatDisplay(
        stat.path,
        f"{stat.count:,}",
        _utc_text(stat.first_utc),
        _utc_text(stat.last_utc),
        ", ".join(stat.rule_ids) if stat.rule_ids else "None recorded",
    )



def website_usage_from_result(result: Mapping[str, object]) -> tuple[WebsiteUsageView, ...]:
    """Parse the additive usage projection of ``list_website_stats``.

    Breadcrumb for reviewers: the denial rows in the same response are not
    needed here, so only the bounded usage entries are validated; the shape
    stays pinned so protected state can never enter the GUI.
    """
    if not isinstance(result, Mapping) or set(result) != {"items", "dropped", "usage"}:
        raise FormError("The service returned invalid website statistics.")
    raw_usage = result["usage"]
    if not isinstance(raw_usage, list) or len(raw_usage) > 256:
        raise FormError("The service returned invalid website usage.")
    expected = {
        "rule_id",
        "day",
        "count",
        "allowance_starts",
        "budget_exhausted",
    }
    parsed: list[WebsiteUsageView] = []
    seen: set[str] = set()
    for item in raw_usage:
        if not isinstance(item, Mapping) or set(item) != expected:
            raise FormError("The service returned an invalid website usage row.")
        rule_id = _canonical_uuid(
            item["rule_id"], "The service returned an invalid usage rule ID."
        )
        if rule_id in seen:
            raise FormError("The service returned an invalid usage rule ID.")
        seen.add(rule_id)
        day = item["day"]
        if not isinstance(day, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            raise FormError("The service returned an invalid usage day.")
        count = item["count"]
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or count > 2**63 - 1
        ):
            raise FormError("The service returned an invalid usage count.")
        allowance = item["allowance_starts"]
        if allowance is not None and (
            isinstance(allowance, bool)
            or not isinstance(allowance, int)
            or allowance < 1
        ):
            raise FormError("The service returned an invalid start allowance.")
        if not isinstance(item["budget_exhausted"], bool):
            raise FormError("The service returned an invalid budget state.")
        parsed.append(
            WebsiteUsageView(
                rule_id,
                day,
                count,
                allowance,
                item["budget_exhausted"],
            )
        )
    return tuple(parsed)

def delay_lock_request(
    rule_id: str,
    wait_seconds: int,
    break_seconds: int,
) -> dict[str, object]:
    """Build the exact request fields for a Delay lock."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    if (
        isinstance(wait_seconds, bool)
        or not isinstance(wait_seconds, int)
        or not 1 <= wait_seconds <= 86400
    ):
        raise FormError("The Delay wait must be between 1 and 86400 seconds.")
    if (
        isinstance(break_seconds, bool)
        or not isinstance(break_seconds, int)
        or not 60 <= break_seconds <= 86400
    ):
        raise FormError("The Delay break must be between 60 and 86400 seconds.")
    return {
        "rule_id": rule_id,
        "lock": {
            "kind": "delay",
            "wait_seconds": wait_seconds,
            "break_seconds": break_seconds,
        },
    }


def request_delay_break_request(rule_id: str) -> dict[str, object]:
    """Build the exact fields for requesting a Delay break."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id}


def cancel_delay_break_request(rule_id: str) -> dict[str, object]:
    """Build the exact fields for cancelling a pending Delay break."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id}

def timed_lock_request(
    rule_id: str,
    local_until: str,
    timezone_name: str,
) -> dict[str, object]:
    """Build the exact request fields for a timed lock."""
    try:
        parsed_id = UUID(rule_id)
    except (AttributeError, TypeError, ValueError) as error:
        raise FormError("The rule ID is invalid.") from error
    if str(parsed_id) != rule_id:
        raise FormError("The rule ID is invalid.")
    return {
        "rule_id": rule_id,
        "lock": {
            "kind": "timed",
            "until_utc": _utc_text(_local_to_utc(local_until, timezone_name)),
        },
    }


def friction_lock_request(rule_id: str) -> dict[str, object]:
    """Build the exact request fields for a friction lock."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id, "lock": {"kind": "friction"}}

def schedule_lock_request(rule_id: str) -> dict[str, object]:
    """Build the exact request fields for a weekly schedule lock."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id, "lock": {"kind": "schedule"}}


def _validated_password(password: object) -> str:
    if not isinstance(password, str):
        raise FormError("The password is invalid.")
    try:
        size = len(password.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise FormError("The password is invalid.") from error
    if size < 8:
        raise FormError("The password must contain at least 8 UTF-8 bytes.")
    if size > 1024:
        raise FormError("The password must contain at most 1024 UTF-8 bytes.")
    return password


def password_lock_request(
    rule_id: str,
    password: str,
    confirmation: str,
) -> dict[str, object]:
    """Build a password lock request without sending its confirmation."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    valid_password = _validated_password(password)
    if confirmation != valid_password:
        raise FormError("The password and confirmation must match.")
    return {
        "rule_id": rule_id,
        "lock": {"kind": "password", "password": valid_password},
    }


def remove_rule_lock_request(rule_id: str) -> dict[str, object]:
    """Build the exact request fields that remove a rule lock."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id, "lock": {"kind": "none"}}
def lock_summary_text(
    summary: LockSummary,
    timezone_name: str,
) -> str:
    """Describe the public state of any supported rule lock."""
    if summary.kind == "delay":
        if summary.wait_seconds is None or summary.break_seconds is None:
            raise FormError("The Delay lock settings are invalid.")
        text = (
            f"Delay lock: {summary.wait_seconds}s wait, "
            f"{summary.break_seconds // 60}m break."
        )
        boundary = summary.pending_until_utc or summary.break_until_utc
        if boundary is None:
            return text + (
                " Request a break while this rule is active."
                if summary.locked
                else " Not effective outside the rule's active period."
            )
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as error:
            raise FormError("The system time zone is invalid.") from error
        utc_text = boundary.strftime("%Y-%m-%d %H:%M:%S UTC")
        local_text = boundary.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S %Z")
        if summary.pending_until_utc is not None:
            return f"{text} Countdown ends: {utc_text} ({local_text} local)."
        return f"{text} Break ends: {utc_text} ({local_text} local)."
    if summary.kind == "schedule":
        return (
            "Schedule lock: active during the rule's weekly periods."
            if summary.locked
            else "Schedule lock: not effective outside the rule's weekly periods."
        )
    state = "locked" if summary.locked else "expired"
    if summary.kind == "friction":
        return (
            "Friction lock: authorization required for weakening changes."
            if summary.locked
            else "Friction lock: not effective."
        )
    if summary.kind == "password":
        text = (
            "Password lock: authorization required for weakening changes."
            if summary.locked
            else "Password lock: not effective."
        )
        if summary.retry_after_utc is None:
            return text
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as error:
            raise FormError("The system time zone is invalid.") from error
        utc_text = summary.retry_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        local_text = summary.retry_after_utc.astimezone(zone).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )
        return f"{text} Retry after: {utc_text} ({local_text} local)."
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise FormError("The system time zone is invalid.") from error
    if summary.until_utc is None:
        raise FormError("The timed lock expiry is invalid.")
    utc_text = summary.until_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    local_text = summary.until_utc.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S %Z")
    return f"Timed lock: {state}. Expiry: {utc_text} ({local_text} local)."


def begin_rule_authorization_request(rule_id: str) -> dict[str, object]:
    """Build the exact request fields that begin friction authorization."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    return {"rule_id": rule_id}


def authorization_challenge_from_result(
    item: Mapping[str, object],
) -> AuthorizationChallenge:
    """Parse a friction or password authorization challenge."""
    expected = {"rule_id", "kind", "challenge_id", "prompt", "expires_in"}
    if not isinstance(item, Mapping) or set(item) != expected:
        raise FormError("The service returned an invalid authorization challenge.")
    rule_id = _canonical_uuid(
        item["rule_id"],
        "The service returned an invalid authorization rule ID.",
    )
    challenge_id = _canonical_uuid(
        item["challenge_id"],
        "The service returned an invalid authorization challenge ID.",
    )
    kind = item["kind"]
    prompt, expires_in = item["prompt"], item["expires_in"]
    if kind not in {"friction", "password"}:
        raise FormError("The service returned an unsupported authorization kind.")
    if kind == "friction" and (not isinstance(prompt, str) or not prompt):
        raise FormError("The service returned invalid authorization text.")
    if kind == "password" and prompt is not None:
        raise FormError("The service returned invalid authorization text.")
    if (
        not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in <= 0
    ):
        raise FormError("The service returned an invalid authorization expiry.")
    return AuthorizationChallenge(
        rule_id,
        kind,
        challenge_id,
        prompt,
        expires_in,
    )


def complete_rule_authorization_request(
    rule_id: str,
    challenge_id: str,
    response: str,
    kind: str | None = None,
) -> dict[str, object]:
    """Build the exact fields that complete rule authorization."""
    _canonical_uuid(rule_id, "The rule ID is invalid.")
    _canonical_uuid(challenge_id, "The authorization challenge ID is invalid.")
    if not isinstance(response, str):
        raise FormError("The authorization response is invalid.")
    if kind not in {None, "friction", "password"}:
        raise FormError("The authorization kind is invalid.")
    if kind == "password":
        _validated_password(response)
    return {
        "rule_id": rule_id,
        "challenge_id": challenge_id,
        "response": response,
    }


def authorization_grant_from_result(
    item: Mapping[str, object],
) -> AuthorizationGrant:
    """Parse the service result for one weakening grant."""
    expected = {"rule_id", "authorized", "expires_in"}
    if not isinstance(item, Mapping) or set(item) != expected:
        raise FormError("The service returned an invalid authorization result.")
    rule_id = _canonical_uuid(
        item["rule_id"],
        "The service returned an invalid authorization rule ID.",
    )
    expires_in = item["expires_in"]
    if item["authorized"] is not True:
        raise FormError("The service did not authorize the weakening change.")
    if (
        not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in != 60
    ):
        raise FormError("The service returned an invalid authorization expiry.")
    return AuthorizationGrant(rule_id, True, expires_in)


def staged_list_upload_calls(
    import_id: str,
    domains: Sequence[str],
) -> tuple[RpcCall, ...]:
    """Plan bounded list chunks and the final commit call."""
    if not isinstance(import_id, str) or not import_id:
        raise FormError("The list import ID is invalid.")
    calls = [
        RpcCall(
            "import_list_chunk",
            {
                "import_id": import_id,
                "domains": list(domains[offset:offset + RPC_LIST_CHUNK_SIZE]),
            },
        )
        for offset in range(0, len(domains), RPC_LIST_CHUNK_SIZE)
    ]
    calls.append(RpcCall("commit_list_import", {"import_id": import_id}))
    return tuple(calls)


def utf8_text_chunks(
    text: str,
    maximum_bytes: int = RPC_TEXT_CHUNK_BYTES,
) -> tuple[str, ...]:
    """Split text without breaking a character or the RPC frame limit."""
    if not isinstance(text, str) or not text:
        raise FormError("The import text is empty.")
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
    ):
        raise FormError("The import chunk size is invalid.")
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in text:
        encoded_bytes = len(character.encode("utf-8"))
        if encoded_bytes > maximum_bytes:
            raise FormError("The import text contains an oversized character.")
        if current and current_bytes + encoded_bytes > maximum_bytes:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += encoded_bytes
    if current:
        chunks.append("".join(current))
    return tuple(chunks)


def staged_native_upload_calls(
    import_id: str,
    text: str,
) -> tuple[RpcCall, ...]:
    """Plan bounded native-state chunks and the final commit call."""
    if not isinstance(import_id, str) or not import_id:
        raise FormError("The native import ID is invalid.")
    calls = tuple(
        RpcCall(
            "native_import_chunk",
            {"import_id": import_id, "text": chunk},
        )
        for chunk in utf8_text_chunks(text)
    )
    return (*calls, RpcCall("commit_native_import", {"import_id": import_id}))


def managed_list_import_metadata(managed_list: ManagedList) -> dict[str, str]:
    """Build the exact metadata object for a staged list import."""
    data = managed_list.to_dict()
    return {
        "id": data["id"],
        "name": data["name"],
        "source": data["source"],
        "version": data["version"],
        "license": data["license"],
    }


def managed_list_from_domains(
    summary: ManagedListSummary,
    domains: Sequence[str],
) -> ManagedList:
    """Combine one safe summary with explicitly fetched domain chunks."""
    return ManagedList.from_dict(
        {
            "id": summary.id,
            "name": summary.name,
            "source": summary.source,
            "version": summary.version,
            "license": summary.license,
            "imported_utc": summary.imported_utc,
            "domains": list(domains),
        }
    )


def snapshot_from_results(
    status: Mapping[str, object],
    policy_result: Mapping[str, object],
    list_items: Sequence[Mapping[str, object]],
    lock_items: Sequence[Mapping[str, object]],
) -> ServiceSnapshot:
    """Convert strict RPC results to GUI data."""
    if set(status) not in (
        {"healthy", "clock_trusted", "clock_reason", "active_counts"},
        {
            "healthy",
            "clock_trusted",
            "clock_reason",
            "network_available",
            "active_counts",
        },
    ):
        raise FormError("The service returned an invalid status.")
    if "network_available" in status and not isinstance(
        status["network_available"], bool
    ):
        raise FormError("The service returned an invalid network capability.")
    active = status["active_counts"]
    if (
        not isinstance(active, Mapping)
        or set(active) != {"website", "application", "network"}
    ):
        raise FormError("The service returned invalid active counts.")
    websites, applications, network = (
        active["website"],
        active["application"],
        active["network"],
    )
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in (websites, applications, network)
    ) or network > len(NETWORK_CONTROLS):
        raise FormError("The service returned invalid active counts.")
    if not isinstance(status["healthy"], bool) or not isinstance(
        status["clock_trusted"], bool
    ):
        raise FormError("The service returned an invalid status.")
    if not isinstance(status["clock_reason"], str):
        raise FormError("The service returned an invalid clock reason.")
    try:
        projection = PolicyProjection.from_dict(policy_result)
    except ValidationError as error:
        raise FormError("The service returned invalid policy values.") from error
    normalized = projection.to_dict()
    rule_items = normalized["rules"]
    exhausted_rule_ids = frozenset(
        item["id"] for item in rule_items if item["budget_exhausted"]
    )
    clean_rule_items = [
        {
            key: value
            for key, value in item.items()
            if key != "budget_exhausted"
        }
        for item in rule_items
    ]
    return ServiceSnapshot(
        status["healthy"],
        status["clock_trusted"],
        status["clock_reason"],
        websites,
        applications,
        network,
        tuple(Rule.from_dict(item) for item in clean_rule_items),
        managed_list_summaries_from_results(list_items),
        lock_summaries_from_results(lock_items),
        exhausted_rule_ids=exhausted_rule_ids,
    )

def duplicate_rule(
    rule: Rule, id_factory: Callable[[], object] = uuid4
) -> Rule:
    data = rule.to_dict()
    data["id"] = str(id_factory())
    data["name"] = f"{data['name']} copy"
    data["enabled"] = False
    data["revision"] = 0
    return Rule.from_dict(data)
def sort_rules(
    rules: Sequence[Rule], sort_filter: str
) -> tuple[Rule, ...]:
    """Sort policy-order rules by recency or case-insensitive name."""
    if sort_filter not in RULE_SORTS:
        raise FormError("Select a valid rule sort.")
    if sort_filter == "recent":
        # The service preserves policy insertion order; newest rules are last.
        return tuple(reversed(rules))
    reverse = sort_filter == "name_desc"
    return tuple(sorted(
        rules,
        key=lambda rule: (rule.name.casefold(), rule.id),
        reverse=reverse,
    ))


def filter_rules(
    rules: Sequence[Rule],
    query: str,
    state_filter: str,
    now_utc: datetime,
    clock_trusted: bool,
    sort_filter: str = "recent",
) -> tuple[Rule, ...]:
    if state_filter not in RULE_FILTERS:
        raise FormError("Select a valid rule filter.")
    if sort_filter not in RULE_SORTS:
        raise FormError("Select a valid rule sort.")
    needle = query.strip().casefold()
    result: list[Rule] = []
    for rule in rules:
        active = rule.is_active(now_utc, clock_trusted=clock_trusted)
        if state_filter == "active" and not active:
            continue
        if state_filter == "inactive" and active:
            continue
        if state_filter == "enabled" and not rule.enabled:
            continue
        if state_filter == "disabled" and rule.enabled:
            continue
        if needle:
            values = [rule.name, *(target.value for target in rule.targets)]
            if not any(needle in value.casefold() for value in values):
                continue
        result.append(rule)
    return sort_rules(result, sort_filter)


def import_preview_text(preview: ImportPreview) -> str:
    lines = [
        f"Accepted domains: {preview.accepted}",
        f"Duplicates: {preview.duplicates}",
        f"Invalid or unsupported rows: {len(preview.issues)}",
        f"Ignored blank lines or comments: {preview.ignored}",
    ]
    if preview.issues:
        lines.append("")
        lines.append("First errors:")
        for issue in preview.issues[:5]:
            lines.append(f"Line {issue.line}: {issue.reason}")
    return "\\n".join(lines)




def daily_schedule_from_result(
    result: Mapping[str, object],
) -> tuple[date, str, tuple[DailyInterval, ...]]:
    """Parse the bounded daily schedule RPC result."""
    if (
        not isinstance(result, Mapping)
        or set(result) != {"date", "timezone", "intervals"}
        or not isinstance(result["date"], str)
        or not isinstance(result["timezone"], str)
        or not isinstance(result["intervals"], list)
        or len(result["intervals"]) > 512
    ):
        raise FormError("The service returned an invalid daily schedule.")
    try:
        local_day = date.fromisoformat(result["date"])
        zone = ZoneInfo(result["timezone"])
    except (ValueError, ZoneInfoNotFoundError) as error:
        raise FormError(
            "The service returned an invalid daily schedule."
        ) from error
    intervals: list[DailyInterval] = []
    for item in result["intervals"]:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {"rule_id", "rule_name", "start", "end"}
            or not isinstance(item["rule_id"], str)
            or not isinstance(item["rule_name"], str)
            or not item["rule_name"].strip()
            or not isinstance(item["start"], str)
            or not isinstance(item["end"], str)
        ):
            raise FormError(
                "The service returned an invalid daily schedule."
            )
        try:
            rule_id = str(UUID(item["rule_id"]))
            start = datetime.fromisoformat(item["start"])
            end = datetime.fromisoformat(item["end"])
        except (ValueError, TypeError) as error:
            raise FormError(
                "The service returned an invalid daily schedule."
            ) from error
        if (
            rule_id != item["rule_id"].lower()
            or start.tzinfo is None
            or end.tzinfo is None
            or end <= start
        ):
            raise FormError(
                "The service returned an invalid daily schedule."
            )
        intervals.append(DailyInterval(
            rule_id,
            item["rule_name"],
            start.astimezone(zone),
            end.astimezone(zone),
        ))
    return (
        local_day,
        result["timezone"],
        tuple(intervals),
    )


def observed_rule_states(
    rules: Sequence[Rule],
    now_utc: datetime,
    clock_trusted: bool,
) -> dict[str, ObservedRuleState]:
    """Get rule activity for one observed GUI poll."""
    return {
        rule.id: ObservedRuleState(
            rule.name,
            rule.is_active(now_utc, clock_trusted=clock_trusted),
        )
        for rule in rules
    }


def detect_rule_transitions(
    previous: Mapping[str, ObservedRuleState],
    current: Mapping[str, ObservedRuleState],
) -> tuple[RuleTransition, ...]:
    """Compare two observed states without changing service policy."""
    transitions: list[RuleTransition] = []
    for rule_id in sorted(set(previous) | set(current)):
        old = previous.get(rule_id)
        new = current.get(rule_id)
        was_active = old.active if old is not None else False
        is_active = new.active if new is not None else False
        if was_active == is_active:
            continue
        state = new if new is not None else old
        if state is not None:
            transitions.append(
                RuleTransition(rule_id, state.name, started=is_active)
            )
    return tuple(transitions)


def _display_time(value: datetime) -> str:
    try:
        zone = ZoneInfo(system_timezone_name())
    except FormError:
        zone = UTC
    return value.astimezone(zone).strftime("%Y-%m-%d %H:%M %Z")


def active_lock_explanation(
    rule: Rule,
    now_utc: datetime,
    clock_trusted: bool,
    lock: LockSummary | None = None,
) -> str:
    """Explain why an effective rule lock blocks weakening changes."""
    if not rule.is_active(now_utc, clock_trusted=clock_trusted):
        return ""
    if lock is None or not lock.locked:
        if rule.schedule.kind == "indefinite":
            return "This rule stays active until you disable it."
        return ""
    if lock.kind == "timed":
        if lock.until_utc is None:
            return ""
        return (
            "This locked rule cannot be weakened before "
            f"{_display_time(lock.until_utc)}."
        )
    if lock.kind == "schedule":
        if not clock_trusted:
            return (
                "This locked rule remains effective until the trusted clock "
                "is restored."
            )
        change = next_state_change(rule, now_utc, clock_trusted)
        if change is not None:
            return (
                "This locked rule cannot be weakened before "
                f"{_display_time(change.at_utc)}."
            )
        return "This locked rule cannot be weakened until its weekly period ends."
    if lock.kind == "delay":
        if lock.pending_until_utc is not None:
            return (
                "This Delay lock is counting down; the rule remains enforced "
                f"until {_display_time(lock.pending_until_utc)}."
            )
        if lock.break_until_utc is not None:
            return (
                "This Delay lock's temporary break ends "
                f"at {_display_time(lock.break_until_utc)}."
            )
        return "Request a temporary break; this Delay lock still blocks weakening changes."
    if lock.kind == "friction":
        return "This rule cannot be weakened before friction authorization is completed."
    if lock.kind == "password":
        return "This rule cannot be weakened before the password unlock condition is met."
    return ""


def _pomodoro_end(schedule: Mapping[str, object]) -> datetime:
    # Breadcrumb: the arithmetic lives on model.Schedule so the service, the
    # GUI, and the daily overview can never disagree about the final end.
    return Schedule.from_dict(dict(schedule)).pomodoro_end_utc()


def _rule_state_text(
    rule: Rule, now_utc: datetime, clock_trusted: bool
) -> str:
    """Name the visible state, including a trusted Pomodoro break."""
    if not rule.enabled:
        return "Disabled"
    active = rule.is_active(now_utc, clock_trusted=clock_trusted)
    schedule = rule.to_dict()["schedule"]
    if schedule["kind"] == "pomodoro" and clock_trusted:
        if active:
            return "Work"
        start = _parse_utc(schedule["start_utc"])
        if start <= now_utc < _pomodoro_end(schedule):
            return "Break"
    return "Active" if active else "Inactive"


def _state_change_action(rule: Rule, change: StateChange) -> str:
    """Describe the next boundary without calling a Pomodoro break an end."""
    schedule = rule.to_dict()["schedule"]
    if schedule["kind"] != "pomodoro":
        return "Starts" if change.active_after else "Ends"
    if change.active_after:
        return "Work starts"
    if change.at_utc == _pomodoro_end(schedule):
        return "Ends"
    return "Break starts"


def _schedule_summary(rule: Rule) -> str:
    schedule = rule.to_dict()["schedule"]
    if schedule["kind"] == "indefinite":
        return "Indefinite"
    if schedule["kind"] == "one_time":
        return (
            f"One time: {_display_time(_parse_utc(schedule['start_utc']))} to "
            f"{_display_time(_parse_utc(schedule['end_utc']))}"
        )
    if schedule["kind"] == "pomodoro":
        cycles = schedule["cycles"]
        cycle_noun = "cycle" if cycles == 1 else "cycles"
        return (
            f"Pomodoro: {cycles} {cycle_noun}, "
            f"{schedule['work_minutes']} min work, "
            f"{schedule['break_minutes']} min break; "
            f"starts {_display_time(_parse_utc(schedule['start_utc']))}"
        )
    count = len(schedule["periods"])
    noun = "period" if count == 1 else "periods"
    return f"Weekly: {count} {noun} ({schedule['timezone']})"


def _target_summary(rule: Rule) -> str:
    targets = rule.to_dict()["targets"]
    websites = sum(item["kind"] == "website" for item in targets)
    applications = sum(item["kind"] == "application" for item in targets)
    managed_lists = sum(item["kind"] == "managed_list" for item in targets)
    url_targets = sum(
        item["kind"] in Target.URL_LIKE_KINDS for item in targets
    )
    parts: list[str] = []
    if websites:
        parts.append(f"{websites} website" + ("s" if websites != 1 else ""))
    if applications:
        parts.append(f"{applications} application" + ("s" if applications != 1 else ""))
    if managed_lists:
        parts.append(
            f"{managed_lists} managed list" + ("s" if managed_lists != 1 else "")
        )
    if url_targets:
        parts.append(f"{url_targets} URL rule" + ("s" if url_targets != 1 else ""))
    networks = sum(item["kind"] == "network" for item in targets)
    if networks:
        parts.append(
            f"{networks} network control" + ("s" if networks != 1 else "")
        )
    return ", ".join(parts)
def _rule_notifications_include(rule: Rule, category: str) -> bool:
    return (
        rule.notifications_enabled
        and category in rule.notification_categories
    )



class GuiController:
    """Coordinate GTK widgets without a module-level GTK type."""

    def __init__(self, modules: GtkModules, application: object, client: Client):
        self.Gtk, self.Gio, self.GLib = modules.Gtk, modules.Gio, modules.GLib
        self.application, self.client = application, client
        self.snapshot: ServiceSnapshot | None = None
        self._observed_states: dict[str, ObservedRuleState] | None = None
        self._warning_keys: set[tuple[str, datetime, bool]] = set()
        self._refreshing = False
        self._poll_source: int | None = None
        self.timezone = system_timezone_name()
        self.theme = load_theme()
        self.gtk_settings = self.Gtk.Settings.get_default()
        self.system_prefers_dark = bool(
            self.gtk_settings.get_property("gtk-application-prefer-dark-theme")
        ) if self.gtk_settings is not None else False
        self._apply_theme(self.theme)
        self.window = self._build_window()
        self.window.connect("close-request", self._window_closed)

    def _apply_theme(self, theme: str) -> None:
        if self.gtk_settings is None:
            return
        if theme == "dark":
            prefer_dark = True
        elif theme == "light":
            prefer_dark = False
        else:
            prefer_dark = self.system_prefers_dark
        self.gtk_settings.set_property(
            "gtk-application-prefer-dark-theme", prefer_dark
        )

    def _theme_changed(self, dropdown: object, _parameter: object) -> None:
        selected = dropdown.get_selected()
        if selected >= len(THEMES):
            return
        theme = THEMES[selected]
        try:
            save_theme(theme)
        except (OSError, ValueError) as error:
            self.notice_label.set_text(f"Theme preference was not saved. {error}")
            self.notice_label.add_css_class("error")
            return
        self.theme = theme
        self._apply_theme(theme)

    def _build_window(self) -> object:
        Gtk = self.Gtk
        window = Gtk.ApplicationWindow(application=self.application)
        window.set_default_size(960, 700)
        window.set_resizable(True)
        header = Gtk.HeaderBar()
        title = Gtk.Label(label="Distraction Blocker")
        title.add_css_class("title")
        header.set_title_widget(title)
        self.refresh_button = Gtk.Button.new_with_mnemonic("_Refresh")
        self.refresh_button.connect("clicked", lambda _button: self.refresh())
        header.pack_end(self.refresh_button)
        self.theme_dropdown = Gtk.DropDown.new_from_strings(THEME_LABELS)
        self.theme_dropdown.set_selected(THEMES.index(self.theme))
        self.theme_dropdown.set_tooltip_text("Select the application theme")
        self.theme_dropdown.connect("notify::selected", self._theme_changed)
        header.pack_end(self.theme_dropdown)
        window.set_titlebar(header)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM))
        for method in (root.set_margin_top, root.set_margin_bottom,
                       root.set_margin_start, root.set_margin_end):
            method(int(Space.LARGE))
        window.set_child(root)
        service_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
        heading = Gtk.Label(label="Service")
        heading.add_css_class("heading")
        heading.set_xalign(0)
        service_row.append(heading)
        self.health_label = Gtk.Label(label="Loading service state.")
        self.health_label.set_xalign(0)
        self.health_label.set_hexpand(True)
        service_row.append(self.health_label)
        self.statistics_button = Gtk.Button.new_with_mnemonic(
            "Denial _statistics"
        )
        self.statistics_button.set_tooltip_text(
            "View recorded application denial counts"
        )
        self.statistics_button.connect(
            "clicked", lambda _button: self.open_denial_statistics()
        )
        service_row.append(self.statistics_button)
        root.append(service_row)
        self.clock_label = Gtk.Label(label="Clock state is not available.")
        self.clock_label.set_xalign(0)
        self.clock_label.set_wrap(True)
        root.append(self.clock_label)
        self.active_label = Gtk.Label(label="")
        self.active_label.set_xalign(0)
        root.append(self.active_label)
        root.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        rule_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
        rules_heading = Gtk.Label(label="Rules")
        rules_heading.add_css_class("title-2")
        rules_heading.set_xalign(0)
        rules_heading.set_hexpand(True)
        rule_header.append(rules_heading)
        self.focus_button = Gtk.Button.new_with_mnemonic("_Quick focus")
        self.focus_button.connect("clicked", lambda _button: self.open_quick_focus())
        rule_header.append(self.focus_button)
        self.add_button = Gtk.Button.new_with_mnemonic("_Add rule")
        self.add_button.add_css_class("suggested-action")
        self.add_button.connect("clicked", lambda _button: self.open_editor())
        rule_header.append(self.add_button)
        root.append(rule_header)
        transfer_bar = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.COMPACT)
        )
        self.lists_button = Gtk.Button.new_with_mnemonic("_Managed lists")
        self.lists_button.connect("clicked", lambda _button: self.open_managed_lists())
        transfer_bar.append(self.lists_button)
        self.overview_button = Gtk.Button.new_with_mnemonic("Daily o_verview")
        self.overview_button.connect("clicked", lambda _button: self.open_daily_overview())
        transfer_bar.append(self.overview_button)
        self.import_domains_button = Gtk.Button.new_with_mnemonic("_Import domains")
        self.import_block_list_button = Gtk.Button.new_with_mnemonic(
            "Import _Block List"
        )
        self.import_block_list_button.connect(
            "clicked", lambda _button: self._choose_block_list_import()
        )
        transfer_bar.append(self.import_block_list_button)
        self.import_domains_button.connect(
            "clicked", lambda _button: self._choose_domain_import()
        )
        transfer_bar.append(self.import_domains_button)
        self.import_backup_button = Gtk.Button.new_with_mnemonic("Import _backup")
        self.import_backup_button.connect(
            "clicked", lambda _button: self._choose_native_import()
        )
        transfer_bar.append(self.import_backup_button)
        self.export_domains_button = Gtk.Button.new_with_mnemonic("Export d_omains")
        self.export_domains_button.connect(
            "clicked", lambda _button: self._choose_export("domains")
        )
        transfer_bar.append(self.export_domains_button)
        self.export_backup_button = Gtk.Button.new_with_mnemonic("Export bac_kup")
        self.export_backup_button.connect(
            "clicked", lambda _button: self._choose_export("native")
        )
        transfer_bar.append(self.export_backup_button)
        transfer_scroller = Gtk.ScrolledWindow()
        transfer_scroller.set_hexpand(True)
        transfer_scroller.set_policy(
            Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER
        )
        transfer_scroller.set_child(transfer_bar)
        root.append(transfer_scroller)
        search_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search rule names and targets")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._filter_changed)
        search_row.append(self.search_entry)
        self.sort_dropdown = Gtk.DropDown.new_from_strings(RULE_SORT_LABELS)
        self.sort_dropdown.set_selected(0)
        self.sort_dropdown.connect("notify::selected", self._filter_changed)
        self.sort_dropdown.set_tooltip_text("Sort matching rules")
        search_row.append(self.sort_dropdown)
        self.filter_dropdown = Gtk.DropDown.new_from_strings(RULE_FILTER_LABELS)
        self.filter_dropdown.set_selected(0)
        self.filter_dropdown.connect("notify::selected", self._filter_changed)
        search_row.append(self.filter_dropdown)
        root.append(search_row)
        self.notice_label = Gtk.Label(label="")
        self.notice_label.set_xalign(0)
        self.notice_label.set_wrap(True)
        root.append(self.notice_label)
        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.rule_list = Gtk.ListBox()
        self.rule_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.rule_list.add_css_class("boxed-list")
        scroller.set_child(self.rule_list)
        root.append(scroller)
        return window

    def present(self) -> None:
        self.window.present()
        self.refresh()
        self._poll_source = self.GLib.timeout_add_seconds(15, self._poll_service)

    def _poll_service(self) -> bool:
        self.refresh(show_busy=False)
        return True

    def _window_closed(self, _window: object) -> bool:
        if self._poll_source is not None:
            self.GLib.source_remove(self._poll_source)
            self._poll_source = None
        self.closed = True
        return False

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.set_sensitive(not busy)
        self.add_button.set_sensitive(not busy)
        self.focus_button.set_sensitive(not busy)
        self.lists_button.set_sensitive(not busy)
        self.overview_button.set_sensitive(not busy)
        self.statistics_button.set_sensitive(not busy)
        for widget in (
            self.import_domains_button,
            self.import_block_list_button,
            self.import_backup_button,
            self.export_domains_button,
            self.export_backup_button,
        ):
            widget.set_sensitive(not busy)
        if busy:
            self.notice_label.set_text("Loading service state.")
            self.notice_label.remove_css_class("error")

    def refresh(self, show_busy: bool = True) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        if show_busy:
            self._set_busy(True)

        def request_snapshot() -> None:
            try:
                status = self.client.request("status")
                rules = self.client.request("list_rules")
                lists = self.client.request("list_managed_lists")
                locks = self.client.request("list_locks")
                if (
                    not isinstance(status, Mapping)
                    or not isinstance(rules, Mapping)
                    or not isinstance(lists, list)
                    or not isinstance(locks, list)
                ):
                    raise FormError("The service returned invalid data.")
                snapshot = snapshot_from_results(status, rules, lists, locks)
            except Exception as error:
                self.GLib.idle_add(self._show_request_error, str(error))
            else:
                self.GLib.idle_add(self._show_snapshot, snapshot)
        threading.Thread(target=request_snapshot, daemon=True).start()

    def _show_request_error(self, detail: str) -> bool:
        self._refreshing = False
        self._set_busy(False)
        self.health_label.set_text("Unavailable")
        self.health_label.add_css_class("error")
        self.clock_label.set_text("The clock state is not available.")
        self.active_label.set_text("")
        self.notice_label.set_text("The service did not respond." + (f" {detail}" if detail else ""))
        self.notice_label.add_css_class("error")
        return False

    def _show_snapshot(self, snapshot: ServiceSnapshot) -> bool:
        self._refreshing = False
        now_utc = datetime.now(UTC)
        current_states = observed_rule_states(
            snapshot.rules, now_utc, snapshot.clock_trusted
        )
        if self._observed_states is not None:
            rules_by_id = {rule.id: rule for rule in snapshot.rules}
            transitions = detect_rule_transitions(
                self._observed_states, current_states
            )
            self._send_transition_notifications(
                tuple(
                    transition
                    for transition in transitions
                    if (
                        (rule := rules_by_id.get(transition.rule_id)) is not None
                        and _rule_notifications_include(rule, "state_changes")
                    )
                )
            )
        self._observed_states = current_states
        self._send_advance_notifications(
            snapshot.rules, now_utc, snapshot.clock_trusted
        )
        self.snapshot = snapshot
        self._set_busy(False)
        self.notice_label.set_text("")
        self.notice_label.remove_css_class("error")
        self.health_label.remove_css_class("error")
        self.clock_label.remove_css_class("error")
        if snapshot.healthy:
            self.health_label.set_text("Healthy")
        else:
            self.health_label.set_text("Unhealthy. Policy changes are disabled.")
            self.health_label.add_css_class("error")
        if snapshot.clock_trusted:
            self.clock_label.set_text(f"Clock: trusted. Time zone: {self.timezone}.")
        else:
            text = "Clock: not trusted. Finite rules stay blocked until root recovery."
            if snapshot.clock_reason.strip():
                text += f" {snapshot.clock_reason.strip()}"
            self.clock_label.set_text(text)
            self.clock_label.add_css_class("error")
        self.active_label.set_text(
            f"Active targets: {snapshot.active_websites} websites, "
            f"{snapshot.active_applications} applications, "
            f"{snapshot.active_network} network controls."
        )
        self.add_button.set_sensitive(snapshot.healthy)
        self.focus_button.set_sensitive(snapshot.healthy and bool(snapshot.rules))
        self.import_domains_button.set_sensitive(snapshot.healthy)
        self.import_backup_button.set_sensitive(snapshot.healthy)
        self._render_rules(snapshot)
        return False

    def _send_advance_notifications(
        self,
        rules: Sequence[Rule],
        now_utc: datetime,
        clock_trusted: bool,
    ) -> None:
        """Warn once when a rule boundary is five minutes away."""
        if not clock_trusted:
            return
        horizon = now_utc + timedelta(minutes=5)
        for rule in rules:
            if not _rule_notifications_include(rule, "upcoming_changes"):
                continue
            change = next_state_change(rule, now_utc, clock_trusted)
            if change is None or not now_utc < change.at_utc <= horizon:
                continue
            key = (rule.id, change.at_utc, change.active_after)
            if key in self._warning_keys:
                continue
            self._warning_keys.add(key)
            action = "starts" if change.active_after else "ends"
            seconds = max(1, int((change.at_utc - now_utc).total_seconds()))
            minutes = max(1, round(seconds / 60))
            try:
                notification = self.Gio.Notification.new(
                    f"Rule {action} in {minutes} minute"
                    + ("" if minutes == 1 else "s")
                )
                notification.set_body(f"{rule.name} {action} soon.")
                self.application.send_notification(
                    f"rule-warning-{rule.id}-{change.at_utc.isoformat()}",
                    notification,
                )
            except Exception:
                continue
        if len(self._warning_keys) > 1024:
            self._warning_keys = set(sorted(self._warning_keys)[-256:])

    def _send_transition_notifications(
        self, transitions: Sequence[RuleTransition]
    ) -> None:
        # Breadcrumb for reviewers: notifications only report two observed
        # states. This path never sends a policy or enforcement request.
        for transition in transitions:
            action = "started" if transition.started else "ended"
            try:
                notification = self.Gio.Notification.new(
                    f"Rule {action}: {transition.rule_name}"
                )
                notification.set_body(
                    "Distraction Blocker observed this service state change."
                )
                self.application.send_notification(
                    f"rule-{transition.rule_id}-{action}", notification
                )
            except Exception:
                # NOTE: Desktop notification failure must not stop GUI refresh
                # or change the root service state.
                continue

    def _filter_changed(self, _widget: object, _parameter: object = None) -> None:
        if self.snapshot is not None:
            self._render_rules(self.snapshot)

    def _clear_rules(self) -> None:
        child = self.rule_list.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.rule_list.remove(child)
            child = next_child

    def _render_rules(self, snapshot: ServiceSnapshot) -> None:
        Gtk = self.Gtk
        self._clear_rules()
        now_utc = datetime.now(UTC)
        state_selected = self.filter_dropdown.get_selected()
        state_filter = (
            RULE_FILTERS[state_selected]
            if state_selected < len(RULE_FILTERS)
            else "all"
        )
        sort_selected = self.sort_dropdown.get_selected()
        sort_filter = (
            RULE_SORTS[sort_selected]
            if sort_selected < len(RULE_SORTS)
            else "recent"
        )
        rules = filter_rules(
            snapshot.rules,
            self.search_entry.get_text(),
            state_filter,
            now_utc,
            snapshot.clock_trusted,
            sort_filter,
        )
        locks_by_rule = {item.rule_id: item for item in snapshot.locks}
        if not rules:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT))
            for method in (box.set_margin_top, box.set_margin_bottom,
                           box.set_margin_start, box.set_margin_end):
                method(int(Space.MEDIUM))
            title_text = "No rules" if not snapshot.rules else "No matching rules"
            message_text = (
                "Add a rule to block a website or application."
                if not snapshot.rules
                else "Change the search text or state filter."
            )
            title = Gtk.Label(label=title_text)
            title.add_css_class("heading")
            title.set_xalign(0)
            message = Gtk.Label(label=message_text)
            message.set_xalign(0)
            box.append(title)
            box.append(message)
            row.set_child(box)
            self.rule_list.append(row)
            return
        for rule in rules:
            self.rule_list.append(
                self._rule_row(
                    rule,
                    now_utc,
                    snapshot,
                    locks_by_rule.get(rule.id),
                )
            )

    def _rule_row(
        self,
        rule: Rule,
        now_utc: datetime,
        snapshot: ServiceSnapshot,
        lock: LockSummary | None,
    ) -> object:
        Gtk = self.Gtk
        data = rule.to_dict()
        # Breadcrumb (allowance seam): an exhausted rule is ACTIVE-BLOCKING
        # regardless of its schedule, so the visible state says so and the
        # scheduled next-change line would be misleading until the reset.
        exhausted = (
            data["enabled"] and rule.id in snapshot.exhausted_rule_ids
        )
        active = exhausted or rule.is_active(
            now_utc, clock_trusted=snapshot.clock_trusted
        )
        kind = data["schedule"]["kind"]
        row = Gtk.ListBoxRow()
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL))
        for method in (outer.set_margin_top, outer.set_margin_bottom,
                       outer.set_margin_start, outer.set_margin_end):
            method(int(Space.SMALL))
        row.set_child(outer)
        heading_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
        name = Gtk.Label(label=data["name"])
        name.add_css_class("heading")
        name.set_xalign(0)
        name.set_hexpand(True)
        heading_row.append(name)
        if exhausted:
            allowance = data.get("allowance_starts")
            state = Gtk.Label(
                label=(
                    f"Blocking — daily start allowance used "
                    f"({allowance} of {allowance} starts)."
                )
            )
            state.add_css_class("warning")
        else:
            state = Gtk.Label(
                label=_rule_state_text(rule, now_utc, snapshot.clock_trusted)
            )
            state.add_css_class("accent" if active else "dim-label")
        heading_row.append(state)
        outer.append(heading_row)
        details = Gtk.Label(label=f"{_target_summary(rule)} · {_schedule_summary(rule)}")
        details.set_xalign(0)
        details.set_wrap(True)
        details.add_css_class("dim-label")
        outer.append(details)
        lock_text = Gtk.Label(
            label=(
                "Rule lock: none."
                if lock is None
                else lock_summary_text(lock, self.timezone)
            )
        )
        lock_text.set_xalign(0)
        lock_text.set_wrap(True)
        lock_text.add_css_class(
            "warning" if lock is not None and lock.locked else "dim-label"
        )
        outer.append(lock_text)
        if not exhausted and data["enabled"] and snapshot.clock_trusted:
            change = next_state_change(rule, now_utc)
            if change is not None:
                action = _state_change_action(rule, change)
                label = Gtk.Label(
                    label=f"Next state change: {action} at {_display_time(change.at_utc)}."
                )
                label.set_xalign(0)
                outer.append(label)
        elif data["enabled"] and kind != "indefinite":
            label = Gtk.Label(label="Next state change: after root restores the trusted clock.")
            label.set_xalign(0)
            outer.append(label)
        explanation = active_lock_explanation(
            rule,
            now_utc,
            snapshot.clock_trusted,
            lock,
        )
        if explanation:
            label = Gtk.Label(label=explanation)
            label.set_xalign(0)
            label.set_wrap(True)
            label.add_css_class("warning")
            outer.append(label)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.COMPACT))
        edit = Gtk.Button.new_with_mnemonic("_Edit")
        edit.set_sensitive(snapshot.healthy)
        edit.connect("clicked", lambda _button, item=rule: self.open_editor(item))
        actions.append(edit)
        duplicate = Gtk.Button.new_with_mnemonic("D_uplicate")
        duplicate.set_sensitive(snapshot.healthy)
        duplicate.connect("clicked", lambda _button, item=rule: self._duplicate_rule(item))
        actions.append(duplicate)
        export = Gtk.Button.new_with_mnemonic("E_xport")
        export.connect(
            "clicked", lambda _button, item=rule: self._choose_export("domains", (item,))
        )
        actions.append(export)
        toggle = Gtk.Button.new_with_mnemonic("_Disable" if data["enabled"] else "_Enable")
        disable_locked = (
            data["enabled"] and lock is not None and lock.locked
        )
        toggle.set_sensitive(snapshot.healthy and not disable_locked)
        if disable_locked:
            toggle.set_tooltip_text(
                "The active lock blocks disabling this rule."
            )
        toggle.connect("clicked", lambda _button, item=rule, enabled=not data["enabled"]: self._set_enabled(item, enabled))
        actions.append(toggle)
        lock_button = Gtk.Button.new_with_mnemonic("_Lock")
        lock_button.set_tooltip_text("Create, change, or remove a rule lock")
        lock_button.connect(
            "clicked",
            lambda _button, item=rule, summary=lock: self.open_rule_lock(
                item, summary
            ),
        )
        actions.append(lock_button)
        if (
            lock is not None
            and lock.kind in {"friction", "password"}
            and lock.locked
        ):
            authorize = Gtk.Button.new_with_mnemonic("_Authorize")
            authorize.set_sensitive(snapshot.healthy)
            authorize.set_tooltip_text(
                "Authorize one weakening change for this rule lock"
            )
            authorize.connect(
                "clicked",
                lambda _button, item=rule: self.open_rule_authorization(item),
            )
            actions.append(authorize)
        if lock is not None and lock.kind == "delay" and lock.locked:
            if lock.pending_until_utc is not None:
                delay_action = Gtk.Button.new_with_mnemonic("_Cancel delay")
                delay_action.set_tooltip_text(
                    "Cancel the pending Delay break."
                )
                delay_action.connect(
                    "clicked",
                    lambda _button, item=rule: self._cancel_delay_break(item),
                )
            elif lock.break_until_utc is None:
                delay_action = Gtk.Button.new_with_mnemonic("_Request break")
                delay_action.set_tooltip_text(
                    "Start the configured Delay countdown."
                )
                delay_action.connect(
                    "clicked",
                    lambda _button, item=rule: self._request_delay_break(item),
                )
            else:
                delay_action = None
            if delay_action is not None:
                delay_action.set_sensitive(snapshot.healthy)
                actions.append(delay_action)
        delete = Gtk.Button.new_with_mnemonic("_Delete")
        delete.add_css_class("destructive-action")
        timed_delete_lock = (
            lock is not None and lock.kind == "timed" and lock.locked
        )
        delete.set_sensitive(snapshot.healthy and not active and not timed_delete_lock)
        if timed_delete_lock:
            delete.set_tooltip_text("The timed lock blocks deleting this rule.")
        elif active:
            delete.set_tooltip_text(explanation or "Disable this rule before you delete it.")
        delete.connect("clicked", lambda _button, item=rule: self._confirm_delete(item))
        actions.append(delete)
        outer.append(actions)
        return row

    def _rpc_error(self, error: Exception) -> str:
        return str(error).strip() or "The service rejected the request."

    def _run_worker(
        self,
        work: Callable[[], object],
        success: Callable[[object], None],
        failure: Callable[[Exception], None] | None = None,
    ) -> None:
        """Run blocking file or service work outside the GTK event thread."""
        def run() -> None:
            try:
                result = work()
            except Exception as error:
                callback = failure or (
                    lambda item: self._show_error(self._rpc_error(item))
                )
                self.GLib.idle_add(callback, error)
            else:
                self.GLib.idle_add(success, result)
        threading.Thread(target=run, daemon=True).start()

    def _request_async(
        self,
        command: str,
        fields: Mapping[str, object],
        success: Callable[[object], None],
        failure: Callable[[Exception], None] | None = None,
    ) -> None:
        self._run_worker(
            lambda: self.client.request(command, **dict(fields)),
            success,
            failure,
        )

    def _refresh_after_request(self, _result: object) -> None:
        self.refresh()
    def _request_delay_break(self, rule: Rule) -> None:
        try:
            fields = request_delay_break_request(rule.id)
        except FormError as error:
            self._show_error(str(error))
            return
        self._request_async(
            "request_delay_break",
            fields,
            self._refresh_after_request,
        )

    def _cancel_delay_break(self, rule: Rule) -> None:
        try:
            fields = cancel_delay_break_request(rule.id)
        except FormError as error:
            self._show_error(str(error))
            return
        self._request_async(
            "cancel_delay_break",
            fields,
            self._refresh_after_request,
        )



    def _set_enabled(self, rule: Rule, enabled: bool) -> None:
        self._request_async(
            "set_enabled",
            {"rule_id": rule.id, "enabled": enabled},
            self._refresh_after_request,
        )

    def _duplicate_rule(self, rule: Rule) -> None:
        try:
            copy = duplicate_rule(rule)
        except (ValidationError, ValueError) as error:
            self._show_error(str(error))
            return
        self._request_async(
            "put_rule",
            {"rule": copy.to_dict()},
            self._refresh_after_request,
        )

    def _show_error(self, message: str) -> None:
        self.notice_label.set_text(message)
        self.notice_label.add_css_class("error")

    def _choose_domain_import(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import domain list",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a local import file.")
                return

            def read_preview() -> ImportPreview:
                preview = parse_domain_text(read_import_text(path))
                if not preview.domains:
                    raise TransferError("The import contains no valid domains.")
                return preview

            self._run_worker(
                read_preview,
                lambda preview: self._confirm_domain_import(
                    preview, Path(path).name
                ),
                lambda error: self._show_error(str(error)),
            )

        chooser.connect("response", respond)
        chooser.show()

    def _confirm_domain_import(self, preview: ImportPreview, filename: str) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Import domains from {filename}?",
            secondary_text=import_preview_text(preview),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Continue", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response == Gtk.ResponseType.ACCEPT:
                self.open_editor(initial_domains=preview.domains)

        dialog.connect("response", respond)
        dialog.present()

    def _choose_block_list_import(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import Block List blocklist",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a Block List export file.")
                return

            def read_preview() -> BlockListImportPreview:
                return parse_block_list_export(
                    read_block_list_text(path),
                    timezone_name=_view_timezone_name(),
                    enabled=False,
                )

            self._run_worker(
                read_preview,
                lambda preview: self._confirm_block_list_import(
                    preview, Path(path).name
                ),
                lambda error: self._show_error(str(error)),
            )

        chooser.connect("response", respond)
        chooser.show()

    def _confirm_block_list_import(
        self, preview: BlockListImportPreview, filename: str
    ) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Import Block List blocks from {filename}?",
            secondary_text=(
                block_list_preview_text(preview)
                + "\n\nImported rules are disabled for review."
            ),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        import_button = dialog.add_button("_Import", Gtk.ResponseType.ACCEPT)
        import_button.set_sensitive(bool(preview.rules))
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response == Gtk.ResponseType.ACCEPT:
                self._run_worker(
                    lambda: self._upload_block_list_rules(preview),
                    self._block_list_import_done,
                    lambda error: self._show_error(str(error)),
                )

        dialog.connect("response", respond)
        dialog.present()
    def _upload_block_list_rules(
        self, preview: BlockListImportPreview
    ) -> int:
        if not preview.rules:
            return 0
        response = self.client.request("begin_rule_import")
        import_id = response["import_id"]
        try:
            for offset in range(0, len(preview.rules), 200):
                self.client.request(
                    "import_rule_chunk",
                    import_id=import_id,
                    rules=[
                        rule.to_dict()
                        for rule in preview.rules[offset : offset + 200]
                    ],
                )
            self.client.request("commit_rule_import", import_id=import_id)
        except Exception:
            try:
                self.client.request("cancel_rule_import", import_id=import_id)
            except Exception:
                pass
            raise
        return len(preview.rules)

    def _block_list_import_done(self, count: int) -> None:
        self.notice_label.set_text(
            f"Imported {count} disabled Block List rule"
            + ("" if count == 1 else "s")
            + ". Review and enable them as needed."
        )
        self.notice_label.remove_css_class("error")
        self.refresh()


    def _choose_native_import(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import native backup",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a local backup file.")
                return

            def read_backup() -> tuple[str, Policy]:
                text = read_native_text(path)
                return text, parse_native_export(text)

            self._run_worker(
                read_backup,
                lambda result: self._confirm_native_import(
                    result[0], result[1], Path(path).name
                ),
                lambda error: self._show_error(str(error)),
            )
        chooser.connect("response", respond)
        chooser.show()

    def _confirm_native_import(
        self, text: str, policy: Policy, filename: str
    ) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Replace policy state from {filename}?",
            secondary_text=(
                f"The backup contains {len(policy.rules)} rules and "
                f"{len(policy.managed_lists)} managed lists. "
                "The service refuses changes that weaken an active rule."
            ),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Import", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            self._run_worker(
                lambda: self._upload_native_text(text),
                lambda result: self._native_import_done(result, filename),
            )
        dialog.connect("response", respond)
        dialog.present()

    def _upload_native_text(self, text: str) -> object:
        begin = self.client.request("begin_native_import")
        if not isinstance(begin, Mapping) or not isinstance(
            begin.get("import_id"), str
        ):
            raise FormError("The service returned an invalid import ID.")
        import_id = begin["import_id"]
        try:
            result: object = None
            for call in staged_native_upload_calls(import_id, text):
                result = self.client.request(call.command, **dict(call.fields))
            return result
        except Exception:
            # Breadcrumb for reviewers: cancellation releases owner-only
            # staged data. A failed upload never commits partial policy state.
            try:
                self.client.request("cancel_native_import", import_id=import_id)
            except Exception:
                pass
            raise

    def _native_import_done(self, result: object, filename: str) -> None:
        if not isinstance(result, Mapping):
            self._show_error("The service returned an invalid import result.")
            return
        self.notice_label.set_text(
            f"Imported {result.get('imported', 0)} rules and "
            f"{result.get('managed_lists', 0)} managed lists from {filename}."
        )
        self.notice_label.remove_css_class("error")
        self.refresh()

    def _choose_export(
        self, export_kind: str, selected_rules: Sequence[Rule] | None = None
    ) -> None:
        if export_kind not in {"domains", "native"}:
            self._show_error("The export type is not supported.")
            return
        rules = (
            tuple(selected_rules)
            if selected_rules is not None
            else (() if self.snapshot is None else self.snapshot.rules)
        )
        summaries = () if self.snapshot is None else self.snapshot.managed_lists
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Export block list",
            self.window,
            Gtk.FileChooserAction.SAVE,
            "_Export",
            "_Cancel",
        )
        chooser.set_current_name(
            "distraction-blocker-domains.txt"
            if export_kind == "domains"
            else "distraction-blocker-backup.json"
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a local export path.")
                return

            def export() -> object:
                managed_lists = self._read_managed_lists(summaries)
                if export_kind == "domains":
                    content = domain_export_text(rules, managed_lists)
                else:
                    policy = Policy.from_dict(
                        {
                            "schema_version": POLICY_SCHEMA_VERSION,
                            "revision": 0,
                            "rules": [rule.to_dict() for rule in rules],
                            "managed_lists": [
                                item.to_dict() for item in managed_lists
                            ],
                        }
                    )
                    content = native_export_text(policy)
                atomic_write_text(path, content)
                return path

            self._run_worker(
                export,
                lambda _result: self._export_done(Path(path).name),
                lambda error: self._show_error(str(error)),
            )
        chooser.connect("response", respond)
        chooser.show()

    def _read_managed_lists(
        self, summaries: Sequence[ManagedListSummary]
    ) -> tuple[ManagedList, ...]:
        managed_lists: list[ManagedList] = []
        for summary in summaries:
            domains: list[str] = []
            offset = 0
            while True:
                result = self.client.request(
                    "read_managed_list",
                    list_id=summary.id,
                    offset=offset,
                    limit=RPC_LIST_CHUNK_SIZE,
                )
                if (
                    not isinstance(result, Mapping)
                    or set(result) != {
                        "id", "offset", "domains", "next_offset"
                    }
                    or result["id"] != summary.id
                    or result["offset"] != offset
                    or not isinstance(result["domains"], list)
                    or len(result["domains"]) > RPC_LIST_CHUNK_SIZE
                    or any(not isinstance(item, str) for item in result["domains"])
                ):
                    raise FormError("The service returned an invalid list chunk.")
                chunk = result["domains"]
                domains.extend(chunk)
                following = offset + len(chunk)
                next_offset = result["next_offset"]
                if next_offset is None:
                    if following != summary.domain_count:
                        raise FormError(
                            "The service returned an incomplete managed list."
                        )
                    break
                if (
                    not isinstance(next_offset, int)
                    or isinstance(next_offset, bool)
                    or not chunk
                    or next_offset != following
                ):
                    raise FormError("The service returned an invalid list offset.")
                offset = next_offset
            if len(domains) != summary.domain_count:
                raise FormError("The service returned an incomplete managed list.")
            managed_lists.append(managed_list_from_domains(summary, domains))
        return tuple(managed_lists)
    def _upload_managed_list_snapshots(
        self,
        managed_lists: Sequence[ManagedList],
        completed: Callable[[str | None], None],
    ) -> None:
        def upload() -> None:
            for managed_list in managed_lists:
                self._upload_list(managed_list)

        self._run_worker(
            upload,
            lambda _result: completed(None),
            lambda error: completed(self._rpc_error(error)),
        )

    def _export_done(self, filename: str) -> None:
        self.notice_label.set_text(f"Exported {filename}.")
        self.notice_label.remove_css_class("error")


    def _confirm_delete(self, rule: Rule) -> None:
        Gtk = self.Gtk
        data = rule.to_dict()
        dialog = Gtk.MessageDialog(
            transient_for=self.window, modal=True, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE, text=f"Delete {data['name']}?",
            secondary_text="This action deletes the rule."
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Delete", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            self._request_async(
                "delete_rule",
                {"rule_id": data["id"]},
                self._refresh_after_request,
            )
        dialog.connect("response", respond)
        dialog.present()

    def open_managed_lists(self) -> None:
        snapshot = self.snapshot
        summaries = () if snapshot is None else snapshot.managed_lists
        healthy = snapshot is not None and snapshot.healthy
        ManagedListWindow(
            GtkModules(self.Gtk, self.Gio, self.GLib),
            self.window,
            summaries,
            starter_categories(datetime.now(UTC)),
            healthy,
            self._choose_managed_list_import,
            self._create_managed_list,
            self._edit_managed_list,
            self._install_starter_category,
            self._confirm_managed_list_delete,
        ).present()

    def _create_managed_list(self, parent: object) -> None:
        ManagedListEditorWindow(
            GtkModules(self.Gtk, self.Gio, self.GLib),
            parent,
            None,
            self._upload_managed_list,
        ).present()

    def _edit_managed_list(
        self, parent: object, summary: ManagedListSummary
    ) -> None:
        self._run_worker(
            lambda: self._read_managed_lists((summary,))[0],
            lambda managed_list: ManagedListEditorWindow(
                GtkModules(self.Gtk, self.Gio, self.GLib),
                parent,
                managed_list,
                self._upload_managed_list,
            ).present(),
            lambda error: self._show_dialog_error(parent, self._rpc_error(error)),
        )

    def _choose_managed_list_import(self, parent: object) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import managed list",
            parent,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a local import file.")
                return

            def read_preview() -> ImportPreview:
                preview = parse_domain_text(read_import_text(path))
                if not preview.domains:
                    raise TransferError("The import contains no valid domains.")
                return preview

            self._run_worker(
                read_preview,
                lambda preview: ManagedListImportWindow(
                    GtkModules(self.Gtk, self.Gio, self.GLib),
                    parent,
                    Path(path).name,
                    preview,
                    self._upload_managed_list,
                ).present(),
                lambda error: self._show_error(str(error)),
            )
        chooser.connect("response", respond)
        chooser.show()

    def _upload_managed_list(
        self,
        managed_list: ManagedList,
        completed: Callable[[str | None], None],
    ) -> None:
        self._run_worker(
            lambda: self._upload_list(managed_list),
            lambda _result: self._managed_list_changed(
                f"Saved {managed_list.name}.", completed
            ),
            lambda error: completed(self._rpc_error(error)),
        )

    def _upload_list(self, managed_list: ManagedList) -> object:
        data = managed_list_import_metadata(managed_list)
        domains = managed_list.domains
        # Breadcrumb for reviewers: the service owns the import timestamp.
        # The GUI sends only user-supplied metadata.
        begin = self.client.request("begin_list_import", metadata=data)
        if not isinstance(begin, Mapping) or not isinstance(
            begin.get("import_id"), str
        ):
            raise FormError("The service returned an invalid list import ID.")
        import_id = begin["import_id"]
        try:
            result: object = None
            for call in staged_list_upload_calls(import_id, domains):
                result = self.client.request(call.command, **dict(call.fields))
            return result
        except Exception:
            # Breadcrumb for reviewers: a failed import never leaves staged
            # owner data until expiry when this best-effort cancel succeeds.
            try:
                self.client.request("cancel_list_import", import_id=import_id)
            except Exception:
                pass
            raise

    def _managed_list_changed(
        self, message: str, completed: Callable[[str | None], None]
    ) -> None:
        completed(None)
        self.notice_label.set_text(message)
        self.notice_label.remove_css_class("error")
        self.refresh()

    def _install_starter_category(
        self,
        managed_list: ManagedList,
        completed: Callable[[str | None], None],
    ) -> None:
        self._upload_managed_list(managed_list, completed)

    def _confirm_managed_list_delete(
        self, parent: object, summary: ManagedListSummary
    ) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=parent,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Delete {summary.name}?",
            secondary_text=(
                "The service deletes only lists that no rule uses."
            ),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Delete", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            self._request_async(
                "delete_managed_list",
                {"list_id": summary.id},
                lambda _result: self._managed_list_deleted(parent, summary.name),
                lambda error: self._show_dialog_error(
                    parent, self._rpc_error(error)
                ),
            )
        dialog.connect("response", respond)
        dialog.present()

    def _show_dialog_error(self, parent: object, message: str) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=parent,
            modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.CLOSE,
            text="The request failed.",
            secondary_text=message,
        )
        dialog.connect("response", lambda item, _response: item.destroy())
        dialog.present()

    def _managed_list_deleted(self, parent: object, name: str) -> None:
        parent.destroy()
        self.notice_label.set_text(f"Deleted {name}.")
        self.notice_label.remove_css_class("error")
        self.refresh()

    def open_quick_focus(self) -> None:
        rules = () if self.snapshot is None else self.snapshot.rules
        QuickFocusWindow(
            self.Gtk,
            self.window,
            rules,
            self._save_focus_rule,
        ).present()

    def _save_focus_rule(
        self,
        source: Rule,
        minutes: int,
        completed: Callable[[str | None], None],
    ) -> None:
        if (
            isinstance(minutes, bool)
            or not isinstance(minutes, int)
            or not 1 <= minutes <= 1440
        ):
            completed("Enter 1 to 1440 focus minutes.")
            return

        def saved(_result: object) -> None:
            completed(None)
            self.notice_label.set_text(f"Started {minutes}-minute focus.")
            self.notice_label.remove_css_class("error")
            self.refresh()

        self._request_async(
            "start_focus",
            {"rule_id": source.id, "minutes": minutes},
            saved,
            lambda error: completed(self._rpc_error(error)),
        )

    def open_daily_overview(self) -> None:
        local_day = datetime.now(ZoneInfo(self.timezone)).date()

        def load():
            result = self.client.request(
                "daily_schedule",
                timezone=self.timezone,
                date=local_day.isoformat(),
            )
            if not isinstance(result, Mapping):
                raise FormError(
                    "The service returned an invalid daily schedule."
                )
            return daily_schedule_from_result(result)

        def show(payload) -> None:
            day, timezone_name, intervals = payload
            DailyOverviewWindow(
                self.Gtk,
                self.window,
                day,
                timezone_name,
                intervals,
            ).present()

        self._run_worker(
            load,
            show,
            lambda error: self._show_error(self._rpc_error(error)),
        )
    def open_denial_statistics(self) -> None:
        DenialStatisticsWindow(
            self.Gtk,
            self.window,
            self._load_denial_statistics,
            self._clear_denial_statistics,
            self._load_website_usage,
            self._choose_statistics_export,
        ).present()
    def _choose_statistics_export(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Export statistics",
            self.window,
            Gtk.FileChooserAction.SAVE,
            "_Export",
            "_Cancel",
        )
        chooser.set_current_name("distraction-blocker-statistics.json")

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self._show_error("Select a local export path.")
                return

            def export() -> str:
                application = self.client.request("list_denial_stats")
                website = self.client.request("list_website_stats")
                content = statistics_export_text(application, website)
                atomic_write_text(path, content)
                return path

            self._run_worker(
                export,
                lambda _result: self._export_done(Path(path).name),
                lambda error: self._show_error(str(error)),
            )

        chooser.connect("response", respond)
        chooser.show()


    def _load_denial_statistics(
        self,
        completed: Callable[[DenialStatistics | None, str | None], None],
    ) -> None:
        def load() -> DenialStatistics:
            # Breadcrumb for reviewers: this read uses only the bounded public
            # RPC. The GUI never reads fanotify or protected statistics files.
            result = self.client.request("list_denial_stats")
            if not isinstance(result, Mapping):
                raise FormError("The service returned invalid denial statistics.")
            return denial_statistics_from_result(result)

        self._run_worker(
            load,
            lambda statistics: completed(statistics, None),
            lambda error: completed(None, self._rpc_error(error)),
        )

    def _clear_denial_statistics(
        self,
        completed: Callable[[str | None], None],
    ) -> None:
        # Breadcrumb for reviewers: clearing observational data is a distinct
        # RPC and never sends a policy, file path, or enforcement request.
        self._request_async(
            "clear_denial_stats",
            {},
            lambda _result: completed(None),
            lambda error: completed(self._rpc_error(error)),
        )

    def _load_website_usage(
        self,
        completed: Callable[
            [tuple[WebsiteUsageView, ...] | None, str | None], None
        ],
    ) -> None:
        def load() -> tuple[WebsiteUsageView, ...]:
            # Breadcrumb: the usage projection rides on the same public RPC
            # result as website denial statistics; nothing protected loads.
            result = self.client.request("list_website_stats")
            return website_usage_from_result(result)

        self._run_worker(
            load,
            lambda usage: completed(usage, None),
            lambda error: completed(None, self._rpc_error(error)),
        )

    def _save_form(
        self,
        form: RuleForm,
        existing: Rule | None,
        completed: Callable[[str | None], None],
    ) -> None:
        try:
            fields = form_to_request(form, existing)
        except (FormError, ValidationError, ValueError) as error:
            completed(str(error))
            return

        def saved(result: object) -> None:
            if existing is None and form.configure_lock_after_save:
                try:
                    if not isinstance(result, Mapping):
                        raise FormError(
                            "The service returned an invalid saved rule."
                        )
                    saved_rule = Rule.from_dict(result)
                except (FormError, ValidationError, ValueError) as error:
                    completed(str(error))
                    return
                completed(None)
                self.refresh()
                self.open_rule_lock(saved_rule, None)
                return
            completed(None)
            self.refresh()

        self._request_async(
            "put_rule",
            fields,
            saved,
            lambda error: completed(self._rpc_error(error)),
        )

    def open_editor(
        self,
        rule: Rule | None = None,
        initial_domains: Sequence[str] = (),
    ) -> None:
        RuleEditor(
            GtkModules(self.Gtk, self.Gio, self.GLib),
            self.window,
            self.timezone,
            rule,
            () if self.snapshot is None else self.snapshot.managed_lists,
            self._save_form,
            initial_domains,
            self._read_managed_lists,
            self._upload_managed_list_snapshots,
        ).present()

    def open_rule_lock(
        self,
        rule: Rule,
        summary: LockSummary | None,
    ) -> None:
        healthy = self.snapshot is not None and self.snapshot.healthy
        RuleLockWindow(
            self.Gtk,
            self.window,
            self.timezone,
            rule,
            summary,
            healthy,
            self._save_rule_lock,
        ).present()

    def _save_rule_lock(
        self,
        fields: Mapping[str, object],
        completed: Callable[[str | None], None],
    ) -> None:
        # Breadcrumb for reviewers: the GUI sends only the public lock input.
        # The root service owns expiry checks and all protected control state.
        def saved(_result: object) -> None:
            completed(None)
            self.refresh()

        self._request_async(
            "set_rule_lock",
            fields,
            saved,
            lambda error: completed(self._rpc_error(error)),
        )

    def open_rule_authorization(self, rule: Rule) -> None:
        RuleAuthorizationWindow(
            self.Gtk,
            self.window,
            rule,
            self._begin_rule_authorization,
            self._complete_rule_authorization,
        ).present()

    def _begin_rule_authorization(
        self,
        rule_id: str,
        completed: Callable[[AuthorizationChallenge | None, str | None], None],
    ) -> None:
        try:
            fields = begin_rule_authorization_request(rule_id)
        except FormError as error:
            completed(None, str(error))
            return

        def began(result: object) -> None:
            try:
                if not isinstance(result, Mapping):
                    raise FormError(
                        "The service returned an invalid authorization challenge."
                    )
                challenge = authorization_challenge_from_result(result)
                if challenge.rule_id != rule_id:
                    raise FormError(
                        "The service returned an authorization challenge for another rule."
                    )
            except FormError as error:
                completed(None, str(error))
                return
            completed(challenge, None)

        self._request_async(
            "begin_rule_authorization",
            fields,
            began,
            lambda error: completed(None, self._rpc_error(error)),
        )

    def _complete_rule_authorization(
        self,
        fields: Mapping[str, object],
        completed: Callable[[AuthorizationGrant | None, str | None], None],
    ) -> None:
        def authorized(result: object) -> None:
            try:
                if not isinstance(result, Mapping):
                    raise FormError(
                        "The service returned an invalid authorization result."
                    )
                grant = authorization_grant_from_result(result)
                if grant.rule_id != fields.get("rule_id"):
                    raise FormError(
                        "The service authorized a change for another rule."
                    )
            except FormError as error:
                completed(None, str(error))
                return
            completed(grant, None)

        self._request_async(
            "complete_rule_authorization",
            fields,
            authorized,
            lambda error: completed(None, self._rpc_error(error)),
        )


class DateTimePicker:
    """Calendar and clock selector with a canonical text value."""

    def __init__(self, Gtk: ModuleType, value: str, accessible_name: str):
        self.Gtk = Gtk
        self.value = picker_text_to_datetime(value)
        self.button = Gtk.MenuButton()
        self.button.set_hexpand(True)
        self.button.set_halign(Gtk.Align.FILL)
        self.button.set_tooltip_text(f"Select {accessible_name.lower()} date and time")
        self.popover = Gtk.Popover()
        content = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        for method in (
            content.set_margin_top,
            content.set_margin_bottom,
            content.set_margin_start,
            content.set_margin_end,
        ):
            method(int(Space.SMALL))
        heading = Gtk.Label(label=f"Select {accessible_name.lower()}")
        heading.add_css_class("heading")
        heading.set_xalign(0)
        content.append(heading)
        self.calendar = Gtk.Calendar()
        content.append(self.calendar)
        time_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.COMPACT)
        )
        time_label = Gtk.Label(label="Time")
        time_label.set_xalign(0)
        time_label.set_hexpand(True)
        time_row.append(time_label)
        self.hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.hour.set_numeric(True)
        self.hour.set_wrap(True)
        self.hour.set_tooltip_text("Hour from 00 to 23")
        time_row.append(self.hour)
        separator = Gtk.Label(label=":")
        time_row.append(separator)
        self.minute = Gtk.SpinButton.new_with_range(0, 59, 1)
        self.minute.set_numeric(True)
        self.minute.set_wrap(True)
        self.minute.set_tooltip_text("Minute from 00 to 59")
        time_row.append(self.minute)
        content.append(time_row)
        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.COMPACT)
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: self.popover.popdown())
        actions.append(cancel)
        apply_button = Gtk.Button.new_with_mnemonic("_Apply")
        apply_button.add_css_class("suggested-action")
        apply_button.connect("clicked", lambda _button: self._apply())
        actions.append(apply_button)
        content.append(actions)
        self.popover.set_child(content)
        self.button.set_popover(self.popover)
        self.set_text(value)

    def _update_label(self) -> None:
        self.button.set_label(self.value.strftime("%b %d, %Y at %H:%M"))

    def _apply(self) -> None:
        self.value = datetime(
            self.calendar.get_year(),
            self.calendar.get_month() + 1,
            self.calendar.get_day(),
            self.hour.get_value_as_int(),
            self.minute.get_value_as_int(),
        )
        self._update_label()
        self.popover.popdown()

    def get_text(self) -> str:
        return picker_datetime_text(self.value)

    def set_text(self, value: str) -> None:
        self.value = picker_text_to_datetime(value)
        self.calendar.set_year(self.value.year)
        self.calendar.set_month(self.value.month - 1)
        self.calendar.set_day(self.value.day)
        self.hour.set_value(self.value.hour)
        self.minute.set_value(self.value.minute)
        self._update_label()

class RuleLockWindow:
    """Create, change, or remove one rule lock."""

    def __init__(
        self,
        Gtk: ModuleType,
        parent: object,
        timezone_name: str,
        rule: Rule,
        summary: LockSummary | None,
        healthy: bool,
        save: Callable[
            [Mapping[str, object], Callable[[str | None], None]],
            None,
        ],
    ):
        self.Gtk = Gtk
        self.timezone_name = timezone_name
        self.rule = rule
        self.summary = summary
        self.healthy = healthy
        self.save = save
        self.primary_button: object | None = None
        self.remove_button: object | None = None
        self.kind_dropdown: object | None = None
        self.expiry_widgets: tuple[object, ...] = ()
        self.delay_wait: object | None = None
        self.delay_break: object | None = None
        self.delay_widgets: tuple[object, ...] = ()
        self.password_entry: object | None = None
        self.password_confirmation: object | None = None
        self.password_widgets: tuple[object, ...] = ()
        self.window = self._build(parent)

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Rule lock",
            transient_for=parent,
            modal=True,
        )
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=int(Space.MEDIUM),
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)

        heading = Gtk.Label(label=f"Rule lock · {self.rule.name}")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        heading.set_wrap(True)
        outer.append(heading)
        intro = Gtk.Label(
            label=(
                "A schedule lock follows a weekly rule schedule and blocks "
                "weakening changes during each active period. "
                "A timed lock blocks weakening changes until its expiry. "
                "A Delay lock starts a countdown before a temporary break. "
                "A friction lock requires exact-text authorization. "
                "A password lock requires its password before one weakening change."
            )
        )
        intro.set_xalign(0)
        intro.set_wrap(True)
        outer.append(intro)

        state_text = (
            "Rule lock: none."
            if self.summary is None
            else lock_summary_text(self.summary, self.timezone_name)
        )
        state = Gtk.Label(label=state_text)
        state.set_xalign(0)
        state.set_wrap(True)
        state.add_css_class(
            "warning"
            if self.summary is not None and self.summary.locked
            else "dim-label"
        )
        outer.append(state)

        can_set = self.summary is None or self.healthy
        if can_set:
            kind_label = Gtk.Label(label="Lock type")
            kind_label.set_xalign(0)
            self.kind_dropdown = Gtk.DropDown.new_from_strings(
                ("Schedule", "Timed", "Delay", "Friction", "Password")
            )
            selected_kind = "timed" if self.summary is None else self.summary.kind
            self.kind_dropdown.set_selected(
                {"schedule": 0, "timed": 1, "delay": 2, "friction": 3, "password": 4}[selected_kind]
            )
            self.kind_dropdown.set_sensitive(
                self.healthy
                and not (
                    self.summary is not None
                    and self.summary.kind in {"timed", "schedule", "delay"}
                    and self.summary.locked
                )
            )
            self.kind_dropdown.set_tooltip_text(
                "Choose a schedule, timed, Delay, friction, or password lock"
            )
            kind_label.set_mnemonic_widget(self.kind_dropdown)
            outer.append(self.kind_dropdown)

            until_label = Gtk.Label(label="Lock expiry")
            until_label.set_xalign(0)
            outer.append(until_label)
            zone = ZoneInfo(self.timezone_name)
            if (
                self.summary is not None
                and self.summary.kind == "timed"
                and self.summary.until_utc is not None
            ):
                initial_until = picker_datetime_text(
                    self.summary.until_utc.astimezone(zone)
                )
            else:
                _start, initial_until = default_one_time_window(datetime.now(zone))
            self.until_picker = DateTimePicker(
                Gtk,
                initial_until,
                "Lock expiry",
            )
            until_label.set_mnemonic_widget(self.until_picker.button)
            outer.append(self.until_picker.button)
            zone_label = Gtk.Label(
                label=f"System time zone: {self.timezone_name}"
            )
            zone_label.set_xalign(0)
            zone_label.add_css_class("dim-label")
            outer.append(zone_label)
            self.expiry_widgets = (
                until_label,
                self.until_picker.button,
                zone_label,
            )
            delay_wait_label = Gtk.Label(label="Delay wait (minutes)")
            delay_wait_label.set_xalign(0)
            outer.append(delay_wait_label)
            self.delay_wait = Gtk.SpinButton.new_with_range(1, 1440, 1)
            self.delay_wait.set_value(
                max(
                    1,
                    (
                        (self.summary.wait_seconds or 300)
                        if self.summary is not None and self.summary.kind == "delay"
                        else 300
                    ) + 59
                ) // 60
            )
            delay_wait_label.set_mnemonic_widget(self.delay_wait)
            outer.append(self.delay_wait)
            delay_break_label = Gtk.Label(label="Temporary break (minutes)")
            delay_break_label.set_xalign(0)
            outer.append(delay_break_label)
            self.delay_break = Gtk.SpinButton.new_with_range(1, 1440, 1)
            self.delay_break.set_value(
                max(
                    1,
                    (
                        (self.summary.break_seconds or 900)
                        if self.summary is not None and self.summary.kind == "delay"
                        else 900
                    ) + 59
                ) // 60
            )
            delay_break_label.set_mnemonic_widget(self.delay_break)
            outer.append(self.delay_break)
            self.delay_widgets = (
                delay_wait_label,
                self.delay_wait,
                delay_break_label,
                self.delay_break,
            )
            for widget in self.delay_widgets:
                widget.set_sensitive(not self._active_delay_lock())

            password_label = Gtk.Label(label="Password")
            password_label.set_xalign(0)
            outer.append(password_label)
            self.password_entry = Gtk.Entry()
            self.password_entry.set_hexpand(True)
            self.password_entry.set_visibility(False)
            self.password_entry.set_placeholder_text("8 to 1024 UTF-8 bytes")
            password_label.set_mnemonic_widget(self.password_entry)
            outer.append(self.password_entry)

            confirmation_label = Gtk.Label(label="Confirm password")
            confirmation_label.set_xalign(0)
            outer.append(confirmation_label)
            self.password_confirmation = Gtk.Entry()
            self.password_confirmation.set_hexpand(True)
            self.password_confirmation.set_visibility(False)
            self.password_confirmation.set_placeholder_text("Retype the password")
            self.password_confirmation.connect(
                "activate", lambda _entry: self._submit()
            )
            confirmation_label.set_mnemonic_widget(self.password_confirmation)
            outer.append(self.password_confirmation)
            self.password_widgets = (
                password_label,
                self.password_entry,
                confirmation_label,
                self.password_confirmation,
            )
            self.kind_dropdown.connect(
                "notify::selected", self._lock_kind_changed
            )
            self._lock_kind_changed(self.kind_dropdown)

        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)

        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=int(Space.SMALL),
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        if self.summary is not None:
            self.remove_button = Gtk.Button.new_with_mnemonic("_Remove lock")
            self.remove_button.add_css_class("destructive-action")
            self.remove_button.set_sensitive(
                self.healthy
                and not (
                    self.summary.kind in {"timed", "schedule", "delay"}
                    and self.summary.locked
                )
            )
            if self.summary.kind in {"timed", "schedule", "delay"} and self.summary.locked:
                self.remove_button.set_tooltip_text(
                    "An active timed, schedule, or Delay lock cannot be removed."
                )
            elif (
                self.summary.kind in {"friction", "password"}
                and self.summary.locked
            ):
                self.remove_button.set_tooltip_text(
                    "Authorize a weakening change before removing this rule lock."
                )
            self.remove_button.connect(
                "clicked",
                lambda _button: self._remove(),
            )
            actions.append(self.remove_button)
        if can_set:
            label = "_Update lock" if self.summary is not None else "_Create lock"
            self.primary_button = Gtk.Button.new_with_mnemonic(label)
            self.primary_button.add_css_class("suggested-action")
            self.primary_button.set_sensitive(
                self.healthy and not self._active_delay_lock()
            )
            self.primary_button.connect(
                "clicked",
                lambda _button: self._submit(),
            )
            actions.append(self.primary_button)
        outer.append(actions)
        if not self.healthy:
            self.error_label.set_text(
                "The service is unhealthy. Lock changes are disabled."
            )
        return window

    def _active_delay_lock(self) -> bool:
        return (
            self.summary is not None
            and self.summary.kind == "delay"
            and self.summary.locked
        )

    def _selected_kind(self) -> str:
        if self.kind_dropdown is None:
            return "timed"
        selected = self.kind_dropdown.get_selected()
        return ("schedule", "timed", "delay", "friction", "password")[selected]

    def _lock_kind_changed(
        self,
        _dropdown: object,
        _parameter: object = None,
    ) -> None:
        selected_kind = self._selected_kind()
        for widget in self.expiry_widgets:
            widget.set_visible(selected_kind == "timed")
        for widget in self.delay_widgets:
            widget.set_visible(selected_kind == "delay")
        for widget in self.password_widgets:
            widget.set_visible(selected_kind == "password")
        if selected_kind != "password":
            if self.password_entry is not None:
                self.password_entry.set_text("")
            if self.password_confirmation is not None:
                self.password_confirmation.set_text("")

    def _set_busy(self, busy: bool) -> None:
        if self.primary_button is not None:
            self.primary_button.set_sensitive(
                self.healthy and not busy and not self._active_delay_lock()
            )
        active_time_lock = (
            self.summary is not None
            and self.summary.kind in {"timed", "schedule", "delay"}
            and self.summary.locked
        )
        if self.kind_dropdown is not None:
            self.kind_dropdown.set_sensitive(
                self.healthy and not busy and not active_time_lock
            )
        if self.remove_button is not None:
            self.remove_button.set_sensitive(
                self.healthy and not busy and not active_time_lock
            )
        for widget in self.delay_widgets:
            widget.set_sensitive(
                self.healthy and not busy and not self._active_delay_lock()
            )
        if self.password_entry is not None:
            self.password_entry.set_sensitive(self.healthy and not busy)
        if self.password_confirmation is not None:
            self.password_confirmation.set_sensitive(self.healthy and not busy)

    def _submit(self) -> None:
        try:
            kind = self._selected_kind()
            if kind == "schedule":
                fields = schedule_lock_request(self.rule.id)
            elif kind == "delay":
                if self.delay_wait is None or self.delay_break is None:
                    raise FormError("The Delay fields are not available.")
                fields = delay_lock_request(
                    self.rule.id,
                    self.delay_wait.get_value_as_int() * 60,
                    self.delay_break.get_value_as_int() * 60,
                )
            elif kind == "friction":
                fields = friction_lock_request(self.rule.id)
            elif kind == "password":
                if (
                    self.password_entry is None
                    or self.password_confirmation is None
                ):
                    raise FormError("The password fields are not available.")
                fields = password_lock_request(
                    self.rule.id,
                    self.password_entry.get_text(),
                    self.password_confirmation.get_text(),
                )
            else:
                fields = timed_lock_request(
                    self.rule.id,
                    self.until_picker.get_text(),
                    self.timezone_name,
                )
                until_utc = _parse_utc(fields["lock"]["until_utc"])
                if (
                    self.summary is not None
                    and self.summary.kind == "timed"
                    and self.summary.until_utc is not None
                    and until_utc <= self.summary.until_utc
                ):
                    raise FormError("Extend the lock to a later expiry.")
        except (FormError, TypeError) as error:
            self.error_label.set_text(str(error))
            return
        self._set_busy(True)
        self.error_label.remove_css_class("error")
        self.error_label.set_text(f"Saving {kind} lock.")
        self.save(fields, self._saved)

    def _remove(self) -> None:
        try:
            fields = remove_rule_lock_request(self.rule.id)
        except FormError as error:
            self.error_label.set_text(str(error))
            return
        self._set_busy(True)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Removing rule lock.")
        self.save(fields, self._saved)

    def _saved(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            return
        self._set_busy(False)
        self.error_label.set_text(message)
        self.error_label.add_css_class("error")

    def present(self) -> None:
        self.window.present()


class RuleAuthorizationWindow:
    """Authorize one weakening change for a friction or password lock."""

    def __init__(
        self,
        Gtk: ModuleType,
        parent: object,
        rule: Rule,
        begin: Callable[
            [str, Callable[[AuthorizationChallenge | None, str | None], None]],
            None,
        ],
        complete: Callable[
            [
                Mapping[str, object],
                Callable[[AuthorizationGrant | None, str | None], None],
            ],
            None,
        ],
    ):
        self.Gtk = Gtk
        self.rule = rule
        self.begin = begin
        self.complete = complete
        self.challenge: AuthorizationChallenge | None = None
        self.finished = False
        self.window = self._build(parent)

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Authorize weakening change",
            transient_for=parent,
            modal=True,
        )
        window.set_default_size(520, 360)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=int(Space.MEDIUM),
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)

        heading = Gtk.Label(label=f"Authorize change · {self.rule.name}")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        heading.set_wrap(True)
        outer.append(heading)
        self.explanation = Gtk.Label(label="")
        self.explanation.set_xalign(0)
        self.explanation.set_wrap(True)
        self.explanation.add_css_class("warning")
        self.explanation.set_visible(False)
        outer.append(self.explanation)

        self.prompt_heading = Gtk.Label(label="Authorization text")
        self.prompt_heading.set_xalign(0)
        self.prompt_heading.set_visible(False)
        outer.append(self.prompt_heading)
        self.prompt_label = Gtk.Label(label="")
        self.prompt_label.set_xalign(0)
        self.prompt_label.set_selectable(True)
        self.prompt_label.add_css_class("monospace")
        self.prompt_label.set_visible(False)
        outer.append(self.prompt_label)

        self.response_label = Gtk.Label(label="Retype authorization text")
        self.response_label.set_xalign(0)
        self.response_label.set_visible(False)
        outer.append(self.response_label)
        self.response_entry = Gtk.Entry()
        self.response_entry.set_hexpand(True)
        self.response_entry.set_visible(False)
        self.response_entry.connect("changed", self._response_changed)
        self.response_entry.connect("activate", lambda _entry: self._submit())
        self.response_label.set_mnemonic_widget(self.response_entry)
        outer.append(self.response_entry)

        self.status_label = Gtk.Label(label="Requesting authorization.")
        self.status_label.set_xalign(0)
        self.status_label.set_wrap(True)
        outer.append(self.status_label)

        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=int(Space.SMALL),
        )
        actions.set_halign(Gtk.Align.END)
        self.close_button = Gtk.Button.new_with_mnemonic("_Cancel")
        self.close_button.connect("clicked", lambda _button: window.destroy())
        actions.append(self.close_button)
        self.authorize_button = Gtk.Button.new_with_mnemonic("_Authorize change")
        self.authorize_button.add_css_class("suggested-action")
        self.authorize_button.set_sensitive(False)
        self.authorize_button.connect(
            "clicked",
            lambda _button: self._submit(),
        )
        actions.append(self.authorize_button)
        outer.append(actions)
        window.set_default_widget(self.authorize_button)
        return window

    def _response_changed(self, _entry: object) -> None:
        ready = False
        if not self.finished and self.challenge is not None:
            response = self.response_entry.get_text()
            if self.challenge.kind == "friction":
                ready = response == self.challenge.prompt
            else:
                try:
                    _validated_password(response)
                except FormError:
                    pass
                else:
                    ready = True
        self.authorize_button.set_sensitive(ready)

    def _challenge_ready(
        self,
        challenge: AuthorizationChallenge | None,
        message: str | None,
    ) -> None:
        if message is not None or challenge is None:
            self.finished = True
            self.status_label.set_text(
                message or "The service did not return an authorization challenge."
            )
            self.status_label.add_css_class("error")
            self.close_button.set_label("_Close")
            return
        self.challenge = challenge
        if challenge.kind == "friction":
            self.explanation.set_text(
                "This step adds friction only. It is not a security check. "
                "Retype the service text exactly to authorize one weakening change."
            )
            self.explanation.set_visible(True)
            self.prompt_label.set_text(challenge.prompt)
            self.prompt_heading.set_visible(True)
            self.prompt_label.set_visible(True)
            self.response_label.set_text("Retype authorization text")
            self.response_entry.set_visibility(True)
            expiry_subject = "authorization text"
        else:
            # Breadcrumb for reviewers: password challenges never render a prompt.
            self.explanation.set_text(
                "Enter the password to authorize one weakening change."
            )
            self.explanation.set_visible(True)
            self.prompt_heading.set_visible(False)
            self.prompt_label.set_visible(False)
            self.response_label.set_text("Password")
            self.response_entry.set_visibility(False)
            expiry_subject = "password authorization"
        self.response_label.set_visible(True)
        self.response_entry.set_visible(True)
        self.status_label.set_text(
            f"This {expiry_subject} expires in {challenge.expires_in} seconds."
        )
        self.response_entry.grab_focus()

    def _submit(self) -> None:
        if self.finished or self.challenge is None:
            return
        response = self.response_entry.get_text()
        if self.challenge.kind == "friction" and response != self.challenge.prompt:
            return
        try:
            fields = complete_rule_authorization_request(
                self.rule.id,
                self.challenge.challenge_id,
                response,
                self.challenge.kind,
            )
        except FormError as error:
            self.status_label.set_text(str(error))
            self.status_label.add_css_class("error")
            return
        self.authorize_button.set_sensitive(False)
        self.response_entry.set_sensitive(False)
        self.status_label.remove_css_class("error")
        self.status_label.set_text("Authorizing the weakening change.")
        self.complete(fields, self._authorization_completed)

    def _authorization_completed(
        self,
        grant: AuthorizationGrant | None,
        message: str | None,
    ) -> None:
        if message is not None or grant is None:
            detail = message or "The service did not authorize the weakening change."
            self.status_label.remove_css_class("accent")
            self.status_label.add_css_class("error")
            if self.challenge is None or self.challenge.kind == "friction":
                self.finished = True
                self.authorize_button.set_sensitive(False)
                self.response_entry.set_sensitive(False)
                self.close_button.set_label("_Close")
                self.status_label.set_text(
                    detail
                    + " Close this window and request new authorization text."
                )
                return
            self.response_entry.set_sensitive(True)
            self.response_entry.set_text("")
            self.status_label.set_text(detail)
            self._response_changed(self.response_entry)
            self.response_entry.grab_focus()
            return
        self.finished = True
        self.authorize_button.set_sensitive(False)
        self.response_entry.set_sensitive(False)
        self.close_button.set_label("_Close")
        self.status_label.remove_css_class("error")
        self.status_label.add_css_class("accent")
        self.status_label.set_text(
            "The next weakening change is authorized for 60 seconds."
        )

    def present(self) -> None:
        self.window.present()
        # Breadcrumb for reviewers: only friction challenges expose service text.
        # Both blocking authorization RPCs run through the controller worker.
        self.begin(self.rule.id, self._challenge_ready)


class WeeklyPeriodRow:
    """One editable weekly period."""

    def __init__(
        self,
        Gtk: ModuleType,
        index: int,
        value: WeeklyPeriodForm,
        remove: Callable[["WeeklyPeriodRow"], None],
    ):
        self.Gtk = Gtk
        self.container = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        heading_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        self.heading = Gtk.Label()
        self.heading.add_css_class("heading")
        self.heading.set_xalign(0)
        self.heading.set_hexpand(True)
        heading_row.append(self.heading)
        remove_button = Gtk.Button.new_with_mnemonic("_Remove")
        remove_button.connect("clicked", lambda _button: remove(self))
        heading_row.append(remove_button)
        self.container.append(heading_row)
        grid = Gtk.Grid()
        grid.set_row_spacing(int(Space.COMPACT))
        grid.set_column_spacing(int(Space.SMALL))
        self.weekday_checks: list[object] = []
        for day, label in enumerate(WEEKDAY_LABELS):
            check = Gtk.CheckButton(label=label)
            check.set_active(day in value.weekdays)
            grid.attach(check, day % 4, day // 4, 1, 1)
            self.weekday_checks.append(check)
        self.container.append(grid)
        times = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        self.start_entry = Gtk.Entry()
        self.start_entry.set_hexpand(True)
        self.start_entry.set_placeholder_text("09:00")
        self.start_entry.set_text(value.start)
        start_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        start_label = Gtk.Label(label="Start (HH:MM)")
        start_label.set_xalign(0)
        start_label.set_mnemonic_widget(self.start_entry)
        start_box.append(start_label)
        start_box.append(self.start_entry)
        times.append(start_box)
        self.end_entry = Gtk.Entry()
        self.end_entry.set_hexpand(True)
        self.end_entry.set_placeholder_text("17:00")
        self.end_entry.set_text(value.end)
        end_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        end_label = Gtk.Label(label="End (HH:MM)")
        end_label.set_xalign(0)
        end_label.set_mnemonic_widget(self.end_entry)
        end_box.append(end_label)
        end_box.append(self.end_entry)
        times.append(end_box)
        self.container.append(times)
        allowance_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        allowance_label = Gtk.Label(label="Timed allowance")
        allowance_label.set_xalign(0)
        allowance_box.append(allowance_label)
        self.allowance_mode_dropdown = Gtk.DropDown.new_from_strings(
            ("No allowance", "Total minutes", "Fixed refill window")
        )
        allowance_box.append(self.allowance_mode_dropdown)
        self.allowance_quota_label = Gtk.Label(label="Allowed minutes")
        self.allowance_quota_label.set_xalign(0)
        allowance_box.append(self.allowance_quota_label)
        self.allowance_quota = Gtk.SpinButton.new_with_range(1, 1440, 1)
        self.allowance_quota.set_numeric(True)
        self.allowance_quota.set_value(value.allowance_quota_minutes or 30)
        allowance_box.append(self.allowance_quota)
        self.allowance_window_label = Gtk.Label(label="Refill window minutes")
        self.allowance_window_label.set_xalign(0)
        allowance_box.append(self.allowance_window_label)
        self.allowance_window = Gtk.SpinButton.new_with_range(1, 1440, 1)
        self.allowance_window.set_numeric(True)
        self.allowance_window.set_value(value.allowance_window_minutes or 60)
        allowance_box.append(self.allowance_window)
        self.container.append(allowance_box)
        self.allowance_mode_dropdown.set_selected(
            {"strict": 0, "total": 1, "fixed_window": 2}.get(value.allowance_mode, 0)
        )
        self.allowance_mode_dropdown.connect(
            "notify::selected", self._allowance_mode_changed
        )
        self._allowance_mode_changed(self.allowance_mode_dropdown)
        self.set_allowance_enabled(False)
        self.set_index(index)
    
    def set_allowance_enabled(self, enabled: bool) -> None:
        """Enable or disable this row's timed allowance controls."""
        for widget in (
            self.allowance_mode_dropdown,
            self.allowance_quota,
            self.allowance_window,
        ):
            widget.set_sensitive(enabled)
    
    def _allowance_mode_changed(
        self, dropdown: object, _parameter: object | None = None
    ) -> None:
        selected = dropdown.get_selected()
        self.allowance_quota_label.set_visible(selected in {1, 2})
        self.allowance_quota.set_visible(selected in {1, 2})
        self.allowance_window_label.set_visible(selected == 2)
        self.allowance_window.set_visible(selected == 2)

    def allowance_value(self) -> PeriodAllowanceForm:
        selected = self.allowance_mode_dropdown.get_selected()
        mode = ("strict", "total", "fixed_window")[selected]
        if mode == "strict":
            return PeriodAllowanceForm(mode)
        quota = self.allowance_quota.get_value_as_int()
        if mode == "total":
            return PeriodAllowanceForm(mode, quota)
        return PeriodAllowanceForm(
            mode, quota, self.allowance_window.get_value_as_int()
        )
    

    def set_index(self, index: int) -> None:
        self.heading.set_text(f"Period {index}")

    def value(self) -> WeeklyPeriodForm:
        return WeeklyPeriodForm(
            tuple(
                index
                for index, check in enumerate(self.weekday_checks)
                if check.get_active()
            ),
            self.start_entry.get_text(),
            self.end_entry.get_text(),
        )


class RuleEditor:
    """Native add and edit window for all schedule forms."""

    def __init__(
        self,
        modules: GtkModules,
        parent: object,
        timezone_name: str,
        existing: Rule | None,
        managed_lists: Sequence[ManagedListSummary],
        save: Callable[
            [RuleForm, Rule | None, Callable[[str | None], None]], None
        ],
        initial_domains: Sequence[str] = (),
        read_managed_lists: Callable[
            [Sequence[ManagedListSummary]], Sequence[ManagedList]
        ] | None = None,
        upload_managed_lists: Callable[
            [Sequence[ManagedList], Callable[[str | None], None]], None
        ] | None = None,
    ):
        self.Gtk, self.GLib = modules.Gtk, modules.GLib
        self.read_managed_lists = read_managed_lists
        self.upload_managed_lists = upload_managed_lists
        self.notifications_enabled_check: object | None = None
        self.notification_checks: dict[str, object] = {}
        if existing is not None:
            schedule = existing.to_dict()["schedule"]
            if schedule["kind"] == "weekly":
                timezone_name = schedule["timezone"]
        self.parent, self.timezone_name = parent, timezone_name
        self.existing, self.managed_lists, self.save = (
            existing,
            tuple(managed_lists),
            save,
        )
        self.target_entries: list[dict[str, str]] = []
        self.application_paths: list[str] = []
        self.url_targets: list[dict[str, str]] = []
        self.url_exceptions: list[dict[str, str]] = []
        self.weekly_rows: list[WeeklyPeriodRow] = []
        local_now = datetime.now(ZoneInfo(timezone_name))
        self.default_one_start, self.default_one_end = default_one_time_window(local_now)
        self.default_pomodoro_start = self.default_one_start
        self.window = self._build()
        if existing is not None:
            self._populate(rule_to_form(existing, self.timezone_name))
        else:
            self._add_weekly_period(
                WeeklyPeriodForm((0, 1, 2, 3, 4), "09:00", "17:00")
            )
            if initial_domains:
                self._set_website_lines(initial_domains)

    def _new_entry(self, placeholder: str = "") -> object:
        entry = self.Gtk.Entry()
        entry.set_hexpand(True)
        entry.set_placeholder_text(placeholder)
        entry.connect("activate", lambda _entry: self._submit())
        return entry

    def _run_worker(
        self,
        work: Callable[[], object],
        success: Callable[[object], None],
    ) -> None:
        def run() -> None:
            try:
                result = work()
            except Exception as error:
                self.GLib.idle_add(self.error_label.set_text, str(error))
            else:
                self.GLib.idle_add(success, result)
        threading.Thread(target=run, daemon=True).start()

    def _label_for(self, text: str, widget: object) -> object:
        label = self.Gtk.Label.new_with_mnemonic(text)
        label.set_xalign(0)
        label.set_mnemonic_widget(widget)
        return label

    def _build(self) -> object:
        Gtk = self.Gtk
        title = "Edit rule" if self.existing is not None else "Add rule"
        window = Gtk.Window(title=title, transient_for=self.parent, modal=True)
        window.set_default_size(650, 700)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        window.set_child(scroller)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        scroller.set_child(outer)
        heading = Gtk.Label(label=title)
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        self.name_entry = self._new_entry("Study time")
        outer.append(self._label_for("Rule _name", self.name_entry))
        outer.append(self.name_entry)

        target_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        target_heading = Gtk.Label(label="Block Targets")
        target_heading.add_css_class("heading")
        target_heading.set_xalign(0)
        target_heading.set_hexpand(True)
        target_row.append(target_heading)

        self.managed_list_checks: dict[str, object] = {}
        managed_button = Gtk.MenuButton()
        managed_button.set_label("Add managed list")
        managed_button.set_tooltip_text(
            "Attach an existing managed list to this rule."
        )
        managed_popover = Gtk.Popover()
        managed_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        managed_box.set_margin_top(int(Space.SMALL))
        managed_box.set_margin_bottom(int(Space.SMALL))
        managed_box.set_margin_start(int(Space.SMALL))
        managed_box.set_margin_end(int(Space.SMALL))
        if self.managed_lists:
            for summary in self.managed_lists:
                check = Gtk.CheckButton(
                    label=f"{summary.name} ({summary.domain_count} domains)"
                )
                check.set_tooltip_text(
                    f"Source: {summary.source}. Version: {summary.version}."
                )
                check.connect("toggled", self._managed_list_toggled)
                managed_box.append(check)
                self.managed_list_checks[summary.id] = check
        else:
            empty_lists = Gtk.Label(
                label="Create or install a managed list from the main window."
            )
            empty_lists.set_wrap(True)
            empty_lists.set_xalign(0)
            empty_lists.add_css_class("dim-label")
            managed_box.append(empty_lists)
        managed_popover.set_child(managed_box)
        managed_button.set_popover(managed_popover)
        target_row.append(managed_button)

        import_domains = Gtk.Button.new_with_mnemonic("Import _domains")
        import_domains.connect(
            "clicked", lambda _button: self._choose_domain_import()
        )
        target_row.append(import_domains)
        import_json = Gtk.Button.new_with_mnemonic("Import _JSON")
        import_json.connect(
            "clicked",
            lambda _button: self._choose_target_list_import(False),
        )
        target_row.append(import_json)
        export_json = Gtk.Button.new_with_mnemonic("E_xport JSON")
        export_json.connect(
            "clicked", lambda _button: self._choose_target_export(False)
        )
        target_row.append(export_json)
        outer.append(target_row)

        self.target_kind_dropdown = Gtk.DropDown.new_from_strings(
            (
                "Auto-detect",
                "Website",
                "Exact path",
                "Wildcard path",
                "Keyword",
                "YouTube video",
                "YouTube channel",
            )
        )
        self.target_entry = Gtk.Entry()
        self.target_entry.set_hexpand(True)
        self.target_entry.set_placeholder_text(
            "example.com, example.com/path, or keyword"
        )
        self.target_entry.connect(
            "activate", lambda _entry: self._add_target(False)
        )
        target_input = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        target_input.append(self.target_kind_dropdown)
        target_input.append(self.target_entry)
        add_target = Gtk.Button.new_with_mnemonic("Add _target")
        add_target.connect(
            "clicked", lambda _button: self._add_target(False)
        )
        target_input.append(add_target)
        outer.append(target_input)
        target_scroller = Gtk.ScrolledWindow()
        target_scroller.set_min_content_height(120)
        self.target_list = Gtk.ListBox()
        self.target_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.target_list.add_css_class("boxed-list")
        target_scroller.set_child(self.target_list)
        outer.append(target_scroller)

        exception_heading = Gtk.Label(label="Block Exceptions")
        exception_heading.add_css_class("heading")
        exception_heading.set_xalign(0)
        outer.append(exception_heading)
        exception_note = Gtk.Label(
            label=(
                "Browser exceptions only. These do not override website, "
                "application, or network enforcement."
            )
        )
        exception_note.set_xalign(0)
        exception_note.set_wrap(True)
        exception_note.add_css_class("dim-label")
        outer.append(exception_note)
        self.exception_kind_dropdown = Gtk.DropDown.new_from_strings(
            (
                "Auto-detect",
                "Exact path",
                "Wildcard path",
                "Keyword",
                "YouTube video",
                "YouTube channel",
            )
        )
        self.exception_entry = Gtk.Entry()
        self.exception_entry.set_hexpand(True)
        self.exception_entry.set_placeholder_text(
            "example.com/allowed or keyword"
        )
        self.exception_entry.connect(
            "activate", lambda _entry: self._add_target(True)
        )
        exception_input = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        exception_input.append(self.exception_kind_dropdown)
        exception_input.append(self.exception_entry)
        add_exception = Gtk.Button.new_with_mnemonic("Add e_xception")
        add_exception.connect(
            "clicked", lambda _button: self._add_target(True)
        )
        exception_input.append(add_exception)
        outer.append(exception_input)
        exception_actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        import_exception_json = Gtk.Button.new_with_mnemonic(
            "Import _URL list"
        )
        import_exception_json.connect(
            "clicked",
            lambda _button: self._choose_target_list_import(True),
        )
        exception_actions.append(import_exception_json)
        export_exception_json = Gtk.Button.new_with_mnemonic(
            "E_xport JSON"
        )
        export_exception_json.connect(
            "clicked", lambda _button: self._choose_target_export(True)
        )
        exception_actions.append(export_exception_json)
        outer.append(exception_actions)
        exception_scroller = Gtk.ScrolledWindow()
        exception_scroller.set_min_content_height(100)
        self.exception_list = Gtk.ListBox()
        self.exception_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.exception_list.add_css_class("boxed-list")
        exception_scroller.set_child(self.exception_list)
        outer.append(exception_scroller)

        app_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        app_label = Gtk.Label(label="Application Blocks")
        app_label.set_xalign(0)
        app_label.set_hexpand(True)
        app_row.append(app_label)
        choose = Gtk.Button.new_with_mnemonic("_Select executable")
        choose.connect("clicked", lambda _button: self._choose_application())
        app_row.append(choose)
        import_app_json = Gtk.Button.new_with_mnemonic("Import _JSON")
        import_app_json.connect(
            "clicked", lambda _button: self._choose_application_import()
        )
        app_row.append(import_app_json)
        export_app_json = Gtk.Button.new_with_mnemonic("E_xport JSON")
        export_app_json.connect(
            "clicked", lambda _button: self._choose_application_export()
        )
        app_row.append(export_app_json)
        outer.append(app_row)
        application_scroller = Gtk.ScrolledWindow()
        application_scroller.set_min_content_height(80)
        self.application_list = Gtk.ListBox()
        self.application_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.application_list.add_css_class("boxed-list")
        application_scroller.set_child(self.application_list)
        outer.append(application_scroller)

        # Compatibility aliases keep the pure URL-entry helper usable by
        # callers that construct an editor without GTK widget setup.
        self.url_entry = self.target_entry
        self.url_kind_dropdown = self.target_kind_dropdown
        self._render_targets()
        network_heading = Gtk.Label(label="Network controls")
        network_heading.set_xalign(0)
        outer.append(network_heading)
        # Breadcrumb (network seam): each checkbox is one network target;
        # the value stored is the control name, and the service rejects the
        # rule when network enforcement is not enabled on this host.
        self.network_checks: dict[str, object] = {}
        network_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        for control, label, tooltip in self._NETWORK_OPTIONS:
            check = Gtk.CheckButton(label=label)
            check.set_tooltip_text(tooltip)
            network_box.append(check)
            check.connect("toggled", self._target_fields_changed)
            self.network_checks[control] = check
        outer.append(network_box)
        network_note = Gtk.Label(
            label="Network controls affect the protected user's own "
            "connections only. Local proxies, VPNs, and system daemons "
            "are outside this scope, so the block is not exhaustive."
        )
        network_note.set_xalign(0)
        network_note.set_wrap(True)
        network_note.add_css_class("dim-label")
        outer.append(network_note)
        notifications_heading = Gtk.Label(label="Notifications")
        notifications_heading.add_css_class("heading")
        notifications_heading.set_xalign(0)
        outer.append(notifications_heading)
        self.notifications_enabled_check = Gtk.CheckButton(
            label="Notifications (On/Off)"
        )
        self.notifications_enabled_check.set_active(True)
        self.notifications_enabled_check.connect(
            "toggled", self._notifications_changed
        )
        outer.append(self.notifications_enabled_check)
        notification_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        for category, label, tooltip in NOTIFICATION_CATEGORY_OPTIONS:
            check = Gtk.CheckButton(label=label)
            check.set_tooltip_text(tooltip)
            check.set_active(True)
            notification_box.append(check)
            self.notification_checks[category] = check
        outer.append(notification_box)
        self._notifications_changed(self.notifications_enabled_check)

        self.configure_lock_check = Gtk.CheckButton(
            label="Configure a lock after saving"
        )
        self.configure_lock_check.set_visible(self.existing is None)
        self.configure_lock_check.set_tooltip_text(
            "After this new rule is saved, open the schedule, timed, "
            "friction, or password lock setup."
        )
        outer.append(self.configure_lock_check)

        # Breadcrumb (allowance seam): 0 in the editor means "no daily
        # limit"; any value from 1 up is stored as allowance_starts and
        # blocks the rule once that many permitted starts are used today.
        self.allowance_spin = Gtk.SpinButton.new_with_range(0, 10000, 1)
        self.allowance_spin.set_numeric(True)
        self.allowance_spin.set_value(0)
        self.allowance_spin.set_tooltip_text(
            "Allowed main-frame starts per day; 0 means no limit"
        )
        outer.append(
            self._label_for("_Daily start allowance", self.allowance_spin)
        )
        outer.append(self.allowance_spin)

        schedule_heading = Gtk.Label(label="Schedule")
        schedule_heading.add_css_class("heading")
        schedule_heading.set_xalign(0)
        outer.append(schedule_heading)
        self.schedule_dropdown = Gtk.DropDown.new_from_strings(SCHEDULE_LABELS)
        self.schedule_dropdown.connect("notify::selected", self._schedule_changed)
        outer.append(self._label_for("Schedule _type", self.schedule_dropdown))
        outer.append(self.schedule_dropdown)
        zone_label = Gtk.Label(label=f"Time zone: {self.timezone_name}")
        zone_label.set_xalign(0)
        zone_label.add_css_class("dim-label")
        outer.append(zone_label)
        self.schedule_stack = Gtk.Stack()
        self.schedule_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        outer.append(self.schedule_stack)

        one_time = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        self.one_start = DateTimePicker(Gtk, self.default_one_start, "start")
        self.one_end = DateTimePicker(Gtk, self.default_one_end, "end")
        one_time.append(
            self._label_for("_Start date and time", self.one_start.button)
        )
        one_time.append(self.one_start.button)
        one_time.append(self._label_for("_End date and time", self.one_end.button))
        one_time.append(self.one_end.button)
        self.schedule_stack.add_named(one_time, "one_time")

        weekly = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        period_header = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        period_label = Gtk.Label(label="Weekly periods")
        period_label.set_xalign(0)
        period_label.set_hexpand(True)
        period_header.append(period_label)
        self.add_period_button = Gtk.Button.new_with_mnemonic("_Add period")
        self.add_period_button.connect(
            "clicked",
            lambda _button: self._add_weekly_period(
                WeeklyPeriodForm((0, 1, 2, 3, 4), "09:00", "17:00")
            ),
        )
        period_header.append(self.add_period_button)
        weekly.append(period_header)
        self.weekly_period_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM)
        )
        weekly.append(self.weekly_period_box)
        note = Gtk.Label(
            label="If an end is not after its start, the period ends on the next day."
        )
        note.set_xalign(0)
        note.set_wrap(True)
        note.add_css_class("dim-label")
        weekly.append(note)
        allowance_heading = Gtk.Label(label="Timed allowance")
        allowance_heading.add_css_class("heading")
        allowance_heading.set_xalign(0)
        weekly.append(allowance_heading)
        self.time_allowance_check = Gtk.CheckButton(
            label="Enable elapsed-time allowance for these periods"
        )
        self.time_allowance_check.set_tooltip_text(
            "Allow focused browser time during each weekly period. "
            "This requires URL-level targets and non-overlapping periods."
        )
        self.time_allowance_check.connect(
            "toggled", self._time_allowance_changed
        )
        weekly.append(self.time_allowance_check)
        self.time_allowance_target_note = Gtk.Label(label="")
        self.time_allowance_target_note.set_xalign(0)
        self.time_allowance_target_note.set_wrap(True)
        self.time_allowance_target_note.add_css_class("dim-label")
        weekly.append(self.time_allowance_target_note)
        self.time_allowance_daily_spin = Gtk.SpinButton.new_with_range(
            0, MAX_TIME_ALLOWANCE_SECONDS // 60, 1
        )
        self.time_allowance_daily_spin.set_numeric(True)
        self.time_allowance_daily_spin.set_value(0)
        self.time_allowance_daily_spin.set_tooltip_text(
            "Optional daily ceiling in minutes; 0 means no ceiling."
        )
        weekly.append(
            self._label_for(
                "Daily timed allowance ceiling (minutes)",
                self.time_allowance_daily_spin,
            )
        )
        weekly.append(self.time_allowance_daily_spin)
        allowance_note = Gtk.Label(
            label="Each period below has its own allowance mode. "
            "No allowance blocks the full period; total and fixed-window "
            "modes permit elapsed browser time."
        )
        allowance_note.set_xalign(0)
        allowance_note.set_wrap(True)
        allowance_note.add_css_class("dim-label")
        weekly.append(allowance_note)
        self._time_allowance_changed(self.time_allowance_check)
        self.schedule_stack.add_named(weekly, "weekly")
        pomodoro = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        self.pomodoro_start = DateTimePicker(
            Gtk, self.default_pomodoro_start, "Pomodoro start"
        )
        pomodoro.append(
            self._label_for("_Start date and time", self.pomodoro_start.button)
        )
        pomodoro.append(self.pomodoro_start.button)
        self.pomodoro_work = Gtk.SpinButton.new_with_range(1, 180, 1)
        self.pomodoro_work.set_numeric(True)
        self.pomodoro_work.set_value(25)
        self.pomodoro_work.set_tooltip_text("Work duration from 1 to 180 minutes")
        pomodoro.append(
            self._label_for("_Work minutes", self.pomodoro_work)
        )
        pomodoro.append(self.pomodoro_work)
        self.pomodoro_break = Gtk.SpinButton.new_with_range(1, 60, 1)
        self.pomodoro_break.set_numeric(True)
        self.pomodoro_break.set_value(5)
        self.pomodoro_break.set_tooltip_text("Break duration from 1 to 60 minutes")
        pomodoro.append(
            self._label_for("_Break minutes", self.pomodoro_break)
        )
        pomodoro.append(self.pomodoro_break)
        self.pomodoro_cycles = Gtk.SpinButton.new_with_range(
            1, MAX_POMODORO_CYCLES, 1
        )
        self.pomodoro_cycles.set_numeric(True)
        self.pomodoro_cycles.set_value(4)
        self.pomodoro_cycles.set_tooltip_text("Cycle count from 1 to 20")
        pomodoro.append(
            self._label_for("_Cycles", self.pomodoro_cycles)
        )
        pomodoro.append(self.pomodoro_cycles)
        pomodoro_note = Gtk.Label(
            label="The rule blocks during work and permits each break. "
            "It ends after the final work interval."
        )

        pomodoro_note.set_xalign(0)
        pomodoro_note.set_wrap(True)
        pomodoro_note.add_css_class("dim-label")
        pomodoro.append(pomodoro_note)
        self.schedule_stack.add_named(pomodoro, "pomodoro")
        indefinite = Gtk.Label(
            label="This rule stays active until you disable it."
        )
        indefinite.set_xalign(0)
        indefinite.set_wrap(True)
        self.schedule_stack.add_named(indefinite, "indefinite")
        self.schedule_stack.set_visible_child_name("one_time")

        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)
        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        self.save_button = Gtk.Button.new_with_mnemonic("_Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", lambda _button: self._submit())
        actions.append(self.save_button)
        outer.append(actions)
        window.set_default_widget(self.save_button)
        return window
    def _notifications_changed(
        self, check: object, _parameter: object | None = None
    ) -> None:
        enabled = check.get_active()
        for category_check in self.notification_checks.values():
            category_check.set_sensitive(enabled)
    def _time_allowance_changed(
        self, check: object, _parameter: object | None = None
    ) -> None:
        enabled = check.get_active()
        if enabled:
            self.allowance_spin.set_value(0)
        self.allowance_spin.set_sensitive(not enabled)
        self.time_allowance_daily_spin.set_sensitive(enabled)
        for row in self.weekly_rows:
            row.set_allowance_enabled(enabled)
        self._update_time_allowance_availability()

    def _block_target_entries(self) -> tuple[dict[str, str], ...]:
        if hasattr(self, "target_entries"):
            return tuple(self.target_entries)
        return tuple(
            [
                {"kind": "website", "value": domain}
                for domain in self._website_lines()
            ]
            + list(self.url_targets)
            + [
                {"kind": "managed_list", "value": list_id}
                for list_id, check in self.managed_list_checks.items()
                if check.get_active()
            ]
        )

    def _timed_allowance_targets_eligible(self) -> bool:
        entries = self._block_target_entries()
        return bool(entries) and all(
            entry.get("kind") in Target.URL_LIKE_KINDS for entry in entries
        ) and not self.application_paths and not any(
            check.get_active() for check in self.network_checks.values()
        )

    def _update_time_allowance_availability(self) -> None:
        check = getattr(self, "time_allowance_check", None)
        note = getattr(self, "time_allowance_target_note", None)
        if check is None or note is None:
            return
        eligible = self._timed_allowance_targets_eligible()
        if not eligible and check.get_active():
            check.set_active(False)
            return
        check.set_sensitive(eligible)
        if eligible:
            note.set_text(
                "Timed allowances apply only to URL-level targets. "
                "Configure one allowance mode for each weekly period."
            )
        else:
            note.set_text(
                "Add at least one URL rule and remove website, application, "
                "managed-list, or network targets to enable timed allowances."
            )
    def _target_fields_changed(
        self, _check: object, _parameter: object | None = None
    ) -> None:
        self._update_time_allowance_availability()



    def _add_weekly_period(self, value: WeeklyPeriodForm) -> None:
        if len(self.weekly_rows) >= MAX_WEEKLY_PERIODS:
            return
        row = WeeklyPeriodRow(
            self.Gtk, len(self.weekly_rows) + 1, value, self._remove_weekly_period
        )
        self.weekly_rows.append(row)
        self.weekly_period_box.append(row.container)
        row.set_allowance_enabled(self.time_allowance_check.get_active())
        self.add_period_button.set_sensitive(
            len(self.weekly_rows) < MAX_WEEKLY_PERIODS
        )

    def _remove_weekly_period(self, row: WeeklyPeriodRow) -> None:
        self.weekly_rows.remove(row)
        self.weekly_period_box.remove(row.container)
        for index, item in enumerate(self.weekly_rows, start=1):
            item.set_index(index)
        self.add_period_button.set_sensitive(True)

    def _schedule_changed(self, dropdown: object, _parameter: object) -> None:
        selected = dropdown.get_selected()
        if selected < len(SCHEDULE_KINDS):
            self.schedule_stack.set_visible_child_name(SCHEDULE_KINDS[selected])

    def _choose_application(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Select an executable",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Select",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response == Gtk.ResponseType.ACCEPT:
                selected = dialog.get_file()
                path = selected.get_path() if selected is not None else None
                if path is None:
                    self.error_label.set_text("Select a local executable file.")
                else:
                    resolved = os.path.realpath(path)
                    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
                        self.error_label.set_text("Select an executable file.")
                    elif resolved not in self.application_paths:
                        self.application_paths.append(resolved)
                        self._render_applications()
            dialog.destroy()
        chooser.connect("response", respond)
        chooser.show()

    def _render_applications(self) -> None:
        Gtk = self.Gtk
        child = self.application_list.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.application_list.remove(child)
            child = next_child
        for path in self.application_paths:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
            )
            for method in (
                box.set_margin_top,
                box.set_margin_bottom,
                box.set_margin_start,
                box.set_margin_end,
            ):
                method(int(Space.COMPACT))
            label = Gtk.Label(label=path)
            label.set_xalign(0)
            label.set_ellipsize(3)
            label.set_hexpand(True)
            box.append(label)
            remove = Gtk.Button.new_with_mnemonic("_Remove")
            remove.set_tooltip_text(f"Remove {path}")
            remove.connect(
                "clicked", lambda _button, item=path: self._remove_application(item)
            )
            box.append(remove)
            row.set_child(box)
            self.application_list.append(row)
        self._update_time_allowance_availability()

    def _remove_application(self, path: str) -> None:
        self.application_paths.remove(path)
        self._render_applications()

    _URL_KINDS = (
        "url_path",
        "url_wildcard",
        "url_keyword",
        "youtube_video",
        "youtube_channel",
    )

    # Breadcrumb (network seam): (control, checkbox label, tooltip); the
    # control names are the network target values stored in the rule.
    _NETWORK_OPTIONS = (
        (
            "whole_internet",
            "Whole internet",
            "Blocks all of the protected user's non-local IPv4 and IPv6 "
            "connections, including existing ones. Loopback stays open.",
        ),
        (
            "alternate_dns",
            "Alternate DNS",
            "Blocks the protected user's remote DNS (TCP/UDP 53) and "
            "encrypted DNS (TCP/UDP 853). The local system resolver "
            "stays available.",
        ),
        (
            "safe_search",
            "Safe search",
            "Routes the protected user's DNS through a local resolver "
            "that enforces safe search on Google, Bing, and YouTube. "
            "Also blocks alternate DNS.",
        ),
        (
            "doh",
            "Known DoH endpoints",
            "Blocks TCP/UDP 443 to the documented public resolver "
            "addresses in the installed catalog. Shared HTTPS addresses "
            "may block unrelated traffic; arbitrary DoH is not covered.",
        ),
        (
            "proxy",
            "Common proxy endpoints",
            "Blocks TCP/UDP traffic to common proxy listener ports. "
            "Local proxies and arbitrary ports are not covered.",
        ),
        (
            "vpn",
            "Common VPN endpoints",
            "Blocks common VPN transport ports plus GRE and ESP. "
            "VPNs on arbitrary ports or through another identity are not covered.",
        ),
    )

    def _managed_list_toggled(self, check: object) -> None:
        list_id = next(
            (
                identifier
                for identifier, candidate in self.managed_list_checks.items()
                if candidate is check
            ),
            None,
        )
        if list_id is None:
            return
        entry = {"kind": "managed_list", "value": list_id}
        present = entry in self.target_entries
        if check.get_active() and not present:
            self.target_entries.append(entry)
        elif not check.get_active() and present:
            self.target_entries.remove(entry)
        self._render_targets()
        self._update_time_allowance_availability()

    @staticmethod
    def _classify_target(value: str, exception: bool) -> tuple[str, str]:
        lowered = value.lower()
        for prefix, kind in (
            ("youtube-video:", "youtube_video"),
            ("youtube-channel:", "youtube_channel"),
        ):
            if lowered.startswith(prefix):
                return kind, value[len(prefix):].strip()
        if "*" in value:
            return "url_wildcard", value
        if "/" in value:
            return "url_path", value
        if not exception:
            try:
                website = Target.from_dict(
                    {"kind": "website", "value": value}
                )
            except ValidationError:
                pass
            else:
                return website.kind, website.value
        return "url_keyword", value

    def _add_target(self, exception: bool) -> None:
        if exception:
            dropdown = self.exception_kind_dropdown
            entry_widget = self.exception_entry
            kinds = ("auto", *self._URL_KINDS)
            target_list = self.url_exceptions
        else:
            dropdown = getattr(self, "target_kind_dropdown", None)
            entry_widget = getattr(self, "target_entry", None)
            kinds = ("auto", "website", *self._URL_KINDS)
            target_list = getattr(self, "target_entries", self.url_targets)
            if dropdown is None:
                dropdown = self.url_kind_dropdown
                entry_widget = self.url_entry
                kinds = self._URL_KINDS
        selected = dropdown.get_selected()
        kind = kinds[selected] if selected < len(kinds) else kinds[0]
        value = entry_widget.get_text().strip()
        if kind == "auto":
            kind, value = self._classify_target(value, exception)
        if not value:
            self.error_label.set_text("Enter a target first.")
            return
        try:
            target = Target.from_dict({"kind": kind, "value": value})
        except ValidationError as error:
            self.error_label.set_text(error.message)
            return
        normalized = target.to_dict()
        if normalized in target_list:
            self.error_label.set_text("That target is already in the list.")
            return
        target_list.append(normalized)
        entry_widget.set_text("")
        self.error_label.set_text("")
        self._render_targets()
        self._update_time_allowance_availability()

    def _add_url_target(self) -> None:
        check = getattr(self, "url_exception_check", None)
        self._add_target(bool(check is not None and check.get_active()))

    @staticmethod
    def _clear_list(widget: object) -> None:
        child = widget.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            widget.remove(child)
            child = next_child

    def _render_list(
        self,
        widget: object,
        entries: Sequence[dict[str, str]],
        *,
        exception: bool = False,
    ) -> None:
        Gtk = self.Gtk
        self._clear_list(widget)
        kind_labels = {
            "website": "Website",
            "managed_list": "Managed list",
            "network": "Network",
            "url_path": "Path",
            "url_wildcard": "Wildcard",
            "url_keyword": "Keyword",
            "youtube_video": "YouTube video",
            "youtube_channel": "YouTube channel",
        }
        managed_names = {
            summary.id: summary.name for summary in self.managed_lists
        }
        for entry in entries:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL,
                spacing=int(Space.SMALL),
            )
            for method in (
                box.set_margin_top,
                box.set_margin_bottom,
                box.set_margin_start,
                box.set_margin_end,
            ):
                method(int(Space.COMPACT))
            value = entry["value"]
            if entry["kind"] == "managed_list":
                value = f"{managed_names.get(value, value)} ({value})"
            prefix = "Exception: " if exception else ""
            label = Gtk.Label(
                label=f"{prefix}[{kind_labels.get(entry['kind'], entry['kind'])}] "
                f"{value}"
            )
            label.set_xalign(0)
            label.set_ellipsize(3)
            label.set_hexpand(True)
            box.append(label)
            remove = Gtk.Button.new_with_mnemonic("_Remove")
            remove.set_tooltip_text(f"Remove {entry['value']}")
            remove.connect(
                "clicked",
                lambda _button, item=dict(entry), is_exception=exception:
                self._remove_target(item, is_exception),
            )
            box.append(remove)
            row.set_child(box)
            widget.append(row)

    def _render_targets(self) -> None:
        if hasattr(self, "target_list"):
            self._render_list(self.target_list, self.target_entries)
            self._render_list(
                self.exception_list, self.url_exceptions, exception=True
            )
            self._render_applications()
            return
        self._render_url_targets()

    def _render_url_targets(self) -> None:
        if hasattr(self, "target_list"):
            self._render_targets()
            return
        self._render_list(self.url_list, self.url_targets)

    def _remove_target(
        self, entry: dict[str, str], exception: bool = False
    ) -> None:
        target_list = self.url_exceptions if exception else self.target_entries
        if entry in target_list:
            target_list.remove(entry)
        if not exception and entry.get("kind") == "managed_list":
            check = self.managed_list_checks.get(entry["value"])
            if check is not None and check.get_active():
                check.set_active(False)
        self._render_targets()
        self._update_time_allowance_availability()

    def _remove_url_target(
        self, entry: dict[str, str], exception: bool = False
    ) -> None:
        if not hasattr(self, "target_entries"):
            target_list = self.url_exceptions if exception else self.url_targets
            if entry in target_list:
                target_list.remove(entry)
            self._render_url_targets()
            self._update_time_allowance_availability()
            return
        self._remove_target(entry, exception)

    def _choose_domain_import(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import domain list",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self.error_label.set_text("Select a local import file.")
                return

            def read_preview() -> ImportPreview:
                preview = parse_domain_text(read_import_text(path))
                if not preview.domains:
                    raise TransferError("The import contains no valid domains.")
                return preview

            self._run_worker(
                read_preview,
                lambda preview: self._confirm_domain_import(
                    preview, Path(path).name
                ),
            )
        chooser.connect("response", respond)
        chooser.show()

    def _confirm_domain_import(
        self, preview: ImportPreview, filename: str
    ) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Add domains from {filename}?",
            secondary_text=import_preview_text(preview),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Add", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            self._set_website_lines(
                (*self._website_lines(), *preview.domains)
            )
        dialog.connect("response", respond)
        dialog.present()

    def _choose_target_list_import(self, exception: bool) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import URL list" if exception else "Import target list",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self.error_label.set_text("Select a local JSON file.")
                return

            def read_preview() -> TargetListPreview:
                preview = parse_target_list_text(
                    read_target_list_text(path),
                    expected_scope="exceptions" if exception else "targets",
                )
                if not preview.targets:
                    raise TransferError("The target list contains no entries.")
                return preview

            self._run_worker(
                read_preview,
                lambda preview: self._confirm_target_list_import(
                    preview, Path(path).name, exception
                ),
            )
        chooser.connect("response", respond)
        chooser.show()

    @staticmethod
    def _missing_managed_snapshots(
        preview: TargetListPreview,
        available_ids: set[str],
    ) -> tuple[ManagedList, ...]:
        return tuple(
            managed
            for managed in preview.managed_lists
            if managed.id not in available_ids
        )

    def _confirm_target_list_import(
        self,
        preview: TargetListPreview,
        filename: str,
        exception: bool,
    ) -> None:
        Gtk = self.Gtk
        available_ids = {summary.id for summary in self.managed_lists}
        missing_snapshots = (
            self._missing_managed_snapshots(preview, available_ids)
            if not exception
            else ()
        )
        secondary = (
            f"{len(preview.targets)} typed entries will be added. "
            "Existing entries are kept."
        )
        if missing_snapshots:
            secondary += (
                f" {len(missing_snapshots)} managed-list snapshot(s) "
                "will also be installed."
            )
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Add entries from {filename}?",
            secondary_text=secondary,
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Add", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def append_targets() -> None:
            target_list = (
                self.url_exceptions if exception else self.target_entries
            )
            for target in preview.targets:
                entry = target.to_dict()
                if entry not in target_list:
                    target_list.append(entry)
            self._render_targets()
            self._update_time_allowance_availability()

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            if not missing_snapshots:
                append_targets()
                return
            upload = getattr(self, "upload_managed_lists", None)
            if upload is None:
                self.error_label.set_text(
                    "Managed-list snapshots cannot be installed here."
                )
                return
            self.error_label.set_text("Installing managed-list snapshots.")
            upload(
                missing_snapshots,
                lambda error: (
                    self.error_label.set_text(error)
                    if error is not None
                    else append_targets()
                ),
            )
        dialog.connect("response", respond)
        dialog.present()

    def _choose_target_export(self, exception: bool) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Export exceptions" if exception else "Export block targets",
            self.window,
            Gtk.FileChooserAction.SAVE,
            "_Save",
            "_Cancel",
        )
        chooser.set_current_name(
            "exceptions.json" if exception else "targets.json"
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self.error_label.set_text("Select a local export path.")
                return
            entries = self.url_exceptions if exception else self.target_entries
            try:
                targets = tuple(Target.from_dict(entry) for entry in entries)
            except ValidationError as error:
                self.error_label.set_text(error.message)
                return
            selected_ids = {
                target.value for target in targets if target.kind == "managed_list"
            }
            summaries = tuple(
                summary
                for summary in self.managed_lists
                if summary.id in selected_ids
            )
            if selected_ids and self.read_managed_lists is None:
                self.error_label.set_text(
                    "Managed-list contents are unavailable for export."
                )
                return
            if selected_ids:
                self._run_worker(
                    lambda: self.read_managed_lists(summaries),
                    lambda managed: self._write_target_export(
                        path, exception, targets, managed
                    ),
                )
            else:
                self._write_target_export(path, exception, targets, ())
        chooser.connect("response", respond)
        chooser.show()

    def _write_target_export(
        self,
        path: str,
        exception: bool,
        targets: Sequence[Target],
        managed_lists: Sequence[ManagedList],
    ) -> None:
        try:
            content = target_list_export_text(
                "exceptions" if exception else "targets",
                targets,
                managed_lists,
            )
            atomic_write_text(path, content)
        except (TransferError, OSError) as error:
            self.error_label.set_text(str(error))
            return
        self.error_label.set_text(f"Exported {Path(path).name}.")
    def _choose_application_import(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Import application list",
            self.window,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            path = selected.get_path() if selected is not None else None
            dialog.destroy()
            if path is None:
                self.error_label.set_text("Select a local JSON file.")
                return

            def read_preview() -> TargetListPreview:
                preview = parse_target_list_text(
                    read_target_list_text(path), expected_scope="applications"
                )
                if not preview.targets:
                    raise TransferError(
                        "The application list contains no entries."
                    )
                return preview

            self._run_worker(
                read_preview,
                lambda preview: self._confirm_application_import(
                    preview, Path(path).name
                ),
            )
        chooser.connect("response", respond)
        chooser.show()

    def _confirm_application_import(
        self, preview: TargetListPreview, filename: str
    ) -> None:
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Add applications from {filename}?",
            secondary_text=(
                f"{len(preview.targets)} executable paths will be added. "
                "Existing paths are kept."
            ),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Add", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            for target in preview.targets:
                if target.value not in self.application_paths:
                    self.application_paths.append(target.value)
            self._render_applications()
        dialog.connect("response", respond)
        dialog.present()

    def _choose_application_export(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Export application blocks",
            self.window,
            Gtk.FileChooserAction.SAVE,
            "_Save",
            "_Cancel",
        )
        chooser.set_current_name("applications.json")

        def respond(dialog: object, response: int) -> None:
            if response != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            selected = dialog.get_file()
            export_path = (
                selected.get_path() if selected is not None else None
            )
            dialog.destroy()
            if export_path is None:
                self.error_label.set_text("Select a local export path.")
                return
            try:
                targets = tuple(
                    Target.from_dict(
                        {"kind": "application", "value": application_path}
                    )
                    for application_path in self.application_paths
                )
                atomic_write_text(
                    export_path,
                    target_list_export_text("applications", targets),
                )
            except (TransferError, ValidationError, OSError) as error:
                self.error_label.set_text(str(error))
                return
            self.error_label.set_text(
                f"Exported {Path(export_path).name}."
            )
        chooser.connect("response", respond)
        chooser.show()


    def _set_website_lines(self, domains: Sequence[str]) -> None:
        if hasattr(self, "target_entries"):
            website_entries: list[dict[str, str]] = []
            for domain in dict.fromkeys(domains):
                target = Target.from_dict({
                    "kind": "website", "value": domain
                })
                website_entries.append(target.to_dict())
            self.target_entries = [
                entry for entry in self.target_entries
                if entry.get("kind") != "website"
            ]
            self.target_entries[0:0] = website_entries
            self._render_targets()
            self._update_time_allowance_availability()
            return
        self.website_view.get_buffer().set_text("\n".join(domains))
        self._update_time_allowance_availability()

    def _website_lines(self) -> tuple[str, ...]:
        if hasattr(self, "target_entries"):
            return tuple(
                entry["value"]
                for entry in self.target_entries
                if entry.get("kind") == "website"
            )
        buffer = self.website_view.get_buffer()
        text = buffer.get_text(
            buffer.get_start_iter(), buffer.get_end_iter(), False
        )
        return tuple(line.strip() for line in text.splitlines() if line.strip())

    def _form(self) -> RuleForm:
        selected = self.schedule_dropdown.get_selected()
        if selected >= len(SCHEDULE_KINDS):
            raise FormError("Select a valid schedule type.")
        target_entries = self._block_target_entries()
        websites = tuple(
            entry["value"]
            for entry in target_entries
            if entry.get("kind") == "website"
        )
        managed_list_ids = tuple(
            entry["value"]
            for entry in target_entries
            if entry.get("kind") == "managed_list"
        )
        url_targets = tuple(
            entry for entry in target_entries
            if entry.get("kind") in Target.URL_LIKE_KINDS
        )
        return RuleForm(
            name=self.name_entry.get_text(),
            websites=websites,
            applications=tuple(self.application_paths),
            managed_list_ids=managed_list_ids,
            target_entries=target_entries,
            network_controls=tuple(
                control
                for control, check in self.network_checks.items()
                if check.get_active()
            ),
            notifications_enabled=self.notifications_enabled_check.get_active(),
            notification_categories=tuple(
                category
                for category, check in self.notification_checks.items()
                if check.get_active()
            ),
            schedule_kind=SCHEDULE_KINDS[selected],
            timezone=self.timezone_name,
            one_time_start=self.one_start.get_text(),
            one_time_end=self.one_end.get_text(),
            weekly_periods=tuple(row.value() for row in self.weekly_rows),
            pomodoro_start=self.pomodoro_start.get_text(),
            pomodoro_work_minutes=self.pomodoro_work.get_value_as_int(),
            pomodoro_break_minutes=self.pomodoro_break.get_value_as_int(),
            pomodoro_cycles=self.pomodoro_cycles.get_value_as_int(),
            url_targets=url_targets,
            url_exceptions=tuple(self.url_exceptions),
            allowance_starts=(
                None if self.allowance_spin.get_value_as_int() == 0
                else self.allowance_spin.get_value_as_int()
            ),
            time_allowance_enabled=(
                SCHEDULE_KINDS[selected] == "weekly"
                and self.time_allowance_check.get_active()
            ),
            time_allowance_periods=tuple(
                row.allowance_value() for row in self.weekly_rows
            ),
            time_allowance_daily_cap_minutes=(
                None
                if self.time_allowance_daily_spin.get_value_as_int() == 0
                else self.time_allowance_daily_spin.get_value_as_int()
            ),
            configure_lock_after_save=self.configure_lock_check.get_active(),
        )

    def _submit(self) -> None:
        try:
            form = self._form()
        except FormError as error:
            self.error_label.set_text(str(error))
            return
        self.save_button.set_sensitive(False)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Saving rule.")
        self.save(form, self.existing, self._saved)

    def _saved(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            return
        self.save_button.set_sensitive(True)
        self.error_label.add_css_class("error")
        self.error_label.set_text(message)

    def _populate(self, form: RuleForm) -> None:
        self.name_entry.set_text(form.name)
        entries = list(form.target_entries)
        if not entries:
            entries = [
                {"kind": "website", "value": domain}
                for domain in form.websites
            ]
            entries.extend(
                {"kind": "managed_list", "value": list_id}
                for list_id in form.managed_list_ids
            )
            entries.extend(form.url_targets)
        if hasattr(self, "target_entries"):
            self.target_entries = entries
            self.url_exceptions = list(form.url_exceptions)
            self._render_targets()
        else:
            self.website_view.get_buffer().set_text("\n".join(form.websites))
            self.url_targets = list(form.url_targets)
            self.url_exceptions = list(form.url_exceptions)
            self._render_applications()
            self._render_url_targets()
        self.application_paths = list(form.applications)
        self._render_applications()
        enabled_check = getattr(self, "notifications_enabled_check", None)
        if enabled_check is not None:
            enabled_check.set_active(form.notifications_enabled)
            for category, check in self.notification_checks.items():
                check.set_active(category in form.notification_categories)
            self._notifications_changed(enabled_check)
        for list_id in form.managed_list_ids:
            check = self.managed_list_checks.get(list_id)
            if check is not None:
                check.set_active(True)
        for control, check in self.network_checks.items():
            check.set_active(control in form.network_controls)
        selected = SCHEDULE_KINDS.index(form.schedule_kind)
        self.schedule_dropdown.set_selected(selected)
        self.schedule_stack.set_visible_child_name(form.schedule_kind)
        # Breadcrumb: 0 means "no daily limit" in the editor.
        self.allowance_spin.set_value(form.allowance_starts or 0)
        time_allowance_check = getattr(self, "time_allowance_check", None)
        if time_allowance_check is not None:
            time_allowance_check.set_active(form.time_allowance_enabled)
            self.time_allowance_daily_spin.set_value(
                form.time_allowance_daily_cap_minutes or 0
            )
        for row in tuple(self.weekly_rows):
            self._remove_weekly_period(row)
        if form.schedule_kind == "weekly":
            for index, period in enumerate(form.weekly_periods):
                allowance = (
                    form.time_allowance_periods[index]
                    if index < len(form.time_allowance_periods)
                    else PeriodAllowanceForm()
                )
                self._add_weekly_period(
                    replace(
                        period,
                        allowance_mode=allowance.mode,
                        allowance_quota_minutes=allowance.quota_minutes,
                        allowance_window_minutes=allowance.window_minutes,
                    )
                )
        elif form.schedule_kind == "pomodoro":
            self.pomodoro_start.set_text(form.pomodoro_start)
            self.pomodoro_work.set_value(form.pomodoro_work_minutes)
            self.pomodoro_break.set_value(form.pomodoro_break_minutes)
            self.pomodoro_cycles.set_value(form.pomodoro_cycles)
        self._update_time_allowance_availability()

    def present(self) -> None:
        self.window.present()
        self.name_entry.grab_focus()


class ManagedListWindow:
    """Administer managed lists without loading their domains."""

    def __init__(
        self,
        modules: GtkModules,
        parent: object,
        summaries: Sequence[ManagedListSummary],
        starters: Sequence[ManagedList],
        healthy: bool,
        choose_import: Callable[[object], None],
        create: Callable[[object], None],
        edit: Callable[[object, ManagedListSummary], None],
        install: Callable[
            [ManagedList, Callable[[str | None], None]], None
        ],
        delete: Callable[[object, ManagedListSummary], None],
    ):
        self.Gtk = modules.Gtk
        self.summaries = tuple(summaries)
        self.starters = tuple(starters)
        self.healthy = healthy
        self.choose_import, self.create, self.edit, self.install, self.delete = (
            choose_import,
            create,
            edit,
            install,
            delete,
        )
        self.window = self._build(parent)

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Managed lists", transient_for=parent, modal=True
        )
        window.set_default_size(760, 640)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)
        heading = Gtk.Label(label="Managed lists")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        intro = Gtk.Label(
            label=(
                "Lists group domains for rule targets. "
                "Normal list views show metadata and counts only."
            )
        )
        intro.set_xalign(0)
        intro.set_wrap(True)
        outer.append(intro)

        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        create_button = Gtk.Button.new_with_mnemonic("_New custom list")
        create_button.set_sensitive(self.healthy)
        create_button.connect(
            "clicked", lambda _button: self.create(window)
        )
        actions.append(create_button)
        import_button = Gtk.Button.new_with_mnemonic("_Import file")
        import_button.set_sensitive(self.healthy)
        import_button.connect(
            "clicked", lambda _button: self.choose_import(window)
        )
        actions.append(import_button)
        starter_names = [item.name for item in self.starters]
        self.starter_dropdown = Gtk.DropDown.new_from_strings(starter_names)
        self.starter_dropdown.set_hexpand(True)
        self.starter_dropdown.connect(
            "notify::selected", lambda *_args: self._update_install_button()
        )
        actions.append(self.starter_dropdown)
        self.install_button = Gtk.Button.new_with_mnemonic(
            "Install _starter category"
        )
        self.install_button.connect(
            "clicked", lambda _button: self._install_selected()
        )
        actions.append(self.install_button)
        outer.append(actions)
        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)

        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        list_box.add_css_class("boxed-list")
        scroller.set_child(list_box)
        outer.append(scroller)
        if not self.summaries:
            row = Gtk.ListBoxRow()
            label = Gtk.Label(
                label="No managed lists. Import a file or install a starter category."
            )
            label.set_xalign(0)
            label.set_wrap(True)
            for method in (
                label.set_margin_top,
                label.set_margin_bottom,
                label.set_margin_start,
                label.set_margin_end,
            ):
                method(int(Space.MEDIUM))
            row.set_child(label)
            list_box.append(row)
        for summary in self.summaries:
            list_box.append(self._summary_row(summary))
        self._update_install_button()
        return window

    def _summary_row(self, summary: ManagedListSummary) -> object:
        Gtk = self.Gtk
        row = Gtk.ListBoxRow()
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.SMALL))
        heading_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        name = Gtk.Label(
            label=f"{summary.name} · {summary.domain_count} domains"
        )
        name.add_css_class("heading")
        name.set_xalign(0)
        name.set_hexpand(True)
        heading_row.append(name)
        edit_button = Gtk.Button.new_with_mnemonic("_Edit roster")
        edit_button.set_sensitive(self.healthy)
        edit_button.connect(
            "clicked",
            lambda _button: self.edit(self.window, summary),
        )
        heading_row.append(edit_button)
        delete_button = Gtk.Button.new_with_mnemonic("_Delete")
        delete_button.add_css_class("destructive-action")
        delete_button.set_sensitive(self.healthy)
        delete_button.connect(
            "clicked",
            lambda _button: self.delete(self.window, summary),
        )
        heading_row.append(delete_button)
        outer.append(heading_row)
        metadata = Gtk.Label(
            label=(
                f"Source: {summary.source} · Version: {summary.version}\n"
                f"License: {summary.license}\nImported: {summary.imported_utc}"
            )
        )
        metadata.set_xalign(0)
        metadata.set_wrap(True)
        metadata.add_css_class("dim-label")
        outer.append(metadata)
        row.set_child(outer)
        return row

    def _update_install_button(self) -> None:
        selected = self.starter_dropdown.get_selected()
        installed = {(item.name, item.source) for item in self.summaries}
        available = (
            selected < len(self.starters)
            and (
                self.starters[selected].name,
                self.starters[selected].source,
            ) not in installed
        )
        self.install_button.set_sensitive(self.healthy and available)

    def _install_selected(self) -> None:
        selected = self.starter_dropdown.get_selected()
        if selected >= len(self.starters):
            return
        self.install_button.set_sensitive(False)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Installing starter category.")
        self.install(self.starters[selected], self._installed)

    def _installed(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            return
        self.error_label.set_text(message)
        self._update_install_button()
        self.error_label.add_css_class("error")

    def present(self) -> None:
        self.window.present()

class ManagedListEditorWindow:
    """Create a managed list or edit its complete domain roster."""

    def __init__(
        self,
        modules: GtkModules,
        parent: object,
        existing: ManagedList | None,
        save: Callable[
            [ManagedList, Callable[[str | None], None]], None
        ],
    ):
        self.Gtk = modules.Gtk
        self.parent = parent
        self.existing = existing
        self.save = save
        self.window = self._build(parent)

    def _entry(self, value: str) -> object:
        entry = self.Gtk.Entry()
        entry.set_hexpand(True)
        entry.set_text(value)
        return entry

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        editing = self.existing is not None
        window = Gtk.Window(
            title="Edit managed list" if editing else "New custom managed list",
            transient_for=parent,
            modal=True,
        )
        window.set_default_size(640, 700)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)
        heading = Gtk.Label(
            label="Edit managed list" if editing else "New custom managed list"
        )
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        intro = Gtk.Label(
            label=(
                "Enter one hostname per line. Changes replace the roster "
                "atomically when you save."
            )
        )
        intro.set_xalign(0)
        intro.set_wrap(True)
        outer.append(intro)
        current = self.existing
        self.name_entry = self._entry("" if current is None else current.name)
        self.source_entry = self._entry(
            "custom" if current is None else current.source
        )
        self.version_entry = self._entry(
            "1" if current is None else current.version
        )
        self.license_entry = self._entry(
            "User-provided domains."
            if current is None
            else current.license
        )
        for text, entry in (
            ("List name", self.name_entry),
            ("Source", self.source_entry),
            ("Data version", self.version_entry),
            ("License note", self.license_entry),
        ):
            label = Gtk.Label(label=text)
            label.set_xalign(0)
            label.set_mnemonic_widget(entry)
            outer.append(label)
            outer.append(entry)
        domain_label = Gtk.Label(label="Domains")
        domain_label.set_xalign(0)
        outer.append(domain_label)
        domain_scroller = Gtk.ScrolledWindow()
        domain_scroller.set_vexpand(True)
        domain_scroller.set_policy(
            Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC
        )
        self.domain_view = Gtk.TextView()
        self.domain_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.domain_view.set_monospace(True)
        self.domain_view.get_buffer().set_text(
            "" if current is None else "\n".join(current.domains)
        )
        domain_scroller.set_child(self.domain_view)
        outer.append(domain_scroller)
        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)
        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        self.save_button = Gtk.Button.new_with_mnemonic("_Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", lambda _button: self._submit())
        actions.append(self.save_button)
        outer.append(actions)
        window.set_default_widget(self.save_button)
        return window

    def _submit(self) -> None:
        buffer = self.domain_view.get_buffer()
        text = buffer.get_text(
            buffer.get_start_iter(), buffer.get_end_iter(), True
        )
        try:
            preview = parse_domain_text(text)
            if preview.issues:
                issue = preview.issues[0]
                raise FormError(
                    f"Invalid domain on line {issue.line}: {issue.reason}"
                )
            if not preview.domains:
                raise FormError("The managed list contains no valid domains.")
            current = self.existing
            managed_list = ManagedList.from_dict(
                {
                    "id": str(uuid4()) if current is None else current.id,
                    "name": self.name_entry.get_text().strip(),
                    "source": self.source_entry.get_text().strip(),
                    "version": self.version_entry.get_text().strip(),
                    "license": self.license_entry.get_text().strip(),
                    "imported_utc": datetime.now(UTC),
                    "domains": list(preview.domains),
                }
            )
        except (TransferError, ValidationError, ValueError) as error:
            self.error_label.set_text(str(error))
            return
        self.save_button.set_sensitive(False)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Saving list.")
        self.save(managed_list, self._saved)

    def _saved(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            self.parent.destroy()
            return
        self.save_button.set_sensitive(True)
        self.error_label.set_text(message)
        self.error_label.add_css_class("error")

    def present(self) -> None:
        self.window.present()
        self.name_entry.grab_focus()



class ManagedListImportWindow:
    """Collect metadata before a staged managed-list upload."""

    def __init__(
        self,
        modules: GtkModules,
        parent: object,
        filename: str,
        preview: ImportPreview,
        upload: Callable[
            [ManagedList, Callable[[str | None], None]], None
        ],
    ):
        self.Gtk = modules.Gtk
        self.parent = parent
        self.filename, self.preview, self.upload = filename, preview, upload
        self.window = self._build(parent)

    def _entry(self, value: str) -> object:
        entry = self.Gtk.Entry()
        entry.set_hexpand(True)
        entry.set_text(value)
        return entry

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Import managed list", transient_for=parent, modal=True
        )
        window.set_default_size(560, 520)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)
        heading = Gtk.Label(label="Import managed list")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        preview_label = Gtk.Label(label=import_preview_text(self.preview))
        preview_label.set_xalign(0)
        preview_label.set_wrap(True)
        outer.append(preview_label)
        self.name_entry = self._entry(Path(self.filename).stem)
        self.source_entry = self._entry(f"file:{self.filename}")
        self.version_entry = self._entry("1")
        self.license_entry = self._entry("User supplied. Review the source license.")
        for text, entry in (
            ("List name", self.name_entry),
            ("Source", self.source_entry),
            ("Data version", self.version_entry),
            ("License note", self.license_entry),
        ):
            label = Gtk.Label(label=text)
            label.set_xalign(0)
            label.set_mnemonic_widget(entry)
            outer.append(label)
            outer.append(entry)
        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)
        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        self.import_button = Gtk.Button.new_with_mnemonic("_Import")
        self.import_button.add_css_class("suggested-action")
        self.import_button.connect("clicked", lambda _button: self._submit())
        actions.append(self.import_button)
        outer.append(actions)
        window.set_default_widget(self.import_button)
        return window

    def _submit(self) -> None:
        try:
            managed_list = ManagedList.from_dict(
                {
                    "id": str(uuid4()),
                    "name": self.name_entry.get_text().strip(),
                    "source": self.source_entry.get_text().strip(),
                    "version": self.version_entry.get_text().strip(),
                    "license": self.license_entry.get_text().strip(),
                    "imported_utc": datetime.now(UTC),
                    "domains": list(self.preview.domains),
                }
            )
        except (ValidationError, ValueError) as error:
            self.error_label.set_text(str(error))
            return
        self.import_button.set_sensitive(False)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Uploading list.")
        self.upload(managed_list, self._uploaded)

    def _uploaded(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            self.parent.destroy()
            return
        self.import_button.set_sensitive(True)
        self.error_label.set_text(message)
        self.error_label.add_css_class("error")

    def present(self) -> None:
        self.window.present()
        self.name_entry.grab_focus()


class QuickFocusWindow:
    """Create an immediate focus rule from an existing rule."""

    def __init__(
        self,
        Gtk: ModuleType,
        parent: object,
        rules: Sequence[Rule],
        save: Callable[
            [Rule, int, Callable[[str | None], None]], None
        ],
    ):
        self.Gtk, self.rules, self.save = Gtk, tuple(rules), save
        self.window = self._build(parent)

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Quick focus", transient_for=parent, modal=True
        )
        window.set_default_size(500, 360)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)
        heading = Gtk.Label(label="Quick focus")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        intro = Gtk.Label(
            label="Copy targets from a rule into an immediate one-time rule."
        )
        intro.set_xalign(0)
        intro.set_wrap(True)
        outer.append(intro)
        source_label = Gtk.Label(label="Source rule")
        source_label.set_xalign(0)
        outer.append(source_label)
        self.rule_dropdown = Gtk.DropDown.new_from_strings(
            [f"{rule.name} · {_target_summary(rule)}" for rule in self.rules]
        )
        source_label.set_mnemonic_widget(self.rule_dropdown)
        outer.append(self.rule_dropdown)
        duration_label = Gtk.Label(label="Duration")
        duration_label.set_xalign(0)
        outer.append(duration_label)
        duration_names = [
            *(f"{minutes} minutes" for minutes in FOCUS_DURATIONS),
            "Custom",
        ]
        self.duration_dropdown = Gtk.DropDown.new_from_strings(duration_names)
        self.duration_dropdown.connect(
            "notify::selected", lambda *_args: self._duration_changed()
        )
        duration_label.set_mnemonic_widget(self.duration_dropdown)
        outer.append(self.duration_dropdown)
        self.custom_minutes_label = Gtk.Label(label="Custom minutes")
        self.custom_minutes_label.set_xalign(0)
        outer.append(self.custom_minutes_label)
        self.custom_minutes = Gtk.Entry()
        self.custom_minutes.set_text("45")
        self.custom_minutes.set_placeholder_text("Minutes")
        self.custom_minutes_label.set_mnemonic_widget(self.custom_minutes)
        outer.append(self.custom_minutes)
        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)
        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        self.start_button = Gtk.Button.new_with_mnemonic("_Start focus")
        self.start_button.add_css_class("suggested-action")
        self.start_button.set_sensitive(bool(self.rules))
        self.start_button.connect("clicked", lambda _button: self._submit())
        actions.append(self.start_button)
        outer.append(actions)
        if not self.rules:
            self.error_label.set_text("Add a rule before you start quick focus.")
        self._duration_changed()
        return window

    def _duration_changed(self) -> None:
        visible = self.duration_dropdown.get_selected() == len(FOCUS_DURATIONS)
        self.custom_minutes_label.set_visible(visible)
        self.custom_minutes.set_visible(visible)

    def _submit(self) -> None:
        rule_index = self.rule_dropdown.get_selected()
        duration_index = self.duration_dropdown.get_selected()
        if rule_index >= len(self.rules):
            self.error_label.set_text("Select a source rule.")
            return
        if duration_index < len(FOCUS_DURATIONS):
            minutes = FOCUS_DURATIONS[duration_index]
        else:
            try:
                minutes = int(self.custom_minutes.get_text().strip())
            except ValueError:
                self.error_label.set_text("Enter a whole number of minutes.")
                return
        self.start_button.set_sensitive(False)
        self.error_label.remove_css_class("error")
        self.error_label.set_text("Starting focus.")
        self.save(self.rules[rule_index], minutes, self._saved)

    def _saved(self, message: str | None) -> None:
        if message is None:
            self.window.destroy()
            return
        self.start_button.set_sensitive(True)
        self.error_label.set_text(message)
        self.error_label.add_css_class("error")

    def present(self) -> None:
        self.window.present()
class DenialStatisticsWindow:
    """Show bounded application-denial statistics from public RPC data."""

    def __init__(
        self,
        Gtk: ModuleType,
        parent: object,
        load: Callable[
            [Callable[[DenialStatistics | None, str | None], None]],
            None,
        ],
        clear: Callable[[Callable[[str | None], None]], None],
        load_usage: Callable[
            [Callable[[tuple[WebsiteUsageView, ...] | None, str | None], None]],
            None,
        ] | None = None,
        export: Callable[[], None] | None = None,
    ):
        self.Gtk = Gtk
        self.load_statistics = load
        self.clear_statistics = clear
        # Breadcrumb: optional website-usage loader; a small pane is enough
        # for v1 and an absent loader simply hides the pane.
        self.load_usage = load_usage
        self.export_statistics = export
        self.closed = False
        self.statistics: DenialStatistics | None = None
        self.window = self._build(parent)

    def _build(self, parent: object) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Application denial statistics",
            transient_for=parent,
            modal=False,
        )
        window.connect("close-request", self._window_closed)
        window.set_default_size(760, 640)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=int(Space.MEDIUM),
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)

        heading = Gtk.Label(label="Application denial statistics")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        intro = Gtk.Label(
            label=(
                "This read-only view reports denied application launches. "
                "It does not change rules or blocking decisions."
            )
        )
        intro.set_xalign(0)
        intro.set_wrap(True)
        outer.append(intro)

        self.dropped_label = Gtk.Label(label="Dropped denial events: loading.")
        self.dropped_label.set_xalign(0)
        self.dropped_label.set_wrap(True)
        outer.append(self.dropped_label)

        actions = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=int(Space.SMALL),
        )
        self.refresh_button = Gtk.Button.new_with_mnemonic("_Refresh")
        self.refresh_button.connect("clicked", lambda _button: self._load())
        actions.append(self.refresh_button)
        self.clear_button = Gtk.Button.new_with_mnemonic("_Clear statistics")
        self.clear_button.add_css_class("destructive-action")
        self.clear_button.set_sensitive(False)
        self.clear_button.set_tooltip_text(
            "Delete recorded denial counts after confirmation"
        )
        self.clear_button.connect(
            "clicked", lambda _button: self._confirm_clear()
        )
        actions.append(self.clear_button)
        if self.export_statistics is not None:
            export = Gtk.Button.new_with_mnemonic("_Export")
            export.set_tooltip_text("Export application and website statistics")
            export.connect("clicked", lambda _button: self.export_statistics())
            actions.append(export)
        outer.append(actions)

        self.status_label = Gtk.Label(label="Loading denial statistics.")
        self.status_label.set_xalign(0)
        self.status_label.set_wrap(True)
        outer.append(self.status_label)

        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("boxed-list")
        scroller.set_child(self.list_box)
        outer.append(scroller)

        close = Gtk.Button.new_with_mnemonic("_Close")
        close.set_halign(Gtk.Align.END)
        close.connect("clicked", lambda _button: self._close())

        usage_heading = Gtk.Label(label="Website start allowances (today)")
        usage_heading.add_css_class("heading")
        usage_heading.set_xalign(0)
        outer.append(usage_heading)
        self.usage_list_box = Gtk.ListBox()
        self.usage_list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.usage_list_box.add_css_class("boxed-list")
        outer.append(self.usage_list_box)
        outer.append(close)
        return window

    def _window_closed(self, _window: object) -> bool:
        self.closed = True
        return False

    def _close(self) -> None:
        self.closed = True
        self.window.destroy()

    def _clear_rows(self) -> None:
        child = self.list_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.list_box.remove(child)
            child = next_child

    def _set_loading(self, message: str) -> None:
        self.status_label.set_text(message)
        self.status_label.remove_css_class("error")
        self.refresh_button.set_sensitive(False)
        self.clear_button.set_sensitive(False)

    def _load(self) -> None:
        self._set_loading("Loading denial statistics.")
        self.load_statistics(self._loaded)
        if self.load_usage is not None:
            self.load_usage(self._usage_loaded)

    def _usage_loaded(
        self,
        usage: tuple[WebsiteUsageView, ...] | None,
        error: str | None,
    ) -> None:
        """Render the small per-rule allowance pane."""
        Gtk = self.Gtk
        child = self.usage_list_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.usage_list_box.remove(child)
            child = next_child
        if usage is None:
            row = Gtk.ListBoxRow()
            message = Gtk.Label(
                label=(
                    "Website start allowances could not be loaded."
                    + (f" {error}" if error else "")
                )
            )
            message.set_xalign(0)
            message.set_wrap(True)
            message.add_css_class("dim-label")
            row.set_child(message)
            self.usage_list_box.append(row)
            return
        if not usage:
            row = Gtk.ListBoxRow()
            message = Gtk.Label(
                label="No rule sets a daily start allowance yet."
            )
            message.set_xalign(0)
            message.set_wrap(True)
            message.add_css_class("dim-label")
            row.set_child(message)
            self.usage_list_box.append(row)
            return
        for item in usage:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=int(Space.COMPACT),
            )
            for method in (
                box.set_margin_top,
                box.set_margin_bottom,
                box.set_margin_start,
                box.set_margin_end,
            ):
                method(int(Space.SMALL))
            if item.allowance_starts is None:
                text = f"Used {item.count} allowed start(s) today (no limit)."
            else:
                text = (
                    f"Used {item.count} of {item.allowance_starts} "
                    "allowed start(s) today."
                )
            if item.budget_exhausted:
                text += " Blocking until the day resets."
            label = Gtk.Label(label=text)
            label.set_xalign(0)
            label.set_wrap(True)
            if item.budget_exhausted:
                label.add_css_class("warning")
            box.append(label)
            rules = Gtk.Label(label=f"Rule ID: {item.rule_id}")
            rules.set_xalign(0)
            rules.set_wrap(True)
            rules.set_selectable(True)
            rules.add_css_class("dim-label")
            box.append(rules)
            row.set_child(box)
            self.usage_list_box.append(row)

    def _loaded(
        self,
        statistics: DenialStatistics | None,
        error: str | None,
    ) -> None:
        if self.closed:
            return
        self.refresh_button.set_sensitive(True)
        if statistics is None:
            self.status_label.set_text(
                "Denial statistics could not be loaded."
                + (f" {error}" if error else "")
            )
            self.status_label.add_css_class("error")
            self.clear_button.set_sensitive(
                self.statistics is not None
                and bool(self.statistics.items or self.statistics.dropped)
            )
            if self.statistics is None:
                self.dropped_label.set_text("Dropped denial events: unavailable.")
                self.dropped_label.remove_css_class("warning")
                self.dropped_label.add_css_class("dim-label")
            return

        self.statistics = statistics
        self.status_label.remove_css_class("error")
        count = len(statistics.items)
        noun = "application" if count == 1 else "applications"
        self.status_label.set_text(f"Showing {count} denied {noun}.")
        if statistics.dropped:
            self.dropped_label.set_text(
                f"Dropped denial events: {statistics.dropped:,}. "
                "The event queue was full, so these events are not included."
            )
            self.dropped_label.remove_css_class("dim-label")
            self.dropped_label.add_css_class("warning")
        else:
            self.dropped_label.set_text("Dropped denial events: 0.")
            self.dropped_label.remove_css_class("warning")
            self.dropped_label.add_css_class("dim-label")
        self.clear_button.set_sensitive(
            bool(statistics.items or statistics.dropped)
        )
        self._render(statistics.items)

    def _render(self, items: Sequence[DenialStatView]) -> None:
        Gtk = self.Gtk
        self._clear_rows()
        if not items:
            row = Gtk.ListBoxRow()
            message = Gtk.Label(
                label=(
                    "No denied application launches have been recorded. "
                    "Use Refresh after the service denies an application."
                )
            )
            message.set_xalign(0)
            message.set_wrap(True)
            for method in (
                message.set_margin_top,
                message.set_margin_bottom,
                message.set_margin_start,
                message.set_margin_end,
            ):
                method(int(Space.MEDIUM))
            row.set_child(message)
            self.list_box.append(row)
            return

        for item in items:
            display = denial_stat_display(item)
            row = Gtk.ListBoxRow()
            box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=int(Space.COMPACT),
            )
            for method in (
                box.set_margin_top,
                box.set_margin_bottom,
                box.set_margin_start,
                box.set_margin_end,
            ):
                method(int(Space.SMALL))
            path = Gtk.Label(label=display.path)
            path.add_css_class("heading")
            path.add_css_class("monospace")
            path.set_xalign(0)
            path.set_wrap(True)
            path.set_selectable(True)
            box.append(path)
            count = Gtk.Label(label=f"Denied launches: {display.count}")
            count.set_xalign(0)
            box.append(count)
            times = Gtk.Label(
                label=(
                    f"First denied: {display.first_utc}\n"
                    f"Last denied: {display.last_utc}"
                )
            )
            times.set_xalign(0)
            times.set_selectable(True)
            times.add_css_class("dim-label")
            box.append(times)
            rules = Gtk.Label(label=f"Rule IDs: {display.rule_ids}")
            rules.set_xalign(0)
            rules.set_wrap(True)
            rules.set_selectable(True)
            rules.add_css_class("dim-label")
            box.append(rules)
            row.set_child(box)
            self.list_box.append(row)

    def _confirm_clear(self) -> None:
        if self.statistics is None or not (
            self.statistics.items or self.statistics.dropped
        ):
            return
        Gtk = self.Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text="Clear all denial statistics?",
            secondary_text=(
                "This deletes the recorded application counts and dropped-event "
                "count. It does not change rules or blocking decisions."
            ),
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Clear statistics", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)

        def respond(_dialog: object, response: int) -> None:
            dialog.destroy()
            if response != Gtk.ResponseType.ACCEPT:
                return
            self._set_loading("Clearing denial statistics.")
            self.clear_statistics(self._cleared)

        dialog.connect("response", respond)
        dialog.present()

    def _cleared(self, error: str | None) -> None:
        if self.closed:
            return
        if error is not None:
            self.refresh_button.set_sensitive(True)
            self.clear_button.set_sensitive(
                self.statistics is not None
                and bool(self.statistics.items or self.statistics.dropped)
            )
            self.status_label.set_text(
                f"Denial statistics could not be cleared. {error}"
            )
            self.status_label.add_css_class("error")
            return
        self._load()

    def present(self) -> None:
        self.window.present()
        self._load()


class DailyOverviewWindow:
    """Show enabled intervals for one day in the system time zone."""

    def __init__(
        self,
        Gtk: ModuleType,
        parent: object,
        local_day: date,
        timezone_name: str,
        intervals: Sequence[DailyInterval],
    ):
        self.Gtk = Gtk
        self.window = self._build(
            parent, local_day, timezone_name, tuple(intervals)
        )

    def _build(
        self,
        parent: object,
        local_day: date,
        timezone_name: str,
        intervals: tuple[DailyInterval, ...],
    ) -> object:
        Gtk = self.Gtk
        window = Gtk.Window(
            title="Daily overview", transient_for=parent, modal=True
        )
        window.set_default_size(620, 540)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM)
        )
        for method in (
            outer.set_margin_top,
            outer.set_margin_bottom,
            outer.set_margin_start,
            outer.set_margin_end,
        ):
            method(int(Space.LARGE))
        window.set_child(outer)
        heading = Gtk.Label(label="Daily overview")
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        date_label = Gtk.Label(
            label=f"{local_day.isoformat()} · System time zone: {timezone_name}"
        )
        date_label.set_xalign(0)
        date_label.add_css_class("dim-label")
        outer.append(date_label)
        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        list_box.add_css_class("boxed-list")
        scroller.set_child(list_box)
        outer.append(scroller)
        if not intervals:
            row = Gtk.ListBoxRow()
            message = Gtk.Label(
                label="No enabled rule intervals occur today."
            )
            message.set_xalign(0)
            for method in (
                message.set_margin_top,
                message.set_margin_bottom,
                message.set_margin_start,
                message.set_margin_end,
            ):
                method(int(Space.MEDIUM))
            row.set_child(message)
            list_box.append(row)
        for interval in intervals:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
            )
            for method in (
                box.set_margin_top,
                box.set_margin_bottom,
                box.set_margin_start,
                box.set_margin_end,
            ):
                method(int(Space.SMALL))
            name = Gtk.Label(label=interval.rule_name)
            name.add_css_class("heading")
            name.set_xalign(0)
            box.append(name)
            end_text = (
                "24:00"
                if interval.end_local.date() > local_day
                else interval.end_local.strftime("%H:%M")
            )
            times = Gtk.Label(
                label=f"{interval.start_local.strftime('%H:%M')} to {end_text}"
            )
            times.set_xalign(0)
            times.add_css_class("dim-label")
            box.append(times)
            row.set_child(box)
            list_box.append(row)
        close = Gtk.Button.new_with_mnemonic("_Close")
        close.set_halign(Gtk.Align.END)
        close.connect("clicked", lambda _button: window.destroy())
        outer.append(close)
        return window

    def present(self) -> None:
        self.window.present()


def run_gui(
    argv: Sequence[str] | None = None,
    client_factory: Callable[[], Client] = Client,
) -> int:
    """Run the native GTK application."""
    modules = load_gtk()
    application = modules.Gtk.Application(
        application_id="org.distraction_blocker.App",
        flags=modules.Gio.ApplicationFlags.DEFAULT_FLAGS,
    )
    controllers: list[GuiController] = []
    def activate(app: object) -> None:
        controller = GuiController(modules, app, client_factory())
        controllers.append(controller)
        controller.present()
    application.connect("activate", activate)
    arguments = ["distraction-blocker"]
    if argv is not None:
        arguments.extend(argv)
    return application.run(arguments)
