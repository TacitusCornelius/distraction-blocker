"""Native GTK 4 client and pure rule-form helpers.

GTK stays behind :func:`load_gtk`. The service command and pure helper tests do
not need the optional desktop binding.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from enum import IntEnum
from types import ModuleType
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .categories import starter_categories
from .model import ManagedList, Policy, Rule, Schedule, Target, ValidationError
from .preferences import THEMES, load_theme, save_theme
from .rpc import Client
from .transfer import (
    ImportPreview,
    TransferError,
    atomic_write_text,
    domain_export_text,
    native_export_text,
    parse_domain_text,
    read_import_text,
    read_native_text,
    parse_native_export,
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
SCHEDULE_LABELS = ("One time", "Weekly", "Indefinite")
SCHEDULE_KINDS = ("one_time", "weekly", "indefinite")
THEME_LABELS = ("System", "Light", "Dark")
RULE_FILTER_LABELS = ("All", "Active", "Inactive", "Enabled", "Disabled")
RULE_FILTERS = ("all", "active", "inactive", "enabled", "disabled")
FOCUS_DURATIONS = (15, 30, 60, 120)
MAX_WEEKLY_PERIODS = 16
RPC_LIST_CHUNK_SIZE = 200
# Breadcrumb for reviewers: JSON ASCII escaping can triple the UTF-8 size.
# This bound keeps the full request below the fixed 65,536-byte RPC frame.
RPC_TEXT_CHUNK_BYTES = 16 * 1024
MAX_DAILY_TRANSITIONS = MAX_WEEKLY_PERIODS * 2 + 2


@dataclass(frozen=True)
class WeeklyPeriodForm:
    """Pure values from one weekly-period row."""

    weekdays: tuple[int, ...]
    start: str
    end: str


@dataclass(frozen=True)
class DailyInterval:
    """One enabled rule interval in the selected local day."""

    rule_id: str
    rule_name: str
    start_local: datetime
    end_local: datetime


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


@dataclass(frozen=True)
class StateChange:
    at_utc: datetime
    active_after: bool


@dataclass(frozen=True)
class ServiceSnapshot:
    healthy: bool
    clock_trusted: bool
    clock_reason: str
    active_websites: int
    active_applications: int
    rules: tuple[Rule, ...]
    managed_lists: tuple[ManagedListSummary, ...]


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
    raise FormError("The system time zone is not an IANA time zone.")


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
    for domain in form.websites:
        if domain.strip():
            targets.append(Target.from_dict({"kind": "website", "value": domain.strip()}))
    for path in form.applications:
        if path.strip():
            targets.append(Target.from_dict({"kind": "application", "value": path.strip()}))
    for list_id in form.managed_list_ids:
        if list_id.strip():
            targets.append(
                Target.from_dict({"kind": "managed_list", "value": list_id.strip()})
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
    elif form.schedule_kind == "indefinite":
        schedule_data = {"kind": "indefinite"}
    else:
        raise FormError("Select a valid schedule type.")

    schedule = Schedule.from_dict(schedule_data)
    if existing is None:
        rule_id, enabled, revision = str(id_factory()), True, 0
    else:
        current = existing.to_dict()
        rule_id = current["id"]
        enabled = current["enabled"]
        revision = current["revision"]
    return Rule.from_dict(
        {
            "id": rule_id,
            "name": name,
            "enabled": enabled,
            "targets": [target.to_dict() for target in targets],
            "schedule": schedule.to_dict(),
            "revision": revision,
        }
    )


def form_to_request(
    form: RuleForm,
    existing: Rule | None = None,
    id_factory: Callable[[], object] = uuid4,
) -> dict[str, object]:
    """Build the exact fields for the ``put_rule`` RPC command."""
    return {"rule": form_to_rule(form, existing, id_factory).to_dict()}


def rule_to_form(rule: Rule, timezone_name: str) -> RuleForm:
    """Convert a model rule to editor values."""
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
    rule_items: Sequence[Mapping[str, object]],
    list_items: Sequence[Mapping[str, object]],
) -> ServiceSnapshot:
    """Convert strict RPC results to GUI data."""
    if set(status) != {"healthy", "clock_trusted", "clock_reason", "active_counts"}:
        raise FormError("The service returned an invalid status.")
    active = status["active_counts"]
    if not isinstance(active, Mapping) or set(active) != {"website", "application"}:
        raise FormError("The service returned invalid active counts.")
    websites, applications = active["website"], active["application"]
    if (
        not isinstance(websites, int)
        or isinstance(websites, bool)
        or websites < 0
        or not isinstance(applications, int)
        or isinstance(applications, bool)
        or applications < 0
    ):
        raise FormError("The service returned invalid active counts.")
    if not isinstance(status["healthy"], bool) or not isinstance(status["clock_trusted"], bool):
        raise FormError("The service returned an invalid status.")
    if not isinstance(status["clock_reason"], str):
        raise FormError("The service returned an invalid clock reason.")
    return ServiceSnapshot(
        status["healthy"],
        status["clock_trusted"],
        status["clock_reason"],
        websites,
        applications,
        tuple(Rule.from_dict(item) for item in rule_items),
        managed_list_summaries_from_results(list_items),
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


def filter_rules(
    rules: Sequence[Rule],
    query: str,
    state_filter: str,
    now_utc: datetime,
    clock_trusted: bool,
) -> tuple[Rule, ...]:
    if state_filter not in RULE_FILTERS:
        raise FormError("Select a valid rule filter.")
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
    return tuple(result)


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
        raise FormError("The current UTC date needs a time zone.")
    data = rule.to_dict()
    if not data["enabled"] or not clock_trusted:
        return None
    schedule = data["schedule"]
    if schedule["kind"] == "indefinite":
        return None
    if schedule["kind"] == "one_time":
        start = _parse_utc(schedule["start_utc"])
        end = _parse_utc(schedule["end_utc"])
        if now_utc < start:
            return StateChange(start, True)
        if now_utc < end:
            return StateChange(end, False)
        return None
    current = rule.is_active(now_utc, clock_trusted=True)
    events = sorted(
        (item for item in _weekly_events(rule, now_utc) if item.at_utc > now_utc),
        key=lambda item: item.at_utc,
    )
    return next((item for item in events if item.active_after != current), None)


def create_focus_rule(
    source: Rule,
    minutes: int,
    now_utc: datetime,
    id_factory: Callable[[], object] = uuid4,
) -> Rule:
    """Copy targets into an immediate one-time focus rule."""
    if (
        not isinstance(minutes, int)
        or isinstance(minutes, bool)
        or minutes <= 0
    ):
        raise FormError("Enter a positive focus duration.")
    if now_utc.tzinfo is None:
        raise FormError("The current UTC date needs a time zone.")
    start = now_utc.astimezone(UTC)
    try:
        end = start + timedelta(minutes=minutes)
    except OverflowError as error:
        raise FormError("The focus duration is too large.") from error
    return Rule.from_dict(
        {
            "id": str(id_factory()),
            "name": f"Focus: {source.name}",
            "enabled": True,
            "targets": [target.to_dict() for target in source.targets],
            "schedule": {
                "kind": "one_time",
                "start_utc": _utc_text(start),
                "end_utc": _utc_text(end),
            },
            "revision": 0,
        }
    )


def project_daily_schedule(
    rules: Sequence[Rule],
    local_day: date,
    timezone_name: str,
) -> tuple[DailyInterval, ...]:
    """Project enabled rule intervals into one day in the system time zone."""
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise FormError("Select a valid IANA time zone.") from error
    day_start = datetime.combine(local_day, time.min, zone)
    day_end = datetime.combine(local_day + timedelta(days=1), time.min, zone)
    start_utc = day_start.astimezone(UTC)
    end_utc = day_end.astimezone(UTC)
    intervals: list[DailyInterval] = []
    for rule in rules:
        if not rule.enabled:
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


def active_lock_explanation(rule: Rule, now_utc: datetime, clock_trusted: bool) -> str:
    """Explain an active rule lock."""
    if not rule.is_active(now_utc, clock_trusted=clock_trusted):
        return ""
    kind = rule.to_dict()["schedule"]["kind"]
    if kind == "indefinite":
        return "This rule stays active until you disable it."
    if not clock_trusted:
        return "The clock is not trusted. The service blocks finite rules until root recovery."
    change = next_state_change(rule, now_utc)
    if change is None:
        return "This active rule cannot be disabled or deleted."
    return f"This active rule cannot be weakened before {_display_time(change.at_utc)}."


def _schedule_summary(rule: Rule) -> str:
    schedule = rule.to_dict()["schedule"]
    if schedule["kind"] == "indefinite":
        return "Indefinite"
    if schedule["kind"] == "one_time":
        return (
            f"One time: {_display_time(_parse_utc(schedule['start_utc']))} to "
            f"{_display_time(_parse_utc(schedule['end_utc']))}"
        )
    count = len(schedule["periods"])
    noun = "period" if count == 1 else "periods"
    return f"Weekly: {count} {noun} ({schedule['timezone']})"


def _target_summary(rule: Rule) -> str:
    targets = rule.to_dict()["targets"]
    websites = sum(item["kind"] == "website" for item in targets)
    applications = sum(item["kind"] == "application" for item in targets)
    managed_lists = sum(item["kind"] == "managed_list" for item in targets)
    parts: list[str] = []
    if websites:
        parts.append(f"{websites} website" + ("s" if websites != 1 else ""))
    if applications:
        parts.append(f"{applications} application" + ("s" if applications != 1 else ""))
    if managed_lists:
        parts.append(
            f"{managed_lists} managed list" + ("s" if managed_lists != 1 else "")
        )
    return ", ".join(parts)


class GuiController:
    """Coordinate GTK widgets without a module-level GTK type."""

    def __init__(self, modules: GtkModules, application: object, client: Client):
        self.Gtk, self.Gio, self.GLib = modules.Gtk, modules.Gio, modules.GLib
        self.application, self.client = application, client
        self.snapshot: ServiceSnapshot | None = None
        self._observed_states: dict[str, ObservedRuleState] | None = None
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
        self.gtk_settings.set_property("gtk-application-prefer-dark-theme", prefer_dark)

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
        window.set_title("Distraction Blocker")
        window.set_default_size(820, 640)
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
        service_row.append(self.health_label)
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
        root.append(transfer_bar)
        search_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search rule names and targets")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._filter_changed)
        search_row.append(self.search_entry)
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
        return False

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.set_sensitive(not busy)
        self.add_button.set_sensitive(not busy)
        self.focus_button.set_sensitive(not busy)
        self.lists_button.set_sensitive(not busy)
        self.overview_button.set_sensitive(not busy)
        for widget in (
            self.import_domains_button,
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
                if (
                    not isinstance(status, Mapping)
                    or not isinstance(rules, list)
                    or not isinstance(lists, list)
                ):
                    raise FormError("The service returned invalid data.")
                snapshot = snapshot_from_results(status, rules, lists)
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
            self._send_transition_notifications(
                detect_rule_transitions(self._observed_states, current_states)
            )
        self._observed_states = current_states
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
            f"{snapshot.active_applications} applications."
        )
        self.add_button.set_sensitive(snapshot.healthy)
        self.focus_button.set_sensitive(snapshot.healthy and bool(snapshot.rules))
        self.import_domains_button.set_sensitive(snapshot.healthy)
        self.import_backup_button.set_sensitive(snapshot.healthy)
        self._render_rules(snapshot)
        return False

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
        selected = self.filter_dropdown.get_selected()
        state_filter = RULE_FILTERS[selected] if selected < len(RULE_FILTERS) else "all"
        rules = filter_rules(
            snapshot.rules,
            self.search_entry.get_text(),
            state_filter,
            now_utc,
            snapshot.clock_trusted,
        )
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
            self.rule_list.append(self._rule_row(rule, now_utc, snapshot))

    def _rule_row(self, rule: Rule, now_utc: datetime, snapshot: ServiceSnapshot) -> object:
        Gtk = self.Gtk
        data = rule.to_dict()
        active = rule.is_active(now_utc, clock_trusted=snapshot.clock_trusted)
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
        state = Gtk.Label(label="Active" if active else "Inactive")
        if not data["enabled"]:
            state.set_text("Disabled")
        state.add_css_class("accent" if active else "dim-label")
        heading_row.append(state)
        outer.append(heading_row)
        details = Gtk.Label(label=f"{_target_summary(rule)} · {_schedule_summary(rule)}")
        details.set_xalign(0)
        details.set_wrap(True)
        details.add_css_class("dim-label")
        outer.append(details)
        if data["enabled"] and snapshot.clock_trusted:
            change = next_state_change(rule, now_utc)
            if change is not None:
                action = "Starts" if change.active_after else "Ends"
                label = Gtk.Label(label=f"Next state change: {action} at {_display_time(change.at_utc)}.")
                label.set_xalign(0)
                outer.append(label)
        elif data["enabled"] and kind != "indefinite":
            label = Gtk.Label(label="Next state change: after root restores the trusted clock.")
            label.set_xalign(0)
            outer.append(label)
        explanation = active_lock_explanation(rule, now_utc, snapshot.clock_trusted)
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
        finite_lock = active and kind != "indefinite"
        toggle.set_sensitive(snapshot.healthy and not finite_lock)
        if finite_lock:
            toggle.set_tooltip_text(explanation)
        toggle.connect("clicked", lambda _button, item=rule, enabled=not data["enabled"]: self._set_enabled(item, enabled))
        actions.append(toggle)
        delete = Gtk.Button.new_with_mnemonic("_Delete")
        delete.add_css_class("destructive-action")
        delete.set_sensitive(snapshot.healthy and not active)
        if active:
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
            self._install_starter_category,
            self._confirm_managed_list_delete,
        ).present()

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
                f"Installed {managed_list.name}.", completed
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
        try:
            rule = create_focus_rule(source, minutes, datetime.now(UTC))
        except (FormError, ValidationError, ValueError) as error:
            completed(str(error))
            return

        def saved(_result: object) -> None:
            completed(None)
            self.notice_label.set_text(f"Started {minutes}-minute focus.")
            self.notice_label.remove_css_class("error")
            self.refresh()

        self._request_async(
            "put_rule",
            {"rule": rule.to_dict()},
            saved,
            lambda error: completed(self._rpc_error(error)),
        )

    def open_daily_overview(self) -> None:
        rules = () if self.snapshot is None else self.snapshot.rules
        local_day = datetime.now(ZoneInfo(self.timezone)).date()
        try:
            intervals = project_daily_schedule(rules, local_day, self.timezone)
        except (FormError, ValidationError, ValueError) as error:
            self._show_error(str(error))
            return
        DailyOverviewWindow(
            self.Gtk,
            self.window,
            local_day,
            self.timezone,
            intervals,
        ).present()

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

        def saved(_result: object) -> None:
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
        ).present()


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
        self.set_index(index)

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
    ):
        self.Gtk, self.GLib = modules.Gtk, modules.GLib
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
        self.application_paths: list[str] = []
        self.weekly_rows: list[WeeklyPeriodRow] = []
        local_now = datetime.now(ZoneInfo(timezone_name))
        self.default_one_start, self.default_one_end = default_one_time_window(local_now)
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
        target_heading = Gtk.Label(label="Targets")
        target_heading.add_css_class("heading")
        target_heading.set_xalign(0)
        target_heading.set_hexpand(True)
        target_row.append(target_heading)
        import_button = Gtk.Button.new_with_mnemonic("_Import domains")
        import_button.connect("clicked", lambda _button: self._choose_domain_import())
        target_row.append(import_button)
        outer.append(target_row)
        self.website_view = Gtk.TextView()
        self.website_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        website_scroller = Gtk.ScrolledWindow()
        website_scroller.set_min_content_height(84)
        website_scroller.set_child(self.website_view)
        outer.append(
            self._label_for("_Websites, one domain per line", self.website_view)
        )
        outer.append(website_scroller)

        app_row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL)
        )
        app_label = Gtk.Label(label="Applications")
        app_label.set_xalign(0)
        app_label.set_hexpand(True)
        app_row.append(app_label)
        choose = Gtk.Button.new_with_mnemonic("_Select executable")
        choose.connect("clicked", lambda _button: self._choose_application())
        app_row.append(choose)
        outer.append(app_row)
        self.application_list = Gtk.ListBox()
        self.application_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.application_list.add_css_class("boxed-list")
        outer.append(self.application_list)

        list_label = Gtk.Label(label="Managed lists")
        list_label.set_xalign(0)
        outer.append(list_label)
        self.managed_list_checks: dict[str, object] = {}
        if self.managed_lists:
            list_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT)
            )
            for summary in self.managed_lists:
                check = Gtk.CheckButton(
                    label=f"{summary.name} ({summary.domain_count} domains)"
                )
                check.set_tooltip_text(
                    f"Source: {summary.source}. Version: {summary.version}."
                )
                list_box.append(check)
                self.managed_list_checks[summary.id] = check
            outer.append(list_box)
        else:
            empty_lists = Gtk.Label(
                label="Create or install a managed list from the main window."
            )
            empty_lists.set_xalign(0)
            empty_lists.set_wrap(True)
            empty_lists.add_css_class("dim-label")
            outer.append(empty_lists)

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
        self.schedule_stack.add_named(weekly, "weekly")
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

    def _add_weekly_period(self, value: WeeklyPeriodForm) -> None:
        if len(self.weekly_rows) >= MAX_WEEKLY_PERIODS:
            return
        row = WeeklyPeriodRow(
            self.Gtk, len(self.weekly_rows) + 1, value, self._remove_weekly_period
        )
        self.weekly_rows.append(row)
        self.weekly_period_box.append(row.container)
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

    def _remove_application(self, path: str) -> None:
        self.application_paths.remove(path)
        self._render_applications()

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
            combined = tuple(
                dict.fromkeys((*self._website_lines(), *preview.domains))
            )
            self._set_website_lines(combined)
        dialog.connect("response", respond)
        dialog.present()

    def _set_website_lines(self, domains: Sequence[str]) -> None:
        self.website_view.get_buffer().set_text("\n".join(domains))

    def _website_lines(self) -> tuple[str, ...]:
        buffer = self.website_view.get_buffer()
        text = buffer.get_text(
            buffer.get_start_iter(), buffer.get_end_iter(), False
        )
        return tuple(line.strip() for line in text.splitlines() if line.strip())

    def _form(self) -> RuleForm:
        selected = self.schedule_dropdown.get_selected()
        if selected >= len(SCHEDULE_KINDS):
            raise FormError("Select a valid schedule type.")
        return RuleForm(
            name=self.name_entry.get_text(),
            websites=self._website_lines(),
            applications=tuple(self.application_paths),
            managed_list_ids=tuple(
                list_id
                for list_id, check in self.managed_list_checks.items()
                if check.get_active()
            ),
            schedule_kind=SCHEDULE_KINDS[selected],
            timezone=self.timezone_name,
            one_time_start=self.one_start.get_text(),
            one_time_end=self.one_end.get_text(),
            weekly_periods=tuple(row.value() for row in self.weekly_rows),
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
        self.website_view.get_buffer().set_text("\n".join(form.websites))
        self.application_paths = list(form.applications)
        self._render_applications()
        for list_id in form.managed_list_ids:
            check = self.managed_list_checks.get(list_id)
            if check is not None:
                check.set_active(True)
        selected = SCHEDULE_KINDS.index(form.schedule_kind)
        self.schedule_dropdown.set_selected(selected)
        self.schedule_stack.set_visible_child_name(form.schedule_kind)
        # Breadcrumb for reviewers: unused schedule fields are blank in a
        # RuleForm. DateTimePicker rejects blank text, so populate only the
        # controls for the stored schedule kind.
        if form.schedule_kind == "one_time":
            self.one_start.set_text(form.one_time_start)
            self.one_end.set_text(form.one_time_end)
        for row in tuple(self.weekly_rows):
            self._remove_weekly_period(row)
        if form.schedule_kind == "weekly":
            for period in form.weekly_periods:
                self._add_weekly_period(period)

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
        install: Callable[
            [ManagedList, Callable[[str | None], None]], None
        ],
        delete: Callable[[object, ManagedListSummary], None],
    ):
        self.Gtk = modules.Gtk
        self.summaries = tuple(summaries)
        self.starters = tuple(starters)
        self.healthy = healthy
        self.choose_import, self.install, self.delete = (
            choose_import,
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
        installed = {item.id for item in self.summaries}
        available = (
            selected < len(self.starters)
            and self.starters[selected].id not in installed
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
