"""Native GTK 4 client and pure rule-form helpers.

GTK stays behind :func:`load_gtk`. The service command and pure helper tests do
not need the optional desktop binding.
"""

from __future__ import annotations

import importlib
import os
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from enum import IntEnum
from types import ModuleType
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import Rule, Schedule, Target, ValidationError
from .rpc import Client
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
    schedule_kind: str
    timezone: str
    one_time_start: str = ""
    one_time_end: str = ""
    weekdays: tuple[int, ...] = ()
    weekly_start: str = ""
    weekly_end: str = ""


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


def _local_to_utc(value: str, timezone_name: str) -> datetime:
    try:
        local_value = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M")
    except ValueError as error:
        raise FormError("Use YYYY-MM-DD HH:MM for each date.") from error
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
    if not targets:
        raise FormError("Add at least one website or application.")

    if form.schedule_kind == "one_time":
        if not form.one_time_start.strip() or not form.one_time_end.strip():
            raise FormError("Enter the start and end date.")
        schedule_data: dict[str, object] = {
            "kind": "one_time",
            "start_utc": _utc_text(_local_to_utc(form.one_time_start, form.timezone)),
            "end_utc": _utc_text(_local_to_utc(form.one_time_end, form.timezone)),
        }
    elif form.schedule_kind == "weekly":
        weekdays = sorted(set(form.weekdays))
        if not weekdays:
            raise FormError("Select at least one weekday.")
        if any(
            not isinstance(day, int) or isinstance(day, bool) or day not in range(7)
            for day in weekdays
        ):
            raise FormError("Select valid weekdays.")
        try:
            ZoneInfo(form.timezone)
        except ZoneInfoNotFoundError as error:
            raise FormError("Select a valid IANA time zone.") from error
        schedule_data = {
            "kind": "weekly",
            "timezone": form.timezone,
            "weekdays": weekdays,
            "start": _normalize_clock(form.weekly_start),
            "end": _normalize_clock(form.weekly_end),
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
            data["name"], websites, applications, kind, timezone_name,
            start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M")
        )
    if kind == "weekly":
        return RuleForm(
            data["name"], websites, applications, kind, schedule["timezone"],
            weekdays=tuple(schedule["weekdays"]),
            weekly_start=schedule["start"], weekly_end=schedule["end"]
        )
    return RuleForm(data["name"], websites, applications, kind, timezone_name)


def snapshot_from_results(
    status: Mapping[str, object], rule_items: Sequence[Mapping[str, object]]
) -> ServiceSnapshot:
    """Convert strict RPC results to GUI data."""
    if set(status) != {"healthy", "clock_trusted", "clock_reason", "active_targets"}:
        raise FormError("The service returned an invalid status.")
    active = status["active_targets"]
    if not isinstance(active, Mapping) or set(active) != {"website", "application"}:
        raise FormError("The service returned invalid active targets.")
    websites, applications = active["website"], active["application"]
    if not isinstance(websites, list) or not isinstance(applications, list):
        raise FormError("The service returned invalid active targets.")
    if not isinstance(status["healthy"], bool) or not isinstance(status["clock_trusted"], bool):
        raise FormError("The service returned an invalid status.")
    if not isinstance(status["clock_reason"], str):
        raise FormError("The service returned an invalid clock reason.")
    return ServiceSnapshot(
        status["healthy"], status["clock_trusted"], status["clock_reason"],
        len(websites), len(applications),
        tuple(Rule.from_dict(item) for item in rule_items),
    )


def _weekly_events(rule: Rule, now_utc: datetime) -> list[StateChange]:
    schedule = rule.to_dict()["schedule"]
    zone = ZoneInfo(schedule["timezone"])
    local_now = now_utc.astimezone(zone)
    start_time = time.fromisoformat(schedule["start"])
    end_time = time.fromisoformat(schedule["end"])
    candidates: set[datetime] = set()
    first_date = local_now.date() - timedelta(days=2)
    for offset in range(12):
        start_date = first_date + timedelta(days=offset)
        if start_date.weekday() not in set(schedule["weekdays"]):
            continue
        end_date = start_date if end_time > start_time else start_date + timedelta(days=1)
        for local_date, local_time in ((start_date, start_time), (end_date, end_time)):
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
        start, end = _parse_utc(schedule["start_utc"]), _parse_utc(schedule["end_utc"])
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
    days = ", ".join(WEEKDAY_LABELS[index][:3] for index in schedule["weekdays"])
    return f"Weekly: {days}, {schedule['start']} to {schedule['end']} ({schedule['timezone']})"


def _target_summary(rule: Rule) -> str:
    targets = rule.to_dict()["targets"]
    websites = sum(item["kind"] == "website" for item in targets)
    applications = sum(item["kind"] == "application" for item in targets)
    parts: list[str] = []
    if websites:
        parts.append(f"{websites} website" + ("s" if websites != 1 else ""))
    if applications:
        parts.append(f"{applications} application" + ("s" if applications != 1 else ""))
    return " and ".join(parts)


class GuiController:
    """Coordinate GTK widgets without a module-level GTK type."""

    def __init__(self, modules: GtkModules, application: object, client: Client):
        self.Gtk, self.Gio, self.GLib = modules.Gtk, modules.Gio, modules.GLib
        self.application, self.client = application, client
        self.snapshot: ServiceSnapshot | None = None
        self.timezone = system_timezone_name()
        self.window = self._build_window()

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
        self.add_button = Gtk.Button.new_with_mnemonic("_Add rule")
        self.add_button.add_css_class("suggested-action")
        self.add_button.connect("clicked", lambda _button: self.open_editor())
        rule_header.append(self.add_button)
        root.append(rule_header)
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

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.set_sensitive(not busy)
        self.add_button.set_sensitive(not busy)
        if busy:
            self.notice_label.set_text("Loading service state.")
            self.notice_label.remove_css_class("error")

    def refresh(self) -> None:
        self._set_busy(True)
        def request_snapshot() -> None:
            try:
                status = self.client.request("status")
                rules = self.client.request("list_rules")
                if not isinstance(status, Mapping) or not isinstance(rules, list):
                    raise FormError("The service returned invalid data.")
                snapshot = snapshot_from_results(status, rules)
            except Exception as error:
                self.GLib.idle_add(self._show_request_error, str(error))
            else:
                self.GLib.idle_add(self._show_snapshot, snapshot)
        threading.Thread(target=request_snapshot, daemon=True).start()

    def _show_request_error(self, detail: str) -> bool:
        self._set_busy(False)
        self.health_label.set_text("Unavailable")
        self.health_label.add_css_class("error")
        self.clock_label.set_text("The clock state is not available.")
        self.active_label.set_text("")
        self.notice_label.set_text("The service did not respond." + (f" {detail}" if detail else ""))
        self.notice_label.add_css_class("error")
        return False

    def _show_snapshot(self, snapshot: ServiceSnapshot) -> bool:
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
        self._render_rules(snapshot)
        return False

    def _clear_rules(self) -> None:
        child = self.rule_list.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.rule_list.remove(child)
            child = next_child

    def _render_rules(self, snapshot: ServiceSnapshot) -> None:
        Gtk = self.Gtk
        self._clear_rules()
        if not snapshot.rules:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT))
            for method in (box.set_margin_top, box.set_margin_bottom,
                           box.set_margin_start, box.set_margin_end):
                method(int(Space.MEDIUM))
            title = Gtk.Label(label="No rules")
            title.add_css_class("heading")
            title.set_xalign(0)
            message = Gtk.Label(label="Add a rule to block a website or application.")
            message.set_xalign(0)
            box.append(title)
            box.append(message)
            row.set_child(box)
            self.rule_list.append(row)
            return
        now_utc = datetime.now(UTC)
        for rule in snapshot.rules:
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

    def _set_enabled(self, rule: Rule, enabled: bool) -> None:
        data = rule.to_dict()
        try:
            self.client.request("set_enabled", rule_id=data["id"], enabled=enabled)
        except Exception as error:
            self.notice_label.set_text(self._rpc_error(error))
            self.notice_label.add_css_class("error")
        else:
            self.refresh()

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
            try:
                self.client.request("delete_rule", rule_id=data["id"])
            except Exception as error:
                self.notice_label.set_text(self._rpc_error(error))
                self.notice_label.add_css_class("error")
            else:
                self.refresh()
        dialog.connect("response", respond)
        dialog.present()

    def _save_form(self, form: RuleForm, existing: Rule | None) -> str | None:
        try:
            self.client.request("put_rule", **form_to_request(form, existing))
        except (FormError, ValidationError, ValueError) as error:
            return str(error)
        except Exception as error:
            return self._rpc_error(error)
        self.refresh()
        return None

    def open_editor(self, rule: Rule | None = None) -> None:
        RuleEditor(
            GtkModules(self.Gtk, self.Gio, self.GLib), self.window, self.timezone,
            rule, self._save_form
        ).present()


class RuleEditor:
    """Native add and edit window for all schedule forms."""

    def __init__(self, modules: GtkModules, parent: object, timezone_name: str,
                 existing: Rule | None,
                 save: Callable[[RuleForm, Rule | None], str | None]):
        self.Gtk = modules.Gtk
        if (
            existing is not None
            and existing.schedule.kind == "weekly"
            and existing.schedule.timezone_name is not None
        ):
            timezone_name = existing.schedule.timezone_name
        self.parent, self.timezone_name = parent, timezone_name
        self.existing, self.save = existing, save
        self.application_paths: list[str] = []
        self.window = self._build()
        if existing is not None:
            self._populate(rule_to_form(existing, self.timezone_name))

    def _new_entry(self, placeholder: str = "") -> object:
        entry = self.Gtk.Entry()
        entry.set_hexpand(True)
        entry.set_placeholder_text(placeholder)
        entry.connect("activate", lambda _entry: self._submit())
        return entry

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
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.MEDIUM))
        for method in (outer.set_margin_top, outer.set_margin_bottom,
                       outer.set_margin_start, outer.set_margin_end):
            method(int(Space.LARGE))
        scroller.set_child(outer)
        heading = Gtk.Label(label=title)
        heading.add_css_class("title-2")
        heading.set_xalign(0)
        outer.append(heading)
        self.name_entry = self._new_entry("Study time")
        outer.append(self._label_for("Rule _name", self.name_entry))
        outer.append(self.name_entry)
        target_heading = Gtk.Label(label="Targets")
        target_heading.add_css_class("heading")
        target_heading.set_xalign(0)
        outer.append(target_heading)
        self.website_view = Gtk.TextView()
        self.website_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        website_scroller = Gtk.ScrolledWindow()
        website_scroller.set_min_content_height(84)
        website_scroller.set_child(self.website_view)
        outer.append(self._label_for("_Websites, one domain per line", self.website_view))
        outer.append(website_scroller)
        app_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
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
        one_time = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL))
        self.one_start = self._new_entry("2026-08-14 09:00")
        self.one_end = self._new_entry("2026-08-14 17:00")
        one_time.append(self._label_for("_Start (YYYY-MM-DD HH:MM)", self.one_start))
        one_time.append(self.one_start)
        one_time.append(self._label_for("_End (YYYY-MM-DD HH:MM)", self.one_end))
        one_time.append(self.one_end)
        self.schedule_stack.add_named(one_time, "one_time")
        weekly = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.SMALL))
        grid = Gtk.Grid()
        grid.set_row_spacing(int(Space.COMPACT))
        grid.set_column_spacing(int(Space.SMALL))
        self.weekday_checks: list[object] = []
        for index, label in enumerate(WEEKDAY_LABELS):
            check = Gtk.CheckButton(label=label)
            grid.attach(check, index % 4, index // 4, 1, 1)
            self.weekday_checks.append(check)
        weekly.append(grid)
        times = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
        start_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT))
        self.weekly_start = self._new_entry("09:00")
        start_box.append(self._label_for("Weekly _start (HH:MM)", self.weekly_start))
        start_box.append(self.weekly_start)
        times.append(start_box)
        end_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=int(Space.COMPACT))
        self.weekly_end = self._new_entry("17:00")
        end_box.append(self._label_for("Weekly _end (HH:MM)", self.weekly_end))
        end_box.append(self.weekly_end)
        times.append(end_box)
        weekly.append(times)
        note = Gtk.Label(label="If the end is not after the start, the rule ends on the next day.")
        note.set_xalign(0)
        note.set_wrap(True)
        note.add_css_class("dim-label")
        weekly.append(note)
        self.schedule_stack.add_named(weekly, "weekly")
        indefinite = Gtk.Label(label="This rule stays active until you disable it.")
        indefinite.set_xalign(0)
        indefinite.set_wrap(True)
        self.schedule_stack.add_named(indefinite, "indefinite")
        self.schedule_stack.set_visible_child_name("one_time")
        self.error_label = Gtk.Label(label="")
        self.error_label.set_xalign(0)
        self.error_label.set_wrap(True)
        self.error_label.add_css_class("error")
        outer.append(self.error_label)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
        actions.set_halign(Gtk.Align.END)
        cancel = Gtk.Button.new_with_mnemonic("_Cancel")
        cancel.connect("clicked", lambda _button: window.destroy())
        actions.append(cancel)
        save = Gtk.Button.new_with_mnemonic("_Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", lambda _button: self._submit())
        actions.append(save)
        outer.append(actions)
        window.set_default_widget(save)
        return window

    def _schedule_changed(self, dropdown: object, _parameter: object) -> None:
        selected = dropdown.get_selected()
        if selected < len(SCHEDULE_KINDS):
            self.schedule_stack.set_visible_child_name(SCHEDULE_KINDS[selected])

    def _choose_application(self) -> None:
        Gtk = self.Gtk
        chooser = Gtk.FileChooserNative.new(
            "Select an executable", self.window, Gtk.FileChooserAction.OPEN,
            "_Select", "_Cancel"
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
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=int(Space.SMALL))
            for method in (box.set_margin_top, box.set_margin_bottom,
                           box.set_margin_start, box.set_margin_end):
                method(int(Space.COMPACT))
            label = Gtk.Label(label=path)
            label.set_xalign(0)
            label.set_ellipsize(3)
            label.set_hexpand(True)
            box.append(label)
            remove = Gtk.Button.new_with_mnemonic("_Remove")
            remove.set_tooltip_text(f"Remove {path}")
            remove.connect("clicked", lambda _button, item=path: self._remove_application(item))
            box.append(remove)
            row.set_child(box)
            self.application_list.append(row)

    def _remove_application(self, path: str) -> None:
        self.application_paths.remove(path)
        self._render_applications()

    def _website_lines(self) -> tuple[str, ...]:
        buffer = self.website_view.get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        return tuple(line.strip() for line in text.splitlines() if line.strip())

    def _form(self) -> RuleForm:
        selected = self.schedule_dropdown.get_selected()
        if selected >= len(SCHEDULE_KINDS):
            raise FormError("Select a valid schedule type.")
        return RuleForm(
            self.name_entry.get_text(), self._website_lines(), tuple(self.application_paths),
            SCHEDULE_KINDS[selected], self.timezone_name,
            self.one_start.get_text(), self.one_end.get_text(),
            tuple(index for index, check in enumerate(self.weekday_checks) if check.get_active()),
            self.weekly_start.get_text(), self.weekly_end.get_text()
        )

    def _submit(self) -> None:
        try:
            form = self._form()
        except FormError as error:
            self.error_label.set_text(str(error))
            return
        message = self.save(form, self.existing)
        if message is None:
            self.window.destroy()
        else:
            self.error_label.set_text(message)

    def _populate(self, form: RuleForm) -> None:
        self.name_entry.set_text(form.name)
        self.website_view.get_buffer().set_text("\n".join(form.websites))
        self.application_paths = list(form.applications)
        self._render_applications()
        selected = SCHEDULE_KINDS.index(form.schedule_kind)
        self.schedule_dropdown.set_selected(selected)
        self.schedule_stack.set_visible_child_name(form.schedule_kind)
        self.one_start.set_text(form.one_time_start)
        self.one_end.set_text(form.one_time_end)
        for index, check in enumerate(self.weekday_checks):
            check.set_active(index in form.weekdays)
        self.weekly_start.set_text(form.weekly_start)
        self.weekly_end.set_text(form.weekly_end)

    def present(self) -> None:
        self.window.present()
        self.name_entry.grab_focus()


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
