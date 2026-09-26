from __future__ import annotations

import os
import subprocess
import sys
import unittest
from datetime import UTC, date, datetime
from uuid import UUID

from distraction_blocker.gui import (
    _rule_state_text,
    _schedule_summary,
    _state_change_action,
    AuthorizationChallenge,
    AuthorizationGrant,
    DenialStatView,
    DenialStatDisplay,
    DenialStatistics,
    FormError,
    GtkUnavailableError,
    LockSummary,
    ManagedListSummary,
    ObservedRuleState,
    RuleEditor,
    RuleForm,
    PeriodAllowanceForm,
    WeeklyPeriodForm,
    authorization_challenge_from_result,
    authorization_grant_from_result,
    begin_rule_authorization_request,
    active_lock_explanation,
    complete_rule_authorization_request,
    default_one_time_window,
    daily_schedule_from_result,
    denial_stat_display,
    denial_statistics_from_result,
    detect_rule_transitions,
    duplicate_rule,
    filter_rules,
    sort_rules,
    form_to_request,
    form_to_rule,
    _target_summary,
    delay_lock_request,
    request_delay_break_request,
    cancel_delay_break_request,
    friction_lock_request,
    schedule_lock_request,
    import_preview_text,
    load_gtk,
    lock_summaries_from_results,
    lock_summary_text,
    managed_list_import_metadata,
    managed_list_summaries_from_results,
    password_lock_request,
    remove_rule_lock_request,
    next_state_change,
    picker_datetime_text,
    picker_text_to_datetime,
    project_daily_schedule,
    rule_to_form,
    snapshot_from_results,
    timed_lock_request,
    staged_list_upload_calls,
    staged_native_upload_calls,
    utf8_text_chunks,
)
from distraction_blocker.model import (
    POLICY_SCHEMA_VERSION,
    ManagedList,
    Rule,
    Target,
)
from distraction_blocker.transfer import (
    ImportIssue,
    ImportPreview,
    TargetListPreview,
)


RULE_ID = "12345678-1234-5678-1234-567812345678"
LIST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SECOND_RULE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def make_rule(
    *,
    rule_id: str = RULE_ID,
    name: str = "Focus",
    enabled: bool = True,
    targets: list[dict[str, str]] | None = None,
    exceptions: list[dict[str, str]] | None = None,
    schedule: dict[str, object] | None = None,
    revision: int = 0,
    allowance_starts: int | None = None,
) -> Rule:
    data = {
        "id": rule_id,
        "name": name,
        "enabled": enabled,
        "targets": targets
        or (
            [{"kind": "url_path", "value": "example.com/feed"}]
            if allowance_starts is not None
            else [{"kind": "website", "value": "example.com"}]
        ),
        "schedule": schedule or {"kind": "indefinite"},
        "revision": revision,
    }
    if exceptions is not None:
        data["exceptions"] = exceptions
    if allowance_starts is not None:
        data["allowance_starts"] = allowance_starts
    return Rule.from_dict(data)

def policy_result(
    rules: tuple[dict[str, object], ...] = (),
    *,
    revision: int = 0,
) -> dict[str, object]:
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "revision": revision,
        "rules": [
            {**rule, "budget_exhausted": rule.get("budget_exhausted", False)}
            for rule in rules
        ],
    }


class GtkLoadingTests(unittest.TestCase):
    def test_missing_binding_has_clear_error(self) -> None:
        def missing(_name: str):
            raise ModuleNotFoundError("No module named 'gi'")

        with self.assertRaisesRegex(
            GtkUnavailableError, "GTK 4 Python bindings are not installed"
        ):
            load_gtk(missing)

    def test_gui_module_import_does_not_load_gtk(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import distraction_blocker.gui; "
                "raise SystemExit('gi' in sys.modules)",
            ],
            cwd=os.getcwd(),
            check=False,
        )
        self.assertEqual(result.returncode, 0)


class FormConversionTests(unittest.TestCase):
    def test_one_time_form_converts_local_dates_to_utc(self) -> None:
        form = RuleForm(
            name="  Focus  ",
            websites=("Exämple.COM.",),
            applications=("/usr/bin/python3",),
            managed_list_ids=(),
            schedule_kind="one_time",
            timezone="America/New_York",
            one_time_start="2026-01-12 09:00",
            one_time_end="2026-01-12 10:30",
        )

        fields = form_to_request(form, id_factory=lambda: UUID(RULE_ID))

        self.assertEqual(set(fields), {"rule"})
        rule = fields["rule"]
        self.assertEqual(rule["id"], RULE_ID)
        self.assertEqual(rule["name"], "Focus")
        self.assertTrue(rule["enabled"])
        self.assertEqual(
            rule["targets"],
            [
                {"kind": "website", "value": "xn--exmple-cua.com"},
                {"kind": "application", "value": os.path.realpath("/usr/bin/python3")},
            ],
        )
        self.assertEqual(
            rule["schedule"],
            {
                "kind": "one_time",
                "start_utc": "2026-01-12T14:00:00.000000Z",
                "end_utc": "2026-01-12T15:30:00.000000Z",
            },
        )

    def test_weekly_form_converts_multiple_periods(self) -> None:
        form = RuleForm(
            name="Week blocks",
            websites=("news.example",),
            applications=(),
            managed_list_ids=(),
            schedule_kind="weekly",
            timezone="Europe/Berlin",
            weekly_periods=(
                WeeklyPeriodForm((4, 0, 2), "08:15", "07:45"),
                WeeklyPeriodForm((6,), "20:00", "22:00"),
            ),
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(
            rule["schedule"],
            {
                "kind": "weekly",
                "timezone": "Europe/Berlin",
                "periods": [
                    {
                        "weekdays": [0, 2, 4],
                        "start": "08:15:00",
                        "end": "07:45:00",
                    },
                    {
                        "weekdays": [6],
                        "start": "20:00:00",
                        "end": "22:00:00",
                    },
                ],
            },
        )
    def test_weekly_form_converts_timed_allowances_per_period(self) -> None:
        form = RuleForm(
            name="Allowance",
            websites=(),
            applications=(),
            managed_list_ids=(),
            schedule_kind="weekly",
            timezone="UTC",
            weekly_periods=(
                WeeklyPeriodForm((0,), "09:00", "17:00"),
                WeeklyPeriodForm((1,), "09:00", "17:00"),
            ),
            url_targets=(
                {"kind": "url_path", "value": "example.com/feed"},
            ),
            time_allowance_enabled=True,
            time_allowance_periods=(
                PeriodAllowanceForm("total", quota_minutes=30),
                PeriodAllowanceForm(
                    "fixed_window", quota_minutes=10, window_minutes=60
                ),
            ),
            time_allowance_daily_cap_minutes=45,
        )
        rule_data = form_to_request(
            form, id_factory=lambda: UUID(RULE_ID)
        )["rule"]
        self.assertEqual(
            rule_data["allowance_time"],
            {
                "periods": [
                    {"mode": "total", "quota_seconds": 1800},
                    {
                        "mode": "fixed_window",
                        "quota_seconds": 600,
                        "window_seconds": 3600,
                    },
                ],
                "daily_cap_seconds": 2700,
            },
        )
        round_trip = rule_to_form(Rule.from_dict(rule_data), "UTC")
        self.assertTrue(round_trip.time_allowance_enabled)
        self.assertEqual(
            round_trip.time_allowance_periods,
            (
                PeriodAllowanceForm("total", 30),
                PeriodAllowanceForm("fixed_window", 10, 60),
            ),
        )
        self.assertEqual(round_trip.time_allowance_daily_cap_minutes, 45)

    def test_pomodoro_form_converts_local_start_and_exact_fields(self) -> None:
        form = RuleForm(
            name="Deep work",
            websites=("example.com",),
            applications=(),
            managed_list_ids=(),
            schedule_kind="pomodoro",
            timezone="America/New_York",
            pomodoro_start="2026-08-14 09:00",
            pomodoro_work_minutes=45,
            pomodoro_break_minutes=10,
            pomodoro_cycles=3,
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(
            rule["schedule"],
            {
                "kind": "pomodoro",
                "start_utc": "2026-08-14T13:00:00.000000Z",
                "work_minutes": 45,
                "break_minutes": 10,
                "cycles": 3,
            },
        )

    def test_pomodoro_form_enforces_each_integer_bound(self) -> None:
        cases = (
            ("pomodoro_work_minutes", 0, "Work minutes"),
            ("pomodoro_work_minutes", 181, "Work minutes"),
            ("pomodoro_break_minutes", 0, "Break minutes"),
            ("pomodoro_break_minutes", 61, "Break minutes"),
            ("pomodoro_cycles", 0, "Cycles"),
            ("pomodoro_cycles", 21, "Cycles"),
        )
        for field, value, message in cases:
            values = {
                "pomodoro_work_minutes": 25,
                "pomodoro_break_minutes": 5,
                "pomodoro_cycles": 4,
            }
            values[field] = value
            form = RuleForm(
                name="Deep work",
                websites=("example.com",),
                applications=(),
                managed_list_ids=(),
                schedule_kind="pomodoro",
                timezone="UTC",
                pomodoro_start="2026-08-14 09:00",
                **values,
            )
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(FormError, message):
                    form_to_request(form, id_factory=lambda: UUID(RULE_ID))

    def test_pomodoro_rule_loads_local_editor_values(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "pomodoro",
                "start_utc": "2026-08-14T13:00:00Z",
                "work_minutes": 45,
                "break_minutes": 10,
                "cycles": 3,
            }
        )

        form = rule_to_form(rule, "America/New_York")

        self.assertEqual(form.schedule_kind, "pomodoro")
        self.assertEqual(form.pomodoro_start, "2026-08-14 09:00")
        self.assertEqual(form.pomodoro_work_minutes, 45)
        self.assertEqual(form.pomodoro_break_minutes, 10)
        self.assertEqual(form.pomodoro_cycles, 3)

    def test_managed_list_can_be_the_only_target(self) -> None:
        form = RuleForm(
            name="Managed",
            websites=(),
            applications=(),
            managed_list_ids=(LIST_ID,),
            schedule_kind="indefinite",
            timezone="UTC",
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(
            rule["targets"], [{"kind": "managed_list", "value": LIST_ID}]
        )
        self.assertEqual(rule["schedule"], {"kind": "indefinite"})

    def test_managed_domain_exclusions_round_trip_per_rule(self) -> None:
        original = make_rule(
            targets=[{"kind": "managed_list", "value": LIST_ID}]
        )
        rule = Rule.from_dict(
            {
                **original.to_dict(),
                "excluded_managed_domains": ["SOCIAL.example."],
            }
        )

        form = rule_to_form(rule, "UTC")
        rebuilt = form_to_request(form, rule)["rule"]

        self.assertEqual(form.excluded_managed_domains, ("social.example",))
        self.assertEqual(
            rebuilt["excluded_managed_domains"], ["social.example"]
        )

    def test_rule_round_trip_keeps_lists_and_weekly_periods(self) -> None:
        rule = make_rule(
            targets=[
                {"kind": "website", "value": "example.com"},
                {"kind": "managed_list", "value": LIST_ID},
            ],
            schedule={
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [
                    {"weekdays": [0, 6], "start": "09:00", "end": "17:00"},
                    {"weekdays": [2], "start": "20:00", "end": "21:00"},
                ],
            },
        )

        form = rule_to_form(rule, "America/New_York")

        self.assertEqual(form.managed_list_ids, (LIST_ID,))
        self.assertEqual(form.timezone, "UTC")
        self.assertEqual(
            form.weekly_periods,
            (
                WeeklyPeriodForm((0, 6), "09:00:00", "17:00:00"),
                WeeklyPeriodForm((2,), "20:00:00", "21:00:00"),
            ),
        )

    def test_form_requires_a_target(self) -> None:
        form = RuleForm(
            name="Empty",
            websites=(),
            applications=(),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
        )

        with self.assertRaisesRegex(FormError, "Add at least one target"):
            form_to_request(form, id_factory=lambda: UUID(RULE_ID))

    def test_rule_round_trip_keeps_url_targets(self) -> None:
        rule = make_rule(
            targets=[
                {"kind": "website", "value": "example.com"},
                {"kind": "url_path", "value": "example.com/feed"},
                {"kind": "url_wildcard", "value": "example.com/vid/*"},
                {"kind": "url_keyword", "value": "casino"},
            ],
        )

        form = rule_to_form(rule, "UTC")
        rebuilt = form_to_request(form, id_factory=lambda: UUID(RULE_ID))

        self.assertEqual(
            form.url_targets,
            (
                {"kind": "url_path", "value": "example.com/feed"},
                {"kind": "url_wildcard", "value": "example.com/vid/*"},
                {"kind": "url_keyword", "value": "casino"},
            ),
        )
        self.assertEqual(rebuilt["rule"], rule.to_dict())
        self.assertIn("3 URL rules", _target_summary(rule))

    def test_rule_round_trip_keeps_url_exceptions(self) -> None:
        rule = make_rule(
            targets=[{"kind": "website", "value": "example.com"}],
            exceptions=[
                {"kind": "url_path", "value": "example.com/allowed"},
                {"kind": "youtube_channel", "value": "@Example.Handle"},
            ],
        )

        form = rule_to_form(rule, "UTC")
        rebuilt = form_to_request(form, id_factory=lambda: UUID(RULE_ID))

        self.assertEqual(
            form.url_exceptions,
            (
                {"kind": "url_path", "value": "example.com/allowed"},
                {"kind": "youtube_channel", "value": "@Example.Handle"},
            ),
        )
        self.assertEqual(rebuilt["rule"], rule.to_dict())

    def test_network_controls_round_trip_through_form(self) -> None:
        rule = make_rule(
            targets=[
                {"kind": "website", "value": "example.com"},
                {"kind": "network", "value": "whole_internet"},
                {"kind": "network", "value": "local_dns"},
                {"kind": "network", "value": "safe_search"},
                {"kind": "network", "value": "proxy"},
                {"kind": "network", "value": "vpn"},
            ],
        )

        form = rule_to_form(rule, "UTC")
        rebuilt = form_to_request(form, id_factory=lambda: UUID(RULE_ID))

        self.assertEqual(
            form.network_controls, ("whole_internet", "local_dns", "safe_search", "proxy", "vpn")
        )
        self.assertEqual(rebuilt["rule"], rule.to_dict())
        self.assertIn("5 network controls", _target_summary(rule))

    def test_network_control_can_be_the_only_target(self) -> None:
        form = RuleForm(
            name="Lock down",
            websites=(),
            applications=(),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
            network_controls=("whole_internet",),
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(
            rule["targets"], [{"kind": "network", "value": "whole_internet"}]
        )

    def test_form_rejects_unknown_network_control(self) -> None:

        form = RuleForm(
            name="Bad",
            websites=(),
            applications=(),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
            network_controls=("deep_packet_inspection",),
        )

        with self.assertRaisesRegex(FormError, "network control"):
            form_to_request(form, id_factory=lambda: UUID(RULE_ID))
    def test_rule_notification_settings_round_trip_through_form(self) -> None:
        form = RuleForm(
            name="Quiet",
            websites=("example.com",),
            applications=(),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
            notifications_enabled=False,
            notification_categories=("state_changes",),
        )
        rule = form_to_rule(form, id_factory=lambda: UUID(RULE_ID))
        self.assertFalse(rule.notifications_enabled)
        self.assertEqual(rule.notification_categories, ("state_changes",))
        self.assertEqual(
            rule_to_form(rule, "UTC").notification_categories,
            ("state_changes",),
        )

    def test_allowance_is_rejected_for_network_targets(self) -> None:
        form = RuleForm(
            name="No budget",
            websites=(),
            applications=(),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
            network_controls=("safe_search",),
            allowance_starts=2,
        )

        with self.assertRaisesRegex(FormError, "URL-level targets"):
            form_to_request(form, id_factory=lambda: UUID(RULE_ID))


class StoredRuleEditorTests(unittest.TestCase):
    def test_weekly_and_indefinite_rules_do_not_load_blank_picker_values(self):
        class TextField:
            def set_text(self, value):
                self.value = value

        class TextView:
            def __init__(self):
                self.buffer = TextField()

            def get_buffer(self):
                return self.buffer

        class Picker:
            def set_text(self, value):
                if not value:
                    raise FormError("blank picker value")

        class Dropdown:
            def set_selected(self, value):
                self.value = value

        class Stack:
            def set_visible_child_name(self, value):
                self.value = value

        class ValueField:
            def set_value(self, value):
                self.value = value

        editor = RuleEditor.__new__(RuleEditor)
        editor.name_entry = TextField()
        editor.website_view = TextView()
        editor.application_paths = []
        editor._render_applications = lambda: None
        editor.url_targets = []
        editor.url_exceptions = []
        rendered_urls = []
        editor._render_url_targets = lambda: rendered_urls.append(
            (tuple(editor.url_targets), tuple(editor.url_exceptions))
        )
        editor.managed_list_checks = {}
        editor.network_checks = {}
        editor.schedule_dropdown = Dropdown()
        editor.schedule_stack = Stack()
        editor.allowance_spin = ValueField()
        editor.one_start = Picker()
        editor.one_end = Picker()
        editor.weekly_rows = []
        editor._remove_weekly_period = editor.weekly_rows.remove
        editor._add_weekly_period = editor.weekly_rows.append
        weekly = make_rule(
            targets=[
                {"kind": "website", "value": "example.com"},
                {"kind": "url_path", "value": "example.com/feed"},
            ],
            exceptions=[
                {"kind": "url_path", "value": "example.com/allowed"},
            ],
            schedule={
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [{
                    "weekdays": [0],
                    "start": "09:00",
                    "end": "10:00",
                }],
            }
        )
        indefinite = make_rule(schedule={"kind": "indefinite"})

        editor._populate(rule_to_form(weekly, "UTC"))
        self.assertEqual(
            rendered_urls[0],
            (
                ({"kind": "url_path", "value": "example.com/feed"},),
                ({"kind": "url_path", "value": "example.com/allowed"},),
            ),
        )
        editor._populate(rule_to_form(indefinite, "UTC"))

        self.assertEqual(editor.weekly_rows, [])

    def test_render_targets_populates_exception_and_application_lists(self) -> None:
        editor = RuleEditor.__new__(RuleEditor)
        editor.target_list = object()
        editor.exception_list = object()
        editor.system_list = object()
        editor.target_entries = []
        editor.url_exceptions = [
            {"kind": "url_path", "value": "reddit.com/allowed"}
        ]
        editor.system_target_entries = []
        editor.application_paths = ["/usr/bin/python3"]
        rendered = []
        editor._render_list = (
            lambda widget, entries, **options:
            rendered.append((widget, tuple(entries), options))
        )
        editor._render_applications = lambda: rendered.append(
            ("applications", tuple(editor.application_paths), {})
        )

        editor._render_targets()

        self.assertIn(
            (
                editor.exception_list,
                ({"kind": "url_path", "value": "reddit.com/allowed"},),
                {"exception": True},
            ),
            rendered,
        )
        self.assertIn(
            ("applications", ("/usr/bin/python3",), {}),
            rendered,
        )

        class TextField:
            def set_text(self, value):
                self.value = value

        class TextView:
            def __init__(self):
                self.buffer = TextField()

            def get_buffer(self):
                return self.buffer

        class Dropdown:
            def set_selected(self, value):
                self.value = value

        class Stack:
            def set_visible_child_name(self, value):
                self.value = value

        class ValueField:
            def set_value(self, value):
                self.value = value

        editor = RuleEditor.__new__(RuleEditor)
        editor.name_entry = TextField()
        editor.website_view = TextView()
        editor.application_paths = []
        editor._render_applications = lambda: None
        editor.url_targets = []
        editor._render_url_targets = lambda: None

        editor.managed_list_checks = {}
        editor.network_checks = {}
        editor.schedule_dropdown = Dropdown()
        editor.schedule_stack = Stack()
        editor.allowance_spin = ValueField()
        editor.pomodoro_start = TextField()
        editor.pomodoro_work = ValueField()
        editor.pomodoro_break = ValueField()
        editor.pomodoro_cycles = ValueField()
        editor.weekly_rows = []
        editor._remove_weekly_period = editor.weekly_rows.remove
        editor._add_weekly_period = editor.weekly_rows.append
        rule = make_rule(
            schedule={
                "kind": "pomodoro",
                "start_utc": "2026-08-14T09:00:00Z",
                "work_minutes": 50,
                "break_minutes": 8,
                "cycles": 5,
            }
        )

        editor._populate(rule_to_form(rule, "UTC"))

        self.assertEqual(editor.pomodoro_start.value, "2026-08-14 09:00")
        self.assertEqual(editor.pomodoro_work.value, 50)
        self.assertEqual(editor.pomodoro_break.value, 8)
        self.assertEqual(editor.pomodoro_cycles.value, 5)

    def test_add_url_target_validates_and_deduplicates(self) -> None:
        class Entry:
            def __init__(self) -> None:
                self.value = ""

            def get_text(self) -> str:
                return self.value

            def set_text(self, value: str) -> None:
                self.value = value

        class Label:
            def __init__(self) -> None:
                self.text = ""

            def set_text(self, value: str) -> None:
                self.text = value

        class Dropdown:
            def __init__(self, selected: int) -> None:
                self.value = selected

            def get_selected(self) -> int:
                return self.value

        editor = RuleEditor.__new__(RuleEditor)
        editor.url_entry = Entry()
        editor.error_label = Label()
        editor.url_kind_dropdown = Dropdown(0)
        editor.url_targets = []
        editor.url_exceptions = []
        editor.url_exception_check = type(
            "Check", (), {"get_active": lambda self: False}
        )()
        editor._render_url_targets = lambda: None

        editor.url_entry.set_text("example.com/feed")
        editor._add_url_target()
        self.assertEqual(
            editor.url_targets,
            [{"kind": "url_path", "value": "example.com/feed"}],
        )
        self.assertEqual(editor.url_entry.value, "")

        editor.url_kind_dropdown = Dropdown(0)
        editor.url_entry.set_text("Example.COM/feed")
        editor._add_url_target()
        self.assertEqual(len(editor.url_targets), 1)
        self.assertIn("already in the list", editor.error_label.text)

        editor.url_kind_dropdown = Dropdown(2)
        editor.url_entry.set_text("a")
        editor._add_url_target()
        self.assertEqual(len(editor.url_targets), 1)
        self.assertIn("2 to 64", editor.error_label.text)


    def test_target_import_selects_missing_managed_snapshots(self) -> None:
        managed = ManagedList.from_dict({
            "id": LIST_ID,
            "name": "Focus",
            "source": "import",
            "version": "1",
            "license": "Test",
            "imported_utc": "2026-01-01T00:00:00Z",
            "domains": ["example.com"],
        })
        preview = TargetListPreview(
            "targets",
            (Target("managed_list", LIST_ID),),
            (managed,),
        )
        self.assertEqual(
            RuleEditor._missing_managed_snapshots(preview, set()),
            (managed,),
        )
        self.assertEqual(
            RuleEditor._missing_managed_snapshots(preview, {LIST_ID}),
            (),
        )


class ScheduleProjectionTests(unittest.TestCase):
    def test_next_change_uses_union_of_weekly_periods(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [
                    {"weekdays": [4], "start": "09:00", "end": "11:00"},
                    {"weekdays": [4], "start": "10:00", "end": "12:00"},
                ],
            }
        )

        change = next_state_change(rule, datetime(2026, 8, 14, 9, 30, tzinfo=UTC))

        self.assertEqual(change.at_utc, datetime(2026, 8, 14, 12, tzinfo=UTC))
        self.assertFalse(change.active_after)

    def test_pomodoro_next_change_names_work_break_and_final_end(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "pomodoro",
                "start_utc": "2026-08-14T09:00:00Z",
                "work_minutes": 25,
                "break_minutes": 5,
                "cycles": 3,
            }
        )
        cases = (
            (
                datetime(2026, 8, 14, 8, 50, tzinfo=UTC),
                datetime(2026, 8, 14, 9, 0, tzinfo=UTC),
                True,
                "Work starts",
            ),
            (
                datetime(2026, 8, 14, 9, 10, tzinfo=UTC),
                datetime(2026, 8, 14, 9, 25, tzinfo=UTC),
                False,
                "Break starts",
            ),
            (
                datetime(2026, 8, 14, 9, 27, tzinfo=UTC),
                datetime(2026, 8, 14, 9, 30, tzinfo=UTC),
                True,
                "Work starts",
            ),
            (
                datetime(2026, 8, 14, 10, 1, tzinfo=UTC),
                datetime(2026, 8, 14, 10, 25, tzinfo=UTC),
                False,
                "Ends",
            ),
        )
        for now, expected_at, active_after, action in cases:
            with self.subTest(now=now):
                change = next_state_change(rule, now)
                self.assertEqual(change.at_utc, expected_at)
                self.assertEqual(change.active_after, active_after)
                self.assertEqual(_state_change_action(rule, change), action)

        self.assertIsNone(
            next_state_change(rule, datetime(2026, 8, 14, 10, 25, tzinfo=UTC))
        )
        self.assertIn("Pomodoro: 3 cycles", _schedule_summary(rule))
        self.assertEqual(
            _rule_state_text(
                rule, datetime(2026, 8, 14, 9, 10, tzinfo=UTC), True
            ),
            "Work",
        )
        self.assertEqual(
            _rule_state_text(
                rule, datetime(2026, 8, 14, 9, 27, tzinfo=UTC), True
            ),
            "Break",
        )
        self.assertEqual(
            active_lock_explanation(
                rule, datetime(2026, 8, 14, 9, 10, tzinfo=UTC), True
            ),
            "",
        )

    def test_active_lock_explanation_requires_effective_lock(self) -> None:
        now = datetime(2026, 8, 14, 9, 10, tzinfo=UTC)
        weekly = make_rule(
            schedule={
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [
                    {"weekdays": [4], "start": "09:00", "end": "10:00"}
                ],
            }
        )
        self.assertEqual(active_lock_explanation(weekly, now, True), "")
        schedule_lock = LockSummary(RULE_ID, "schedule", True, None, None)
        self.assertIn(
            "This locked rule cannot be weakened before",
            active_lock_explanation(weekly, now, True, schedule_lock),
        )
        friction_lock = LockSummary(RULE_ID, "friction", True, None, None)
        self.assertEqual(
            active_lock_explanation(weekly, now, True, friction_lock),
            "This rule cannot be weakened before friction authorization is completed.",
        )
        untrusted = active_lock_explanation(
            weekly, now, False, schedule_lock
        )
        self.assertEqual(
            untrusted,
            "This locked rule remains effective until the trusted clock is restored.",
        )

    def test_daily_projection_contains_only_pomodoro_work_intervals(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "pomodoro",
                "start_utc": "2026-08-14T09:00:00Z",
                "work_minutes": 25,
                "break_minutes": 5,
                "cycles": 3,
            }
        )

        intervals = project_daily_schedule((rule,), date(2026, 8, 14), "UTC")

        self.assertEqual(
            [
                (
                    item.start_local.strftime("%H:%M"),
                    item.end_local.strftime("%H:%M"),
                )
                for item in intervals
            ],
            [("09:00", "09:25"), ("09:30", "09:55"), ("10:00", "10:25")],
        )

    def test_daily_projection_uses_requested_system_zone(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "one_time",
                "start_utc": "2026-01-12T14:00:00Z",
                "end_utc": "2026-01-12T15:30:00Z",
            }
        )

        intervals = project_daily_schedule(
            (rule,), date(2026, 1, 12), "America/New_York"
        )

        self.assertEqual(len(intervals), 1)
        self.assertEqual(intervals[0].start_local.strftime("%H:%M"), "09:00")
        self.assertEqual(intervals[0].end_local.strftime("%H:%M"), "10:30")
        self.assertEqual(getattr(intervals[0].start_local.tzinfo, "key", None), "America/New_York")

    def test_daily_projection_clips_cross_midnight_period(self) -> None:
        rule = make_rule(
            schedule={
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [
                    {"weekdays": [4], "start": "23:00", "end": "01:00"}
                ],
            }
        )

        friday = project_daily_schedule((rule,), date(2026, 8, 14), "UTC")
        saturday = project_daily_schedule((rule,), date(2026, 8, 15), "UTC")

        self.assertEqual(
            (friday[0].start_local.hour, friday[0].end_local.day), (23, 15)
        )
        self.assertEqual(
            (saturday[0].start_local.hour, saturday[0].end_local.hour), (0, 1)
        )


    def test_daily_schedule_rpc_result_is_strict(self) -> None:
        day, timezone_name, intervals = daily_schedule_from_result({
            "date": "2026-08-20",
            "timezone": "UTC",
            "intervals": [{
                "rule_id": RULE_ID,
                "rule_name": "Focus",
                "start": "2026-08-20T09:00:00+00:00",
                "end": "2026-08-20T10:00:00+00:00",
            }],
        })
        self.assertEqual(day, date(2026, 8, 20))
        self.assertEqual(timezone_name, "UTC")
        self.assertEqual(intervals[0].rule_id, RULE_ID)
        with self.assertRaises(FormError):
            daily_schedule_from_result({
                "date": "2026-08-20",
                "timezone": "UTC",
                "intervals": [],
                "extra": True,
            })


class TransitionTests(unittest.TestCase):
    def test_transition_detection_reports_only_observed_changes(self) -> None:
        previous = {
            RULE_ID: ObservedRuleState("Focus", False),
            SECOND_RULE_ID: ObservedRuleState("Rest", True),
        }
        current = {
            RULE_ID: ObservedRuleState("Focus", True),
            SECOND_RULE_ID: ObservedRuleState("Rest", False),
        }

        transitions = detect_rule_transitions(previous, current)

        self.assertEqual(
            [(item.rule_name, item.started) for item in transitions],
            [("Focus", True), ("Rest", False)],
        )
        self.assertEqual(detect_rule_transitions({}, {}), ())



class StagedUploadTests(unittest.TestCase):
    def test_list_upload_uses_200_item_chunks_then_commit(self) -> None:
        calls = staged_list_upload_calls(
            "stage-id", tuple(f"d{index}.example" for index in range(401))
        )

        self.assertEqual(
            [len(call.fields["domains"]) for call in calls[:-1]], [200, 200, 1]
        )
        self.assertTrue(all(call.command == "import_list_chunk" for call in calls[:-1]))
        self.assertEqual(calls[-1].command, "commit_list_import")

    def test_list_begin_metadata_omits_service_owned_timestamp(self) -> None:
        managed_list = ManagedList.from_dict(
            {
                "id": LIST_ID,
                "name": "Social",
                "source": "file:social.txt",
                "version": "4",
                "license": "Source license.",
                "imported_utc": datetime(2026, 8, 14, tzinfo=UTC),
                "domains": ["example.com"],
            }
        )

        metadata = managed_list_import_metadata(managed_list)

        self.assertEqual(
            set(metadata), {"id", "name", "source", "version", "license"}
        )
        self.assertNotIn("imported_utc", metadata)

    def test_native_chunks_preserve_unicode_and_byte_limit(self) -> None:
        text = "aé🙂b"
        chunks = utf8_text_chunks(text, maximum_bytes=5)

        self.assertEqual("".join(chunks), text)
        self.assertTrue(all(len(chunk.encode("utf-8")) <= 5 for chunk in chunks))
        calls = staged_native_upload_calls("native-stage", text)
        self.assertEqual(calls[-1].command, "commit_native_import")


class ServiceResultTests(unittest.TestCase):
    def test_managed_list_summary_rejects_domain_data(self) -> None:
        item = {
            "id": LIST_ID,
            "name": "Social",
            "source": "built-in:social",
            "version": "1",
            "license": "Starter data.",
            "imported_utc": "2026-08-14T12:00:00.000000Z",
            "domain_count": 5,
        }

        summaries = managed_list_summaries_from_results((item,))

        self.assertEqual(
            summaries,
            (
                ManagedListSummary(
                    LIST_ID,
                    "Social",
                    "built-in:social",
                    "1",
                    "Starter data.",
                    "2026-08-14T12:00:00.000000Z",
                    5,
                ),
            ),
        )
        with self.assertRaisesRegex(FormError, "summary"):
            managed_list_summaries_from_results(({**item, "domains": []},))

    def test_lock_summary_accepts_public_timed_and_friction_fields(self) -> None:
        timed = {
            "rule_id": RULE_ID,
            "kind": "timed",
            "locked": True,
            "until_utc": "2026-08-14T16:00:00.000000Z",
            "retry_after_utc": None,
        }
        friction = {
            "rule_id": SECOND_RULE_ID,
            "kind": "friction",
            "locked": True,
            "until_utc": None,
            "retry_after_utc": None,
        }

        summaries = lock_summaries_from_results((timed, friction))

        self.assertEqual(
            summaries,
            (
                LockSummary(
                    RULE_ID,
                    "timed",
                    True,
                    datetime(2026, 8, 14, 16, tzinfo=UTC),
                    None,
                ),
                LockSummary(
                    SECOND_RULE_ID,
                    "friction",
                    True,
                    None,
                    None,
                ),
            ),
        )
        self.assertEqual(
            lock_summary_text(summaries[0], "America/New_York"),
            (
                "Timed lock: locked. Expiry: 2026-08-14 16:00:00 UTC "
                "(2026-08-14 12:00:00 EDT local)."
            ),
        )
        self.assertEqual(
            lock_summary_text(summaries[1], "America/New_York"),
            "Friction lock: authorization required for weakening changes.",
        )
        with self.assertRaisesRegex(FormError, "summary"):
            lock_summaries_from_results(({**timed, "salt": "protected"},))
        with self.assertRaisesRegex(FormError, "unsupported lock kind"):
            lock_summaries_from_results(({**timed, "kind": "pin"},))
        with self.assertRaisesRegex(FormError, "expiry"):
            lock_summaries_from_results(
                ({**friction, "until_utc": timed["until_utc"]},)
            )

    def test_schedule_lock_summary_and_request(self) -> None:
        item = {
            "rule_id": RULE_ID,
            "kind": "schedule",
            "locked": True,
            "until_utc": None,
            "retry_after_utc": None,
        }
        summary = lock_summaries_from_results((item,))[0]
        self.assertEqual(
            lock_summary_text(summary, "UTC"),
            "Schedule lock: active during the rule's weekly periods.",
        )
        self.assertEqual(
            schedule_lock_request(RULE_ID),
            {"rule_id": RULE_ID, "lock": {"kind": "schedule"}},
        )
    def test_delay_lock_summary_and_requests(self) -> None:
        item = {
            "rule_id": RULE_ID,
            "kind": "delay",
            "locked": True,
            "until_utc": None,
            "retry_after_utc": None,
            "wait_seconds": 60,
            "break_seconds": 1800,
            "pending_until_utc": "2026-08-14T16:01:00Z",
            "break_until_utc": None,
        }
        summary = lock_summaries_from_results((item,))[0]
        self.assertEqual(summary.wait_seconds, 60)
        self.assertIn("Countdown ends", lock_summary_text(summary, "UTC"))
        self.assertEqual(
            delay_lock_request(RULE_ID, 60, 1800),
            {
                "rule_id": RULE_ID,
                "lock": {
                    "kind": "delay",
                    "wait_seconds": 60,
                    "break_seconds": 1800,
                },
            },
        )
        self.assertEqual(request_delay_break_request(RULE_ID), {"rule_id": RULE_ID})
        self.assertEqual(cancel_delay_break_request(RULE_ID), {"rule_id": RULE_ID})
        with self.assertRaisesRegex(FormError, "Delay"):
            delay_lock_request(RULE_ID, 0, 1800)
        with self.assertRaisesRegex(FormError, "state"):
            lock_summaries_from_results(
                ({**item, "break_until_utc": item["pending_until_utc"]},)
            )


    def test_rule_lock_requests_cover_all_kinds_and_removal(self) -> None:
        password = "correct horse"
        self.assertEqual(
            timed_lock_request(
                RULE_ID,
                "2026-08-14 12:00",
                "America/New_York",
            ),
            {
                "rule_id": RULE_ID,
                "lock": {
                    "kind": "timed",
                    "until_utc": "2026-08-14T16:00:00Z",
                },
            },
        )
        self.assertEqual(
            friction_lock_request(RULE_ID),
            {"rule_id": RULE_ID, "lock": {"kind": "friction"}},
        )
        self.assertEqual(
            password_lock_request(RULE_ID, password, password),
            {
                "rule_id": RULE_ID,
                "lock": {"kind": "password", "password": password},
            },
        )
        self.assertEqual(
            remove_rule_lock_request(RULE_ID),
            {"rule_id": RULE_ID, "lock": {"kind": "none"}},
        )

    def test_password_lock_request_validates_secret_before_rpc(self) -> None:
        self.assertEqual(
            password_lock_request(RULE_ID, "éééé", "éééé")["lock"]["password"],
            "éééé",
        )
        with self.assertRaisesRegex(FormError, "at least 8"):
            password_lock_request(RULE_ID, "short", "short")
        with self.assertRaisesRegex(FormError, "match"):
            password_lock_request(RULE_ID, "long enough", "different")
        with self.assertRaisesRegex(FormError, "at most 1024"):
            password_lock_request(RULE_ID, "x" * 1025, "x" * 1025)

    def test_authorization_requests_and_results_preserve_service_text(self) -> None:
        challenge_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        prompt = "Ab3dE5fG7hJ9"
        challenge = authorization_challenge_from_result(
            {
                "rule_id": RULE_ID,
                "kind": "friction",
                "challenge_id": challenge_id,
                "prompt": prompt,
                "expires_in": 120,
            }
        )

        self.assertEqual(
            challenge,
            AuthorizationChallenge(
                RULE_ID,
                "friction",
                challenge_id,
                prompt,
                120,
            ),
        )
        self.assertEqual(
            begin_rule_authorization_request(RULE_ID),
            {"rule_id": RULE_ID},
        )
        self.assertEqual(
            complete_rule_authorization_request(
                RULE_ID,
                challenge.challenge_id,
                challenge.prompt,
            ),
            {
                "rule_id": RULE_ID,
                "challenge_id": challenge_id,
                "response": prompt,
            },
        )
        self.assertEqual(
            authorization_grant_from_result(
                {"rule_id": RULE_ID, "authorized": True, "expires_in": 60}
            ),
            AuthorizationGrant(RULE_ID, True, 60),
        )
        with self.assertRaisesRegex(FormError, "challenge"):
            authorization_challenge_from_result(
                {
                    "rule_id": RULE_ID,
                    "kind": "friction",
                    "challenge_id": challenge_id,
                    "prompt": prompt,
                    "expires_in": 120,
                    "generated_by_gui": False,
                }
            )

    def test_password_secret_appears_only_in_outbound_requests(self) -> None:
        challenge_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        password = "private password"
        public_result = {
            "rule_id": RULE_ID,
            "kind": "password",
            "locked": True,
            "until_utc": None,
            "retry_after_utc": "2026-08-14T16:05:00Z",
        }

        summary = lock_summaries_from_results((public_result,))[0]
        challenge = authorization_challenge_from_result(
            {
                "rule_id": RULE_ID,
                "kind": "password",
                "challenge_id": challenge_id,
                "prompt": None,
                "expires_in": 120,
            }
        )
        set_request = password_lock_request(RULE_ID, password, password)
        complete_request = complete_rule_authorization_request(
            RULE_ID,
            challenge_id,
            password,
            "password",
        )
        begin_request = begin_rule_authorization_request(RULE_ID)

        self.assertEqual(summary.kind, "password")
        self.assertIsNone(summary.until_utc)
        self.assertEqual(
            summary.retry_after_utc,
            datetime(2026, 8, 14, 16, 5, tzinfo=UTC),
        )
        self.assertIsNone(challenge.prompt)
        self.assertNotIn("password", public_result.keys())
        self.assertNotIn(password, repr(public_result))
        self.assertNotIn(password, repr(begin_request))
        self.assertNotIn(password, repr(summary))
        self.assertNotIn(password, repr(challenge))
        self.assertEqual(set_request["lock"]["password"], password)
        self.assertEqual(complete_request["response"], password)
        self.assertNotIn("confirmation", set_request["lock"])
        with self.assertRaisesRegex(FormError, "at least 8"):
            complete_rule_authorization_request(
                RULE_ID,
                challenge_id,
                "short",
                "password",
            )
        self.assertEqual(
            lock_summary_text(summary, "America/New_York"),
            (
                "Password lock: authorization required for weakening changes. "
                "Retry after: 2026-08-14 16:05:00 UTC "
                "(2026-08-14 12:05:00 EDT local)."
            ),
        )
        with self.assertRaisesRegex(FormError, "summary"):
            lock_summaries_from_results(
                ({**public_result, "password": password},)
            )
        with self.assertRaisesRegex(FormError, "authorization text"):
            authorization_challenge_from_result(
                {
                    "rule_id": RULE_ID,
                    "kind": "password",
                    "challenge_id": challenge_id,
                    "prompt": password,
                    "expires_in": 120,
                }
            )

    def test_snapshot_keeps_public_lock_summaries_beside_rules(self) -> None:
        snapshot = snapshot_from_results(
            {
                "healthy": True,
                "clock_trusted": True,
                "clock_reason": "",
                "active_counts": {"website": 0, "application": 0, "network": 0},
            },
            policy_result((make_rule().to_dict(),)),
            (),
            (
                {
                    "rule_id": RULE_ID,
                    "kind": "timed",
                    "locked": False,
                    "until_utc": "2026-08-14T16:00:00Z",
                    "retry_after_utc": None,
                },
            ),
        )

        self.assertEqual(snapshot.locks[0].rule_id, RULE_ID)
        self.assertFalse(snapshot.locks[0].locked)

    def test_snapshot_uses_integer_active_counts(self) -> None:
        rule = make_rule()
        snapshot = snapshot_from_results(
            {
                "healthy": True,
                "clock_trusted": True,
                "clock_reason": "",
                "active_counts": {"website": 203, "application": 2, "network": 3},
            },
            policy_result((rule.to_dict(),), revision=3),
            (),
            (),
        )

        self.assertEqual(snapshot.active_websites, 203)
        self.assertEqual(snapshot.active_applications, 2)
        self.assertEqual(snapshot.active_network, 3)
        with self.assertRaisesRegex(FormError, "active counts"):
            snapshot_from_results(
                {
                    "healthy": True,
                    "clock_trusted": True,
                    "clock_reason": "",
                    "active_counts": {"website": [], "application": 0, "network": 0},
                },
                policy_result(),
                (),
                (),
            )

    def test_snapshot_requires_network_active_count(self) -> None:
        # Breadcrumb (network seam): a status without the network count is
        # an older service; the GUI fails closed instead of guessing 0.
        status = {
            "healthy": True,
            "clock_trusted": True,
            "clock_reason": "",
            "active_counts": {"website": 0, "application": 0},
        }
        with self.assertRaisesRegex(FormError, "active counts"):
            snapshot_from_results(status, policy_result(), (), ())

    def test_snapshot_rejects_unknown_policy_schema(self) -> None:
        status = {
            "healthy": True,
            "clock_trusted": True,
            "clock_reason": "",
            "active_counts": {"website": 0, "application": 0, "network": 0},
        }
        unsupported = policy_result()
        unsupported["schema_version"] = POLICY_SCHEMA_VERSION + 1
        with self.assertRaisesRegex(FormError, "policy values"):
            snapshot_from_results(status, unsupported, (), ())


class DenialStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.row = {
            "path": "/usr/bin/example-app",
            "count": 1200,
            "first_utc": "2026-08-14T12:00:00Z",
            "last_utc": "2026-08-14T12:05:00+00:00",
            "rule_ids": [RULE_ID, SECOND_RULE_ID],
        }

    def test_exact_result_parses_to_immutable_display_values(self) -> None:
        statistics = denial_statistics_from_result(
            {"items": [self.row], "dropped": 7}
        )

        self.assertEqual(
            statistics,
            DenialStatistics(
                (
                    DenialStatView(
                        "/usr/bin/example-app",
                        1200,
                        datetime(2026, 8, 14, 12, tzinfo=UTC),
                        datetime(2026, 8, 14, 12, 5, tzinfo=UTC),
                        (RULE_ID, SECOND_RULE_ID),
                    ),
                ),
                7,
            ),
        )
        self.assertEqual(
            denial_stat_display(statistics.items[0]),
            DenialStatDisplay(
                "/usr/bin/example-app",
                "1,200",
                "2026-08-14T12:00:00Z",
                "2026-08-14T12:05:00Z",
                f"{RULE_ID}, {SECOND_RULE_ID}",
            ),
        )
        empty_rules = denial_statistics_from_result(
            {"items": [{**self.row, "rule_ids": []}], "dropped": 0}
        )
        self.assertEqual(
            denial_stat_display(empty_rules.items[0]).rule_ids,
            "None recorded",
        )

    def test_parser_rejects_non_exact_or_invalid_rows(self) -> None:
        invalid_results = (
            {"items": (self.row,), "dropped": 0},
            {"items": [self.row]},
            {"items": [self.row], "dropped": 0, "policy": {}},
            {"items": [{**self.row, "secret": "protected"}], "dropped": 0},
            {
                "items": [
                    {**self.row, "path": "/usr/bin/../bin/example-app"}
                ],
                "dropped": 0,
            },
            {"items": [{**self.row, "path": "../example-app"}], "dropped": 0},
            {"items": [{**self.row, "count": True}], "dropped": 0},
            {
                "items": [
                    {
                        **self.row,
                        "first_utc": "2026-08-14T13:00:00Z",
                    }
                ],
                "dropped": 0,
            },
            {
                "items": [
                    {
                        **self.row,
                        "rule_ids": [SECOND_RULE_ID, RULE_ID],
                    }
                ],
                "dropped": 0,
            },
            {"items": [self.row], "dropped": False},
        )

        for result in invalid_results:
            with self.subTest(result=result):
                with self.assertRaises(FormError):
                    denial_statistics_from_result(result)

    def test_parser_enforces_the_256_path_view_bound(self) -> None:
        items = [
            {**self.row, "path": f"/usr/bin/example-{index}"}
            for index in range(257)
        ]

        with self.assertRaisesRegex(FormError, "statistics"):
            denial_statistics_from_result({"items": items, "dropped": 0})


class ExistingWorkflowTests(unittest.TestCase):
    def test_default_window_and_picker_round_trip(self) -> None:
        start, end = default_one_time_window(datetime(2026, 8, 13, 12, 3, 1))
        self.assertEqual(start, "2026-08-13 12:05")
        self.assertEqual(end, "2026-08-13 13:05")
        selected = picker_text_to_datetime("2026-12-31 23:59")
        self.assertEqual(picker_datetime_text(selected), "2026-12-31 23:59")

    def test_duplicate_stays_disabled_with_new_identity(self) -> None:
        original = make_rule(revision=7)
        copy = duplicate_rule(
            original,
            id_factory=lambda: UUID(SECOND_RULE_ID),
        )
        self.assertEqual(copy.id, SECOND_RULE_ID)
        self.assertFalse(copy.enabled)
        self.assertEqual(copy.targets, original.targets)
        self.assertEqual(copy.schedule, original.schedule)

    def test_filter_and_preview_helpers_keep_existing_workflows(self) -> None:
        active = make_rule()
        disabled = make_rule(
            rule_id=SECOND_RULE_ID,
            name="Rest",
            enabled=False,
            targets=[{"kind": "website", "value": "social.example"}],
        )
        now = datetime(2026, 8, 13, 12, tzinfo=UTC)
        self.assertEqual(
            filter_rules((active, disabled), "SOCIAL", "all", now, True),
            (disabled,),
        )
        preview = ImportPreview(
            ("example.com",),
            2,
            3,
            (ImportIssue(9, "*bad*", "website value must be a hostname"),),
        )
        text = import_preview_text(preview)
        self.assertIn("Accepted domains: 1", text)
        self.assertIn("Line 9", text)
    def test_rule_sort_options_are_deterministic(self) -> None:
        first = make_rule(name="Zulu")
        second = make_rule(rule_id=SECOND_RULE_ID, name="alpha", enabled=False)

        self.assertEqual(sort_rules((first, second), "recent"), (second, first))
        self.assertEqual(
            sort_rules((first, second), "name_asc"), (second, first)
        )
        self.assertEqual(
            sort_rules((first, second), "name_desc"), (first, second)
        )




class WebsiteUsageViewTests(unittest.TestCase):
    # Breadcrumb: v1 surfaces allowances as a small pane over the additive
    # list_website_stats projection; the parser pins that wire shape.

    def _result(self, **overrides):
        row = {
            "rule_id": RULE_ID,
            "day": "2026-01-01",
            "count": 2,
            "allowance_starts": 5,
            "budget_exhausted": False,
        }
        row.update(overrides)
        return {"items": [], "dropped": 0, "usage": [row]}

    def test_parses_usage_rows(self):
        from distraction_blocker.gui import website_usage_from_result
        parsed = website_usage_from_result(self._result())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].rule_id, RULE_ID)
        self.assertEqual(parsed[0].count, 2)
        self.assertEqual(parsed[0].allowance_starts, 5)
        self.assertFalse(parsed[0].budget_exhausted)

    def test_rejects_unknown_fields_and_bad_values(self):
        from distraction_blocker.gui import website_usage_from_result
        with self.assertRaises(FormError):
            website_usage_from_result({"items": [], "dropped": 0})
        bad = self._result(count=True)
        with self.assertRaises(FormError):
            website_usage_from_result(bad)

    def test_form_round_trips_allowance(self):
        rule = make_rule(allowance_starts=4)
        form = rule_to_form(rule, "UTC")
        self.assertEqual(form.allowance_starts, 4)
        rebuilt = form_to_rule(form, existing=rule)
        self.assertEqual(rebuilt.to_dict()["allowance_starts"], 4)
        no_budget = rule_to_form(make_rule(), "UTC")
        self.assertIsNone(no_budget.allowance_starts)
        self.assertNotIn(
            "allowance_starts", form_to_rule(no_budget).to_dict()
        )

    def test_form_round_trips_system_targets_and_toggle(self):
        rule = Rule.from_dict({
            "id": RULE_ID,
            "name": "Scoped",
            "enabled": True,
            "targets": [{"kind": "website", "value": "browser.example"}],
            "system_blocking": True,
            "system_targets": [
                {"kind": "website", "value": "system.example"},
            ],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        form = rule_to_form(rule, "UTC")
        rebuilt = form_to_rule(form, existing=rule)
        self.assertTrue(form.system_blocking)
        self.assertEqual(rebuilt.system_targets[0].value, "system.example")

    def test_form_rejects_allowance_for_non_browser_targets(self):
        form = RuleForm(
            name="Budgeted",
            websites=(),
            applications=("/bin/app",),
            managed_list_ids=(),
            schedule_kind="indefinite",
            timezone="UTC",
            allowance_starts=2,
        )
        with self.assertRaisesRegex(FormError, "URL-level"):
            form_to_rule(form)
    def test_timed_allowance_accepts_managed_list_targets(self):
        form = RuleForm(
            name="Managed allowance",
            websites=(),
            applications=(),
            managed_list_ids=(LIST_ID,),
            schedule_kind="weekly",
            timezone="UTC",
            weekly_periods=(WeeklyPeriodForm((0,), "09:00", "17:00"),),
            time_allowance_enabled=True,
            time_allowance_periods=(PeriodAllowanceForm("total", 30),),
        )
        self.assertIsNotNone(form_to_rule(form).time_allowance)

    def test_timed_allowance_rejects_active_system_targets(self):
        form = RuleForm(
            name="System allowance",
            websites=("example.com",),
            applications=(),
            managed_list_ids=(),
            schedule_kind="weekly",
            timezone="UTC",
            weekly_periods=(WeeklyPeriodForm((0,), "09:00", "17:00"),),
            time_allowance_enabled=True,
            time_allowance_periods=(PeriodAllowanceForm("total", 30),),
            system_blocking=True,
            system_target_entries=(
                {"kind": "website", "value": "system.example"},
            ),
        )
        with self.assertRaisesRegex(FormError, "URL-level"):
            form_to_rule(form)

    def test_snapshot_collects_exhausted_rule_ids(self):
        status = {
            "healthy": True,
            "clock_trusted": True,
            "clock_reason": "",
            "active_counts": {"website": 0, "application": 0, "network": 0},
        }
        item = make_rule().to_dict()
        item["budget_exhausted"] = True
        snapshot = snapshot_from_results(
            status, policy_result((item,)), [], []
        )
        self.assertEqual(snapshot.exhausted_rule_ids, {RULE_ID})



class NotificationDispatchTests(unittest.TestCase):
    def test_upcoming_notifications_follow_per_rule_categories(self) -> None:
        from distraction_blocker.gui import GuiController

        class Notification:
            def __init__(self, title):
                self.title = title

            @classmethod
            def new(cls, title):
                return cls(title)

            def set_body(self, body):
                self.body = body

        Gio = type("Gio", (), {"Notification": Notification})

        class Application:
            def __init__(self):
                self.sent = []

            def send_notification(self, notification_id, notification):
                self.sent.append((notification_id, notification))

        controller = GuiController.__new__(GuiController)
        controller.Gio = Gio
        controller.application = Application()
        controller._warning_keys = set()
        now = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)
        base = make_rule(
            schedule={
                "kind": "one_time",
                "start_utc": "2026-08-14T09:00:00Z",
                "end_utc": "2026-08-14T09:05:00Z",
            }
        )
        disabled = Rule.from_dict({
            **base.to_dict(),
            "notifications": {
                "enabled": False,
                "categories": ["upcoming_changes"],
            },
        })
        controller._send_advance_notifications((disabled,), now, True)
        self.assertEqual(controller.application.sent, [])

        state_only = Rule.from_dict({
            **base.to_dict(),
            "notifications": {
                "enabled": True,
                "categories": ["state_changes"],
            },
        })
        controller._send_advance_notifications((state_only,), now, True)
        self.assertEqual(controller.application.sent, [])

        upcoming = Rule.from_dict({
            **base.to_dict(),
            "notifications": {
                "enabled": True,
                "categories": ["upcoming_changes"],
            },
        })
        controller._send_advance_notifications((upcoming,), now, True)
        self.assertEqual(len(controller.application.sent), 1)

if __name__ == "__main__":
    unittest.main()
