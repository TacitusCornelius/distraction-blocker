from __future__ import annotations

import os
import subprocess
import sys
import unittest
from datetime import UTC, date, datetime
from uuid import UUID

from distraction_blocker.gui import (
    FormError,
    GtkUnavailableError,
    ManagedListSummary,
    ObservedRuleState,
    RuleEditor,
    RuleForm,
    WeeklyPeriodForm,
    create_focus_rule,
    default_one_time_window,
    detect_rule_transitions,
    duplicate_rule,
    filter_rules,
    form_to_request,
    import_preview_text,
    load_gtk,
    managed_list_import_metadata,
    managed_list_summaries_from_results,
    next_state_change,
    picker_datetime_text,
    picker_text_to_datetime,
    project_daily_schedule,
    rule_to_form,
    snapshot_from_results,
    staged_list_upload_calls,
    staged_native_upload_calls,
    utf8_text_chunks,
)
from distraction_blocker.model import ManagedList, Rule
from distraction_blocker.transfer import ImportIssue, ImportPreview


RULE_ID = "12345678-1234-5678-1234-567812345678"
LIST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SECOND_RULE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def make_rule(
    *,
    rule_id: str = RULE_ID,
    name: str = "Focus",
    enabled: bool = True,
    targets: list[dict[str, str]] | None = None,
    schedule: dict[str, object] | None = None,
    revision: int = 0,
) -> Rule:
    return Rule.from_dict(
        {
            "id": rule_id,
            "name": name,
            "enabled": enabled,
            "targets": targets or [{"kind": "website", "value": "example.com"}],
            "schedule": schedule or {"kind": "indefinite"},
            "revision": revision,
        }
    )


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

        editor = RuleEditor.__new__(RuleEditor)
        editor.name_entry = TextField()
        editor.website_view = TextView()
        editor.application_paths = []
        editor._render_applications = lambda: None
        editor.managed_list_checks = {}
        editor.schedule_dropdown = Dropdown()
        editor.schedule_stack = Stack()
        editor.one_start = Picker()
        editor.one_end = Picker()
        editor.weekly_rows = []
        editor._remove_weekly_period = editor.weekly_rows.remove
        editor._add_weekly_period = editor.weekly_rows.append
        weekly = make_rule(
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
        editor._populate(rule_to_form(indefinite, "UTC"))

        self.assertEqual(editor.weekly_rows, [])


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


class FocusAndTransitionTests(unittest.TestCase):
    def test_focus_rule_copies_targets_for_exact_duration(self) -> None:
        source = make_rule(
            name="Work block",
            targets=[
                {"kind": "website", "value": "example.com"},
                {"kind": "managed_list", "value": LIST_ID},
            ],
        )
        now = datetime(2026, 8, 14, 12, 0, 30, tzinfo=UTC)

        focus = create_focus_rule(
            source,
            30,
            now,
            id_factory=lambda: UUID(SECOND_RULE_ID),
        )

        self.assertEqual(focus.id, SECOND_RULE_ID)
        self.assertEqual(focus.name, "Focus: Work block")
        self.assertEqual(focus.targets, source.targets)
        self.assertTrue(focus.enabled)
        self.assertEqual(
            focus.to_dict()["schedule"],
            {
                "kind": "one_time",
                "start_utc": "2026-08-14T12:00:30.000000Z",
                "end_utc": "2026-08-14T12:30:30.000000Z",
            },
        )

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

    def test_snapshot_uses_integer_active_counts(self) -> None:
        rule = make_rule()
        snapshot = snapshot_from_results(
            {
                "healthy": True,
                "clock_trusted": True,
                "clock_reason": "",
                "active_counts": {"website": 203, "application": 2},
            },
            (rule.to_dict(),),
            (),
        )

        self.assertEqual(snapshot.active_websites, 203)
        self.assertEqual(snapshot.active_applications, 2)
        with self.assertRaisesRegex(FormError, "active counts"):
            snapshot_from_results(
                {
                    "healthy": True,
                    "clock_trusted": True,
                    "clock_reason": "",
                    "active_counts": {"website": [], "application": 0},
                },
                (),
                (),
            )


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


if __name__ == "__main__":
    unittest.main()
