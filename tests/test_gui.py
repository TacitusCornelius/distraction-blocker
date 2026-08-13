from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime
from uuid import UUID

from distraction_blocker.gui import (
    FormError,
    GtkUnavailableError,
    RuleForm,
    form_to_request,
    load_gtk,
    next_state_change,
    rule_to_form,
)
from distraction_blocker.model import Rule


RULE_ID = "12345678-1234-5678-1234-567812345678"


class GtkLoadingTests(unittest.TestCase):
    def test_missing_binding_has_clear_error(self) -> None:
        def missing(_name: str):
            raise ModuleNotFoundError("No module named 'gi'")

        with self.assertRaisesRegex(
            GtkUnavailableError, "GTK 4 Python bindings are not installed"
        ):
            load_gtk(missing)


class FormConversionTests(unittest.TestCase):
    def test_one_time_form_converts_local_dates_to_utc(self) -> None:
        form = RuleForm(
            name="  Focus  ",
            websites=("Exämple.COM.",),
            applications=("/usr/bin/python3",),
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
        self.assertEqual(rule["revision"], 0)
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

    def test_weekly_form_converts_weekdays_and_clock_values(self) -> None:
        form = RuleForm(
            name="Weekday block",
            websites=("news.example",),
            applications=(),
            schedule_kind="weekly",
            timezone="Europe/Berlin",
            weekdays=(4, 0, 2),
            weekly_start="08:15",
            weekly_end="07:45",
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(
            rule["schedule"],
            {
                "kind": "weekly",
                "timezone": "Europe/Berlin",
                "weekdays": [0, 2, 4],
                "start": "08:15:00",
                "end": "07:45:00",
            },
        )

    def test_indefinite_form_uses_manual_stop_schedule(self) -> None:
        form = RuleForm(
            name="Manual block",
            websites=(),
            applications=("/bin/echo",),
            schedule_kind="indefinite",
            timezone="UTC",
        )

        rule = form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]

        self.assertEqual(rule["schedule"], {"kind": "indefinite"})

    def test_edit_preserves_service_identity_and_revision(self) -> None:
        existing = Rule.from_dict(
            {
                "id": RULE_ID,
                "name": "Old name",
                "enabled": False,
                "targets": [{"kind": "website", "value": "old.example"}],
                "schedule": {"kind": "indefinite"},
                "revision": 7,
            }
        )
        form = RuleForm(
            name="New name",
            websites=("new.example",),
            applications=(),
            schedule_kind="indefinite",
            timezone="UTC",
        )

        rule = form_to_request(form, existing=existing)["rule"]

        self.assertEqual(rule["id"], RULE_ID)
        self.assertFalse(rule["enabled"])
        self.assertEqual(rule["revision"], 7)
        self.assertEqual(rule["name"], "New name")

    def test_rule_round_trip_keeps_weekly_form_values(self) -> None:
        rule = Rule.from_dict(
            {
                "id": RULE_ID,
                "name": "Weekly",
                "enabled": True,
                "targets": [{"kind": "website", "value": "example.com"}],
                "schedule": {
                    "kind": "weekly",
                    "timezone": "UTC",
                    "weekdays": [0, 6],
                    "start": "09:00",
                    "end": "17:00",
                },
                "revision": 2,
            }
        )

        form = rule_to_form(rule, "America/New_York")

        self.assertEqual(form.timezone, "UTC")
        self.assertEqual(form.weekdays, (0, 6))
        self.assertEqual(form.weekly_start, "09:00:00")
        self.assertEqual(form.weekly_end, "17:00:00")

    def test_form_requires_a_target(self) -> None:
        form = RuleForm(
            name="Empty",
            websites=(),
            applications=(),
            schedule_kind="indefinite",
            timezone="UTC",
        )

        with self.assertRaisesRegex(FormError, "Add at least one"):
            form_to_request(form, id_factory=lambda: UUID(RULE_ID))

    def test_one_time_next_change_moves_from_start_to_end(self) -> None:
        form = RuleForm(
            name="Window",
            websites=("example.com",),
            applications=(),
            schedule_kind="one_time",
            timezone="UTC",
            one_time_start="2026-08-14 09:00",
            one_time_end="2026-08-14 10:00",
        )
        rule = Rule.from_dict(
            form_to_request(form, id_factory=lambda: UUID(RULE_ID))["rule"]
        )

        before = next_state_change(rule, datetime(2026, 8, 14, 8, tzinfo=UTC))
        active = next_state_change(rule, datetime(2026, 8, 14, 9, 30, tzinfo=UTC))

        self.assertEqual(before.at_utc, datetime(2026, 8, 14, 9, tzinfo=UTC))
        self.assertTrue(before.active_after)
        self.assertEqual(active.at_utc, datetime(2026, 8, 14, 10, tzinfo=UTC))
        self.assertFalse(active.active_after)

    def test_weekly_next_change_handles_dst_fall_back(self) -> None:
        rule = Rule.from_dict({
            "id": RULE_ID,
            "name": "Fold",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {
                "kind": "weekly",
                "timezone": "America/New_York",
                "weekdays": [6],
                "start": "00:30",
                "end": "01:30",
            },
            "revision": 0,
        })
        change = next_state_change(rule, datetime(2026, 11, 1, 5, 45, tzinfo=UTC))
        self.assertEqual(change.at_utc, datetime(2026, 11, 1, 6, 0, tzinfo=UTC))
        self.assertTrue(change.active_after)


if __name__ == "__main__":
    unittest.main()
