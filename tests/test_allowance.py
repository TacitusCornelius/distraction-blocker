import unittest
from datetime import datetime, timedelta, timezone

from distraction_blocker.allowance import (
    AllowanceError,
    AllowanceUsageReport,
    AllowanceUsageState,
    UsageInterval,
    allowance_decision,
    occurrence_at,
    occurrences_between,
)
from distraction_blocker.model import Rule


UTC = timezone.utc
RULE_ID = "12345678-1234-5678-9234-567812345678"


def rule(periods, allowances, *, timezone_name="UTC", daily_cap=None):
    return Rule.from_dict({
        "id": RULE_ID,
        "name": "Allowance",
        "enabled": True,
        "targets": [{"kind": "url_path", "value": "example.test/path"}],
        "schedule": {
            "kind": "weekly",
            "timezone": timezone_name,
            "periods": periods,
        },
        "revision": 0,
        "allowance_time": {
            "periods": allowances,
            "daily_cap_seconds": daily_cap,
        },
    })


def at(hour, minute=0, second=0):
    return datetime(2026, 1, 5, hour, minute, second, tzinfo=UTC)


class AllowanceEngineTests(unittest.TestCase):
    def test_occurrence_at_assigns_cross_midnight_to_start_date(self):
        selected = rule(
            [{"weekdays": [0], "start": "23:00", "end": "01:00"}],
            [{"mode": "total", "quota_seconds": 1800}],
        )
        occurrence = occurrence_at(selected.schedule, datetime(2026, 1, 6, 0, 30, tzinfo=UTC))
        self.assertIsNotNone(occurrence)
        self.assertEqual(occurrence.period_index, 0)
        self.assertEqual(occurrence.occurrence_date.isoformat(), "2026-01-05")
        self.assertEqual(occurrence.start_utc, datetime(2026, 1, 5, 23, tzinfo=UTC))
        self.assertEqual(occurrence.end_utc, datetime(2026, 1, 6, 1, tzinfo=UTC))

    def test_total_budget_counts_union_once_and_ignores_future_usage(self):
        selected = rule(
            [{"weekdays": [0], "start": "09:00", "end": "10:00"}],
            [{"mode": "total", "quota_seconds": 1800}],
        )
        decision = allowance_decision(
            selected,
            at(9, 30),
            (
                UsageInterval(at(9, 5), at(9, 20)),
                UsageInterval(at(9, 10), at(9, 25)),
                UsageInterval(at(9, 40), at(9, 50)),
            ),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.period_used_seconds, 1200)
        self.assertEqual(decision.period_remaining_seconds, 600)
        self.assertEqual(decision.remaining_seconds, 600)

    def test_each_period_occurrence_has_independent_total_budget(self):
        selected = rule(
            [
                {"weekdays": [0], "start": "09:00", "end": "10:00"},
                {"weekdays": [1], "start": "09:00", "end": "10:00"},
            ],
            [
                {"mode": "total", "quota_seconds": 600},
                {"mode": "total", "quota_seconds": 600},
            ],
        )
        monday = allowance_decision(
            selected,
            at(9, 30),
            (UsageInterval(at(9), at(9, 10)),),
        )
        tuesday = allowance_decision(
            selected,
            datetime(2026, 1, 6, 9, 30, tzinfo=UTC),
            (UsageInterval(at(9), at(9, 10)),),
        )
        self.assertEqual(monday.period_remaining_seconds, 0)
        self.assertEqual(tuesday.period_remaining_seconds, 600)

    def test_fixed_window_starts_at_first_usage_and_rolls_forward(self):
        selected = rule(
            [{"weekdays": [0], "start": "09:00", "end": "10:00"}],
            [{"mode": "fixed_window", "quota_seconds": 600, "window_seconds": 1800}],
        )
        decision = allowance_decision(
            selected,
            at(9, 20),
            (UsageInterval(at(9, 5), at(9, 15)),),
        )
        self.assertEqual(decision.window_start_utc, at(9, 5))
        self.assertEqual(decision.window_end_utc, at(9, 35))
        self.assertEqual(decision.period_used_seconds, 600)
        self.assertEqual(decision.period_remaining_seconds, 0)
        self.assertFalse(decision.allowed)

        refreshed = allowance_decision(
            selected,
            at(9, 36),
            (UsageInterval(at(9, 5), at(9, 15)),),
        )
        self.assertEqual(refreshed.window_start_utc, at(9, 36))
        self.assertEqual(refreshed.period_used_seconds, 0)
        self.assertTrue(refreshed.allowed)

        continued = allowance_decision(
            selected,
            at(9, 36),
            (
                UsageInterval(at(9, 5), at(9, 15)),
                UsageInterval(at(9, 34), at(9, 40)),
            ),
        )
        self.assertEqual(continued.window_start_utc, at(9, 35))
        self.assertEqual(continued.period_used_seconds, 60)
        self.assertTrue(continued.allowed)
        boundary_gap = allowance_decision(
            selected,
            at(9, 36),
            (
                UsageInterval(at(9, 5), at(9, 15)),
                UsageInterval(at(9, 34), at(9, 35)),
            ),
        )
        self.assertEqual(boundary_gap.window_start_utc, at(9, 36))
        self.assertEqual(boundary_gap.period_used_seconds, 0)
        self.assertTrue(boundary_gap.allowed)

        first_navigation = allowance_decision(selected, at(9, 35))
        self.assertEqual(first_navigation.window_start_utc, at(9, 35))
        self.assertTrue(first_navigation.allowed)

    def test_daily_cap_is_shared_by_enabled_periods(self):
        selected = rule(
            [
                {"weekdays": [0], "start": "09:00", "end": "10:00"},
                {"weekdays": [0], "start": "11:00", "end": "12:00"},
            ],
            [
                {"mode": "total", "quota_seconds": 1800},
                {"mode": "total", "quota_seconds": 1800},
            ],
            daily_cap=600,
        )
        decision = allowance_decision(
            selected,
            at(11, 30),
            (UsageInterval(at(9), at(9, 8, 20)),),
        )
        self.assertEqual(decision.daily_used_seconds, 500)
        self.assertEqual(decision.daily_remaining_seconds, 100)
        self.assertEqual(decision.remaining_seconds, 100)

    def test_strict_period_is_always_blocked(self):
        selected = rule(
            [{"weekdays": [0], "start": "09:00", "end": "10:00"}],
            [{"mode": "strict"}],
        )
        decision = allowance_decision(selected, at(9, 1))
        self.assertTrue(decision.active)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.remaining_seconds, 0)

    def test_daily_cap_resets_at_rule_local_midnight(self):
        selected = rule(
            [{"weekdays": [0], "start": "00:30", "end": "02:00"}],
            [{"mode": "total", "quota_seconds": 3600}],
            timezone_name="America/New_York",
            daily_cap=600,
        )
        now = datetime(2026, 1, 5, 6, 0, tzinfo=UTC)
        decision = allowance_decision(
            selected,
            now,
            (UsageInterval(datetime(2026, 1, 5, 4, 30, tzinfo=UTC), datetime(2026, 1, 5, 5, tzinfo=UTC)),),
        )
        self.assertEqual(decision.daily_used_seconds, 0)
        self.assertEqual(decision.daily_remaining_seconds, 600)

    def test_dst_spring_forward_uses_real_elapsed_duration(self):
        selected = rule(
            [{"weekdays": [6], "start": "01:00", "end": "04:00"}],
            [{"mode": "total", "quota_seconds": 10800}],
            timezone_name="America/New_York",
        )
        occurrences = occurrences_between(
            selected.schedule,
            datetime(2026, 3, 8, tzinfo=UTC),
            datetime(2026, 3, 9, tzinfo=UTC),
        )
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0].end_utc - occurrences[0].start_utc, timedelta(hours=2))

    def test_dst_fall_back_uses_real_elapsed_duration(self):
        selected = rule(
            [{"weekdays": [6], "start": "01:00", "end": "04:00"}],
            [{"mode": "total", "quota_seconds": 10800}],
            timezone_name="America/New_York",
        )
        occurrences = occurrences_between(
            selected.schedule,
            datetime(2026, 11, 1, tzinfo=UTC),
            datetime(2026, 11, 2, tzinfo=UTC),
        )
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0].end_utc - occurrences[0].start_utc, timedelta(hours=4))

    def test_nonexistent_dst_boundary_moves_forward_through_gap(self):
        selected = rule(
            [{"weekdays": [6], "start": "02:30", "end": "05:00"}],
            [{"mode": "total", "quota_seconds": 3600}],
            timezone_name="America/New_York",
        )
        occurrences = occurrences_between(
            selected.schedule,
            datetime(2026, 3, 8, tzinfo=UTC),
            datetime(2026, 3, 9, tzinfo=UTC),
        )
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0].start_utc, datetime(2026, 3, 8, 7, 30, tzinfo=UTC))
        self.assertEqual(occurrences[0].end_utc, datetime(2026, 3, 8, 9, tzinfo=UTC))

    def test_usage_state_round_trip_and_duplicate_identity(self):
        report = AllowanceUsageReport(
            "22345678-1234-5678-9234-567812345678",
            RULE_ID,
            at(9),
            at(9, 1),
        )
        state = AllowanceUsageState.empty().record(report)
        self.assertTrue(state.contains(report.report_id))
        self.assertEqual(state.record(report), state)
        restored = AllowanceUsageState.from_dict(state.to_dict())
        self.assertEqual(restored, state)
        self.assertEqual(len(restored.for_rule(RULE_ID)), 1)

    def test_invalid_usage_and_non_weekly_inputs_fail_closed(self):
        selected = rule(
            [{"weekdays": [0], "start": "09:00", "end": "10:00"}],
            [{"mode": "total", "quota_seconds": 600}],
        )
        with self.assertRaises(AllowanceError):
            UsageInterval(at(9), at(9))
        with self.assertRaises(AllowanceError):
            allowance_decision(selected, at(9), (object(),))
        no_allowance_data = selected.to_dict()
        no_allowance_data.pop("allowance_time")
        no_allowance = Rule.from_dict(no_allowance_data)
        self.assertIsNone(allowance_decision(no_allowance, at(9)))


if __name__ == "__main__":
    unittest.main()
