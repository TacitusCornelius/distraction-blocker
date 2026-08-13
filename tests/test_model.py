import unittest
from datetime import datetime, timezone
import uuid

from distraction_blocker.model import Policy, Rule, Schedule, Target, ValidationError


class ModelTests(unittest.TestCase):
    def test_target_normalizes_idna_and_rejects_paths(self):
        self.assertEqual(Target.from_dict({"kind": "website", "value": "Bücher.Example."}).value, "xn--bcher-kva.example")
        with self.assertRaises(ValidationError):
            Target.from_dict({"kind": "website", "value": "example.test/path"})

    def test_rejects_bool_integer_and_unknown_field(self):
        with self.assertRaises(ValidationError):
            Schedule.from_dict({"kind": "weekly", "timezone": "UTC", "weekdays": [True], "start": "09:00", "end": "10:00"})
        with self.assertRaises(ValidationError):
            Target.from_dict({"kind": "website", "value": "example.test", "extra": 1})

    def test_one_time_boundaries_and_untrusted_fail_closed(self):
        schedule = Schedule.from_dict({"kind": "one_time", "start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T01:00:00Z"})
        self.assertTrue(schedule.is_active(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 1, 1, 0, tzinfo=timezone.utc)))
        rule = Rule.from_dict({"id": str(uuid.uuid4()), "name": "x", "enabled": True, "targets": [{"kind": "website", "value": "example.test"}], "schedule": schedule.to_dict(), "revision": 0})
        self.assertTrue(rule.is_active(datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc), clock_trusted=False))

    def test_weekly_midnight_and_dst(self):
        schedule = Schedule.from_dict({"kind": "weekly", "timezone": "America/New_York", "weekdays": [4], "start": "23:00", "end": "01:00"})
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 4, 30, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 5, 30, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 3, 7, 0, tzinfo=timezone.utc)))

    def test_policy_round_trip(self):
        policy = Policy.from_dict({"revision": 1, "rules": []})
        self.assertEqual(policy.to_dict(), {"revision": 1, "rules": []})


if __name__ == "__main__":
    unittest.main()
