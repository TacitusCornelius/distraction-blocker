import unittest
from datetime import datetime, timezone
import uuid

from distraction_blocker.model import ManagedList, Policy, Rule, Schedule, Target, ValidationError


LIST_ID = "11111111-1111-4111-8111-111111111111"


def managed_list():
    return ManagedList.from_dict({
        "id": LIST_ID,
        "name": "Starter",
        "source": "built-in:test",
        "version": "1",
        "license": "Test license",
        "imported_utc": "2026-01-01T00:00:00Z",
        "domains": ["Example.COM."],
    })


class ModelTests(unittest.TestCase):
    def test_target_normalizes_idna_and_rejects_paths(self):
        self.assertEqual(Target.from_dict({"kind": "website", "value": "Bücher.Example."}).value, "xn--bcher-kva.example")
        with self.assertRaises(ValidationError):
            Target.from_dict({"kind": "website", "value": "example.test/path"})

    def test_managed_list_target_and_reference_validation(self):
        item = managed_list()
        target = Target.from_dict({"kind": "managed_list", "value": LIST_ID.upper()})
        self.assertEqual(target.value, LIST_ID)
        rule = Rule.from_dict({"id": str(uuid.uuid4()), "name": "x", "enabled": True, "targets": [target.to_dict()], "schedule": {"kind": "indefinite"}, "revision": 0})
        policy = Policy.from_dict({"revision": 1, "rules": [rule.to_dict()], "managed_lists": [item.to_dict()]})
        self.assertEqual(policy.managed_lists[0].domains, ("example.com",))
        with self.assertRaises(ValidationError):
            Policy.from_dict({"revision": 1, "rules": [rule.to_dict()], "managed_lists": []})

    def test_rejects_bool_integer_and_unknown_field(self):
        with self.assertRaises(ValidationError):
            Schedule.from_dict({"kind": "weekly", "timezone": "UTC", "periods": [{"weekdays": [True], "start": "09:00", "end": "10:00"}]})
        with self.assertRaises(ValidationError):
            Target.from_dict({"kind": "website", "value": "example.test", "extra": 1})

    def test_one_time_boundaries_and_untrusted_fail_closed(self):
        schedule = Schedule.from_dict({"kind": "one_time", "start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T01:00:00Z"})
        self.assertTrue(schedule.is_active(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 1, 1, 0, tzinfo=timezone.utc)))
        rule = Rule.from_dict({"id": str(uuid.uuid4()), "name": "x", "enabled": True, "targets": [{"kind": "website", "value": "example.test"}], "schedule": schedule.to_dict(), "revision": 0})
        self.assertTrue(rule.is_active(datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc), clock_trusted=False))

    def test_weekly_period_union_across_midnight(self):
        schedule = Schedule.from_dict({"kind": "weekly", "timezone": "America/New_York", "periods": [
            {"weekdays": [4], "start": "23:00", "end": "01:00"},
            {"weekdays": [0], "start": "09:00", "end": "10:00"},
        ]})
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 4, 30, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 5, 30, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 3, 7, 0, tzinfo=timezone.utc)))

    def test_policy_round_trip(self):
        policy = Policy.from_dict({"revision": 1, "rules": [], "managed_lists": [managed_list().to_dict()]})
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)


if __name__ == "__main__":
    unittest.main()
