import unittest
from datetime import datetime, timezone
import uuid

from distraction_blocker.model import (
    MAX_ALLOWANCE_STARTS,
    POLICY_SCHEMA_VERSION,
    ManagedList,
    Policy,
    PolicyProjection,
    Rule,
    Schedule,
    Target,
    ValidationError,
)


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
        target = Target.from_dict({"kind": "managed_list", "value": LIST_ID})
        self.assertEqual(target.value, LIST_ID)
        rule = Rule.from_dict({"id": str(uuid.uuid4()), "name": "x", "enabled": True, "targets": [target.to_dict()], "schedule": {"kind": "indefinite"}, "revision": 0})
        policy = Policy.from_dict({"schema_version": POLICY_SCHEMA_VERSION, "revision": 1, "rules": [rule.to_dict()], "managed_lists": [item.to_dict()]})
        self.assertEqual(policy.managed_lists[0].domains, ("example.com",))
        with self.assertRaises(ValidationError):
            Policy.from_dict({"schema_version": POLICY_SCHEMA_VERSION, "revision": 1, "rules": [rule.to_dict()], "managed_lists": []})

    def test_ids_accept_only_canonical_uuids(self):
        # Breadcrumb: the model demands the same strict canonical form as
        # control.py and statistics.py; IDs are service-generated uuid4 text,
        # so there is no interactive path that needs lenient normalization.
        canonical = str(uuid.uuid4())
        target_dict = {"kind": "website", "value": "example.test"}
        self.assertEqual(Rule.from_dict({"id": canonical, "name": "x", "enabled": True, "targets": [target_dict], "schedule": {"kind": "indefinite"}, "revision": 0}).id, canonical)
        for bad in (canonical.upper(), "{" + canonical + "}", canonical.replace("-", ""), "not-a-uuid", 123):
            with self.assertRaises(ValidationError):
                Rule.from_dict({"id": bad, "name": "x", "enabled": True, "targets": [target_dict], "schedule": {"kind": "indefinite"}, "revision": 0})
            data = managed_list().to_dict()
            data["id"] = bad
            with self.assertRaises(ValidationError):
                ManagedList.from_dict(data)
            with self.assertRaises(ValidationError):
                Target.from_dict({"kind": "managed_list", "value": bad})

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

    def test_pomodoro_round_trip_and_half_open_transitions(self):
        schedule = Schedule.from_dict({
            "kind": "pomodoro",
            "start_utc": "2026-01-01T00:00:00Z",
            "work_minutes": 25,
            "break_minutes": 5,
            "cycles": 2,
        })
        self.assertEqual(Schedule.from_dict(schedule.to_dict()), schedule)
        self.assertFalse(schedule.is_active(datetime(2025, 12, 31, 23, 59, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 1, 0, 25, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 1, 0, 27, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 1, 0, 54, 59, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 1, 0, 55, tzinfo=timezone.utc)))

    def test_pomodoro_rejects_invalid_limits_and_fields(self):
        base = {
            "kind": "pomodoro",
            "start_utc": "2026-01-01T00:00:00Z",
            "work_minutes": 25,
            "break_minutes": 5,
            "cycles": 2,
        }
        for field, values in {
            "work_minutes": (0, 181),
            "break_minutes": (0, 61),
            "cycles": (0, 21),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    invalid = dict(base, **{field: value})
                    with self.assertRaises(ValidationError):
                        Schedule.from_dict(invalid)
        with self.assertRaises(ValidationError):
            Schedule.from_dict(dict(base, extra=True))
        with self.assertRaises(ValidationError):
            Schedule.from_dict({key: value for key, value in base.items() if key != "cycles"})

    def test_untrusted_pomodoro_rule_stays_active_during_break(self):
        schedule = Schedule.from_dict({
            "kind": "pomodoro",
            "start_utc": "2026-01-01T00:00:00Z",
            "work_minutes": 25,
            "break_minutes": 5,
            "cycles": 2,
        })
        rule = Rule.from_dict({
            "id": str(uuid.uuid4()),
            "name": "focus",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.test"}],
            "schedule": schedule.to_dict(),
            "revision": 0,
        })
        self.assertTrue(rule.is_active(datetime(2026, 1, 1, 0, 27, tzinfo=timezone.utc), clock_trusted=False))
        self.assertTrue(rule.is_active(datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc), clock_trusted=False))

    def test_weekly_period_union_across_midnight(self):
        schedule = Schedule.from_dict({"kind": "weekly", "timezone": "America/New_York", "periods": [
            {"weekdays": [4], "start": "23:00", "end": "01:00"},
            {"weekdays": [0], "start": "09:00", "end": "10:00"},
        ]})
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 4, 30, tzinfo=timezone.utc)))
        self.assertTrue(schedule.is_active(datetime(2026, 1, 3, 5, 30, tzinfo=timezone.utc)))
        self.assertFalse(schedule.is_active(datetime(2026, 1, 3, 7, 0, tzinfo=timezone.utc)))

    def test_existing_schedule_kinds_round_trip(self):
        schedules = (
            {"kind": "indefinite"},
            {"kind": "one_time", "start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T01:00:00Z"},
            {"kind": "weekly", "timezone": "UTC", "periods": [{"weekdays": [0], "start": "09:00", "end": "10:00"}]},
        )
        for data in schedules:
            with self.subTest(kind=data["kind"]):
                schedule = Schedule.from_dict(data)
                self.assertEqual(Schedule.from_dict(schedule.to_dict()), schedule)

    def test_policy_round_trip(self):
        policy = Policy.from_dict({"schema_version": POLICY_SCHEMA_VERSION, "revision": 1, "rules": [], "managed_lists": [managed_list().to_dict()]})
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)
        self.assertEqual(policy.to_dict()["schema_version"], POLICY_SCHEMA_VERSION)

    def test_policy_refuses_missing_or_unknown_schema_version(self):
        # Breadcrumb: storage migrates verified old envelopes. Public model
        # input remains strict, so callers cannot guess a future schema.
        base = {"revision": 1, "rules": [], "managed_lists": []}
        with self.assertRaises(ValidationError):
            Policy.from_dict(base)
        for version in (POLICY_SCHEMA_VERSION - 1, POLICY_SCHEMA_VERSION + 1):
            with self.subTest(version=version):
                with self.assertRaises(ValidationError):
                    Policy.from_dict({"schema_version": version, **base})
                with self.assertRaises(ValidationError):
                    Policy(1, (), (), version)




class UrlTargetTests(unittest.TestCase):
    def test_url_target_kinds_canonicalize_and_round_trip(self):
        cases = (
            ({"kind": "url_path", "value": "Example.COM/feed"},
             {"kind": "url_path", "value": "example.com/feed"}),
            ({"kind": "url_path", "value": "example.com/"},
             {"kind": "url_path", "value": "example.com/"}),
            ({"kind": "url_wildcard", "value": "example.com/vid/*"},
             {"kind": "url_wildcard", "value": "example.com/vid/*"}),
            ({"kind": "url_keyword", "value": "  Casino "},
             {"kind": "url_keyword", "value": "casino"}),
        )
        for raw, expected in cases:
            with self.subTest(value=raw["value"]):
                target = Target.from_dict(raw)
                self.assertEqual(target.to_dict(), expected)
                self.assertEqual(Target.from_dict(target.to_dict()), target)

    def test_url_target_rejects_invalid_values(self):
        bad = (
            {"kind": "url_path", "value": "example.com"},
            {"kind": "url_path", "value": "example.com/a?x=1"},
            {"kind": "url_path", "value": "example.com/a#top"},
            {"kind": "url_path", "value": "example.com/a*"},
            {"kind": "url_path", "value": "example.com/sp ace"},
            {"kind": "url_wildcard", "value": "*.example.com/*"},
            {"kind": "url_wildcard", "value": "example.com/*a*"},
            {"kind": "url_wildcard", "value": "example.com/vid"},
            {"kind": "url_keyword", "value": "a"},
            {"kind": "url_keyword", "value": "two words"},
            {"kind": "url_keyword", "value": "x" * 65},
        )
        for data in bad:
            with self.subTest(value=data["value"]):
                with self.assertRaises(ValidationError):
                    Target.from_dict(data)

    def test_policy_round_trips_url_targets(self):
        policy = Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 1,
            "rules": [{
                "id": "12345678-1234-5678-1234-567812345678",
                "name": "URL",
                "enabled": True,
                "targets": [
                    {"kind": "url_path", "value": "example.com/feed"},
                    {"kind": "url_wildcard", "value": "example.com/v/*"},
                    {"kind": "url_keyword", "value": "casino"},
                ],
                "schedule": {"kind": "indefinite"},
                "revision": 0,
            }],
            "managed_lists": [],
        })
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)
    def test_policy_round_trips_url_exceptions_and_rejects_network(self):
        rule = {
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "URL",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "exceptions": [
                {"kind": "url_path", "value": "example.com/allowed"},
                {"kind": "youtube_video", "value": "dQw4w9WgXcQ"},
            ],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        }
        policy = Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 1,
            "rules": [rule],
            "managed_lists": [],
        })
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)
        with self.assertRaises(ValidationError):
            Rule.from_dict({
                **rule,
                "exceptions": [{"kind": "network", "value": "vpn"}],
            })


class YoutubeTargetTests(unittest.TestCase):
    def test_youtube_target_kinds_validate(self):
        good = Target.from_dict(
            {"kind": "youtube_video", "value": "dQw4w9WgXcQ"}
        )
        self.assertEqual(good.value, "dQw4w9WgXcQ")
        channel = Target.from_dict(
            {"kind": "youtube_channel", "value": "@Example.Handle"}
        )
        self.assertEqual(channel.value, "@Example.Handle")
        channel_id = Target.from_dict(
            {"kind": "youtube_channel", "value": "UC" + "a1_-" * 5 + "ab"}
        )
        self.assertEqual(len(channel_id.value), 24)
        bad = (
            ("youtube_video", "short"),
            ("youtube_video", "waytoolongvideo"),
            ("youtube_channel", "@no"),
            ("youtube_channel", "UC" + "*" * 22),
        )
        for kind, value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    Target.from_dict({"kind": kind, "value": value})




class NetworkTargetTests(unittest.TestCase):
    # Breadcrumb: a network target carries a fixed control name from the
    # closed NETWORK_CONTROLS set, never raw firewall input.

    def test_network_control_values_round_trip(self):
        for value in ("whole_internet", "alternate_dns", "safe_search", "doh", "proxy", "vpn"):
            with self.subTest(value=value):
                target = Target.from_dict({"kind": "network", "value": value})
                self.assertEqual(target.to_dict(), {"kind": "network", "value": value})
                self.assertEqual(Target.from_dict(target.to_dict()), target)

    def test_network_target_rejects_unknown_and_raw_values(self):
        bad = (
            "whole-internet",
            "dns",
            "safe_search extra",
            "ip6tables -A OUTPUT",
            "1.2.3.4",
            "",
        )
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    Target.from_dict({"kind": "network", "value": value})
        # Breadcrumb: a non-string cannot masquerade as a control name.
        with self.assertRaises(ValidationError):
            Target.from_dict({"kind": "network", "value": 53})

    def test_network_targets_round_trip_through_policy(self):
        policy = Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 1,
            "rules": [{
                "id": "12345678-1234-5678-9234-567812345678",
                "name": "Network",
                "enabled": True,
                "targets": [
                    {"kind": "network", "value": "safe_search"},
                    {"kind": "network", "value": "alternate_dns"},
                    {"kind": "website", "value": "example.test"},
                ],
                "schedule": {"kind": "indefinite"},
                "revision": 0,
            }],
            "managed_lists": [],
        })
        self.assertEqual(Policy.from_dict(policy.to_dict()), policy)

    def test_network_targets_refuse_allowance(self):
        # Breadcrumb: network controls have no URL-level start events the
        # extension can count, so a budget cannot apply to them.
        with self.assertRaisesRegex(
            ValidationError, "URL-level targets"
        ):
            Rule.from_dict(
                allowance_rule_dict(
                    targets=[{"kind": "network", "value": "safe_search"}],
                    allowance_starts=5,
                )
            )




RULE_ID = "12345678-1234-5678-9234-567812345678"

def allowance_rule_dict(**extra):
    data = {
        "id": RULE_ID,
        "name": "Budgeted",
        "enabled": True,
        "targets": [
            {
                "kind": "url_path"
                if extra.get("allowance_starts") is not None
                else "website",
                "value": "example.com/feed"
                if extra.get("allowance_starts") is not None
                else "example.com",
            }
        ],
        "schedule": {"kind": "indefinite"},
        "revision": 0,
    }
    data.update(extra)
    return data


class AllowanceStartsTests(unittest.TestCase):
    # Breadcrumb: allowance_starts is the first OPTIONAL rule field, so its
    # absence and presence must both round-trip through the signed policy.

    def test_absent_field_round_trips_as_none(self):
        rule = Rule.from_dict(allowance_rule_dict())
        self.assertIsNone(rule.allowance_starts)
        self.assertNotIn("allowance_starts", rule.to_dict())

    def test_positive_integer_round_trips(self):
        rule = Rule.from_dict(allowance_rule_dict(allowance_starts=5))
        self.assertEqual(rule.allowance_starts, 5)
        self.assertEqual(rule.to_dict()["allowance_starts"], 5)
        reparsed = Rule.from_dict(rule.to_dict())
        self.assertEqual(reparsed, rule)

    def test_rejects_bool_zero_negative_and_non_int(self):
        for bad in (
            True,
            False,
            0,
            -1,
            "5",
            5.0,
            None,
            MAX_ALLOWANCE_STARTS + 1,
        ):
            with self.assertRaises(ValidationError):
                Rule.from_dict(allowance_rule_dict(allowance_starts=bad))

    def test_unknown_field_is_refused(self):
        with self.assertRaises(ValidationError):
            Rule.from_dict(allowance_rule_dict(allowance_startss=5))


    def test_rejects_allowance_for_non_url_targets(self):
        with self.assertRaisesRegex(
            ValidationError, "URL-level targets"
        ):
            Rule.from_dict(
                allowance_rule_dict(
                    targets=[{"kind": "website", "value": "example.com"}],
                    allowance_starts=5,
                )
            )


class PolicyProjectionTests(unittest.TestCase):
    def _rule(self):
        return allowance_rule_dict(allowance_starts=5)

    def test_round_trips_strict_projection(self):
        projection = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 9,
            "rules": [
                {**self._rule(), "budget_exhausted": False},
            ],
        }
        self.assertEqual(
            PolicyProjection.from_dict(projection).to_dict(),
            projection,
        )

    def test_rejects_bool_versions_and_invalid_rule_mappings(self):
        base = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 0,
            "rules": [],
        }
        for field in ("schema_version", "revision"):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    PolicyProjection.from_dict({**base, field: True})
        invalid_rule = self._rule()
        invalid_rule["budget_exhausted"] = False
        invalid_rule["extra"] = True
        with self.assertRaises(ValidationError):
            PolicyProjection.from_dict(
                {**base, "rules": [invalid_rule]}
            )


if __name__ == "__main__":
    unittest.main()
