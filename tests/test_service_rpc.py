import json
import socket
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from distraction_blocker.control import ControlState
from distraction_blocker.model import POLICY_SCHEMA_VERSION, ManagedList, Policy, Rule
from distraction_blocker.rpc import Client, RpcServer, response_fits
from distraction_blocker.service import BlockerService
from distraction_blocker.transfer import native_export_text
from distraction_blocker.statistics import (
    DenialBuffer,
    StatisticsState,
    WebsiteDenialState,
    WebsiteUsageState,
)


class FakeClock:
    trusted = True
    reason = ""

    def __init__(self, current=None):
        self.current = current or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self):
        return self.current

    def checkpoint(self):
        return None

    def clear_latch(self):
        self.trusted = True
        return self.current

class FakeStore:

    def __init__(self, policy, controls=None, statistics=None):
        self.policy = policy
        self.controls = controls or ControlState.empty()
        self.statistics = statistics or StatisticsState.empty()
        self.website_statistics = WebsiteDenialState.empty()
        self.website_usage = WebsiteUsageState.empty()
        self.statistics_saves = []
        self.fail_statistics = False
        self.fail_policy = False

    def initialize(self):
        return None

    def load_statistics(self):
        return self.statistics

    def save_statistics(self, state):
        if self.fail_statistics:
            raise OSError("statistics storage unavailable")
        self.statistics = state
        self.statistics_saves.append(state)
        return None

    def load_website_statistics(self):
        return self.website_statistics

    def save_website_statistics(self, state):
        if self.fail_statistics:
            raise OSError("statistics storage unavailable")
        self.website_statistics = state
        return None

    def load_website_usage(self):
        return self.website_usage

    def save_website_usage(self, state):
        if self.fail_statistics:
            raise OSError("statistics storage unavailable")
        self.website_usage = state
        return None

    def initialize(self):
        return None

    def load_statistics(self):
        return self.statistics

    def save_statistics(self, state):
        if self.fail_statistics:
            raise OSError("statistics storage unavailable")
        self.statistics = state
        self.statistics_saves.append(state)
        return None

    def load(self):
        return type(
            "Load",
            (),
            {
                "policy": self.policy,
                "controls": self.controls,
                "degraded": False,
            },
        )()

    def save(
        self, policy, controls, high_water_utc, clock_untrusted=False
    ):
        if self.fail_policy:
            raise OSError("policy storage unavailable")
        self.policy = policy
        self.controls = controls


class FakeHosts:
    def __init__(self):
        self.values = set()

    def apply(self, values):
        self.values = set(values)


class FakeApplications:
    healthy = True

    def __init__(self):
        self.started = False
        self.values = set()

    def start(self):
        self.started = True

    def set_blocked(self, values):
        self.values = set(values)
    def set_denial_buffer(self, buffer):
        self.denial_buffer = buffer

    def set_rule_ids_provider(self, provider):
        self.rule_ids_provider = provider


class ServiceTests(unittest.TestCase):
    def test_start_order_and_strict_fields(self):
        raw = {"schema_version": POLICY_SCHEMA_VERSION, "revision": 0, "rules": [], "managed_lists": []}
        service = BlockerService(FakeStore(Policy.from_dict(raw)), FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        self.assertTrue(service.applications.started)
        self.assertEqual(service.dispatch(1000, {"command": "status", "extra": 1})["ok"], False)
        self.assertEqual(service.dispatch(1000, {"command": "list_rules"})["ok"], True)

    def test_failed_policy_save_does_not_change_live_enforcement(self):

        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Stored",
            "enabled": False,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (rule,)))
        hosts = FakeHosts()
        service = BlockerService(
            store, FakeClock(), hosts, FakeApplications()
        )
        service.start()
        store.fail_policy = True

        with self.assertRaisesRegex(OSError, "policy storage"):
            service.dispatch(1000, {
                "command": "set_enabled",
                "rule_id": rule.id,
                "enabled": True,
            })

        self.assertEqual(hosts.values, set())
        self.assertFalse(service.policy.rules[0].enabled)
    def test_save_rejects_policy_when_projection_is_too_large(self):
        rules = tuple(
            Rule.from_dict(
                {
                    "id": f"00000000-0000-4000-8000-{index:012d}",
                    "name": f"r{index}",
                    "enabled": True,
                    "targets": [
                        {
                            "kind": "url_path",
                            "value": f"h{index}.example/x",
                        }
                    ],
                    "schedule": {"kind": "indefinite"},
                    "revision": 0,
                }
            )
            for index in range(324)
        )
        store = FakeStore(Policy(0, ()))
        service = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications()
        )
        service.start()
        result = service.dispatch(
            1000,
            {
                "command": "replace_rules",
                "rules": [rule.to_dict() for rule in rules],
            },
        )
        self.assertEqual(result["error"]["code"], "too_large")
        self.assertEqual(store.policy.rules, ())

    def test_denial_stats_drain_associates_all_active_rules_and_clear(self):
        first = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "First",
            "enabled": True,
            "targets": [{"kind": "application", "value": "/usr/bin/example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        second = Rule.from_dict({
            "id": "22345678-1234-5678-1234-567812345678",
            "name": "Second",
            "enabled": True,
            "targets": [{"kind": "application", "value": "/usr/bin/example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (first, second)))
        buffer = DenialBuffer()
        service = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications(), buffer
        )
        service.start()
        self.assertTrue(buffer.record("/usr/bin/example"))
        service.tick()
        result = service.dispatch(1000, {"command": "list_denial_stats"})
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["result"]["items"][0]["rule_ids"],
            [first.id, second.id],
        )
        self.assertEqual(result["result"]["dropped"], 0)
        self.assertTrue(
            service.dispatch(1000, {"command": "clear_denial_stats"})["ok"]
        )
        self.assertEqual(
            service.dispatch(1000, {"command": "list_denial_stats"})["result"],
            {"items": [], "dropped": 0},
        )

    def test_denial_stats_persist_after_interval_and_load_on_restart(self):
        rule = Rule.from_dict({
            "id": "32345678-1234-5678-1234-567812345678",
            "name": "App",
            "enabled": True,
            "targets": [{"kind": "application", "value": "/usr/bin/example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (rule,)))
        buffer = DenialBuffer()
        service = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications(), buffer
        )
        service.start()
        buffer.record("/usr/bin/example")
        service.tick()
        self.assertEqual(store.statistics_saves, [])
        service._last_statistics_persist -= 5
        service.tick()
        self.assertEqual(len(store.statistics_saves), 1)
        restarted = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications(), DenialBuffer()
        )
        restarted.start()
        listed = restarted.dispatch(1000, {"command": "list_denial_stats"})
        self.assertEqual(len(listed["result"]["items"]), 1)

    def test_statistics_storage_failure_keeps_enforcement_healthy(self):
        store = FakeStore(Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 0, "rules": [], "managed_lists": [],
        }))
        buffer = DenialBuffer()
        applications = FakeApplications()
        service = BlockerService(
            store, FakeClock(), FakeHosts(), applications, buffer
        )
        service.start()
        store.fail_statistics = True
        buffer.record("/usr/bin/example")
        service._last_statistics_persist -= 5
        service.tick()
        self.assertTrue(service.healthy)

    def test_clean_close_flushes_pending_statistics(self):
        store = FakeStore(Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 0, "rules": [], "managed_lists": [],
        }))
        buffer = DenialBuffer()
        service = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications(), buffer
        )
        service.start()
        buffer.record("/usr/bin/example")
        service.close()
        self.assertEqual(len(store.statistics_saves), 1)

    def test_active_finite_rule_rejects_weaker_changes(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Work",
            "enabled": True,
            "targets": [
                {"kind": "website", "value": "example.com"},
                {"kind": "application", "value": "/usr/bin/example"},
            ],
            "schedule": {
                "kind": "one_time",
                "start_utc": "2025-01-01T00:00:00Z",
                "end_utc": "2027-01-01T00:00:00Z",
            },
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), FakeClock(), FakeHosts(), FakeApplications()
        )
        service.start()
        disabled = service.dispatch(
            1000, {"command": "set_enabled", "rule_id": rule.id, "enabled": False}
        )
        self.assertEqual(disabled["error"]["code"], "active_rule")
        deleted = service.dispatch(1000, {"command": "delete_rule", "rule_id": rule.id})
        self.assertEqual(deleted["error"]["code"], "active_rule")
        changed = rule.to_dict()
        changed["targets"] = changed["targets"][:1]
        edited = service.dispatch(1000, {"command": "put_rule", "rule": changed})
        self.assertEqual(edited["error"]["code"], "active_rule")

    def test_indefinite_rule_can_be_disabled_then_deleted(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Manual",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), FakeClock(), FakeHosts(), FakeApplications()
        )
        service.start()
        disabled = service.dispatch(
            1000, {"command": "set_enabled", "rule_id": rule.id, "enabled": False}
        )
        self.assertTrue(disabled["ok"])
        deleted = service.dispatch(1000, {"command": "delete_rule", "rule_id": rule.id})
        self.assertTrue(deleted["ok"])

    def test_timed_lock_blocks_weakening_but_allows_rename_and_root(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Protected",
            "enabled": False,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        clock = FakeClock()
        store = FakeStore(Policy(0, (rule,)))
        service = BlockerService(
            store, clock, FakeHosts(), FakeApplications()
        )
        service.start()
        until = clock.current + timedelta(hours=1)

        locked = service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {
                "kind": "timed",
                "until_utc": until.isoformat().replace("+00:00", "Z"),
            },
        })
        self.assertTrue(locked["ok"])
        self.assertTrue(
            service.dispatch(1000, {"command": "list_locks"})
            ["result"][0]["locked"]
        )
        refused = service.dispatch(
            1000, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertEqual(refused["error"]["code"], "timed_lock")
        renamed = rule.to_dict()
        renamed["name"] = "Renamed"
        self.assertTrue(service.dispatch(
            1000, {"command": "put_rule", "rule": renamed}
        )["ok"])
        deleted = service.dispatch(
            0, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertTrue(deleted["ok"])
        self.assertEqual(store.controls, ControlState.empty())

    def test_timed_lock_expires_only_with_trusted_clock(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Protected",
            "enabled": False,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        clock = FakeClock()
        service = BlockerService(
            FakeStore(Policy(0, (rule,))),
            clock,
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        until = clock.current + timedelta(minutes=5)
        service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {
                "kind": "timed",
                "until_utc": until.isoformat().replace("+00:00", "Z"),
            },
        })
        clock.current = until + timedelta(seconds=1)
        clock.trusted = False
        refused = service.dispatch(
            1000, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertEqual(refused["error"]["code"], "timed_lock")
        clock.trusted = True
        deleted = service.dispatch(
            1000, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertTrue(deleted["ok"])

    def test_friction_authorization_is_exact_and_single_use(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Friction",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        set_lock = service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {"kind": "friction"},
        })
        self.assertTrue(set_lock["ok"])
        refused = service.dispatch(1000, {
            "command": "set_enabled",
            "rule_id": rule.id,
            "enabled": False,
        })
        self.assertEqual(
            refused["error"]["code"], "authorization_required"
        )
        first = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        wrong = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": first["challenge_id"],
            "response": "WRONG",
        })
        self.assertEqual(wrong["error"]["code"], "incorrect_response")
        reused = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": first["challenge_id"],
            "response": first["prompt"],
        })
        self.assertEqual(reused["error"]["code"], "not_found")
        second = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        authorized = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": second["challenge_id"],
            "response": second["prompt"],
        })
        self.assertTrue(authorized["ok"])
        disabled = service.dispatch(1000, {
            "command": "set_enabled",
            "rule_id": rule.id,
            "enabled": False,
        })
        self.assertTrue(disabled["ok"])
        second_change = service.dispatch(
            1000, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertEqual(
            second_change["error"]["code"], "authorization_required"
        )

    def test_friction_challenge_expires_and_native_import_needs_grant(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Friction",
            "enabled": False,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {"kind": "friction"},
        })
        with patch(
            "distraction_blocker.service._authorization_now",
            return_value=100.0,
        ):
            challenge = service.dispatch(1000, {
                "command": "begin_rule_authorization",
                "rule_id": rule.id,
            })["result"]
        with patch(
            "distraction_blocker.service._authorization_now",
            return_value=221.0,
        ):
            expired = service.dispatch(1000, {
                "command": "complete_rule_authorization",
                "rule_id": rule.id,
                "challenge_id": challenge["challenge_id"],
                "response": challenge["prompt"],
            })
        self.assertEqual(expired["error"]["code"], "not_found")

        refused = service.dispatch(
            1000, {"command": "replace_rules", "rules": []}
        )
        self.assertEqual(
            refused["error"]["code"], "authorization_required"
        )
        live = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": live["challenge_id"],
            "response": live["prompt"],
        })
        replaced = service.dispatch(
            1000, {"command": "replace_rules", "rules": []}
        )
        self.assertTrue(replaced["ok"])
        self.assertEqual(service.controls, ControlState.empty())

    def test_password_lock_persists_delay_and_grants_one_change(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Password",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        clock = FakeClock()
        store = FakeStore(Policy(0, (rule,)))
        service = BlockerService(
            store, clock, FakeHosts(), FakeApplications()
        )
        service.start()
        password = "correct horse"
        set_lock = service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {"kind": "password", "password": password},
        })
        self.assertTrue(set_lock["ok"])
        summary = service.dispatch(
            1000, {"command": "list_locks"}
        )["result"][0]
        self.assertEqual(summary["kind"], "password")
        self.assertNotIn(password, str(summary))
        first = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        self.assertIsNone(first["prompt"])
        wrong = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": first["challenge_id"],
            "response": "wrong password",
        })
        self.assertEqual(wrong["error"]["code"], "invalid_password")
        self.assertEqual(store.controls.locks[0].failures, 1)
        portable = native_export_text(store.policy)
        self.assertNotIn(password, portable)
        self.assertNotIn(store.controls.locks[0].salt_hex, portable)
        self.assertNotIn(store.controls.locks[0].digest_hex, portable)
        service = BlockerService(
            store, clock, FakeHosts(), FakeApplications()
        )
        service.start()
        limited = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })
        self.assertEqual(limited["error"]["code"], "rate_limited")
        clock.current += timedelta(seconds=3)
        second = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        authorized = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": second["challenge_id"],
            "response": password,
        })
        self.assertTrue(authorized["ok"])
        self.assertEqual(store.controls.locks[0].failures, 0)
        disabled = service.dispatch(1000, {
            "command": "set_enabled",
            "rule_id": rule.id,
            "enabled": False,
        })
        self.assertTrue(disabled["ok"])
        refused = service.dispatch(
            1000, {"command": "delete_rule", "rule_id": rule.id}
        )
        self.assertEqual(
            refused["error"]["code"], "authorization_required"
        )
        self.assertNotIn(
            store.controls.locks[0].salt_hex,
            str(service.dispatch(1000, {"command": "list_rules"})),
        )

    def test_start_focus_uses_service_time_and_source_targets(self):
        source = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Work",
            "enabled": False,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        clock = FakeClock(
            datetime(2026, 8, 20, 12, 0, 30, tzinfo=timezone.utc)
        )
        service = BlockerService(
            FakeStore(Policy(0, (source,))),
            clock,
            FakeHosts(),
            FakeApplications(),
        )
        service.start()

        result = service.dispatch(1000, {
            "command": "start_focus",
            "rule_id": source.id,
            "minutes": 30,
        })

        self.assertTrue(result["ok"])
        focus = Rule.from_dict(result["result"])
        self.assertEqual(focus.name, "Focus: Work")
        self.assertEqual(focus.targets, source.targets)
        self.assertEqual(
            focus.to_dict()["schedule"],
            {
                "kind": "one_time",
                "start_utc": "2026-08-20T12:00:30.000000Z",
                "end_utc": "2026-08-20T12:30:30.000000Z",
            },
        )
        daily = service.dispatch(1000, {
            "command": "daily_schedule",
            "timezone": "UTC",
            "date": "2026-08-20",
        })
        self.assertTrue(daily["ok"])
        self.assertEqual(
            daily["result"]["intervals"],
            [{
                "rule_id": focus.id,
                "rule_name": focus.name,
                "start": "2026-08-20T12:00:30+00:00",
                "end": "2026-08-20T12:30:30+00:00",
            }],
        )

    def test_tick_applies_a_new_schedule_boundary(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Timed",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {
                "kind": "one_time",
                "start_utc": "2026-01-01T01:00:00Z",
                "end_utc": "2026-01-01T03:00:00Z",
            },
            "revision": 0,
        })
        clock = FakeClock(datetime(2026, 1, 1, 0, tzinfo=timezone.utc))
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), clock, FakeHosts(), FakeApplications()
        )
        service.start()
        self.assertEqual(service.hosts.values, set())
        clock.current = datetime(2026, 1, 1, 2, tzinfo=timezone.utc)
        service.tick()
        self.assertEqual(service.hosts.values, {"example.com"})

    def test_managed_list_expands_and_status_is_bounded(self):
        managed = ManagedList.from_dict({
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "Social",
            "source": "starter",
            "version": "1",
            "license": "CC0",
            "imported_utc": "2026-01-01T00:00:00Z",
            "domains": ["one.example", "two.example"],
        })
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Block list",
            "enabled": True,
            "targets": [{"kind": "managed_list", "value": managed.id}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,), (managed,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        self.assertEqual(service.hosts.values, set(managed.domains))
        status = service.dispatch(1000, {"command": "status"})
        self.assertEqual(status["result"]["active_counts"], {"website": 2, "application": 0})
        self.assertNotIn("active_targets", status["result"])
        listed = service.dispatch(1000, {"command": "list_managed_lists"})
        self.assertNotIn("domains", listed["result"][0])
        chunk = service.dispatch(1000, {"command": "read_managed_list", "list_id": managed.id, "offset": 0})
        self.assertEqual(chunk["result"]["domains"], list(managed.domains))

    def test_rule_cannot_refer_to_unknown_managed_list(self):
        store = FakeStore(Policy(0, ()))
        service = BlockerService(
            store, FakeClock(), FakeHosts(), FakeApplications()
        )
        service.start()
        rule = {
            "id": "99999999-9999-4999-8999-999999999999",
            "name": "Missing list",
            "enabled": True,
            "targets": [{
                "kind": "managed_list",
                "value": "11111111-1111-4111-8111-111111111111",
            }],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        }

        result = service.dispatch(1000, {"command": "put_rule", "rule": rule})

        self.assertEqual(result["error"]["code"], "bad_value")
        self.assertEqual(store.policy, Policy(0, ()))
        self.assertEqual(service.hosts.values, set())

    def test_list_import_uses_one_shape_and_service_timestamp(self):
        clock = FakeClock(datetime(2026, 8, 14, 12, 30, tzinfo=timezone.utc))
        store = FakeStore(Policy(0, ()))
        service = BlockerService(
            store, clock, FakeHosts(), FakeApplications()
        )
        service.start()
        metadata = {
            "id": "77777777-7777-4777-8777-777777777777",
            "name": "Imported",
            "source": "file:test.txt",
            "version": "1",
            "license": "Test",
        }
        alias = service.dispatch(
            1000, {"command": "begin_list_import", "list": metadata}
        )
        self.assertEqual(alias["error"]["code"], "bad_request")
        begun = service.dispatch(
            1000, {"command": "begin_list_import", "metadata": metadata}
        )
        token = begun["result"]["import_id"]
        added = service.dispatch(
            1000,
            {
                "command": "import_list_chunk",
                "import_id": token,
                "domains": ["example.com"],
            },
        )
        self.assertTrue(added["ok"])
        committed = service.dispatch(
            1000, {"command": "commit_list_import", "import_id": token}
        )
        self.assertTrue(committed["ok"])
        self.assertEqual(
            store.policy.managed_lists[0].imported_utc, clock.current
        )

    def test_staged_list_commit_rejects_removed_active_domain(self):
        managed = ManagedList.from_dict({
            "id": "22222222-2222-4222-8222-222222222222",
            "name": "List",
            "source": "import",
            "version": "1",
            "license": "MIT",
            "imported_utc": "2026-01-01T00:00:00Z",
            "domains": ["keep.example", "remove.example"],
        })
        rule = Rule.from_dict({
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Block",
            "enabled": True,
            "targets": [{"kind": "managed_list", "value": managed.id}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,), (managed,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        metadata = {key: value for key, value in managed.to_dict().items() if key not in {"domains", "imported_utc"}}
        begun = service.dispatch(1000, {"command": "begin_list_import", "metadata": metadata})
        token = begun["result"]["import_id"]
        service.dispatch(1000, {"command": "import_list_chunk", "import_id": token, "domains": ["keep.example"]})
        result = service.dispatch(1000, {"command": "commit_list_import", "import_id": token})
        self.assertEqual(result["error"]["code"], "active_rule")
        self.assertEqual(service.policy.managed_lists[0].domains, managed.domains)


    def test_staged_native_commit_writes_policy_once(self):
        old = Rule.from_dict({
            "id": "33333333-3333-4333-8333-333333333333",
            "name": "Old",
            "enabled": False,
            "targets": [{"kind": "website", "value": "old.example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        replacement = Rule.from_dict({
            "id": "44444444-4444-4444-8444-444444444444",
            "name": "Imported",
            "enabled": True,
            "targets": [{"kind": "website", "value": "new.example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (old,)))
        service = BlockerService(store, FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        begun = service.dispatch(1000, {"command": "begin_native_import"})
        token = begun["result"]["import_id"]
        text = json.dumps({
            "schema_version": POLICY_SCHEMA_VERSION,
            "revision": 0,
            "rules": [replacement.to_dict()],
            "managed_lists": [],
        })
        service.dispatch(1000, {"command": "native_import_chunk", "import_id": token, "text": text})
        result = service.dispatch(1000, {"command": "commit_native_import", "import_id": token})
        self.assertTrue(result["ok"])
        self.assertEqual(store.policy.rules, (replacement,))
        self.assertEqual(service.hosts.values, {"new.example"})

    def test_native_import_replaces_inactive_rules_atomically(self):
        old = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Old",
            "enabled": False,
            "targets": [{"kind": "website", "value": "old.example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        replacement = Rule.from_dict({
            "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Imported",
            "enabled": True,
            "targets": [{"kind": "website", "value": "new.example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (old,)))
        service = BlockerService(store, FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        result = service.dispatch(
            1000,
            {"command": "replace_rules", "rules": [replacement.to_dict()]},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(store.policy.rules, (replacement,))
        self.assertEqual(service.hosts.values, {"new.example"})

    def test_native_import_refuses_invalid_data_without_partial_save(self):
        old = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Keep",
            "enabled": False,
            "targets": [{"kind": "website", "value": "keep.example"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        store = FakeStore(Policy(0, (old,)))
        service = BlockerService(store, FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        invalid = old.to_dict()
        invalid["targets"] = []
        result = service.dispatch(
            1000,
            {"command": "replace_rules", "rules": [invalid]},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(store.policy.rules, (old,))

    def test_native_import_cannot_remove_active_finite_rule(self):
        active = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Locked",
            "enabled": True,
            "targets": [{"kind": "website", "value": "keep.example"}],
            "schedule": {
                "kind": "one_time",
                "start_utc": "2025-01-01T00:00:00Z",
                "end_utc": "2027-01-01T00:00:00Z",
            },
            "revision": 0,
        })
        store = FakeStore(Policy(0, (active,)))
        service = BlockerService(store, FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        result = service.dispatch(1000, {"command": "replace_rules", "rules": []})
        self.assertEqual(result["error"]["code"], "active_rule")
        self.assertEqual(store.policy.rules, (active,))

    def test_only_root_can_clear_the_clock_latch(self):
        clock = FakeClock()
        clock.trusted = False
        service = BlockerService(
            FakeStore(Policy(0, ())), clock, FakeHosts(), FakeApplications()
        )
        service.start()
        refused = service.dispatch(1000, {"command": "clear_clock_latch"})
        self.assertEqual(refused["error"]["code"], "forbidden")
        recovered = service.dispatch(0, {"command": "clear_clock_latch"})
        self.assertTrue(recovered["ok"])

    def test_clear_denial_stats_discards_pending_buffer_events(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "App",
            "enabled": True,
            "targets": [{"kind": "application", "value": "/usr/bin/app"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), FakeClock(), FakeHosts(),
            FakeApplications(),
        )
        service.start()
        buffer = service.denial_buffer
        self.assertTrue(buffer.record("/usr/bin/app"))
        cleared = service.dispatch(1000, {"command": "clear_denial_stats"})
        self.assertTrue(cleared["ok"])
        service.tick()
        result = service.dispatch(1000, {"command": "list_denial_stats"})
        self.assertEqual(result["result"], {"items": [], "dropped": 0})

    def test_website_denial_reports_merge_and_persist(self) -> None:
        service = BlockerService(
            FakeStore(Policy(0, ())), FakeClock(), FakeHosts(),
            FakeApplications(),
        )
        service.start()
        first = service.dispatch(1000, {
            "command": "report_website_denials",
            "entries": [
                {
                    "rule_id": "12345678-1234-5678-1234-567812345678",
                    "value": "example.com/feed",
                    "count": 3,
                },
                {"kind": "url_keyword", "value": "casino"},
            ],
        })
        self.assertEqual(first["error"]["code"], "bad_value")
        second = service.dispatch(1000, {
            "command": "report_website_denials",
            "entries": [
                {
                    "rule_id": "12345678-1234-5678-1234-567812345678",
                    "value": "example.com/feed",
                    "count": 3,
                },
                {
                    "rule_id": "22222222-2222-4222-8222-222222222222",
                    "value": "casino",
                    "count": 1,
                },
            ],
        })
        self.assertTrue(second["ok"])
        again = service.dispatch(1000, {
            "command": "report_website_denials",
            "entries": [{
                "rule_id": "12345678-1234-5678-1234-567812345678",
                "value": "example.com/feed",
                "count": 2,
            }],
        })
        self.assertTrue(again["ok"])
        listed = service.dispatch(1000, {"command": "list_website_stats"})
        rows = {row["value"]: row for row in listed["result"]["items"]}
        self.assertEqual(rows["example.com/feed"]["count"], 5)
        self.assertEqual(rows["casino"]["count"], 1)
        self.assertEqual(
            len(rows["example.com/feed"]["rule_ids"]),
            1,
        )
        saved = service.store.website_statistics
        self.assertEqual(saved, service._website_statistics)
        self.assertEqual(
            next(r for r in saved.items if r.value == "example.com/feed").count,
            5,
        )

    def test_friction_authorization_treats_non_ascii_as_incorrect(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "Friction",
            "enabled": True,
            "targets": [{"kind": "website", "value": "example.com"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), FakeClock(), FakeHosts(),
            FakeApplications(),
        )
        service.start()
        service.dispatch(1000, {
            "command": "set_rule_lock",
            "rule_id": rule.id,
            "lock": {"kind": "friction"},
        })
        challenge = service.dispatch(1000, {
            "command": "begin_rule_authorization",
            "rule_id": rule.id,
        })["result"]
        wrong = service.dispatch(1000, {
            "command": "complete_rule_authorization",
            "rule_id": rule.id,
            "challenge_id": challenge["challenge_id"],
            "response": challenge["prompt"][:-1] + "\u00e9",
        })
        self.assertEqual(wrong["error"]["code"], "incorrect_response")


    def test_closed_peer_does_not_escape_connection_handler(self):
        service = type("Service", (), {
            "dispatch": lambda self, uid, request: {"ok": True, "result": "ok"},
        })()
        server = RpcServer(service, "/unused", os.getuid())
        left, right = socket.socketpair()
        try:
            right.sendall(b'{"command":"status"}\n')
            right.close()
            server._serve_connection(left)
        finally:
            left.close()




    def test_allowance_increase_is_rejected_for_active_rule(self):
        old = Rule.from_dict(
            {
                "id": "99999999-9999-4999-8999-999999999999",
                "name": "Active",
                "enabled": True,
                "targets": [
                    {"kind": "url_path", "value": "example.com/feed"}
                ],
                "schedule": {"kind": "indefinite"},
                "revision": 0,
            }
        )
        updated = old.to_dict()
        updated["allowance_starts"] = 2
        service = BlockerService(
            FakeStore(Policy(0, (old,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        result = service.dispatch(
            1000, {"command": "put_rule", "rule": updated}
        )
        self.assertEqual(result["error"]["code"], "active_rule")

    def test_allowance_increase_is_rejected_by_rule_lock(self):
        old = closed_weekly_rule(allowance_starts=2)
        updated = old.to_dict()
        updated["allowance_starts"] = 3
        service = BlockerService(
            FakeStore(Policy(0, (old,))),
            FakeClock(),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        locked = service.dispatch(
            1000,
            {
                "command": "set_rule_lock",
                "rule_id": old.id,
                "lock": {"kind": "friction"},
            },
        )
        self.assertTrue(locked["ok"])
        result = service.dispatch(
            1000, {"command": "put_rule", "rule": updated}
        )
        self.assertEqual(result["error"]["code"], "authorization_required")


def closed_weekly_rule(rule_id="12345678-1234-5678-1234-567812345678", **extra):
    """A weekly rule that is CLOSED at the FakeClock default instant."""
    # Breadcrumb: 2026-01-01 is a Thursday, so a Monday-only period keeps
    # the schedule inactive while the allowance tests run.
    data = {
        "id": rule_id,
        "name": "Budgeted",
        "enabled": True,
        "targets": [
            {
                "kind": "url_path"
                if "allowance_starts" in extra
                else "website",
                "value": "example.com/feed"
                if "allowance_starts" in extra
                else "example.com",
            }
        ],
        "schedule": {
            "kind": "weekly",
            "timezone": "UTC",
            "periods": [{"weekdays": [0], "start": "09:00:00", "end": "17:00:00"}],
        },
        "revision": 0,
    }
    data.update(extra)
    return Rule.from_dict(data)


class WebsiteUsageTests(unittest.TestCase):
    def _service(self, *rules):
        service = BlockerService(
            FakeStore(Policy(0, rules)), FakeClock(), FakeHosts(),
            FakeApplications(),
        )
        service.start()
        return service

    def _report(self, service, entries):
        return service.dispatch(1000, {
            "command": "report_website_usage",
            "entries": entries,
        })

    def test_report_validation_mirrors_denials(self):
        service = self._service(closed_weekly_rule())
        missing = service.dispatch(1000, {"command": "report_website_usage"})
        self.assertEqual(missing["error"]["code"], "bad_request")
        self.assertEqual(
            missing["error"]["message"], "entries is required"
        )
        empty = self._report(service, [])
        self.assertEqual(empty["error"]["code"], "bad_request")
        bad_fields = self._report(service, [{"rule_id": "x"}])
        self.assertEqual(bad_fields["error"]["code"], "bad_value")
        bool_count = self._report(service, [{
            "rule_id": "12345678-1234-5678-1234-567812345678",
            "value": "example.com",
            "count": True,
        }])
        self.assertEqual(bool_count["error"]["code"], "bad_type")

    def test_batch_is_atomic_before_commit(self):
        service = self._service(closed_weekly_rule())
        rejected = self._report(service, [
            {
                "rule_id": "12345678-1234-5678-1234-567812345678",
                "value": "example.com",
                "count": 1,
            },
            {
                "rule_id": "12345678-1234-5678-1234-567812345678",
                "value": "bad" + chr(127) + "value",
                "count": 1,
            },
        ])
        self.assertEqual(rejected["error"]["code"], "bad_value")
        self.assertEqual(len(service._website_usage.items), 0)
        self.assertEqual(len(service.store.website_usage.items), 0)

    def test_unknown_and_non_allowance_usage_rows_are_rejected(self):
        budgeted = closed_weekly_rule(allowance_starts=2)
        unbudgeted = closed_weekly_rule(
            rule_id="22222222-2222-4222-8222-222222222222",
            name="No budget",
        )
        service = self._service(budgeted, unbudgeted)
        self.assertTrue(
            self._report(
                service,
                [{
                    "rule_id": budgeted.id,
                    "value": "example.com/feed",
                    "count": 1,
                }],
            )["ok"]
        )
        before = service._website_usage
        for rule_id in (
            "33333333-3333-4333-8333-333333333333",
            unbudgeted.id,
        ):
            with self.subTest(rule_id=rule_id):
                rejected = self._report(
                    service,
                    [{
                        "rule_id": rule_id,
                        "value": "example.com/feed",
                        "count": 1,
                    }],
                )
                self.assertEqual(rejected["error"]["code"], "bad_value")
                self.assertEqual(service._website_usage, before)
                self.assertEqual(service.store.website_usage, before)

    def test_list_website_stats_prunes_usage_once(self):
        service = self._service(closed_weekly_rule(allowance_starts=2))
        with patch.object(
            service,
            "_pruned_website_usage",
            wraps=service._pruned_website_usage,
        ) as prune:
            result = service.dispatch(
                1000, {"command": "list_website_stats"}
            )
        self.assertTrue(result["ok"])
        self.assertEqual(prune.call_count, 1)

    def test_exhausted_rule_blocks_despite_closed_schedule(self):
        rule = closed_weekly_rule(allowance_starts=2)
        unbudgeted = closed_weekly_rule(
            rule_id="22222222-2222-4222-8222-222222222222",
            name="No budget",
        )
        service = self._service(rule, unbudgeted)
        policy = service.dispatch(1000, {"command": "list_rules"})["result"]
        self.assertEqual(
            set(policy), {"schema_version", "revision", "rules"}
        )
        self.assertEqual(policy["schema_version"], POLICY_SCHEMA_VERSION)
        listed = policy["rules"]
        by_id = {item["id"]: item for item in listed}
        self.assertFalse(by_id[rule.id]["budget_exhausted"])
        self.assertFalse(by_id[unbudgeted.id]["budget_exhausted"])
        self.assertEqual(service.hosts.values, set())

        reported = self._report(service, [{
            "rule_id": rule.id,
            "value": "example.com/feed",
            "count": 1,
        }])
        self.assertTrue(reported["ok"])
        still_under = service.dispatch(
            1000, {"command": "list_rules"}
        )["result"]["rules"]
        under = next(
            item for item in still_under if item["id"] == rule.id
        )
        self.assertFalse(under["budget_exhausted"])

        self._report(service, [{
            "rule_id": rule.id,
            "value": "example.com/feed",
            "count": 1,
        }])
        after = service.dispatch(
            1000, {"command": "list_rules"}
        )["result"]["rules"]
        exhausted_row = next(item for item in after if item["id"] == rule.id)
        self.assertTrue(exhausted_row["budget_exhausted"])
        unbudgeted_row = next(
            item for item in after if item["id"] == unbudgeted.id
        )
        self.assertFalse(unbudgeted_row["budget_exhausted"])
        # Enforcement: the exhausted rule's targets join the blocked set.
        self.assertEqual(service.hosts.values, set())
        # Persistence: the signed state file holds the counted starts.
        saved = service.store.website_usage
        self.assertEqual(saved.items[0].count, 2)

    def test_daily_schedule_projects_full_day_when_exhausted(self):
        rule = closed_weekly_rule(allowance_starts=1)
        service = self._service(rule)
        day = service.clock.now().date().isoformat()
        before = service.dispatch(1000, {
            "command": "daily_schedule",
            "timezone": "UTC",
            "date": day,
        })["result"]
        self.assertEqual(before["intervals"], [])
        self._report(service, [{
            "rule_id": rule.id,
            "value": "example.com/feed",
            "count": 1,
        }])
        after = service.dispatch(1000, {
            "command": "daily_schedule",
            "timezone": "UTC",
            "date": day,
        })["result"]
        self.assertEqual(len(after["intervals"]), 1)
        interval = after["intervals"][0]
        self.assertEqual(interval["rule_id"], rule.id)
        self.assertTrue(interval["start"].startswith(day + "T00:00"))
        self.assertNotEqual(interval["end"][:10], day)

    def test_stale_rows_are_pruned_and_count_as_zero(self):
        rule = closed_weekly_rule(allowance_starts=1)
        service = BlockerService(
            FakeStore(Policy(0, (rule,))), FakeClock(), FakeHosts(),
            FakeApplications(),
        )
        # Breadcrumb: seed yesterday's row; the lazy reset must treat it as
        # zero during start(), so the rule never projects as exhausted.
        service.store.website_usage = WebsiteUsageState.empty().record(
            rule.id, 5, "2025-12-31"
        )
        service.start()
        result = service.dispatch(
            1000, {"command": "list_rules"}
        )["result"]["rules"]
        self.assertFalse(result[0]["budget_exhausted"])
        self.assertEqual(service.hosts.values, set())
        # Breadcrumb: pruning is opportunistic and in memory; the signed
        # file only updates on the next observational write.
        self.assertEqual(service._website_usage.items, ())

    def test_list_website_stats_adds_usage_projection(self):
        rule = closed_weekly_rule(allowance_starts=3)
        service = self._service(rule)
        self._report(service, [{
            "rule_id": rule.id,
            "value": "example.com/feed",
            "count": 1,
        }])
        result = service.dispatch(
            1000, {"command": "list_website_stats"}
        )["result"]
        self.assertEqual(set(result), {"items", "dropped", "usage"})
        usage = result["usage"]
        self.assertEqual(len(usage), 1)
        row = usage[0]
        self.assertEqual(set(row), {
            "rule_id", "day", "count", "allowance_starts",
            "budget_exhausted",
        })
        self.assertEqual(row["rule_id"], rule.id)
        self.assertEqual(row["day"], "2026-01-01")
        self.assertEqual(row["count"], 1)
        self.assertEqual(row["allowance_starts"], 3)
        self.assertFalse(row["budget_exhausted"])

    def test_combined_website_statistics_response_fits_rpc(self):
        rules = tuple(
            closed_weekly_rule(
                rule_id=f"00000000-0000-4000-8000-{index:012d}",
                allowance_starts=3,
            )
            for index in range(256)
        )
        service = self._service(*rules)
        denials = WebsiteDenialState.empty()
        usage = WebsiteUsageState.empty()
        for index, rule in enumerate(rules):
            denials = denials.record(
                f"{index}.example/" + "x" * 480,
                rule.id,
                service.clock.now(),
            )
            usage = usage.record(rule.id, 1, "2026-01-01")
        service._website_statistics = denials
        service._website_usage = usage

        response = service.dispatch(
            1000, {"command": "list_website_stats"}
        )

        self.assertTrue(response["ok"])
        self.assertTrue(response_fits(response))
        self.assertEqual(len(response["result"]["usage"]), 256)
        self.assertLess(
            len(response["result"]["items"]),
            len(denials.items),
        )


class RpcTests(unittest.TestCase):
    def test_client_server_round_trip(self):
        service = type("Service", (), {
            "dispatch": lambda self, uid, request: {"ok": True, "result": request["command"]},
            "tick": lambda self: None,
        })()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "control.sock")
            server = RpcServer(service, path, os.getuid())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            for _ in range(100):
                if os.path.exists(path):
                    break
                import time
                time.sleep(0.01)
            self.assertEqual(Client(path).request("status"), "status")
            server.close()
            thread.join(timeout=1)
