import json
import socket
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from distraction_blocker.model import ManagedList, Policy, Rule
from distraction_blocker.rpc import Client, RpcServer
from distraction_blocker.service import BlockerService


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
    def __init__(self, policy):
        self.policy = policy

    def initialize(self):
        return None

    def load(self):
        return type("Load", (), {"policy": self.policy, "degraded": False})()

    def save(self, policy, high_water_utc, clock_untrusted=False):
        self.policy = policy


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


class ServiceTests(unittest.TestCase):
    def test_start_order_and_strict_fields(self):
        raw = {"revision": 0, "rules": [], "managed_lists": []}
        service = BlockerService(FakeStore(Policy.from_dict(raw)), FakeClock(), FakeHosts(), FakeApplications())
        service.start()
        self.assertTrue(service.applications.started)
        self.assertEqual(service.dispatch(1000, {"command": "status", "extra": 1})["ok"], False)
        self.assertEqual(service.dispatch(1000, {"command": "list_rules"})["ok"], True)

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
        text = json.dumps({"revision": 0, "rules": [replacement.to_dict()], "managed_lists": []})
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
