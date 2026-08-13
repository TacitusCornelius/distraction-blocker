import json
import socket
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from distraction_blocker.model import Policy, Rule
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
        raw = {"revision": 0, "rules": []}
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
