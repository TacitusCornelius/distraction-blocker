import hashlib
import hmac
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from distraction_blocker.model import Policy
from distraction_blocker.storage import ProtectedStore, StorageError


class StorageTests(unittest.TestCase):
    def test_atomic_signed_save_and_load(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.initialize()
            store.save(Policy(2, ()), datetime(2026, 1, 1, tzinfo=timezone.utc))
            self.assertEqual(store.load().policy.revision, 2)
            self.assertEqual(Path(directory, "policy.json").stat().st_mode & 0o777, 0o600)

    def test_bad_primary_recovers_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.save(Policy(1, ()), None)
            Path(directory, "policy.json").write_text("tampered")
            result = store.load()
            self.assertTrue(result.degraded)
            self.assertEqual(result.policy.revision, 1)

    def test_signed_v1_policy_migrates_weekly_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.initialize()
            payload = {
                "clock_untrusted": False,
                "high_water_utc": None,
                "policy": {
                    "revision": 4,
                    "rules": [{
                        "id": "12345678-1234-5678-9234-567812345678",
                        "name": "Old weekly rule",
                        "enabled": True,
                        "targets": [{"kind": "website", "value": "example.com"}],
                        "schedule": {
                            "kind": "weekly",
                            "timezone": "UTC",
                            "weekdays": [0, 2],
                            "start": "09:00:00",
                            "end": "17:00:00",
                        },
                        "revision": 0,
                    }],
                },
            }
            unsigned = {"version": 1, "payload": payload}
            envelope = {
                **unsigned,
                "hmac": hmac.new(
                    b"k" * 32,
                    store._canonical(unsigned),
                    hashlib.sha256,
                ).hexdigest(),
            }
            Path(directory, "policy.json").write_bytes(store._canonical(envelope))
            result = store.load()
            self.assertEqual(result.policy.to_dict()["managed_lists"], [])
            self.assertEqual(
                result.policy.rules[0].to_dict()["schedule"]["periods"],
                [{
                    "weekdays": [0, 2],
                    "start": "09:00:00",
                    "end": "17:00:00",
                }],
            )
            self.assertEqual(
                json.loads(Path(directory, "policy.json").read_text())["version"],
                2,
            )

    def test_bad_both_refuses_start(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.save(Policy(1, ()), None)
            Path(directory, "policy.json").write_text("bad")
            Path(directory, "policy.json.bak").write_text("bad")
            with self.assertRaises(StorageError):
                store.load()


if __name__ == "__main__":
    unittest.main()
