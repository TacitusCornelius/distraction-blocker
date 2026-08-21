import hashlib
import hmac
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from distraction_blocker.control import ControlState, RuleLock
from distraction_blocker.model import Policy
from distraction_blocker.statistics import StatisticsState, WebsiteDenialState
from distraction_blocker.storage import ProtectedStore, StorageError


class StorageTests(unittest.TestCase):
    def test_atomic_signed_save_and_load(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            until = datetime(2026, 1, 2, tzinfo=timezone.utc)
            controls = ControlState((RuleLock.timed("12345678-1234-5678-9234-567812345678", until),))
            store.save(Policy(2, ()), controls, datetime(2026, 1, 1, tzinfo=timezone.utc), False)
            loaded = store.load()
            self.assertEqual(loaded.policy.revision, 2)
            self.assertEqual(loaded.controls, controls)
            self.assertEqual(Path(directory, "policy.json").stat().st_mode & 0o777, 0o600)
            envelope = json.loads(Path(directory, "policy.json").read_text())
            self.assertEqual(envelope["version"], 3)
            self.assertNotIn("controls", envelope["payload"]["policy"])

    def test_bad_primary_recovers_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.save(Policy(1, ()), ControlState.empty(), None, False)
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
                        "schedule": {"kind": "weekly", "timezone": "UTC", "weekdays": [0, 2], "start": "09:00:00", "end": "17:00:00"},
                        "revision": 0,
                    }],
                },
            }
            unsigned = {"version": 1, "payload": payload}
            envelope = {**unsigned, "hmac": hmac.new(b"k" * 32, store._canonical(unsigned), hashlib.sha256).hexdigest()}
            Path(directory, "policy.json").write_bytes(store._canonical(envelope))
            result = store.load()
            self.assertEqual(result.controls, ControlState.empty())
            self.assertEqual(result.policy.to_dict()["managed_lists"], [])
            self.assertEqual(result.policy.rules[0].to_dict()["schedule"]["periods"], [{"weekdays": [0, 2], "start": "09:00:00", "end": "17:00:00"}])
            self.assertEqual(json.loads(Path(directory, "policy.json").read_text())["version"], 3)

    def test_signed_v2_adds_empty_controls_and_migrates_to_v3(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.initialize()
            payload = {"clock_untrusted": True, "high_water_utc": "2026-01-01T00:00:00.000000Z", "policy": Policy(4, ()).to_dict()}
            unsigned = {"version": 2, "payload": payload}
            envelope = {**unsigned, "hmac": hmac.new(b"k" * 32, store._canonical(unsigned), hashlib.sha256).hexdigest()}
            Path(directory, "policy.json").write_bytes(store._canonical(envelope))
            result = store.load()
            self.assertEqual(result.controls, ControlState.empty())
            self.assertTrue(result.clock_untrusted)
            self.assertEqual(json.loads(Path(directory, "policy.json").read_text())["version"], 3)

    def test_invalid_v2_hmac_never_migrates(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.initialize()
            payload = {"clock_untrusted": False, "high_water_utc": None, "policy": Policy(4, ()).to_dict()}
            envelope = {"version": 2, "payload": payload, "hmac": "0" * 64}
            Path(directory, "policy.json").write_bytes(store._canonical(envelope))
            with self.assertRaises(StorageError):
                store.load()
            self.assertEqual(json.loads(Path(directory, "policy.json").read_text())["version"], 2)

    def test_bad_both_refuses_start(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.save(Policy(1, ()), ControlState.empty(), None, False)
            Path(directory, "policy.json").write_text("bad")
            Path(directory, "policy.json.bak").write_text("bad")
            with self.assertRaises(StorageError):
                store.load()

    def test_statistics_is_separate_signed_atomic_file(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            state = StatisticsState.empty().record(
                "/tmp/app",
                (
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                ),
                "2026-01-01T00:00:00Z",
            )
            store.save_statistics(state)
            loaded = store.load_statistics()
            self.assertEqual(loaded, state)
            self.assertEqual(Path(directory, "statistics.json").stat().st_mode & 0o777, 0o600)
            self.assertFalse(Path(directory, "policy.json").exists())

    def test_worst_case_legal_statistics_state_saves_within_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            state = StatisticsState.empty()
            for index in range(256):
                state = state.record(
                    f"/usr/lib/app-{index:03d}/" + "x" * 3900,
                    (),
                    "2026-01-01T00:00:00Z",
                )
            store.save_statistics(state)

    def test_website_statistics_round_trip_and_bad_signature_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            state = WebsiteDenialState.empty().record(
                "example.com/feed",
                "11111111-1111-4111-8111-111111111111",
                "2026-01-01T00:00:00Z",
                times=3,
            )
            store.save_website_statistics(state)
            self.assertEqual(store.load_website_statistics(), state)
            path = Path(directory, "website-statistics.json")
            envelope = json.loads(path.read_text())
            envelope["hmac"] = "0" * 64
            path.write_bytes(store._canonical(envelope))
            with self.assertRaises(StorageError):
                store.load_website_statistics()

    def test_missing_statistics_is_empty_and_bad_signature_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            self.assertEqual(store.load_statistics(), StatisticsState.empty())
            store.save_statistics(StatisticsState.empty())
            path = Path(directory, "statistics.json")
            envelope = json.loads(path.read_text())
            envelope["hmac"] = "0" * 64
            path.write_bytes(store._canonical(envelope))
            with self.assertRaises(StorageError):
                store.load_statistics()


if __name__ == "__main__":
    unittest.main()
