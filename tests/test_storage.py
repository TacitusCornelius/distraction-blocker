import hashlib
import hmac
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from distraction_blocker.control import ControlState, RuleLock
from distraction_blocker.model import POLICY_SCHEMA_VERSION, Policy
from distraction_blocker.statistics import (
    StatisticsState,
    WebsiteDenialState,
    WebsiteUsageState,
)
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
            self.assertEqual(envelope["version"], 4)
            self.assertEqual(
                envelope["payload"]["policy"]["schema_version"],
                POLICY_SCHEMA_VERSION,
            )
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
            self.assertEqual(json.loads(Path(directory, "policy.json").read_text())["version"], 4)

    def test_signed_v2_adds_empty_controls_and_migrates_to_v4(self):
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
            self.assertEqual(json.loads(Path(directory, "policy.json").read_text())["version"], 4)

    def test_signed_v3_adds_policy_schema_and_migrates_to_v4(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            store.initialize()
            old_policy = Policy(4, ()).to_dict()
            old_policy.pop("schema_version")
            payload = {
                "clock_untrusted": False,
                "high_water_utc": None,
                "policy": old_policy,
                "controls": ControlState.empty().to_dict(),
            }
            unsigned = {"version": 3, "payload": payload}
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
            self.assertEqual(result.policy.schema_version, POLICY_SCHEMA_VERSION)
            rewritten = json.loads(Path(directory, "policy.json").read_text())
            self.assertEqual(rewritten["version"], 4)
            self.assertEqual(
                rewritten["payload"]["policy"]["schema_version"],
                POLICY_SCHEMA_VERSION,
            )


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

    def test_pre_unification_envelope_still_loads(self):
        # Breadcrumb: this blob was produced by the pre-unification code,
        # before the three signed states shared _BoundedState. It pins the
        # exact wire bytes so the refactor stays byte-compatible on disk.
        blob = (
            '{"hmac":"47fd72adf23fc82496a404a8ff354501ad06d376bd57292521d38d784ed5a413",'
            '"payload":{"dropped":7,"items":['
            '{"count":1,"first_utc":"2026-02-03T00:00:00.000000Z","last_utc":"2026-02-03T00:00:00.000000Z","path":"/opt/Other App","rule_ids":[]},'
            '{"count":3,"first_utc":"2026-01-01T10:00:00.000000Z","last_utc":"2026-01-02T11:30:00.000000Z","path":"/usr/bin/game.exe","rule_ids":["12345678-1234-5678-9234-567812345678","12345678-1234-5678-9234-56781234567a"]}]}'
            ',"version":1}'
        )
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            Path(directory, "statistics.json").write_text(blob)
            state = store.load_statistics()
            self.assertEqual(state.dropped, 7)
            self.assertEqual(
                [row.path for row in state.items],
                ["/opt/Other App", "/usr/bin/game.exe"],
            )
            store.save_statistics(state)
            self.assertEqual(
                Path(directory, "statistics.json").read_text(), blob
            )



class WebsiteUsageStorageTests(unittest.TestCase):
    # Breadcrumb: website-usage.json is the third signed bounded state file
    # and must behave exactly like its siblings.

    def test_website_usage_round_trip_and_bad_signature_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            state = WebsiteUsageState.empty().record(
                "11111111-1111-4111-8111-111111111111", 4, "2026-01-01"
            )
            store.save_website_usage(state)
            self.assertEqual(store.load_website_usage(), state)
            path = Path(directory, "website-usage.json")
            envelope = json.loads(path.read_text())
            self.assertEqual(envelope["version"], 1)
            envelope["hmac"] = "0" * 64
            path.write_bytes(store._canonical(envelope))
            with self.assertRaises(StorageError):
                store.load_website_usage()

    def test_missing_website_usage_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"k" * 32)
            self.assertEqual(
                store.load_website_usage(), WebsiteUsageState.empty()
            )


if __name__ == "__main__":
    unittest.main()
