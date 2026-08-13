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
