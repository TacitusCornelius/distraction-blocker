import unittest
from datetime import datetime, timedelta, timezone

from distraction_blocker.control import ControlError, ControlState, RuleLock


RULE_ID = "12345678-1234-5678-9234-567812345678"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class ControlTests(unittest.TestCase):
    def test_timed_lock_round_trip_and_summary(self):
        lock = RuleLock.timed(RULE_ID, NOW + timedelta(minutes=5))
        state = ControlState((lock,))
        restored = ControlState.from_dict(state.to_dict())
        self.assertEqual(restored, state)
        summary = restored.summaries(NOW)[0]
        self.assertEqual(set(summary), {"rule_id", "kind", "locked", "until_utc", "retry_after_utc"})
        self.assertTrue(summary["locked"])
        self.assertEqual(summary["rule_id"], RULE_ID)

    def test_expired_only_with_trusted_clock(self):
        lock = RuleLock.timed(RULE_ID, NOW)
        self.assertFalse(lock.is_effective(NOW, clock_trusted=True))
        self.assertTrue(lock.is_effective(NOW, clock_trusted=False))
        self.assertFalse(lock.is_effective(NOW, clock_trusted=False, root=True))

    def test_friction_lock_round_trip_is_always_effective(self):
        lock = RuleLock.friction(RULE_ID)
        restored = RuleLock.from_dict(lock.to_dict())
        self.assertEqual(restored, lock)
        self.assertTrue(restored.is_effective(NOW))
        self.assertTrue(
            restored.is_effective(NOW, clock_trusted=False)
        )
        self.assertIsNone(restored.to_summary(NOW)["until_utc"])


    def test_password_hash_and_failure_delay_round_trip(self):
        lock = RuleLock.password_lock(
            RULE_ID, "correct horse", salt=b"s" * 16
        )
        self.assertTrue(lock.verify_password("correct horse"))
        self.assertFalse(lock.verify_password("incorrect horse"))
        serialized = lock.to_dict()
        self.assertNotIn("correct horse", str(serialized))
        restored = RuleLock.from_dict(serialized)
        failed = restored.with_password_failure(NOW)
        self.assertEqual(failed.failures, 1)
        self.assertEqual(failed.retry_seconds(NOW), 2)
        reset = failed.with_password_success()
        self.assertEqual(reset.failures, 0)
        self.assertIsNone(reset.retry_after_utc)

    def test_control_state_rejects_unknown_or_duplicate_records(self):
        with self.assertRaises(ControlError):
            ControlState.from_dict({"locks": [], "denial_stats": [], "denial_drops": 0})
        lock = RuleLock.timed(RULE_ID, NOW)
        with self.assertRaises(ControlError):
            ControlState((lock, lock))
        with self.assertRaises(ControlError):
            RuleLock.from_dict({"rule_id": RULE_ID, "kind": "password", "until_utc": NOW.isoformat()})


if __name__ == "__main__":
    unittest.main()
