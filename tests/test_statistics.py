import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from distraction_blocker.statistics import (
    MAX_COUNT,
    MAX_STATE_BYTES,
    DenialBuffer,
    DenialStat,
    StatisticsState,
)
RULE_A = "11111111-1111-4111-8111-111111111111"
RULE_B = "22222222-2222-4222-8222-222222222222"
RULE_C = "33333333-3333-4333-8333-333333333333"




class StatisticsTests(unittest.TestCase):
    def test_buffer_overflow_is_nonblocking_and_counted(self):
        buffer = DenialBuffer(maxsize=1)
        self.assertTrue(buffer.record("/relative/app", at_utc="2026-01-01T00:00:00Z"))
        self.assertFalse(buffer.record("/other", at_utc="2026-01-01T00:00:01Z"))
        self.assertEqual(buffer.dropped, 1)
        state = buffer.drain_into()
        self.assertEqual(state.dropped, 1)
        self.assertEqual(len(state.items), 1)

    def test_record_merges_rule_ids_and_saturates_count(self):
        stamp = "2026-01-01T00:00:00Z"
        state = StatisticsState((
            DenialStat("/app", MAX_COUNT, stamp, stamp, (RULE_A,)),
        ))
        state = state.record(
            "/app", (RULE_C, RULE_B), "2025-12-31T00:00:00Z"
        )
        row = state.items[0]
        self.assertEqual(row.count, MAX_COUNT)
        self.assertEqual(row.rule_ids, (RULE_A, RULE_B, RULE_C))
        self.assertEqual(row.first_utc, "2025-12-31T00:00:00.000000Z")

    def test_state_evicts_oldest_then_path_tie_break(self):
        state = StatisticsState.empty()
        for index in range(256):
            state = state.record(f"/app-{index:03d}", (), "2026-01-01T00:00:00Z")
        state = state.record("/new", (), "2026-01-01T00:00:00Z")
        paths = {row.path for row in state.items}
        self.assertNotIn("/app-000", paths)
        self.assertIn("/new", paths)
        self.assertEqual(len(paths), 256)

    def test_rows_and_outer_result_have_exact_shape(self):
        state = StatisticsState.empty().record(
            "/app",
            (RULE_B, RULE_A),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(set(state.to_dict()), {"items", "dropped"})
        self.assertEqual(set(state.to_dict()["items"][0]), {"path", "count", "first_utc", "last_utc", "rule_ids"})
        self.assertEqual(
            state.to_dict()["items"][0]["rule_ids"],
            [RULE_A, RULE_B],
        )
        with self.assertRaises(FrozenInstanceError):
            state.items[0].count = 2

    def test_clear_resets_rows_and_dropped(self):
        state = StatisticsState.empty().record("/app", (), "2026-01-01T00:00:00Z").add_dropped(4)
        self.assertEqual(state.clear(), StatisticsState.empty())

    def test_byte_budget_evicts_oldest_rows_until_state_fits(self):
        state = StatisticsState.empty()
        state = state.record("/old", (), "2025-12-31T00:00:00Z")
        for index in range(255):
            state = state.record(
                f"/app-{index:03d}/" + "x" * 3900,
                (),
                "2026-01-01T00:00:00Z",
            )
        state = state.record("/new", (), "2026-01-02T00:00:00Z")
        size = len(json.dumps(
            state.to_dict(), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8"))
        self.assertLessEqual(size, MAX_STATE_BYTES)
        paths = {row.path for row in state.items}
        self.assertNotIn("/old", paths)
        self.assertIn("/new", paths)

    def test_buffer_discard_drops_pending_events_and_overflow(self):
        buffer = DenialBuffer(maxsize=2)
        self.assertTrue(buffer.record("/a"))
        self.assertTrue(buffer.record("/b"))
        self.assertFalse(buffer.record("/c"))
        self.assertEqual(buffer.discard(), 3)
        self.assertEqual(len(buffer), 0)
        self.assertEqual(buffer.dropped, 0)
        self.assertEqual(buffer.drain_into().dropped, 0)


if __name__ == "__main__":
    unittest.main()
