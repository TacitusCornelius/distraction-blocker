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




import uuid

from distraction_blocker.statistics import (
    MAX_PATHS,
    WebsiteUsageStat,
    WebsiteUsageState,
)


def usage_rule(n: int) -> str:
    # Deterministic canonical UUIDs; the 4/8 nibbles keep the v4 shape.
    return f"{n:08d}-1111-4111-8111-111111111111"


class WebsiteUsageTests(unittest.TestCase):
    # Breadcrumb: usage rows bucket per rule per LOCAL day. Staleness is
    # resolved lazily via fresh()/count_for(); no timers exist.

    def test_record_merges_same_day_and_resets_on_new_day(self):
        rule = usage_rule(1)
        state = WebsiteUsageState.empty()
        state = state.record(rule, 2, "2026-01-01")
        state = state.record(rule, 3, "2026-01-01")
        self.assertEqual(state.count_for(rule, "2026-01-01"), 5)
        next_day = state.record(rule, 1, "2026-01-02")
        self.assertEqual(next_day.count_for(rule, "2026-01-02"), 1)
        # The old day's row is replaced, not merged.
        self.assertEqual(len(next_day.items), 1)

    def test_row_and_state_shapes_are_exact(self):
        row = WebsiteUsageStat(usage_rule(2), "2026-01-01", 4)
        self.assertEqual(
            row.to_dict(),
            {"rule_id": usage_rule(2), "day": "2026-01-01", "count": 4},
        )
        state = WebsiteUsageState((row,), 0)
        self.assertEqual(
            state.to_dict(),
            {"items": [row.to_dict()], "dropped": 0},
        )
        self.assertEqual(WebsiteUsageState.from_dict(state.to_dict()), state)

    def test_fresh_prunes_stale_and_unknown_rows(self):
        kept = WebsiteUsageStat(usage_rule(1), "2026-01-01", 2)
        stale = WebsiteUsageStat(usage_rule(2), "2025-12-31", 9)
        state = WebsiteUsageState((stale, kept), 0)
        days = {usage_rule(1): "2026-01-01", usage_rule(2): "2026-01-01"}
        fresh = state.fresh(days.get)
        self.assertEqual(fresh.items, (kept,))
        # Unknown rules resolve to None and are pruned too.
        self.assertEqual(state.fresh(lambda _rid: None).items, ())

    def test_count_for_treats_stale_rows_as_zero(self):
        rule = usage_rule(3)
        state = WebsiteUsageState.empty().record(rule, 7, "2025-12-31")
        self.assertEqual(state.count_for(rule, "2026-01-01"), 0)

    def test_record_rejects_bad_counts_and_days(self):
        with self.assertRaises(ValueError):
            WebsiteUsageState.empty().record(usage_rule(1), 0, "2026-01-01")
        with self.assertRaises(ValueError):
            WebsiteUsageState.empty().record(usage_rule(1), True, "2026-01-01")
        with self.assertRaises(ValueError):
            WebsiteUsageState.empty().record(usage_rule(1), 1, "2026-1-1")

    def test_row_capacity_evicts_oldest_day_then_rule(self):
        state = WebsiteUsageState.empty()
        for index in range(MAX_PATHS):
            state = state.record(usage_rule(index + 1), 1, "2026-01-01")
        overflow = state.record(usage_rule(MAX_PATHS + 1), 1, "2025-12-31")
        self.assertEqual(len(overflow.items), MAX_PATHS)
        self.assertEqual(overflow.dropped, 1)
        # The oldest day is evicted first.
        self.assertNotIn(
            usage_rule(1), {row.rule_id for row in overflow.items}
        )
        self.assertIn(
            usage_rule(MAX_PATHS + 1),
            {row.rule_id for row in overflow.items},
        )

    def test_duplicate_rows_and_bad_ids_are_refused(self):
        row = WebsiteUsageStat(usage_rule(1), "2026-01-01", 1)
        with self.assertRaises(ValueError):
            WebsiteUsageState((row, row))
        with self.assertRaises(ValueError):
            WebsiteUsageStat("not-a-uuid", "2026-01-01", 1)


if __name__ == "__main__":
    unittest.main()
