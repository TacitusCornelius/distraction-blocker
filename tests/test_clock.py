import unittest
from datetime import datetime, timezone

from distraction_blocker.clock import TrustedClock


class ClockTests(unittest.TestCase):
    def test_boot_time_ignores_backward_wall_jump_and_latches(self):
        wall = iter([1000.0, 900.0, 900.0])
        boot = iter([10.0, 11.0, 12.0])
        state = {}
        clock = TrustedClock(lambda: state, lambda value, latched=False: state.update(high_water_utc=value, clock_untrusted=latched), True, wall=lambda: next(wall), boottime=lambda: next(boot))
        value = clock.now()
        self.assertFalse(clock.trusted)
        self.assertEqual(value, datetime.fromtimestamp(1001, timezone.utc))
        clock.checkpoint()
        self.assertTrue(state["clock_untrusted"])

    def test_forward_jump_is_untrusted_and_latch_survives(self):
        wall = iter([1000.0, 1100.0])
        boot = iter([1.0, 2.0])
        state = {}
        clock = TrustedClock(lambda: state, lambda value, latched=False: state.update(high_water_utc=value, clock_untrusted=latched), True, wall=lambda: next(wall), boottime=lambda: next(boot))
        clock.now()
        self.assertFalse(clock.trusted)
        reboot = TrustedClock(lambda: state, lambda *args: None, True, wall=lambda: 1000.0, boottime=lambda: 5.0)
        self.assertFalse(reboot.trusted)

    def test_initial_unsynchronized_clock_recovers_after_time_sync(self):
        synchronized = {"value": False}
        wall = iter([1000.0, 1001.0, 1002.0])
        boot = iter([10.0, 11.0, 12.0])
        clock = TrustedClock(
            lambda: {},
            lambda *args: None,
            lambda: synchronized["value"],
            wall=lambda: next(wall),
            boottime=lambda: next(boot),
        )
        clock.now()
        self.assertFalse(clock.trusted)
        synchronized["value"] = True
        clock.now()
        self.assertTrue(clock.trusted)

    def test_root_recovery_clears_a_detected_clock_latch(self):
        wall = iter([1000.0, 1100.0, 1002.0])
        boot = iter([1.0, 2.0, 3.0])
        state = {}
        clock = TrustedClock(
            lambda: state,
            lambda value, latched=False: state.update(
                high_water_utc=value, clock_untrusted=latched
            ),
            True,
            wall=lambda: next(wall),
            boottime=lambda: next(boot),
        )
        clock.now()
        self.assertFalse(clock.trusted)
        clock.clear_latch()
        self.assertTrue(clock.trusted)
        self.assertFalse(state["clock_untrusted"])


if __name__ == "__main__":
    unittest.main()
