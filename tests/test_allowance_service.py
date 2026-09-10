import unittest
from datetime import datetime, timedelta, timezone

from distraction_blocker.allowance import (
    AllowanceUsageReport,
    AllowanceUsageState,
    MAX_USAGE_REPORTS,
)
from distraction_blocker.model import Policy, Rule
from distraction_blocker.service import BlockerService
from tests.test_service_rpc import FakeApplications, FakeClock, FakeHosts, FakeStore


UTC = timezone.utc
RULE_ID = "12345678-1234-5678-9234-567812345678"


def timed_rule(quota=60):
    return Rule.from_dict({
        "id": RULE_ID,
        "name": "Timed",
        "enabled": True,
        "targets": [{"kind": "url_path", "value": "example.test/path"}],
        "schedule": {
            "kind": "weekly",
            "timezone": "UTC",
            "periods": [{"weekdays": [0], "start": "09:00", "end": "10:00"}],
        },
        "revision": 0,
        "allowance_time": {
            "periods": [{"mode": "total", "quota_seconds": quota}],
            "daily_cap_seconds": None,
        },
    })


class AllowanceStore(FakeStore):
    def __init__(self, policy):
        super().__init__(policy)
        self.allowance_usage = AllowanceUsageState.empty()
        self.allowance_saves = []

    def load_allowance_usage(self):
        return self.allowance_usage

    def save_allowance_usage(self, state):
        self.allowance_usage = state
        self.allowance_saves.append(state)


class AllowanceServiceTests(unittest.TestCase):
    def make_service(self, clock=None, quota=60):
        store = AllowanceStore(Policy(0, (timed_rule(quota),)))
        service = BlockerService(
            store,
            clock or FakeClock(datetime(2026, 1, 5, 9, tzinfo=UTC)),
            FakeHosts(),
            FakeApplications(),
        )
        service.start()
        return service, store

    def test_lease_reserves_budget_and_report_is_idempotent(self):
        service, store = self.make_service()
        lease = service.dispatch(1000, {
            "command": "request_allowance_lease",
            "rule_id": RULE_ID,
            "seconds": 30,
        })
        self.assertTrue(lease["ok"], lease)
        token = lease["result"]["lease_id"]
        start = datetime(2026, 1, 5, 9, tzinfo=UTC)
        end = start + timedelta(seconds=30)
        service.clock.current = end
        report = {
            "command": "report_allowance_usage",
            "lease_id": token,
            "report_id": "22345678-1234-5678-9234-567812345678",
            "start_utc": start.isoformat().replace("+00:00", "Z"),
            "end_utc": end.isoformat().replace("+00:00", "Z"),
        }
        accepted = service.dispatch(1000, report)
        self.assertTrue(accepted["ok"], accepted)
        self.assertEqual(accepted["result"]["remaining_seconds"], 30)
        duplicate = service.dispatch(1000, report)
        self.assertTrue(duplicate["ok"])
        self.assertTrue(duplicate["result"]["duplicate"])
        self.assertEqual(len(store.allowance_saves), 1)
        renewed = service.dispatch(1000, {
            "command": "request_allowance_lease",
            "rule_id": RULE_ID,
            "seconds": 30,
        })
        self.assertTrue(renewed["ok"], renewed)
        self.assertEqual(renewed["result"]["seconds"], 30)
        second_end = end + timedelta(seconds=30)
        service.clock.current = second_end
        second = service.dispatch(1000, {
            "command": "report_allowance_usage",
            "lease_id": renewed["result"]["lease_id"],
            "report_id": "32345678-1234-5678-9234-567812345678",
            "start_utc": end.isoformat().replace("+00:00", "Z"),
            "end_utc": second_end.isoformat().replace("+00:00", "Z"),
        })
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["result"]["remaining_seconds"], 0)
        listed = service.dispatch(1000, {"command": "list_rules"})
        self.assertTrue(listed["result"]["rules"][0]["budget_exhausted"])

    def test_report_must_stay_inside_lease(self):
        service, _store = self.make_service()
        lease = service.dispatch(1000, {
            "command": "request_allowance_lease",
            "rule_id": RULE_ID,
            "seconds": 10,
        })["result"]
        service.clock.current += timedelta(seconds=11)
        invalid = service.dispatch(1000, {
            "command": "report_allowance_usage",
            "lease_id": lease["lease_id"],
            "report_id": "32345678-1234-5678-9234-567812345678",
            "start_utc": lease["start_utc"],
            "end_utc": (
                datetime(2026, 1, 5, 9, 0, 11, tzinfo=UTC)
                .isoformat()
                .replace("+00:00", "Z")
            ),
        })
        self.assertEqual(invalid["error"]["code"], "bad_value")

    def test_full_usage_ledger_returns_storage_error(self):
        service, store = self.make_service()
        lease = service.dispatch(1000, {
            "command": "request_allowance_lease",
            "rule_id": RULE_ID,
            "seconds": 30,
        })["result"]
        base = datetime(2026, 1, 1, tzinfo=UTC)
        full = tuple(
            AllowanceUsageReport(
                f"42345678-1234-5678-9234-{index:012x}",
                RULE_ID,
                base + timedelta(seconds=index * 2),
                base + timedelta(seconds=index * 2 + 1),
            )
            for index in range(MAX_USAGE_REPORTS)
        )
        service._allowance_usage = AllowanceUsageState(full)
        start = datetime.fromisoformat(lease["start_utc"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(lease["end_utc"].replace("Z", "+00:00"))
        service.clock.current = end
        result = service.dispatch(1000, {
            "command": "report_allowance_usage",
            "lease_id": lease["lease_id"],
            "report_id": "52345678-1234-5678-9234-567812345678",
            "start_utc": start.isoformat().replace("+00:00", "Z"),
            "end_utc": end.isoformat().replace("+00:00", "Z"),
        })
        self.assertEqual(result["error"]["code"], "storage")
        self.assertEqual(len(store.allowance_saves), 0)

    def test_untrusted_clock_denies_new_leases(self):
        clock = FakeClock(datetime(2026, 1, 5, 9, tzinfo=UTC))
        clock.trusted = False
        service, _store = self.make_service(clock)
        result = service.dispatch(1000, {
            "command": "request_allowance_lease",
            "rule_id": RULE_ID,
            "seconds": 1,
        })
        self.assertEqual(result["error"]["code"], "clock_untrusted")


if __name__ == "__main__":
    unittest.main()
