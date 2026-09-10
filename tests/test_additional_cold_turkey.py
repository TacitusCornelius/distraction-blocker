from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from distraction_blocker.actions import ScheduledAction, ScheduledActionsState, new_action
from distraction_blocker.cli import main
from distraction_blocker.model import Schedule, Policy
from distraction_blocker.service import BlockerService
from distraction_blocker.storage import ProtectedStore
from distraction_blocker.transfer import statistics_export_text
from tests.test_service_rpc import (
    FakeApplications,
    FakeClock,
    FakeHosts,
    FakeStore,
)


class ActionModelTests(unittest.TestCase):
    def test_one_time_action_is_due_once(self) -> None:
        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": "2026-01-01T00:00:00.000000Z",
            "end_utc": "2026-01-01T00:01:00.000000Z",
        })
        action = new_action("lock", schedule)
        now = datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc)
        occurrence = action.occurrence_at(now)
        self.assertEqual(occurrence, schedule.start_utc)
        fired = ScheduledAction(
            action.id, action.kind, action.enabled, action.schedule,
            action.revision, occurrence,
        )
        self.assertIsNone(fired.occurrence_at(now))

    def test_state_round_trip_is_strict_and_bounded(self) -> None:
        schedule = Schedule.from_dict({
            "kind": "weekly",
            "timezone": "UTC",
            "periods": [{"weekdays": [0], "start": "09:00", "end": "09:05"}],
        })
        action = new_action("logout", schedule)
        state = ScheduledActionsState((action,))
        self.assertEqual(
            ScheduledActionsState.from_dict(state.to_dict()), state
        )
        with self.assertRaises(ValueError):
            ScheduledActionsState.from_dict({"version": 1, "items": [{"id": "bad"}]})






class ActionStorageTests(unittest.TestCase):
    def test_scheduled_actions_use_independent_signed_storage(self) -> None:
        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": "2026-01-01T00:00:00.000000Z",
            "end_utc": "2026-01-01T00:01:00.000000Z",
        })
        state = ScheduledActionsState((new_action("lock", schedule),))
        with tempfile.TemporaryDirectory() as directory:
            store = ProtectedStore(directory, key_source=b"x" * 32)
            store.initialize()
            store.save_scheduled_actions(state)
            self.assertEqual(store.load_scheduled_actions(), state)

class ServiceActionTests(unittest.TestCase):

    def test_due_action_runs_once_and_persists_last_fired(self) -> None:
        class ActionStore(FakeStore):
            def __init__(self):
                super().__init__(Policy(0, ()))
                self.actions = ScheduledActionsState.empty()
                self.action_saves = []

            def load_scheduled_actions(self):
                return self.actions

            def save_scheduled_actions(self, state):
                self.actions = state
                self.action_saves.append(state)

        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": "2026-01-01T00:00:00.000000Z",
            "end_utc": "2026-01-01T00:01:00.000000Z",
        })
        action = new_action("lock", schedule)
        store = ActionStore()
        store.actions = ScheduledActionsState((action,))
        fired: list[str] = []
        service = BlockerService(
            store,
            FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc)),
            FakeHosts(),
            FakeApplications(),
            action_runner=lambda scheduled, _uid: fired.append(scheduled.kind),
        )
        service.start()
        service.tick()
        service.tick()
        self.assertEqual(fired, ["lock"])
        self.assertEqual(len(store.action_saves), 1)
        self.assertIsNotNone(store.actions.items[0].last_fired_utc)
    def test_failed_action_uses_retry_backoff(self) -> None:
        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": "2026-01-01T00:00:00.000000Z",
            "end_utc": "2026-01-01T00:01:00.000000Z",
        })
        action = new_action("lock", schedule)
        calls = []

        def fail(_action, _uid):
            calls.append(True)
            raise OSError("not available")

        service = BlockerService(
            FakeStore(Policy(0, ())),
            FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc)),
            FakeHosts(),
            FakeApplications(),
            action_runner=fail,
        )
        service.actions = ScheduledActionsState((action,))
        with patch("distraction_blocker.service.time.monotonic", side_effect=[100.0, 101.0]):
            service._run_scheduled_actions()
            service._run_scheduled_actions()
        self.assertEqual(len(calls), 1)


    def test_notification_action_blocks_for_its_schedule_window(self) -> None:
        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": "2026-01-01T00:00:00.000000Z",
            "end_utc": "2026-01-01T00:01:00.000000Z",
        })
        action = new_action("notifications", schedule)
        calls = []
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
        service = BlockerService(
            FakeStore(Policy(0, ())),
            clock,
            FakeHosts(),
            FakeApplications(),
            notification_runner=lambda _action, _uid, block: calls.append(block),
        )
        service.actions = ScheduledActionsState((action,))
        service._run_scheduled_actions()
        clock.current = datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc)
        service._run_scheduled_actions()
        self.assertEqual(calls, [True, False])

class CliFeatureTests(unittest.TestCase):
    def test_actions_add_and_stats_export_use_public_interfaces(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.calls = []

            def request(self, command, **fields):
                self.calls.append((command, fields))
                if command == "list_denial_stats":
                    return {"items": [], "dropped": 0}
                if command == "list_website_stats":
                    return {"items": [], "dropped": 0, "usage": []}
                return {}

        fake = FakeClient()
        output: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            export_path = Path(directory) / "stats.json"
            self.assertEqual(
                main(
                    ["stats", "--export", str(export_path)],
                    client=fake,
                    output=output.append,
                    now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
                ),
                0,
            )
            self.assertIn("\"kind\": \"statistics\"", export_path.read_text())
        action = FakeClient()
        self.assertEqual(
            main(
                ["actions", "add", "--kind", "lock", "--at", "2026-01-01 12:00"],
                client=action,
                output=lambda _text: None,
            ),
            0,
        )
        command, fields = action.calls[-1]
        self.assertEqual(command, "put_scheduled_action")
        self.assertEqual(fields["action"]["kind"], "lock")


    def test_actions_can_be_enabled_or_disabled(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.calls = []

            def request(self, command, **fields):
                self.calls.append((command, fields))
                return {}

        client = FakeClient()
        self.assertEqual(
            main(
                [
                    "actions",
                    "disable",
                    "12345678-1234-5678-1234-567812345678",
                ],
                client=client,
                output=lambda _text: None,
            ),
            0,
        )
        self.assertEqual(client.calls[0][0], "set_scheduled_action_enabled")
        self.assertFalse(client.calls[0][1]["enabled"])

class StatisticsExportTests(unittest.TestCase):
    def test_statistics_export_is_deterministic(self) -> None:
        exported = datetime(2026, 1, 1, tzinfo=timezone.utc)
        text = statistics_export_text(
            {"items": [], "dropped": 0},
            {"items": [], "dropped": 0, "usage": []},
            exported,
        )
        self.assertIn('"exported_utc": "2026-01-01T00:00:00Z"', text)
        self.assertEqual(text, statistics_export_text(
            {"items": [], "dropped": 0},
            {"items": [], "dropped": 0, "usage": []},
            exported,
        ))


class NotificationControlTests(unittest.TestCase):
    def test_block_saves_original_values_and_unblock_restores_them(self) -> None:
        from distraction_blocker import notifications

        values = {"show-banners": True, "show-in-lock-screen": False}

        def fake_run(command, **_kwargs):
            class Result:
                returncode = 0
                stderr = ""
                stdout = str(values[command[3]]) if command[1] == "get" else ""
            if command[1] == "set":
                values[command[3]] = command[4] == "true"
            return Result()

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            notifications.os.environ, {"XDG_CONFIG_HOME": directory}
        ), patch.object(notifications.subprocess, "run", side_effect=fake_run):
            notifications.block()
            self.assertEqual(values, {"show-banners": False, "show-in-lock-screen": False})
            notifications.unblock()
            self.assertEqual(values, {"show-banners": True, "show-in-lock-screen": False})


    def test_saved_notification_state_is_private(self) -> None:
        from distraction_blocker import notifications

        values = {"show-banners": True, "show-in-lock-screen": True}

        def fake_run(command, **_kwargs):
            class Result:
                returncode = 0
                stderr = ""
                stdout = str(values[command[3]]) if command[1] == "get" else ""
            if command[1] == "set":
                values[command[3]] = command[4] == "true"
            return Result()

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            notifications.os.environ, {"XDG_CONFIG_HOME": directory}
        ), patch.object(notifications.subprocess, "run", side_effect=fake_run):
            notifications.block()
            state = notifications.state_path()
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)

if __name__ == "__main__":
    unittest.main()
