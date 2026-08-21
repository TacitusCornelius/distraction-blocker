from __future__ import annotations

import builtins
import importlib
import sys
import types
import unittest
from unittest import mock


class CommandImportTests(unittest.TestCase):
    def test_cli_import_does_not_need_gtk(self) -> None:
        sys.modules.pop("distraction_blocker.__main__", None)
        with mock.patch.dict(sys.modules, {"gi": None}):
            module = importlib.import_module("distraction_blocker.__main__")

        self.assertTrue(callable(module.main))

    def test_service_command_never_imports_gui_or_gtk(self) -> None:
        from distraction_blocker import __main__ as command

        calls: list[object] = []
        fake_service = types.ModuleType("distraction_blocker.service")

        def service_main(argv=None) -> int:
            calls.append(argv)
            return 23

        fake_service.main = service_main
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"gi", "gui", "distraction_blocker.gui"}:
                raise AssertionError(f"The service path imported {name}")
            return original_import(name, globals, locals, fromlist, level)

        with mock.patch.dict(
            sys.modules,
            {
                "distraction_blocker.service": fake_service,
                "gi": None,
            },
        ), mock.patch("builtins.__import__", side_effect=guarded_import):
            result = command.main(["service"])

        self.assertEqual(result, 23)
        self.assertEqual(calls, [[]])

    def test_json_status_is_deterministic(self) -> None:
        from distraction_blocker import cli

        class FakeClient:
            def request(self, command, **fields):
                self.call = (command, fields)
                return {"healthy": True, "active_counts": {"website": 2, "application": 0}}

        output: list[str] = []
        result = cli.main(["--json", "status"], client=FakeClient(), output=output.append)

        self.assertEqual(result, 0)
        self.assertEqual(
            output,
            ['{"active_counts":{"application":0,"website":2},"healthy":true}'],
        )

    def test_status_is_human_readable_without_json_flag(self) -> None:
        from distraction_blocker import cli

        class FakeClient:
            def request(self, command, **_fields):
                self.call = command
                return {
                    "healthy": True,
                    "clock_trusted": True,
                    "active_counts": {
                        "website": 2,
                        "application": 1,
                    },
                }

        output = []
        result = cli.main(
            ["status"], client=FakeClient(), output=output.append
        )
        self.assertEqual(result, 0)
        self.assertEqual(output[0], "Service: healthy")
        self.assertIn("Active websites: 2", output)
        self.assertFalse(any(line.startswith("{") for line in output))

    def test_password_lock_uses_hidden_input(self) -> None:
        from distraction_blocker import cli

        class FakeClient:
            def request(self, command, **fields):
                self.call = (command, fields)
                return {"locked": True}

        hidden = iter(("a" * 8, "a" * 8))
        output: list[str] = []
        fake = FakeClient()
        result = cli.main(
            ["lock-password", "00000000-0000-0000-0000-000000000000"],
            client=fake,
            getpass_fn=lambda _prompt: next(hidden),
            output=output.append,
        )

        self.assertEqual(result, 0)
        self.assertEqual(fake.call[0], "set_rule_lock")
        self.assertNotIn("a" * 8, output)


    def test_common_commands_use_only_rpc_requests(self) -> None:
        from distraction_blocker import cli

        rule_id = "11111111-1111-4111-8111-111111111111"
        cases = (
            (["rules"], ("list_rules", {})),
            (["managed-lists"], ("list_managed_lists", {})),
            (["focus", rule_id, "25"], (
                "start_focus", {"rule_id": rule_id, "minutes": 25}
            )),
            (["stats"], ("list_denial_stats", {})),
            (["enable", rule_id], (
                "set_enabled", {"rule_id": rule_id, "enabled": True}
            )),
            (["disable", rule_id], (
                "set_enabled", {"rule_id": rule_id, "enabled": False}
            )),
            (["delete", rule_id], ("delete_rule", {"rule_id": rule_id})),
            (["lock-friction", rule_id], (
                "set_rule_lock",
                {"rule_id": rule_id, "lock": {"kind": "friction"}},
            )),
            (["clear-lock", rule_id], (
                "set_rule_lock",
                {"rule_id": rule_id, "lock": {"kind": "none"}},
            )),
        )

        for argv, expected in cases:
            with self.subTest(argv=argv):
                class FakeClient:
                    def request(self, command, **fields):
                        self.call = (command, fields)
                        return {}

                fake = FakeClient()
                result = cli.main(argv, client=fake, output=lambda _text: None)
                self.assertEqual(result, 0)
                self.assertEqual(fake.call, expected)

    def test_authorize_uses_service_prompt_or_hidden_password(self) -> None:
        from distraction_blocker import cli

        rule_id = "11111111-1111-4111-8111-111111111111"

        class FakeClient:
            def __init__(self, kind):
                self.kind = kind
                self.calls = []

            def request(self, command, **fields):
                self.calls.append((command, fields))
                if command == "begin_rule_authorization":
                    return {
                        "kind": self.kind,
                        "challenge_id": "challenge",
                        "prompt": "ABC234"
                        if self.kind == "friction"
                        else None,
                    }
                return {"authorized": True}

        friction = FakeClient("friction")
        prompts = []
        cli.main(
            ["authorize", rule_id],
            client=friction,
            input_fn=lambda prompt: prompts.append(prompt) or "ABC234",
            output=lambda _text: None,
        )
        self.assertIn("ABC234", prompts[0])
        self.assertEqual(
            friction.calls[-1][1]["response"], "ABC234"
        )

        password = FakeClient("password")
        cli.main(
            ["authorize", rule_id],
            client=password,
            getpass_fn=lambda _prompt: "hidden value",
            output=lambda _text: None,
        )
        self.assertEqual(
            password.calls[-1][1]["response"], "hidden value"
        )

    def test_today_with_explicit_date_is_deterministic(self) -> None:
        from distraction_blocker import cli

        class FakeClient:
            def request(self, command, **fields):
                self.call = (command, fields)
                return {
                    "date": "2026-08-20",
                    "timezone": "UTC",
                    "intervals": [],
                }

        output = []
        fake = FakeClient()
        result = cli.main(
            [
                "--json",
                "today",
                "--date",
                "2026-08-20",
                "--timezone",
                "UTC",
            ],
            client=fake,
            output=output.append,
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            fake.call,
            (
                "daily_schedule",
                {"timezone": "UTC", "date": "2026-08-20"},
            ),
        )
        self.assertEqual(
            output,
            ['{"date":"2026-08-20","intervals":[],"timezone":"UTC"}'],
        )


if __name__ == "__main__":
    unittest.main()
