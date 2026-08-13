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


if __name__ == "__main__":
    unittest.main()
