from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import install


class InstallerSecurityTests(unittest.TestCase):
    def test_package_copy_refuses_internal_symlink_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            protected = root / "protected"
            protected.write_text("must not copy", encoding="utf-8")
            (source / "leak").symlink_to(protected)
            destination = root / "installed"
            descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(install, "set_mode"), patch.object(
                    install, "fail", side_effect=SystemExit(2)
                ):
                    with self.assertRaises(SystemExit):
                        install.copy_tree(descriptor, destination)
            finally:
                os.close(descriptor)
            self.assertFalse((destination / "leak").exists())

    def test_cli_collision_requires_ownership_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "distraction-blocker"
            path.write_text("unrelated tool\n", encoding="ascii")
            with patch.object(install, "CLI_PATH", path), patch.object(
                install, "fail", side_effect=SystemExit(2)
            ):
                with self.assertRaises(SystemExit):
                    install.check_cli_collision()
            path.write_text(
                f"#!/usr/bin/python3\n{install.CLI_MARKER}\n",
                encoding="ascii",
            )
            with patch.object(install, "CLI_PATH", path):
                install.check_cli_collision()


class NativeHostTests(unittest.TestCase):
    def test_handle_allowlist_forwards_and_refuses(self) -> None:
        import io
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "host_entry",
            Path(__file__).resolve().parent.parent
            / "packaging"
            / "host_entry.py",
        )
        host_entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host_entry)

        with patch.object(
            host_entry,
            "Client",
            lambda socket_path: type(
                "C", (), {"request": lambda self, command: {"healthy": True}}
            )(),
        ):
            allowed = host_entry.handle({"command": "status"})
            self.assertTrue(allowed["ok"])
            self.assertEqual(allowed["result"], {"healthy": True})
        denied = host_entry.handle({"command": "delete_rule"})
        self.assertFalse(denied["ok"])
        fields = host_entry.handle({"command": "status", "extra": 1})
        self.assertEqual(fields["error"]["code"], "forbidden")

    def test_handle_forwards_report_with_fields(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "host_entry",
            Path(__file__).resolve().parent.parent
            / "packaging"
            / "host_entry.py",
        )
        host_entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host_entry)
        seen = {}

        def fake_request(self, **request):
            seen.update(request)
            return {"accepted": 1, "dropped": 0}

        with patch.object(
            host_entry,
            "Client",
            lambda socket_path: type(
                "C", (), {"request": fake_request}
            )(),
        ):
            forwarded = host_entry.handle({
                "command": "report_website_denials",
                "entries": [{
                    "rule_id": "12345678-1234-5678-1234-567812345678",
                    "value": "example.com/feed",
                    "count": 2,
                }],
            })
        self.assertTrue(forwarded["ok"])
        self.assertEqual(seen["command"], "report_website_denials")
        self.assertEqual(len(seen["entries"]), 1)
        widened = host_entry.handle({
            "command": "report_website_denials",
            "entries": [],
            "extra": True,
        })
        self.assertEqual(widened["error"]["code"], "forbidden")

    def test_message_framing_round_trip(self) -> None:
        import io
        import struct
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "host_entry",
            Path(__file__).resolve().parent.parent
            / "packaging"
            / "host_entry.py",
        )
        host_entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host_entry)

        message = {"ok": True, "result": {"items": [1, 2, 3]}}
        outgoing = io.BytesIO()
        host_entry.send_message(outgoing, message)
        encoded = outgoing.getvalue()
        (length,) = struct.unpack("@I", encoded[:4])
        self.assertEqual(length, len(encoded) - 4)

        class Stream:
            def __init__(self, data: bytes) -> None:
                self._data = io.BytesIO(data)

            def read(self, count: int) -> bytes:
                return self._data.read(count)

        wrapper = Stream(encoded)
        self.assertEqual(host_entry.read_message(wrapper), message)
        self.assertIsNone(host_entry.read_message(Stream(b"")))


if __name__ == "__main__":
    unittest.main()


class InstallerSourceTests(unittest.TestCase):
    def test_install_files_uses_only_its_parameters(self):
        # Breadcrumb: install_files receives owner_uid as a parameter; a
        # reference to main()'s local `args` inside it is a latent NameError
        # that only detonates on a real install run.
        import ast

        source = Path(install.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "install_files"
        )
        names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
        self.assertNotIn("args", names)


if __name__ == "__main__":
    unittest.main()
