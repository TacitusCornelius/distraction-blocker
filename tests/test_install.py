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


if __name__ == "__main__":
    unittest.main()
