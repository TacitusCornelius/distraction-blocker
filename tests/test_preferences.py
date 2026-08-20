from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from distraction_blocker.preferences import load_theme, save_theme


class ThemePreferenceTests(unittest.TestCase):
    def test_missing_and_malformed_files_use_system_theme(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preferences.json"
            self.assertEqual(load_theme(path), "system")
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(load_theme(path), "system")
            path.write_text('{"version":true,"theme":"dark"}', encoding="utf-8")
            self.assertEqual(load_theme(path), "system")

    def test_saves_each_theme_with_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config" / "preferences.json"
            for theme in ("system", "light", "dark"):
                save_theme(theme, path)
                self.assertEqual(load_theme(path), theme)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(value, {"theme": theme, "version": 1})

    def test_refuses_unknown_theme_and_symlink_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "not supported"):
                save_theme("blue", root / "preferences.json")
            target = root / "target"
            target.write_text("keep", encoding="utf-8")
            link = root / "preferences.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(OSError, "regular file"):
                save_theme("dark", link)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
