"""Guard the shared extension core against adapter drift."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


class ExtensionCoreSyncTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.build = self.root / "extension" / "build.py"

    def run_build_check(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", str(self.build), "--check"],
            capture_output=True,
            text=True,
            cwd=str(self.root),
        )

    def test_adapters_match_shared_core(self):
        result = self.run_build_check()
        self.assertEqual(
            result.returncode,
            0,
            f"adapter core is stale; run: python3 extension/build.py\n{result.stdout}",
        )

    def test_core_module_stays_browser_agnostic(self):
        # Breadcrumb: the core answers policy questions only; if it ever
        # references a browser API, adapters can no longer share it safely.
        source = (self.root / "extension" / "core" / "engine.js").read_text()
        for banned in ("browser.", "chrome.", "webRequest", "connectNative"):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
