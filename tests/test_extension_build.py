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

    def test_core_modules_stay_browser_agnostic(self):
        # Breadcrumb: the core answers policy questions only; if it ever
        # references a browser API, adapters can no longer share it safely.
        for source_path in (self.root / "extension" / "core").glob("*.js"):
            source = source_path.read_text()
            for banned in ("browser.", "chrome.", "webRequest", "connectNative"):
                self.assertNotIn(banned, f"{source_path.name}: {source}")

    def test_adapter_manifests_share_version(self):
        import json

        versions = set()
        for target in ("firefox", "chromium"):
            manifest = self.root / "extension" / target / "manifest.json"
            if manifest.is_file():
                versions.add(json.loads(manifest.read_text())["version"])
        self.assertEqual(len(versions), 1, f"manifest versions diverge: {versions}")

    def test_firefox_mv2_uses_browser_action(self):
        import json

        manifest = json.loads(
            (self.root / "extension" / "firefox" / "manifest.json").read_text()
        )
        self.assertEqual(manifest["manifest_version"], 2)
        self.assertIn("browser_action", manifest)
        self.assertNotIn("action", manifest)

    def test_chromium_manifest_key_matches_packaged_extension_id(self):
        # Breadcrumb: Chromium derives the extension id from the manifest
        # "key" (SHA-256 over the DER SPKI, first 16 bytes), while the native
        # messaging policy in packaging/ hardcodes that id in allowed_origins.
        # Nothing else couples them, so this test fails loudly when either
        # side changes alone.
        import base64
        import hashlib
        import json

        manifest = json.loads(
            (self.root / "extension" / "chromium" / "manifest.json").read_text()
        )
        spki = base64.b64decode(manifest["key"])
        digest = hashlib.sha256(spki).hexdigest()[:32]
        # Breadcrumb: Chromium spells each hex digit in the a-p alphabet
        # (0-f map to a-p rather than literal hex text), and native
        # messaging origins embed the compact undashed form.
        extension_id = "".join(chr(ord("a") + int(digit, 16)) for digit in digest)
        policy = json.loads(
            (
                self.root / "packaging" / "org.distraction_blocker.chromium.json"
            ).read_text()
        )
        origins = policy["allowed_origins"]
        self.assertEqual(len(origins), 1, f"unexpected origin count: {origins}")
        self.assertEqual(origins[0], f"chrome-extension://{extension_id}/*")
        # Breadcrumb: Chromium-flavored builds (Chrome for Testing) match on
        # allowed_extensions instead; both must pin the same id.
        extensions = policy.get("allowed_extensions")
        self.assertEqual(extensions, [f"{extension_id}/*"])


    def test_adapter_manifests_reference_matching_icon_assets(self):
        import json
        import struct

        expected_sizes = {"16", "32", "48", "128"}
        for target, action_key in (
            ("firefox", "browser_action"),
            ("chromium", "action"),
        ):
            extension_root = self.root / "extension" / target
            manifest = json.loads((extension_root / "manifest.json").read_text())
            self.assertEqual(set(manifest["icons"]), expected_sizes)
            self.assertEqual(
                set(manifest[action_key]["default_icon"]), {"16", "32", "48"}
            )
            for size in ("16", "32", "48"):
                self.assertEqual(
                    manifest[action_key]["default_icon"][size],
                    manifest["icons"][size],
                )
            for size, relative_path in manifest["icons"].items():
                icon_path = extension_root / relative_path
                self.assertTrue(icon_path.is_file(), icon_path)
                with icon_path.open("rb") as icon:
                    self.assertEqual(icon.read(8), b"\x89PNG\r\n\x1a\n")
                    icon.read(8)
                    self.assertEqual(
                        struct.unpack(">II", icon.read(8)),
                        (int(size), int(size)),
                    )
                    png_bit_depth, png_color_type = icon.read(2)
                    self.assertIn(png_bit_depth, (8, 16))
                    self.assertEqual(png_color_type, 6)

if __name__ == "__main__":
    unittest.main()
