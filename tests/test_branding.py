from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from distraction_blocker import tray

from scripts import install
from scripts import uninstall


ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging"


class BrandingPackagingTests(unittest.TestCase):
    def test_focus_shield_assets_are_valid_theme_icons(self):
        app_icon = PACKAGING / "org.distraction_blocker.svg"
        symbolic_icon = PACKAGING / "org.distraction_blocker-symbolic.svg"

        app_root = ET.parse(app_icon).getroot()
        symbolic_root = ET.parse(symbolic_icon).getroot()
        self.assertEqual(app_root.attrib["viewBox"], "0 0 128 128")
        self.assertEqual(symbolic_root.attrib["viewBox"], "0 0 16 16")
        self.assertIn("currentColor", symbolic_icon.read_text(encoding="utf-8"))
    def test_desktop_entries_reference_installed_application_icon(self):
        app_entry = (PACKAGING / "org.distraction_blocker.App.desktop").read_text(
            encoding="utf-8"
        )
        tray_entry = (PACKAGING / "org.distraction_blocker.Tray.desktop").read_text(
            encoding="utf-8"
        )
        self.assertIn("Icon=org.distraction_blocker\n", app_entry)
        self.assertIn("StartupNotify=true\n", app_entry)
        self.assertIn("Icon=org.distraction_blocker\n", tray_entry)
        self.assertIn("Categories=Utility;\n", tray_entry)

    def test_installer_copies_both_icon_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "icons"
            descriptor = os.open(PACKAGING, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(install.os, "fchown"), patch.object(
                    install.os, "fchmod"
                ):
                    install.copy_asset(
                        descriptor,
                        "org.distraction_blocker.svg",
                        destination / "org.distraction_blocker.svg",
                    )
                    install.copy_asset(
                        descriptor,
                        "org.distraction_blocker-symbolic.svg",
                        destination / "org.distraction_blocker-symbolic.svg",
                    )
            finally:
                os.close(descriptor)

            self.assertTrue((destination / "org.distraction_blocker.svg").is_file())
            self.assertTrue(
                (destination / "org.distraction_blocker-symbolic.svg").is_file()
            )

    def test_installer_rejects_unowned_existing_icon(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "org.distraction_blocker.svg"
            path.write_text("foreign icon\n", encoding="utf-8")
            with patch.object(install, "fail", side_effect=SystemExit(2)):
                with self.assertRaises(SystemExit):
                    install.check_icon_asset(path)

    def test_uninstaller_rejects_unowned_icon(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "org.distraction_blocker.svg"
            path.write_text("foreign icon\n", encoding="utf-8")
            with patch.object(uninstall, "fail", side_effect=SystemExit(2)):
                with self.assertRaises(SystemExit):
                    uninstall.remove_owned_icon(path)
    def test_installer_refreshes_hicolor_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            theme_dir = root / "hicolor"
            theme_dir.mkdir()
            updater = root / "gtk-update-icon-cache"
            updater.write_text("stub\n", encoding="ascii")
            with (
                patch.object(install, "ICON_THEME_DIR", theme_dir),
                patch.object(install, "ICON_CACHE_UPDATER", updater),
                patch.object(
                    install.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=0),
                ) as run,
            ):
                install.refresh_icon_cache()

            run.assert_called_once_with(
                [
                    str(updater),
                    "--force",
                    "--ignore-theme-index",
                    str(theme_dir),
                ],
                check=False,
            )

    def test_tray_uses_symbolic_focus_shield(self):
        class Widget:
            def __init__(self, label=None):
                self.label = label
                self.children = []

            def append(self, child):
                self.children.append(child)

            def connect(self, *_args, **_kwargs):
                return None

            def get_children(self):
                return list(self.children)

            def remove(self, child):
                self.children.remove(child)

            def set_label(self, label):
                self.label = label

            def set_sensitive(self, _sensitive):
                return None

            def set_submenu(self, _submenu):
                return None
            def set_menu(self, _menu):
                return None

            def show_all(self):
                return None
        indicator = Widget()

        indicator_factory = Mock(return_value=indicator)
        gtk = SimpleNamespace(
            Menu=Widget,
            MenuItem=Widget,
            SeparatorMenuItem=Widget,
            main=lambda: None,
            main_quit=lambda: None,
        )
        app_indicator = SimpleNamespace(
            Indicator=SimpleNamespace(new=indicator_factory),
            IndicatorStatus=SimpleNamespace(ACTIVE="active"),
        )
        client = type(
            "Client",
            (),
            {
                "request": lambda _self, command, **_kwargs: {
                    "status": {"healthy": True},
                    "list_rules": {"rules": []},
                    "list_scheduled_actions": [],
                }[command]
            },
        )()
        with (
            patch.object(tray, "_load_modules", return_value=(gtk, app_indicator)),
            patch.object(
                tray,
                "current_notification_state",
                return_value=SimpleNamespace(show_banners=True),
            ),
        ):
            self.assertEqual(tray.run_tray(client_factory=lambda: client), 0)

        self.assertEqual(
            indicator_factory.call_args.args,
            (
                "distraction-blocker",
                "org.distraction_blocker-symbolic",
                "active",
            ),
        )



if __name__ == "__main__":
    unittest.main()
