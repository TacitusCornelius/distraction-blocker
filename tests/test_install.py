from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import install


class InstallerSecurityTests(unittest.TestCase):
    def test_network_risk_requires_both_explicit_flags(self):
        for flag in ("--enable-network-controls", "--accept-network-risk"):
            with self.subTest(flag=flag), patch(
                "sys.argv", ["install.py", "--confirm", "--owner-uid", "1000", flag]
            ), patch.object(install.os, "geteuid", return_value=0):
                with self.assertRaises(SystemExit) as error:
                    install.main()
                self.assertEqual(error.exception.code, 2)

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
    def test_package_asset_refuses_symlinked_destination_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "manifest.json").write_text("{}\n", encoding="utf-8")
            home = root / "home"
            home.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (home / ".mozilla").symlink_to(outside, target_is_directory=True)
            destination = home / ".mozilla" / "native-messaging-hosts" / "manifest.json"
            descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    install.copy_asset(descriptor, "manifest.json", destination)
            finally:
                os.close(descriptor)
            self.assertFalse((outside / "native-messaging-hosts").exists())

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

    def test_invalid_owner_is_rejected_before_network_account_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing_uid = 987654
            with (
                patch.object(install, "installation_exists", return_value=False),
                patch.object(install, "check_cli_collision"),
                patch.object(install, "UNIT", root / "unit"),
                patch.object(install, "DESKTOP", root / "desktop"),
                patch.object(install, "LEGACY_DESKTOP", root / "legacy"),
                patch.object(install.pwd, "getpwuid", side_effect=KeyError),
                patch.object(
                    install,
                    "ensure_dns_user",
                    side_effect=AssertionError("must validate owner first"),
                ),
            ):
                with self.assertRaises(SystemExit) as raised:
                    install.install_files(root, missing_uid, True, False)
            self.assertEqual(raised.exception.code, 2)


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


    def test_report_website_usage_is_forwarded_with_pinned_fields(self) -> None:
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
                "command": "report_website_usage",
                "entries": [{
                    "rule_id": "12345678-1234-5678-1234-567812345678",
                    "value": "example.com",
                    "count": 1,
                }],
            })
        self.assertTrue(forwarded["ok"])
        self.assertEqual(seen["command"], "report_website_usage")
        widened = host_entry.handle({
            "command": "report_website_usage",
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



class UninstallManifestTests(unittest.TestCase):
    """Per-owner native-messaging manifests must be removed exactly where
    install.py wrote them; see scripts/uninstall.py remove_native_manifests."""

    OWNER_PAIRS = (
        (".mozilla/native-messaging-hosts", "org.distraction_blocker.extension.json"),
        (".mozilla/native-messaging-hosts", "org.distraction_blocker.firefox.json"),
        (".librewolf/native-messaging-hosts", "org.distraction_blocker.extension.json"),
        (".librewolf/native-messaging-hosts", "org.distraction_blocker.firefox.json"),
        (
            ".config/chromium/NativeMessagingHosts",
            "org.distraction_blocker.extension.json",
        ),
        (
            ".config/chromium/NativeMessagingHosts",
            "org.distraction_blocker.chromium.json",
        ),
        (
            ".config/google-chrome/NativeMessagingHosts",
            "org.distraction_blocker.extension.json",
        ),
        (
            ".config/google-chrome/NativeMessagingHosts",
            "org.distraction_blocker.chromium.json",
        ),
    )


    def test_removes_every_per_owner_manifest_written_by_installer(self):
        import types

        from scripts import uninstall
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            (state / "owner.uid").write_text("1000\n", encoding="ascii")
            home = root / "home"
            for subdir, name in self.OWNER_PAIRS:
                manifest = home / subdir / name
                manifest.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_text("{}\n", encoding="utf-8")
            bystander = home / ".mozilla" / "native-messaging-hosts" / "other.json"
            bystander.write_text("{}\n", encoding="utf-8")
            account = types.SimpleNamespace(pw_dir=str(home))
            with (
                patch.object(uninstall, "STATE", state),
                patch.object(uninstall, "NATIVE_MANIFESTS", ()),
                patch.object(uninstall, "LEGACY_NATIVE_MANIFESTS", ()),
                patch.object(uninstall.pwd, "getpwuid", return_value=account),
            ):
                uninstall.remove_native_manifests()
            for subdir, name in self.OWNER_PAIRS:
                self.assertFalse((home / subdir / name).exists())
            self.assertTrue(bystander.exists())

    def test_refuses_symlinked_per_owner_manifest(self):
        import types

        from scripts import uninstall

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            (state / "owner.uid").write_text("1000\n", encoding="ascii")
            home = root / "home"
            first_subdir, first_name = self.OWNER_PAIRS[0]
            target = root / "outside.json"
            target.write_text("{}\n", encoding="utf-8")
            manifest = home / first_subdir / first_name
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.symlink_to(target)
            account = types.SimpleNamespace(pw_dir=str(home))
            with (
                patch.object(uninstall, "STATE", state),
                patch.object(uninstall, "NATIVE_MANIFESTS", ()),
                patch.object(uninstall, "LEGACY_NATIVE_MANIFESTS", ()),
                patch.object(uninstall.pwd, "getpwuid", return_value=account),
            ):
                with self.assertRaises(SystemExit) as raised:
                    uninstall.remove_native_manifests()
            self.assertEqual(raised.exception.code, 2)
            self.assertTrue(target.exists())

    def test_refuses_symlinked_per_owner_manifest_parent(self):
        import types

        from scripts import uninstall

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            (state / "owner.uid").write_text("1000\n", encoding="ascii")
            home = root / "home"
            home.mkdir()
            outside = root / "outside"
            outside.mkdir()
            first_subdir, first_name = self.OWNER_PAIRS[0]
            (home / ".mozilla").symlink_to(outside, target_is_directory=True)
            victim = outside / "native-messaging-hosts" / first_name
            victim.parent.mkdir(parents=True)
            victim.write_text("{}\n", encoding="utf-8")
            account = types.SimpleNamespace(pw_dir=str(home))
            with (
                patch.object(uninstall, "STATE", state),
                patch.object(uninstall, "NATIVE_MANIFESTS", ()),
                patch.object(uninstall, "LEGACY_NATIVE_MANIFESTS", ()),
                patch.object(uninstall.pwd, "getpwuid", return_value=account),
            ):
                with self.assertRaises(SystemExit) as raised:
                    uninstall.remove_native_manifests()
            self.assertEqual(raised.exception.code, 2)
            self.assertTrue(victim.exists())

    def test_uninstall_pairs_mirror_install_writes(self):
        import ast

        # Breadcrumb: a drift between the installer's per-owner writes and
        # the uninstaller's removal pairs silently orphans manifests; pin
        # the two literal pair tables to each other.
        scripts_root = Path(install.__file__).parent
        trees = {}
        for module_name in ("install", "uninstall"):
            tree = ast.parse(
                (scripts_root / f"{module_name}.py").read_text(encoding="utf-8")
            )
            literals = {
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            trees[module_name] = literals
        for subdir, name in self.OWNER_PAIRS:
            self.assertIn(subdir, trees["uninstall"])
            self.assertIn(name, trees["uninstall"])
            leaf = subdir.rsplit("/", 1)[-1]
            self.assertIn(leaf, trees["install"])
            self.assertIn(name, trees["install"])

    def test_installer_removes_only_legacy_manifest_names(self):
        from scripts import install

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            system_paths = (
                root / "system-firefox.json",
                root / "system-chromium.json",
            )
            for path in system_paths:
                path.write_text("{}\n", encoding="utf-8")
            for subdir, name in install.LEGACY_OWNER_NATIVE_MANIFESTS:
                path = home / subdir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
            bystander = home / ".mozilla/native-messaging-hosts/other.json"
            bystander.write_text("{}\n", encoding="utf-8")

            with patch.object(
                install, "LEGACY_SYSTEM_NATIVE_MANIFESTS", system_paths
            ):
                install.remove_legacy_native_manifests(home)

            self.assertTrue(all(not path.exists() for path in system_paths))
            for subdir, name in install.LEGACY_OWNER_NATIVE_MANIFESTS:
                self.assertFalse((home / subdir / name).exists())
            self.assertTrue(bystander.exists())

    def test_uninstall_reloads_systemd_after_unit_removal(self):
        from scripts import uninstall

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unit = root / "distraction-blocker.service"
            unit.write_text("[Service]\n", encoding="utf-8")
            calls = []
            with (
                patch("sys.argv", ["uninstall.py", "--confirm"]),
                patch.object(uninstall.os, "geteuid", return_value=0),
                patch.object(uninstall, "UNIT", unit),
                patch.object(uninstall, "DESKTOP", root / "desktop"),
                patch.object(uninstall, "LEGACY_DESKTOP", root / "legacy-desktop"),
                patch.object(uninstall, "PREFIX", root / "prefix"),
                patch.object(uninstall, "RUN", root / "run"),
                patch.object(uninstall, "STATE", root / "state"),
                patch.object(uninstall, "require_installation"),
                patch.object(uninstall, "clear_hosts"),
                patch.object(uninstall, "remove_cli"),
                patch.object(uninstall, "remove_native_manifests"),
                patch.object(
                    uninstall,
                    "run_systemctl",
                    side_effect=lambda args: calls.append(args),
                ),
            ):
                self.assertEqual(uninstall.main(), 0)

            self.assertEqual(
                calls,
                [
                    ["disable", "--now", "distraction-blocker.service"],
                    ["daemon-reload"],
                ],
            )





if __name__ == "__main__":
    unittest.main()


