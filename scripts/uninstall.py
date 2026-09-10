#!/usr/bin/env python3
"""Remove only Distraction Blocker paths."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import stat
import shutil
import subprocess
import sys
from typing import NoReturn

HOST_MANIFEST_FILENAME = "org.distraction_blocker.extension.json"
LEGACY_FIREFOX_MANIFEST_FILENAME = "org.distraction_blocker.firefox.json"
LEGACY_CHROMIUM_MANIFEST_FILENAME = "org.distraction_blocker.chromium.json"
FIREFOX_NATIVE_MANIFEST_DIRECTORIES = (
    "/usr/lib/mozilla/native-messaging-hosts",
    "/usr/lib/librewolf/native-messaging-hosts",
)
CHROMIUM_NATIVE_MANIFEST_DIRECTORIES = (
    "/etc/chromium/native-messaging-hosts",
    "/etc/opt/chrome/native-messaging-hosts",
)
NATIVE_MANIFESTS = tuple(
    Path(directory) / HOST_MANIFEST_FILENAME
    for directory in (
        *FIREFOX_NATIVE_MANIFEST_DIRECTORIES,
        *CHROMIUM_NATIVE_MANIFEST_DIRECTORIES,
    )
)
LEGACY_NATIVE_MANIFESTS = (
    *(
        Path(directory) / LEGACY_FIREFOX_MANIFEST_FILENAME
        for directory in FIREFOX_NATIVE_MANIFEST_DIRECTORIES
    ),
    *(
        Path(directory) / LEGACY_CHROMIUM_MANIFEST_FILENAME
        for directory in CHROMIUM_NATIVE_MANIFEST_DIRECTORIES
    ),
)
OWNER_NATIVE_MANIFESTS = (
    (".mozilla/native-messaging-hosts", HOST_MANIFEST_FILENAME),
    (".mozilla/native-messaging-hosts", LEGACY_FIREFOX_MANIFEST_FILENAME),
    (".librewolf/native-messaging-hosts", HOST_MANIFEST_FILENAME),
    (".librewolf/native-messaging-hosts", LEGACY_FIREFOX_MANIFEST_FILENAME),
    (".config/chromium/NativeMessagingHosts", HOST_MANIFEST_FILENAME),
    (
        ".config/chromium/NativeMessagingHosts",
        LEGACY_CHROMIUM_MANIFEST_FILENAME,
    ),
    (".config/google-chrome/NativeMessagingHosts", HOST_MANIFEST_FILENAME),
    (
        ".config/google-chrome/NativeMessagingHosts",
        LEGACY_CHROMIUM_MANIFEST_FILENAME,
    ),
)
PREFIX = Path("/usr/lib/distraction-blocker")
STATE = Path("/var/lib/distraction-blocker")
RUN = Path("/run/distraction-blocker")
UNIT = Path("/etc/systemd/system/distraction-blocker.service")
TRAY_AUTOSTART_DESKTOP = Path("/etc/xdg/autostart/org.distraction_blocker.Tray.desktop")
DESKTOP = Path("/usr/share/applications/org.distraction_blocker.App.desktop")
TRAY_DESKTOP = Path("/usr/share/applications/org.distraction_blocker.Tray.desktop")
LEGACY_DESKTOP = Path("/usr/share/applications/distraction-blocker.desktop")
CLI_PATH = Path("/usr/local/bin/distraction-blocker")
# would keep the state directory alive after uninstall because rmdir only
# removes an empty directory.
POLICY_FILES = (
    "hmac.key",
    "policy.json",
    "policy.json.bak",
    "statistics.json",
    "website-statistics.json",
    "website-usage.json",
    "scheduled-actions.json",
)
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"
CLI_MARKER = "# distraction-blocker-owned-wrapper-v1"
DNS_USER = "distraction-blocker-dns"
DNS_UNIT = Path("/etc/systemd/system/distraction-blocker-dns.service")
FENCE_UNIT = Path("/etc/systemd/system/distraction-blocker-network-restore.service")
SANDBOX_DROPIN_DIR = Path("/etc/systemd/system/distraction-blocker.service.d")
SANDBOX_DROPIN = SANDBOX_DROPIN_DIR / "network.conf"
NETWORK_ASSET_MARKER = b"# distraction-blocker-network-owned-v1"

def _open_directory_chain(path: Path) -> int:
    """Open an absolute directory path without following symlinks."""
    if not path.is_absolute():
        fail(f"manifest path is not absolute: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path.parts[0], flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _remove_manifest(path: Path) -> None:
    try:
        parent_fd = _open_directory_chain(path.parent)
    except FileNotFoundError:
        return
    except OSError as error:
        fail(f"manifest parent path is unsafe: {path}: {error}")
    try:
        try:
            metadata = os.stat(
                path.name, dir_fd=parent_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"refusing to remove a symlink at {path}")
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"refusing to remove an unsafe manifest path: {path}")
        os.unlink(path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
def check_network_asset(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if (
        path.is_symlink() or not path.is_file()
        or metadata.st_uid != 0 or metadata.st_mode & 0o022
        or path.read_bytes().splitlines()[:1] != [NETWORK_ASSET_MARKER]
    ):
        fail(f"refusing to remove an unowned network asset: {path}")


def enforcement_module():
    """Import the network enforcement module from the source tree."""
    source_root = Path(__file__).resolve().parent.parent
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from distraction_blocker import network_enforcement

    return network_enforcement


def network_teardown() -> None:
    """Stop and remove only the network resources this install owned.

    Recovery runs first and cleans the owned firewall table, the dedicated
    resolver, and its configuration. Any failure aborts the whole
    uninstall so unrelated resources are never touched by a half-finished
    cleanup.
    """
    module = enforcement_module()
    marker = Path(module.marker_path(STATE))
    marker_present = module.is_network_enabled(STATE)
    has_units = (
        DNS_UNIT.exists()
        or FENCE_UNIT.exists()
        or SANDBOX_DROPIN.exists()
    )
    if not marker_present and not has_units:
        if marker.exists() or marker.is_symlink():
            fail(f"the network enablement marker is invalid: {marker}")
        return
    for path in (DNS_UNIT, FENCE_UNIT, SANDBOX_DROPIN):
        check_network_asset(path)
    try:
        status = module.main(["recover"])
    except Exception as exc:
        fail(f"network recovery failed: {exc}; aborting before removal")
    if status != 0:
        fail("network recovery failed; aborting before removal")
    for path in (DNS_UNIT, FENCE_UNIT, SANDBOX_DROPIN):
        if path.is_file():
            path.unlink()
    if SANDBOX_DROPIN_DIR.exists():
        if SANDBOX_DROPIN_DIR.is_symlink() or not SANDBOX_DROPIN_DIR.is_dir():
            fail(f"the sandbox drop-in path is unsafe: {SANDBOX_DROPIN_DIR}")
        if not any(SANDBOX_DROPIN_DIR.iterdir()):
            SANDBOX_DROPIN_DIR.rmdir()
    # Breadcrumb: remove only the dedicated resolver account with the
    # exact attributes the installer gave it.
    try:
        account = pwd.getpwnam(DNS_USER)
    except KeyError:
        return
    if (
        0 < account.pw_uid < 1000
        and account.pw_shell == "/usr/sbin/nologin"
        and account.pw_dir == "/nonexistent"
    ):
        subprocess.run(["/usr/sbin/userdel", DNS_USER], check=True)


def fail(message: str) -> NoReturn:
    print(f"Uninstall refused: {message}", file=sys.stderr)
    raise SystemExit(2)
def _owner_uid() -> int | None:
    owner_file = STATE / "owner.uid"
    if not owner_file.is_file() or owner_file.is_symlink():
        return None
    try:
        return int(owner_file.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None

def restore_owner_notifications(uid: int | None) -> None:
    if uid is None:
        return
    try:
        account = pwd.getpwuid(uid)
    except KeyError:
        return
    config_root = Path(account.pw_dir) / ".config"
    preference_root = config_root / "distraction-blocker"
    for directory in (config_root, preference_root):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            fail("refusing to read an unsafe notification preference path")
    source = preference_root / "notifications.json"
    if not source.exists():
        return
    if source.is_symlink() or not source.is_file():
        fail("refusing to read an unsafe notification preference path")
    try:
        saved = json.loads(source.read_text(encoding="utf-8"))
        if (
            set(saved) != {"show_banners", "show_in_lock_screen"}
            or not isinstance(saved["show_banners"], bool)
            or not isinstance(saved["show_in_lock_screen"], bool)
        ):
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        fail("saved notification preferences are invalid")
    try:
        for key in ("show-banners", "show-in-lock-screen"):
            value = "true" if saved[key.replace("-", "_")] else "false"
            subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    account.pw_name,
                    "--",
                    "/usr/bin/gsettings",
                    "set",
                    "org.gnome.desktop.notifications",
                    key,
                    value,
                ],
                check=True,
                timeout=30,
            )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"could not restore notification preferences: {error}")
    source.unlink()

def run_systemctl(args: list[str]) -> None:
    result = subprocess.run(["/usr/bin/systemctl", *args], check=False)
    if result.returncode != 0:
        fail("systemd rejected the requested change")


def require_installation() -> None:
    marker = PREFIX / MARKER_NAME
    if PREFIX.is_symlink() or marker.is_symlink():
        fail("the install path is a symlink")
    if not marker.is_file():
        fail("the install marker is missing")
    if marker.read_text(encoding="ascii") != MARKER_TEXT:
        fail("the install marker is invalid")


def clear_hosts() -> None:
    source_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(source_root))
    from distraction_blocker.enforcement import HostsEnforcer

    HostsEnforcer("/etc/hosts").clear()


def remove_cli() -> None:
    """Remove only the wrapper that carries our ownership marker."""
    if CLI_PATH.is_symlink():
        fail(f"refusing to remove a symlink at {CLI_PATH}")
    if not CLI_PATH.exists():
        return
    if not CLI_PATH.is_file():
        fail(f"refusing to remove an unsafe CLI path: {CLI_PATH}")
    try:
        owned = CLI_MARKER in CLI_PATH.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        owned = False
    if not owned:
        fail(f"refusing to remove an unrelated CLI path: {CLI_PATH}")
    CLI_PATH.unlink()


def remove_native_manifests() -> None:
    for path in (*NATIVE_MANIFESTS, *LEGACY_NATIVE_MANIFESTS):
        _remove_manifest(path)
    # Breadcrumb: the installer also placed per-owner copies under the
    # desktop user's home; remove current and legacy names.
    owner_file = STATE / "owner.uid"
    homes = []
    if owner_file.is_file():
        try:
            uid = int(owner_file.read_text(encoding="ascii").strip())
            homes.append(Path(pwd.getpwuid(uid).pw_dir))
        except (OSError, ValueError, KeyError):
            pass
    for home in homes:
        for subdir, manifest_name in OWNER_NATIVE_MANIFESTS:
            _remove_manifest(home / subdir / manifest_name)



def main() -> int:
    parser = argparse.ArgumentParser(description="Remove Distraction Blocker")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm removal on this host",
    )
    parser.add_argument(
        "--remove-policy",
        action="store_true",
        help="remove the protected policy and key",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        fail("run as root")
    if not args.confirm:
        fail("pass --confirm; this default protects the current host")

    try:
        require_installation()
        owner_uid = _owner_uid()
        # Breadcrumb for reviewers: use systemctl as an argument list, never through a shell.
        if not UNIT.is_file() or UNIT.is_symlink():
            fail("the service unit is missing or unsafe")
        run_systemctl(["disable", "--now", "distraction-blocker.service"])
        restore_owner_notifications(owner_uid)
        clear_hosts()
        network_teardown()
        remove_cli()
        for path in (
            UNIT,
            DESKTOP,
            TRAY_DESKTOP,
            TRAY_AUTOSTART_DESKTOP,
            LEGACY_DESKTOP,
        ):
            if path.is_symlink():
                fail(f"refusing to remove a symlink at {path}")
            if path.is_file():
                path.unlink()
        run_systemctl(["daemon-reload"])
        remove_native_manifests()
        if PREFIX.is_symlink():
            fail("refusing to remove a symlink at the install path")
        if PREFIX.exists():
            shutil.rmtree(PREFIX)

        if RUN.is_symlink():
            fail("refusing to remove a symlink at the runtime path")
        if RUN.exists():
            shutil.rmtree(RUN)

        if STATE.is_symlink():
            fail("refusing to remove a symlink at the state path")
        if STATE.exists():
            owner = STATE / "owner.uid"
            if owner.is_symlink():
                fail("refusing to remove a symlink at the owner file")
            if owner.exists():
                owner.unlink()
            if args.remove_policy:
                for name in POLICY_FILES:
                    path = STATE / name
                    if path.is_symlink():
                        fail(f"refusing to remove a symlink at {path}")
                    if path.is_file():
                        path.unlink()
            try:
                STATE.rmdir()
            except OSError:
                pass
    except OSError as exc:
        fail(f"removal failed: {exc.strerror or exc}")
    print("Distraction Blocker removed.")
    return 0


if __name__ == "__main__":
    main()
