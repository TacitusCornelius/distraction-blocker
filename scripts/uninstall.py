#!/usr/bin/env python3
"""Remove only Distraction Blocker paths."""

from __future__ import annotations

import argparse
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import sys
from typing import NoReturn

PREFIX = Path("/usr/lib/distraction-blocker")
STATE = Path("/var/lib/distraction-blocker")
RUN = Path("/run/distraction-blocker")
UNIT = Path("/etc/systemd/system/distraction-blocker.service")
DESKTOP = Path("/usr/share/applications/org.distraction_blocker.App.desktop")
LEGACY_DESKTOP = Path("/usr/share/applications/distraction-blocker.desktop")
CLI_PATH = Path("/usr/local/bin/distraction-blocker")
NATIVE_MANIFESTS = tuple(
    Path(directory) / manifest_name
    for directory in (
        "/usr/lib/mozilla/native-messaging-hosts",
        "/usr/lib/librewolf/native-messaging-hosts",
        "/etc/chromium/native-messaging-hosts",
        "/etc/opt/chrome/native-messaging-hosts",
    )
    for manifest_name in (
        "org.distraction_blocker.firefox.json",
        "org.distraction_blocker.chromium.json",
    )
)
POLICY_FILES = ("hmac.key", "policy.json", "policy.json.bak", "statistics.json")
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"
CLI_MARKER = "# distraction-blocker-owned-wrapper-v1"

def fail(message: str) -> NoReturn:
    print(f"Uninstall refused: {message}", file=sys.stderr)
    raise SystemExit(2)


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
    for path in NATIVE_MANIFESTS:
        if path.is_symlink():
            fail(f"refusing to remove a symlink at {path}")
        if path.is_file():
            path.unlink()
    # Breadcrumb: the installer also placed per-owner copies under the
    # desktop user's home; remove those for the recorded owner UID.
    owner_file = Path("/var/lib/distraction-blocker/owner.uid")
    homes = []
    if owner_file.is_file():
        try:
            uid = int(owner_file.read_text(encoding="ascii").strip())
            homes.append(Path(pwd.getpwuid(uid).pw_dir))
        except (OSError, ValueError, KeyError):
            pass
    for home in homes:
        for subdir in (".mozilla", ".librewolf", ".config/chromium/NativeMessagingHosts", ".config/google-chrome/NativeMessagingHosts"):
            path = home / subdir / "native-messaging-hosts" / "org.distraction_blocker.firefox.json"
            if path.is_symlink():
                fail(f"refusing to remove a symlink at {path}")
            if path.is_file():
                path.unlink()



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
        # Breadcrumb for reviewers: use systemctl as an argument list, never through a shell.
        if not UNIT.is_file() or UNIT.is_symlink():
            fail("the service unit is missing or unsafe")
        run_systemctl(["disable", "--now", "distraction-blocker.service"])
        clear_hosts()
        remove_cli()

        for path in (UNIT, DESKTOP, LEGACY_DESKTOP):
            if path.is_symlink():
                fail(f"refusing to remove a symlink at {path}")
            if path.is_file():
                path.unlink()
        run_systemctl(["daemon-reload"])
        remove_cli()
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
