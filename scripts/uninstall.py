#!/usr/bin/env python3
"""Remove only Distraction Blocker paths."""

from __future__ import annotations

import argparse
import os
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
POLICY_FILES = ("hmac.key", "policy.json", "policy.json.bak")
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"


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

        for path in (UNIT, DESKTOP, LEGACY_DESKTOP):
            if path.is_symlink():
                fail(f"refusing to remove a symlink at {path}")
            if path.is_file():
                path.unlink()
        run_systemctl(["daemon-reload"])

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
