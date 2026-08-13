#!/usr/bin/env python3
"""Install Distraction Blocker without invoking a shell or sudo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable, NoReturn

PREFIX = Path("/usr/lib/distraction-blocker")
STATE = Path("/var/lib/distraction-blocker")
RUN = Path("/run/distraction-blocker")
UNIT = Path("/etc/systemd/system/distraction-blocker.service")
DESKTOP = Path("/usr/share/applications/distraction-blocker.desktop")
PACKAGE_NAME = "distraction_blocker"
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"


def fail(message: str) -> NoReturn:
    print(f"Install refused: {message}", file=sys.stderr)
    raise SystemExit(2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install Distraction Blocker")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm installation on this host",
    )
    parser.add_argument(
        "--owner-uid",
        type=int,
        required=True,
        help="UID of the protected desktop user",
    )
    return parser.parse_args()


def run_systemctl(args: Iterable[str]) -> None:
    # Breadcrumb for reviewers: pass an argument list so a service name cannot become shell code.
    result = subprocess.run(["/usr/bin/systemctl", *args], check=False)
    if result.returncode != 0:
        fail("systemd rejected the requested change")


def set_mode(path: Path, mode: int) -> None:
    path.chmod(mode)
    os.chown(path, 0, 0)


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        fail("the source package is missing")
    if destination.exists() or destination.is_symlink():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for item in destination.rglob("*"):
        if item.is_symlink():
            fail("the source package contains a symlink")
        if item.is_dir():
            set_mode(item, 0o755)
        else:
            set_mode(item, 0o644)
    set_mode(destination, 0o755)


def copy_asset(source: Path, destination: Path, mode: int = 0o644) -> None:
    if not source.is_file() or source.is_symlink():
        fail("a packaging file is missing")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    set_mode(destination, mode)


def installation_exists() -> bool:
    marker = PREFIX / MARKER_NAME
    if PREFIX.is_symlink() or marker.is_symlink():
        fail("the install path is a symlink")
    if not PREFIX.exists():
        return False
    if not PREFIX.is_dir() or not marker.is_file():
        fail("the install path does not belong to Distraction Blocker")
    try:
        valid = marker.read_text(encoding="ascii") == MARKER_TEXT
    except OSError as error:
        fail(f"cannot read the install marker: {error.strerror or error}")
    if not valid:
        fail("the install marker is invalid")
    return True


def install_files(source_root: Path, owner_uid: int) -> None:
    upgrading = installation_exists()
    if not upgrading:
        for path in (UNIT, DESKTOP):
            if path.exists() or path.is_symlink():
                fail(f"refusing to replace an existing path: {path}")
    package_source = source_root / PACKAGE_NAME
    copy_tree(package_source, PREFIX / PACKAGE_NAME)

    packaging = source_root / "packaging"
    copy_asset(packaging / "daemon_entry.py", PREFIX / "daemon_entry.py", 0o755)
    copy_asset(packaging / "gui_entry.py", PREFIX / "gui_entry.py", 0o755)
    copy_asset(packaging / "distraction-blocker.service", UNIT)
    copy_asset(packaging / "distraction-blocker.desktop", DESKTOP)

    marker = PREFIX / MARKER_NAME
    marker.write_text(MARKER_TEXT, encoding="ascii")
    set_mode(marker, 0o644)
    for path in (STATE, RUN):
        if path.is_symlink() or path.exists() and not path.is_dir():
            fail(f"protected path is not a directory: {path}")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    RUN.mkdir(mode=0o755, parents=True, exist_ok=True)
    set_mode(STATE, 0o700)
    set_mode(RUN, 0o755)
    owner_file = STATE / "owner.uid"
    if owner_file.is_symlink():
        fail("the owner UID file is a symlink")
    owner_file.write_text(f"{owner_uid}\n", encoding="ascii")
    set_mode(owner_file, 0o600)


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        fail("run as root")
    if not args.confirm:
        fail("pass --confirm; this default protects the current host")
    if args.owner_uid <= 0 or args.owner_uid > 2**31 - 1:
        fail("owner UID is not valid")
    source_root = Path(__file__).resolve().parent.parent
    if source_root == Path("/") or not (source_root / PACKAGE_NAME).is_dir():
        fail("the source package is missing")

    try:
        install_files(source_root, args.owner_uid)
        run_systemctl(["daemon-reload"])
        run_systemctl(["enable", "distraction-blocker.service"])
        run_systemctl(["restart", "distraction-blocker.service"])
    except OSError as exc:
        fail(f"installation failed: {exc.strerror or exc}")
    print("Distraction Blocker installed.")
    return 0


if __name__ == "__main__":
    main()
