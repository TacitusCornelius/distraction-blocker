#!/usr/bin/env python3
"""Install Distraction Blocker without invoking a shell or sudo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterable, NoReturn

PREFIX = Path("/usr/lib/distraction-blocker")
STATE = Path("/var/lib/distraction-blocker")
RUN = Path("/run/distraction-blocker")
UNIT = Path("/etc/systemd/system/distraction-blocker.service")
DESKTOP = Path("/usr/share/applications/org.distraction_blocker.App.desktop")
LEGACY_DESKTOP = Path("/usr/share/applications/distraction-blocker.desktop")
CLI_PATH = Path("/usr/local/bin/distraction-blocker")
PACKAGE_NAME = "distraction_blocker"
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"
CLI_MARKER = "# distraction-blocker-owned-wrapper-v1"


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


def _source_fd(parent_fd: int, name: str, *, directory: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(descriptor)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode):
        os.close(descriptor)
        fail("the source contains an unsafe file type")
    return descriptor


def _copy_descriptor(
    source_fd: int, destination: Path, mode: int
) -> None:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if destination.is_symlink() or (
        destination.exists() and not destination.is_file()
    ):
        fail(f"refusing to replace an unsafe path: {destination}")
    target_fd, temporary_name = tempfile.mkstemp(
        prefix=".distraction-blocker-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(source_fd), "rb") as source_stream:
            with os.fdopen(target_fd, "wb") as target_stream:
                target_fd = -1
                shutil.copyfileobj(source_stream, target_stream)
                target_stream.flush()
                os.fsync(target_stream.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if target_fd >= 0:
            os.close(target_fd)


def _copy_directory(source_fd: int, destination: Path) -> None:
    for name in sorted(os.listdir(source_fd)):
        if name == "__pycache__" or name.endswith(".pyc"):
            continue
        metadata = os.stat(
            name, dir_fd=source_fd, follow_symlinks=False
        )
        target = destination / name
        if stat.S_ISLNK(metadata.st_mode):
            fail("the source package contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = _source_fd(source_fd, name, directory=True)
            try:
                target.mkdir(mode=0o755)
                set_mode(target, 0o755)
                _copy_directory(child_fd, target)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            child_fd = _source_fd(source_fd, name, directory=False)
            try:
                _copy_descriptor(child_fd, target, 0o644)
            finally:
                os.close(child_fd)
        else:
            fail("the source package contains an unsafe file type")


def copy_tree(source_fd: int, destination: Path) -> None:
    if destination.is_symlink():
        fail("the installed package path is a symlink")
    if destination.exists():
        if not destination.is_dir():
            fail("the installed package path is unsafe")
        shutil.rmtree(destination)
    destination.mkdir(mode=0o755, parents=True)
    set_mode(destination, 0o755)
    _copy_directory(source_fd, destination)


def copy_asset(
    source_dir_fd: int,
    source_name: str,
    destination: Path,
    mode: int = 0o644,
) -> None:
    source_fd = _source_fd(
        source_dir_fd, source_name, directory=False
    )
    try:
        _copy_descriptor(source_fd, destination, mode)
    finally:
        os.close(source_fd)


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


def check_cli_collision() -> None:
    """Allow creation or replacement of only our marked wrapper."""
    if CLI_PATH.is_symlink():
        fail(f"refusing to replace an existing path: {CLI_PATH}")
    if not CLI_PATH.exists():
        return
    if not CLI_PATH.is_file():
        fail(f"refusing to replace an existing path: {CLI_PATH}")
    try:
        owned = CLI_MARKER in CLI_PATH.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        owned = False
    if not owned:
        fail(f"refusing to replace an existing path: {CLI_PATH}")



def install_files(source_root: Path, owner_uid: int) -> None:
    upgrading = installation_exists()
    check_cli_collision()
    if not upgrading:
        for path in (UNIT, DESKTOP, LEGACY_DESKTOP):
            if path.exists() or path.is_symlink():
                fail(f"refusing to replace an existing path: {path}")
    elif LEGACY_DESKTOP.is_symlink() or (
        LEGACY_DESKTOP.exists() and not LEGACY_DESKTOP.is_file()
    ):
        fail(f"the old desktop path is unsafe: {LEGACY_DESKTOP}")
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = os.open(source_root, root_flags)
    try:
        package_fd = _source_fd(
            root_fd, PACKAGE_NAME, directory=True
        )
        packaging_fd = _source_fd(
            root_fd, "packaging", directory=True
        )
        try:
            copy_tree(package_fd, PREFIX / PACKAGE_NAME)
            copy_asset(
                packaging_fd,
                "daemon_entry.py",
                PREFIX / "daemon_entry.py",
                0o755,
            )
            copy_asset(
                packaging_fd,
                "gui_entry.py",
                PREFIX / "gui_entry.py",
                0o755,
            )
            copy_asset(
                packaging_fd, "cli_entry.py", CLI_PATH, 0o755
            )
            copy_asset(
                packaging_fd, "distraction-blocker.service", UNIT
            )
            copy_asset(
                packaging_fd,
                "org.distraction_blocker.App.desktop",
                DESKTOP,
            )
        finally:
            os.close(packaging_fd)
            os.close(package_fd)
    finally:
        os.close(root_fd)
    if upgrading and LEGACY_DESKTOP.is_file():
        # Breadcrumb for reviewers: version 1.2 aligns the desktop filename
        # with the GTK application ID so Gio notifications have an identity.
        LEGACY_DESKTOP.unlink()
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
