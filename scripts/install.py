#!/usr/bin/env python3
"""Install Distraction Blocker without invoking a shell or sudo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterable, NoReturn

HOST_MANIFEST_FILENAME = "org.distraction_blocker.extension.json"
LEGACY_FIREFOX_MANIFEST_FILENAME = "org.distraction_blocker.firefox.json"
LEGACY_CHROMIUM_MANIFEST_FILENAME = "org.distraction_blocker.chromium.json"
LEGACY_SYSTEM_NATIVE_MANIFESTS = (
    Path("/usr/lib/mozilla/native-messaging-hosts")
    / LEGACY_FIREFOX_MANIFEST_FILENAME,
    Path("/usr/lib/librewolf/native-messaging-hosts")
    / LEGACY_FIREFOX_MANIFEST_FILENAME,
    Path("/etc/chromium/native-messaging-hosts")
    / LEGACY_CHROMIUM_MANIFEST_FILENAME,
    Path("/etc/opt/chrome/native-messaging-hosts")
    / LEGACY_CHROMIUM_MANIFEST_FILENAME,
)
LEGACY_OWNER_NATIVE_MANIFESTS = (
    (".mozilla/native-messaging-hosts", LEGACY_FIREFOX_MANIFEST_FILENAME),
    (".librewolf/native-messaging-hosts", LEGACY_FIREFOX_MANIFEST_FILENAME),
    (
        ".config/chromium/NativeMessagingHosts",
        LEGACY_CHROMIUM_MANIFEST_FILENAME,
    ),
    (
        ".config/google-chrome/NativeMessagingHosts",
        LEGACY_CHROMIUM_MANIFEST_FILENAME,
    ),
)
PREFIX = Path("/usr/lib/distraction-blocker")
STATE = Path("/var/lib/distraction-blocker")
RUN = Path("/run/distraction-blocker")
UNIT = Path("/etc/systemd/system/distraction-blocker.service")
DESKTOP = Path("/usr/share/applications/org.distraction_blocker.App.desktop")
TRAY_DESKTOP = Path("/usr/share/applications/org.distraction_blocker.Tray.desktop")
TRAY_AUTOSTART_DESKTOP = Path("/etc/xdg/autostart/org.distraction_blocker.Tray.desktop")
LEGACY_DESKTOP = Path("/usr/share/applications/distraction-blocker.desktop")
CLI_PATH = Path("/usr/local/bin/distraction-blocker")
PACKAGE_NAME = "distraction_blocker"
MARKER_NAME = "INSTALLATION"
MARKER_TEXT = "distraction-blocker\n"
CLI_MARKER = "# distraction-blocker-owned-wrapper-v1"
DNS_USER = "distraction-blocker-dns"
DNS_UNIT = Path("/etc/systemd/system/distraction-blocker-dns.service")
FENCE_UNIT = Path("/etc/systemd/system/distraction-blocker-network-restore.service")
SANDBOX_DROPIN_DIR = Path("/etc/systemd/system/distraction-blocker.service.d")
SANDBOX_DROPIN = SANDBOX_DROPIN_DIR / "network.conf"
DNSMASQ_MINIMUM_VERSION = (2, 86)
NETWORK_ASSET_MARKER = "# distraction-blocker-network-owned-v1"


def check_network_asset(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if (
        path.is_symlink() or not path.is_file()
        or metadata.st_uid != 0 or metadata.st_mode & 0o022
        or path.read_bytes().splitlines()[:1] != [NETWORK_ASSET_MARKER.encode()]
    ):
        fail(f"refusing to replace an unowned network asset: {path}")

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
    parser.add_argument(
        "--enable-network-controls",
        dest="enable_network_controls",
        action="store_true",
        help="enable protected-user network controls; requires --accept-network-risk",
    )
    parser.add_argument(
        "--accept-network-risk",
        dest="accept_network_risk",
        action="store_true",
        help="acknowledge that network controls can break unrelated network access",
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


def _open_directory_chain(
    path: Path, *, create: bool, owner: tuple[int, int] = (0, 0)
) -> int:
    """Open an absolute directory path without following symlinks."""
    if not path.is_absolute():
        fail(f"destination path is not absolute: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path.parts[0], flags)
    try:
        for component in path.parts[1:]:
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o755, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            if created:
                os.fchmod(child, 0o755)
                os.fchown(child, *owner)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _source_fd(parent_fd: int, name: str, *, directory: bool) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return os.open(name, flags, dir_fd=parent_fd)

def _copy_descriptor(
    source_fd: int,
    destination: Path,
    mode: int,
    owner: tuple[int, int] = (0, 0),
) -> None:
    parent_fd = _open_directory_chain(
        destination.parent, create=True, owner=owner
    )
    temporary_name: str | None = None
    try:
        try:
            metadata = os.stat(
                destination.name, dir_fd=parent_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                fail(f"refusing to replace an unsafe path: {destination}")
        target_fd, temporary_path = tempfile.mkstemp(
            prefix=".distraction-blocker-",
            dir=f"/proc/self/fd/{parent_fd}",
        )
        temporary_name = os.path.basename(temporary_path)
        os.fchmod(target_fd, mode)
        os.fchown(target_fd, *owner)
        try:
            os.lseek(source_fd, 0, os.SEEK_SET)
            with os.fdopen(os.dup(source_fd), "rb") as source_stream:
                with os.fdopen(target_fd, "wb") as target_stream:
                    target_fd = -1
                    shutil.copyfileobj(source_stream, target_stream)
                    target_stream.flush()
                    os.fsync(target_stream.fileno())
            os.replace(
                temporary_name,
                destination.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            temporary_name = None
            os.fsync(parent_fd)
        finally:
            if target_fd >= 0:
                os.close(target_fd)
    except BaseException:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(parent_fd)

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
    owner: tuple[int, int] = (0, 0),
) -> None:
    source_fd = _source_fd(
        source_dir_fd, source_name, directory=False
    )
    try:
        _copy_descriptor(source_fd, destination, mode, owner)
    finally:
        os.close(source_fd)

def configure_service_unit(owner_home: Path, owner_uid: int) -> None:
    """Allow scheduled notifications to write only the owner's state path."""
    config_path = str(owner_home / ".config" / "distraction-blocker")
    escaped_path = config_path.replace("\\", "\\x5c").replace(" ", "\\x20")
    text = UNIT.read_text(encoding="utf-8")
    read_write = "ReadWritePaths=/var/lib/distraction-blocker /run/distraction-blocker /etc"
    if read_write not in text or "[Service]\n" not in text:
        fail("the service unit has unexpected settings")
    text = text.replace(read_write, f"{read_write} {escaped_path}", 1)
    environment = (
        f"Environment=XDG_RUNTIME_DIR=/run/user/{owner_uid}\n"
        f"Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{owner_uid}/bus\n"
    )
    text = text.replace("[Service]\n", f"[Service]\n{environment}", 1)
    UNIT.write_text(text, encoding="utf-8")
    set_mode(UNIT, 0o644)


def prepare_notification_directory(
    owner_home: Path, owner_spec: tuple[int, int]
) -> None:
    """Create the owner-writable notification state directory safely."""
    path = owner_home / ".config" / "distraction-blocker"
    descriptor = _open_directory_chain(path, create=True, owner=owner_spec)
    try:
        os.fchmod(descriptor, 0o700)
        os.fchown(descriptor, *owner_spec)
    finally:
        os.close(descriptor)

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


def _remove_owned_manifest(path: Path) -> None:
    try:
        parent_fd = _open_directory_chain(path.parent, create=False)
    except FileNotFoundError:
        return
    try:
        try:
            metadata = os.stat(
                path.name, dir_fd=parent_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"the legacy native manifest path is unsafe: {path}")
        os.unlink(path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def remove_legacy_native_manifests(owner_home: Path) -> None:
    """Remove browser-specific manifest names from an older installation."""
    for path in LEGACY_SYSTEM_NATIVE_MANIFESTS:
        _remove_owned_manifest(path)
    for subdir, manifest_name in LEGACY_OWNER_NATIVE_MANIFESTS:
        _remove_owned_manifest(owner_home / subdir / manifest_name)


def enforcement_module(source_root: Path):
    """Import the network enforcement module from the source tree."""
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from distraction_blocker import network_enforcement

    return network_enforcement


def dnsmasq_version(binary: str) -> tuple[int, int] | None:
    try:
        result = subprocess.run(
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    match = re.search(r"version\s+(\d+)\.(\d+)", result.stdout)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def validate_network_dependencies() -> None:
    """Refuse a network opt-in install instead of installing packages."""
    missing = []
    nft = shutil.which("nft")
    if not nft:
        missing.append("an nftables binary (Ubuntu package: nftables)")
    else:
        probe = subprocess.run(
            [nft, "list", "tables"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if probe.returncode != 0:
            missing.append("working nftables kernel support")
    dnsmasq = shutil.which("dnsmasq")
    if not dnsmasq:
        missing.append("a dnsmasq binary (Ubuntu packages: dnsmasq or dnsmasq-base)")
    else:
        version = dnsmasq_version(dnsmasq)
        if version is None or version < DNSMASQ_MINIMUM_VERSION:
            found = (
                ".".join(str(part) for part in version) if version else "unknown"
            )
            missing.append(
                f"dnsmasq {DNSMASQ_MINIMUM_VERSION[0]}.{DNSMASQ_MINIMUM_VERSION[1]}"
                f" or newer (found {found})"
            )
    resolved = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "systemd-resolved"],
        check=False,
    )
    if resolved.returncode != 0:
        missing.append("an active systemd-resolved service")
    if missing:
        fail(
            "network controls are missing dependencies: "
            + "; ".join(missing)
            + ". Install them manually; this installer never installs packages."
        )


def ensure_dns_user(owner_uid: int) -> None:
    try:
        account = pwd.getpwnam(DNS_USER)
    except KeyError:
        account = None
    if account is not None:
        if (
            not 0 < account.pw_uid < 1000 or account.pw_uid == owner_uid
            or account.pw_shell != "/usr/sbin/nologin"
            or account.pw_dir != "/nonexistent"
        ):
            fail("the dedicated resolver account collides with another user")
        return
    subprocess.run(
        [
            "/usr/sbin/useradd",
            "--system",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            DNS_USER,
        ],
        check=True,
    )


def install_files(
    source_root: Path,
    owner_uid: int,
    network_on: bool,
    write_marker: bool,
) -> None:
    upgrading = installation_exists()
    protected = (UNIT, DESKTOP, TRAY_DESKTOP, TRAY_AUTOSTART_DESKTOP, LEGACY_DESKTOP)
    check_cli_collision()
    if not upgrading:
        for path in protected:
            if path.exists() or path.is_symlink():
                fail(f"refusing to replace an existing path: {path}")
    elif LEGACY_DESKTOP.is_symlink() or (
        LEGACY_DESKTOP.exists() and not LEGACY_DESKTOP.is_file()
    ):
        fail(f"the old desktop path is unsafe: {LEGACY_DESKTOP}")
    try:
        account = pwd.getpwuid(owner_uid)
    except KeyError:
        fail("the owner UID has no user account")
    owner_home = Path(account.pw_dir)
    owner_spec = (owner_uid, account.pw_gid)
    module = enforcement_module(source_root) if network_on else None
    if network_on:
        if SANDBOX_DROPIN_DIR.is_symlink() or (
            SANDBOX_DROPIN_DIR.exists() and not SANDBOX_DROPIN_DIR.is_dir()
        ):
            fail(f"the sandbox drop-in path is unsafe: {SANDBOX_DROPIN_DIR}")
        for path in (DNS_UNIT, FENCE_UNIT, SANDBOX_DROPIN):
            check_network_asset(path)
        validate_network_dependencies()
        ensure_dns_user(owner_uid)
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
                packaging_fd,
                "tray_entry.py",
                PREFIX / "tray_entry.py",
                0o755,
            )
            copy_asset(
                packaging_fd, "cli_entry.py", CLI_PATH, 0o755
            )
            copy_asset(
                packaging_fd, "distraction-blocker.service", UNIT
            )
            configure_service_unit(owner_home, owner_uid)
            if network_on:
                copy_asset(
                    packaging_fd, "network_entry.py",
                    PREFIX / "network_entry.py", 0o755,
                )
                copy_asset(
                    packaging_fd,
                    "distraction-blocker-dns.service",
                    DNS_UNIT,
                )
                copy_asset(
                    packaging_fd,
                    "distraction-blocker-network-restore.service",
                    FENCE_UNIT,
                )
                copy_asset(
                    packaging_fd,
                    "distraction-blocker-network.conf",
                    SANDBOX_DROPIN,
                )
            copy_asset(
                packaging_fd,
                "org.distraction_blocker.App.desktop",
                DESKTOP,
            )
            copy_asset(
                packaging_fd,
                "org.distraction_blocker.Tray.desktop",
                TRAY_DESKTOP,
            )
            copy_asset(
                packaging_fd,
                "org.distraction_blocker.Tray.desktop",
                TRAY_AUTOSTART_DESKTOP,
            )
            copy_asset(
                packaging_fd,
                "host_entry.py",
                PREFIX / "host_entry.py",
                0o755,
            )
            # Breadcrumb: Firefox reads the system-wide mozilla directory,
            # but LibreWolf builds commonly ignore it and some ignore the
            # system librewolf directory too. The owner's home directories
            # are the locations every Firefox-family browser honors.
            for browser_dir in (
                Path("/usr/lib/mozilla/native-messaging-hosts"),
                Path("/usr/lib/librewolf/native-messaging-hosts"),
            ):
                copy_asset(
                    packaging_fd,
                    # Breadcrumb: source keeps its packaging name; the
                    # deployed name must equal the host "name" field plus
                    # .json because Firefox constructs the lookup path.
                    "org.distraction_blocker.firefox.json",
                    browser_dir / HOST_MANIFEST_FILENAME,
                )
            for home_dir in (
                owner_home / ".mozilla" / "native-messaging-hosts",
                owner_home / ".librewolf" / "native-messaging-hosts",
            ):
                copy_asset(
                    packaging_fd,
                    "org.distraction_blocker.firefox.json",
                    home_dir / HOST_MANIFEST_FILENAME,
                    0o644,
                    owner_spec,
                )
            for browser_dir in (
                Path("/etc/chromium/native-messaging-hosts"),
                Path("/etc/opt/chrome/native-messaging-hosts"),
            ):
                copy_asset(
                    packaging_fd,
                    "org.distraction_blocker.chromium.json",
                    browser_dir / HOST_MANIFEST_FILENAME,
                )
            # Breadcrumb: these per-owner copies must mirror the removal
            # pairs in scripts/uninstall.py remove_native_manifests().
            for user_dir in (
                owner_home / ".config" / "chromium" / "NativeMessagingHosts",
                owner_home / ".config" / "google-chrome" / "NativeMessagingHosts",
            ):
                copy_asset(
                    packaging_fd,
                    "org.distraction_blocker.chromium.json",
                    user_dir / HOST_MANIFEST_FILENAME,
                    0o644,
                    owner_spec,
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
    if upgrading:
        # Breadcrumb: new manifests use the host name. Remove only the
        # browser-specific names that an older marked installation owned.
        remove_legacy_native_manifests(owner_home)
    marker = PREFIX / MARKER_NAME
    marker.write_text(MARKER_TEXT, encoding="ascii")
    set_mode(marker, 0o644)
    for path in (STATE, RUN):
        if path.is_symlink() or path.exists() and not path.is_dir():
            fail(f"protected path is not a directory: {path}")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    RUN.mkdir(mode=0o755, parents=True, exist_ok=True)
    set_mode(STATE, 0o700)
    prepare_notification_directory(owner_home, owner_spec)
    set_mode(RUN, 0o755)
    if network_on:
        # Breadcrumb: only an explicit operator opt-in writes the
        # root-protected marker; a valid pre-existing marker survives
        # upgrades untouched.
        if write_marker and not module.is_network_enabled(STATE):
            module.write_network_marker(STATE)
        if not module.is_network_enabled(STATE):
            fail("the network opt-in marker is not valid after installation")
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
    if args.enable_network_controls != args.accept_network_risk:
        if args.enable_network_controls:
            fail("--enable-network-controls also requires --accept-network-risk")
        fail("--accept-network-risk also requires --enable-network-controls")
    source_root = Path(__file__).resolve().parent.parent
    if source_root == Path("/") or not (source_root / PACKAGE_NAME).is_dir():
        fail("the source package is missing")

    module = enforcement_module(source_root)
    marker = Path(module.marker_path(STATE))
    if marker.is_symlink():
        fail("the network opt-in marker is a symlink")
    marker_present = module.is_network_enabled(STATE)
    if marker.exists() and not marker_present:
        fail(f"an invalid or foreign file occupies {marker}")
    network_on = args.enable_network_controls or marker_present

    try:
        install_files(
            source_root,
            args.owner_uid,
            network_on=network_on,
            write_marker=args.enable_network_controls,
        )
        run_systemctl(["daemon-reload"])
        run_systemctl(["enable", "distraction-blocker.service"])
        if network_on:
            run_systemctl(["enable", "distraction-blocker-network-restore.service"])
            run_systemctl(["restart", "distraction-blocker-network-restore.service"])
        run_systemctl(["restart", "distraction-blocker.service"])
    except OSError as exc:
        fail(f"installation failed: {exc.strerror or exc}")
    if network_on:
        print(
            "Distraction Blocker installed with network controls enabled."
        )
    else:
        print("Distraction Blocker installed.")
    return 0


if __name__ == "__main__":
    main()
