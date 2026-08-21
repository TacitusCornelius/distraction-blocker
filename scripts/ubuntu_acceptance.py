#!/usr/bin/env python3
"""Run destructive acceptance checks in a marked Ubuntu virtual machine."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import time
from uuid import uuid4

MARKER = Path("/etc/distraction-blocker-test-vm")
STATE_DIRECTORY = Path("/var/lib/distraction-blocker-acceptance")
STATE = STATE_DIRECTORY / "state.json"
INSTALL_MARKER = Path("/usr/lib/distraction-blocker/INSTALLATION")
POLICY = Path("/var/lib/distraction-blocker/policy.json")
SOCKET = Path("/run/distraction-blocker/control.sock")
TEST_EXECUTABLE = Path("/usr/local/lib/distraction-blocker-acceptance-app")
TEST_DOMAIN = "blocked.invalid"
TEST_WEEKLY_DOMAIN = "weekly.invalid"
TEST_POMODORO_DOMAIN = "pomodoro.invalid"
TIMED_LOCK_RULE = "11111111-1111-4111-8111-111111111111"
FRICTION_LOCK_RULE = "22222222-2222-4222-8222-222222222222"
PASSWORD_LOCK_RULE = "33333333-3333-4333-8333-333333333333"
POMODORO_RULE = "44444444-4444-4444-8444-444444444444"
CLI_PATH = Path("/usr/local/bin/distraction-blocker")
HOST_PATH = Path("/usr/lib/distraction-blocker/host_entry.py")
NATIVE_MANIFESTS = (
    Path("/usr/lib/mozilla/native-messaging-hosts/org.distraction_blocker.firefox.json"),
    Path("/usr/lib/librewolf/native-messaging-hosts/org.distraction_blocker.firefox.json"),
)
MARKER_PURPOSE = "distraction-blocker-acceptance"


class AcceptanceError(RuntimeError):
    """An acceptance condition failed."""


def command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=30)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise AcceptanceError(f"{args[0]} failed: {detail}")
    return result


def require_vm() -> int:
    if os.geteuid() != 0:
        raise AcceptanceError("Run this script as root in the test virtual machine.")
    virtual = command(["/usr/bin/systemd-detect-virt", "--vm", "--quiet"], check=False)
    if virtual.returncode != 0:
        raise AcceptanceError("This acceptance script requires a virtual machine.")
    if MARKER.is_symlink() or not MARKER.is_file():
        raise AcceptanceError(f"Create the protected test marker at {MARKER}.")
    metadata = MARKER.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise AcceptanceError("The test marker must belong to root and use mode 0600.")
    try:
        data = json.loads(MARKER.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("The test marker is not valid JSON.") from error
    if not isinstance(data, dict) or set(data) != {"purpose", "owner_uid"}:
        raise AcceptanceError("The test marker has invalid fields.")
    if data["purpose"] != MARKER_PURPOSE:
        raise AcceptanceError("The test marker has the wrong purpose.")
    owner_uid = data["owner_uid"]
    if isinstance(owner_uid, bool) or not isinstance(owner_uid, int) or owner_uid <= 0:
        raise AcceptanceError("The test marker has an invalid owner UID.")
    try:
        pwd.getpwuid(owner_uid)
    except KeyError as error:
        raise AcceptanceError("The test owner UID does not exist.") from error
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if "ID=ubuntu" not in os_release.splitlines():
        raise AcceptanceError("This acceptance script supports Ubuntu only.")
    return owner_uid


def wait_for_service() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        active = command(["/usr/bin/systemctl", "is-active", "--quiet", "distraction-blocker.service"], check=False)
        if active.returncode == 0 and SOCKET.exists():
            return
        time.sleep(0.2)
    raise AcceptanceError("The service did not become ready.")


def installed_client():
    sys.path.insert(0, "/usr/lib/distraction-blocker")
    from distraction_blocker.rpc import Client

    return Client(str(SOCKET))


def install(source_root: Path, owner_uid: int) -> None:
    command([
        sys.executable,
        str(source_root / "scripts" / "install.py"),
        "--confirm",
        "--owner-uid",
        str(owner_uid),
    ])
    wait_for_service()


def make_test_executable() -> None:
    TEST_EXECUTABLE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile("/usr/bin/true", TEST_EXECUTABLE)
    TEST_EXECUTABLE.chmod(0o755)
    os.chown(TEST_EXECUTABLE, 0, 0)


def add_active_rule() -> str:
    now = datetime.now(timezone.utc)
    list_id = str(uuid4())
    client = installed_client()
    begun = client.request(
        "begin_list_import",
        metadata={
            "id": list_id,
            "name": "Acceptance managed list",
            "source": "acceptance",
            "version": "1",
            "license": "Acceptance test data",
        },
    )
    import_id = begun["import_id"]
    client.request(
        "import_list_chunk", import_id=import_id, domains=[TEST_DOMAIN]
    )
    client.request("commit_list_import", import_id=import_id)
    rule_id = str(uuid4())
    rule = {
        "id": rule_id,
        "name": "Acceptance block",
        "enabled": True,
        "targets": [
            {"kind": "managed_list", "value": list_id},
            {"kind": "application", "value": str(TEST_EXECUTABLE)},
        ],
        "schedule": {
            "kind": "one_time",
            "start_utc": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "end_utc": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        },
        "revision": 0,
    }
    client.request("put_rule", rule=rule)
    status = client.request("status")
    if status.get("active_counts") != {"website": 1, "application": 1}:
        raise AcceptanceError("Managed-list active counts are wrong.")
    summaries = client.request("list_managed_lists")
    if len(summaries) != 1 or "domains" in summaries[0]:
        raise AcceptanceError("A normal list response exposed managed domains.")
    return rule_id


def add_active_weekly_rule() -> str:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)
    end = now + timedelta(hours=1)
    later = now + timedelta(days=2)
    rule_id = str(uuid4())
    installed_client().request(
        "put_rule",
        rule={
            "id": rule_id,
            "name": "Acceptance weekly periods",
            "enabled": True,
            "targets": [{"kind": "website", "value": TEST_WEEKLY_DOMAIN}],
            "schedule": {
                "kind": "weekly",
                "timezone": "UTC",
                "periods": [
                    {
                        "weekdays": [start.weekday()],
                        "start": start.strftime("%H:%M:%S"),
                        "end": end.strftime("%H:%M:%S"),
                    },
                    {
                        "weekdays": [later.weekday()],
                        "start": "02:00:00",
                        "end": "03:00:00",
                    },
                ],
            },
            "revision": 0,
        },
    )
    return rule_id


def add_v13_state(owner_uid: int) -> None:
    now = datetime.now(timezone.utc)
    client = installed_client()
    for rule_id, name in (
        (TIMED_LOCK_RULE, "Timed lock acceptance"),
        (FRICTION_LOCK_RULE, "Friction lock acceptance"),
        (PASSWORD_LOCK_RULE, "Password lock acceptance"),
    ):
        client.request(
            "put_rule",
            rule={
                "id": rule_id,
                "name": name,
                "enabled": False,
                "targets": [{
                    "kind": "website",
                    "value": f"{rule_id[:8]}.invalid",
                }],
                "schedule": {"kind": "indefinite"},
                "revision": 0,
            },
        )
    client.request(
        "set_rule_lock",
        rule_id=TIMED_LOCK_RULE,
        lock={
            "kind": "timed",
            "until_utc": (now + timedelta(hours=2))
            .isoformat()
            .replace("+00:00", "Z"),
        },
    )
    client.request(
        "set_rule_lock",
        rule_id=FRICTION_LOCK_RULE,
        lock={"kind": "friction"},
    )
    client.request(
        "set_rule_lock",
        rule_id=PASSWORD_LOCK_RULE,
        lock={
            "kind": "password",
            "password": "acceptance secret",
        },
    )
    # Breadcrumb: the service treats uid 0 as outside the lock boundary, so
    # a root client is refused authorization by design. Exercise the
    # begin/complete flow as the desktop user, exactly like the GUI does.
    account = pwd.getpwuid(owner_uid)
    probe = "\n".join((
        "import sys",
        "sys.path.insert(0, '/usr/lib/distraction-blocker')",
        "from distraction_blocker.rpc import Client, RpcError",
        f"client = Client('{SOCKET}')",
        f"rule_id = '{PASSWORD_LOCK_RULE}'",
        "challenge = client.request('begin_rule_authorization', rule_id=rule_id)",
        "try:",
        "    client.request(",
        "        'complete_rule_authorization',",
        "        rule_id=rule_id,",
        "        challenge_id=challenge['challenge_id'],",
        "        response='incorrect secret',",
        "    )",
        "except RpcError as error:",
        "    if error.code != 'invalid_password':",
        "        raise SystemExit(error.code)",
        "else:",
        "    raise SystemExit('the wrong password was accepted')",
    ))
    command([
        "/usr/sbin/runuser",
        "-u",
        account.pw_name,
        "--",
        "/usr/bin/python3",
        "-c",
        probe,
    ])
    client.request(
        "put_rule",
        rule={
            "id": POMODORO_RULE,
            "name": "Pomodoro acceptance",
            "enabled": True,
            "targets": [{
                "kind": "website",
                "value": TEST_POMODORO_DOMAIN,
            }],
            "schedule": {
                "kind": "pomodoro",
                "start_utc": (now - timedelta(minutes=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "work_minutes": 60,
                "break_minutes": 1,
                "cycles": 2,
            },
            "revision": 0,
        },
    )


EXT_RULE = "55555555-5555-4555-8555-555555555555"


def _framed(payload: dict) -> bytes:
    encoded = json.dumps(payload).encode("utf-8")
    return struct.pack("@I", len(encoded)) + encoded


def _read_framed(stream) -> dict:
    header = stream.read(4)
    if len(header) < 4:
        raise AcceptanceError("the native host closed its output early")
    (length,) = struct.unpack("@I", header)
    return json.loads(stream.read(length).decode("utf-8"))


def check_extension_policy_link(owner_uid: int) -> None:
    """Exercise the installed native-messaging link as the desktop user.

    The browser would speak this exact framing to this exact root-owned
    binary, so a passing probe proves the whole chain: manifest placement,
    allowlist enforcement, socket ownership, rule visibility, and denial
    statistics persistence.
    """
    if HOST_PATH.is_symlink() or not HOST_PATH.is_file():
        raise AcceptanceError("the native messaging host is not installed")
    for manifest in NATIVE_MANIFESTS:
        if not manifest.is_file():
            raise AcceptanceError(f"native manifest is missing: {manifest}")
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if (
            data.get("type") != "stdio"
            or data.get("path") != str(HOST_PATH)
            or "{e4f1a2b3-9c8d-4e5f-a6b7-8c9d0e1f2a3b}"
            not in data.get("allowed_extensions", [])
        ):
            raise AcceptanceError("a native manifest has unexpected content")

    client = installed_client()
    client.request(
        "put_rule",
        rule={
            "id": EXT_RULE,
            "name": "Extension policy acceptance",
            "enabled": True,
            "targets": [{"kind": "url_path", "value": "ext.invalid/feed"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        },
    )

    account = pwd.getpwuid(owner_uid)
    process = subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            account.pw_name,
            "--",
            "/usr/bin/python3",
            "-I",
            str(HOST_PATH),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        # Breadcrumb: feed every frame first, then read; the host answers
        # strictly in order.
        process.stdin.write(_framed({"command": "status"}))
        process.stdin.write(
            _framed({
                "command": "delete_rule",
                "rule_id": EXT_RULE,
            })
        )
        process.stdin.write(
            _framed({
                "command": "report_website_denials",
                "entries": [{
                    "rule_id": EXT_RULE,
                    "value": "ext.invalid/feed",
                    "count": 2,
                }],
            })
        )
        process.stdin.write(_framed({"command": "list_website_stats"}))
        process.stdin.close()

        status = _read_framed(process.stdout)
        if not status.get("ok") or not status["result"].get("healthy"):
            raise AcceptanceError("the extension host cannot see a healthy service")
        forbidden = _read_framed(process.stdout)
        if forbidden.get("ok") is not False or forbidden["error"]["code"] != "forbidden":
            raise AcceptanceError("the native host allowed a policy change")
        report = _read_framed(process.stdout)
        if not report.get("ok"):
            raise AcceptanceError("the denial report was refused")
        listed = _read_framed(process.stdout)
        rows = {row["value"]: row for row in listed["result"]["items"]}
        row = rows.get("ext.invalid/feed")
        if row is None or row["count"] != 2:
            raise AcceptanceError("website denial statistics were not recorded")
    finally:
        process.kill()
        process.wait()
    stored = json.loads(
        Path("/var/lib/distraction-blocker/website-statistics.json").read_text(
            encoding="utf-8"
        )
    )


def check_v13_state(owner_uid: int) -> None:
    client = installed_client()
    locks = client.request("list_locks")
    kinds = {item["rule_id"]: item["kind"] for item in locks}
    expected = {
        TIMED_LOCK_RULE: "timed",
        FRICTION_LOCK_RULE: "friction",
        PASSWORD_LOCK_RULE: "password",
    }
    if any(kinds.get(rule_id) != kind for rule_id, kind in expected.items()):
        raise AcceptanceError("Version 1.3 locks did not persist.")
    rules = {item["id"]: item for item in client.request("list_rules")}
    schedule = rules.get(POMODORO_RULE, {}).get("schedule")
    if not isinstance(schedule, dict) or schedule.get("kind") != "pomodoro":
        raise AcceptanceError("The Pomodoro schedule did not persist.")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        statistics = client.request("list_denial_stats")
        if any(
            item.get("path") == str(TEST_EXECUTABLE)
            and item.get("count", 0) > 0
            for item in statistics.get("items", [])
        ):
            break
        time.sleep(0.2)
    else:
        raise AcceptanceError("Application denial statistics were not recorded.")
    account = pwd.getpwuid(owner_uid)
    result = command([
        "/usr/sbin/runuser",
        "-u",
        account.pw_name,
        "--",
        str(CLI_PATH),
        "--json",
        "status",
    ])
    try:
        cli_status = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError("The public CLI returned invalid JSON.") from error
    if cli_status.get("healthy") is not True:
        raise AcceptanceError("The public CLI did not report healthy state.")


def check_domain_block(domain: str = TEST_DOMAIN) -> None:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
    }
    if not addresses or not addresses <= {"0.0.0.0", "::"}:
        raise AcceptanceError(f"The test domain was not blocked: {domain}")


def check_executable_block() -> None:
    try:
        result = subprocess.run([str(TEST_EXECUTABLE)], check=False, timeout=5)
    except PermissionError:
        return
    if result.returncode == 0:
        raise AcceptanceError("The blocked executable started.")


def check_gui_exit(owner_uid: int) -> None:
    account = pwd.getpwuid(owner_uid)

    def become_owner() -> None:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(owner_uid)

    code = (
        "import sys;"
        "sys.path.insert(0,'/usr/lib/distraction-blocker');"
        "from distraction_blocker.rpc import Client;"
        "Client().request('status')"
    )
    base_environment = {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{owner_uid}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{owner_uid}/bus",
    }
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_SESSION_TYPE"):
        if name in os.environ:
            base_environment[name] = os.environ[name]
    broadway = None
    if "DISPLAY" not in base_environment and "WAYLAND_DISPLAY" not in base_environment:
        runtime = Path(base_environment["XDG_RUNTIME_DIR"])
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(runtime, owner_uid, account.pw_gid)
        base_environment["GDK_BACKEND"] = "broadway"
        base_environment["BROADWAY_DISPLAY"] = ":5"
        broadway = subprocess.Popen(
            ["/usr/bin/gtk4-broadwayd", ":5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=become_owner,
            env=base_environment,
        )
        time.sleep(1)
        if broadway.poll() is not None:
            raise AcceptanceError("The headless GTK backend did not start.")
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        preexec_fn=become_owner,
        env=base_environment,
    )
    if result.returncode != 0:
        raise AcceptanceError("The configured user could not use the service client.")
    gui = subprocess.Popen(
        ["/usr/bin/python3", "-I", "/usr/lib/distraction-blocker/gui_entry.py", "gui"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=become_owner,
        env=base_environment,
    )
    try:
        time.sleep(2)
        if gui.poll() is not None:
            _output, error = gui.communicate(timeout=2)
            raise AcceptanceError(f"The GUI exited during startup: {error.strip()}")
        gui.terminate()
        try:
            gui.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gui.kill()
            gui.wait(timeout=5)
        check_domain_block()
        check_executable_block()
    finally:
        if broadway is not None:
            broadway.terminate()
            try:
                broadway.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broadway.kill()
                broadway.wait(timeout=5)


def change_time_and_restore() -> None:
    original_wall = time.time()
    original_boot = time.monotonic()
    ntp = command(["/usr/bin/timedatectl", "show", "-p", "NTP", "--value"], check=False)
    ntp_enabled = ntp.returncode == 0 and ntp.stdout.strip() == "yes"
    command(["/usr/bin/timedatectl", "set-ntp", "false"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        current = command(
            ["/usr/bin/timedatectl", "show", "-p", "NTP", "--value"],
            check=False,
        )
        if current.returncode == 0 and current.stdout.strip() == "no":
            break
        time.sleep(0.25)
    else:
        raise AcceptanceError("The VM did not disable network time.")
    time.sleep(1)
    try:
        changed = datetime.fromtimestamp(original_wall + 86400, timezone.utc)
        command(["/usr/bin/timedatectl", "set-time", changed.strftime("%Y-%m-%d %H:%M:%S")])
        time.sleep(2)
        status = installed_client().request("status")
        if status.get("clock_trusted") is not False:
            raise AcceptanceError("The service trusted the changed wall clock.")
        check_domain_block()
        check_executable_block()
    finally:
        restored = datetime.fromtimestamp(
            original_wall + (time.monotonic() - original_boot), timezone.utc
        )
        command(["/usr/bin/timedatectl", "set-time", restored.strftime("%Y-%m-%d %H:%M:%S")], check=False)
        if ntp_enabled:
            command(["/usr/bin/timedatectl", "set-ntp", "true"], check=False)


def tamper_primary_and_restart() -> None:
    content = bytearray(POLICY.read_bytes())
    marker = content.find(b'"hmac":"')
    if marker < 0:
        raise AcceptanceError("The primary policy has no signature.")
    position = marker + len(b'"hmac":"')
    content[position] = ord("0") if content[position] != ord("0") else ord("1")
    POLICY.write_bytes(content)
    command(["/usr/bin/systemctl", "restart", "distraction-blocker.service"])
    wait_for_service()
    status = installed_client().request("status")
    if status.get("clock_trusted") is not False:
        raise AcceptanceError("The clock-tamper latch did not survive policy recovery.")
    check_domain_block()
    check_executable_block()


def cleanup(source_root: Path, *, strict: bool = False) -> None:
    if INSTALL_MARKER.is_file():
        command([
            sys.executable,
            str(source_root / "scripts" / "uninstall.py"),
            "--confirm",
            "--remove-policy",
        ], check=strict)
    try:
        TEST_EXECUTABLE.unlink()
    except FileNotFoundError:
        pass
    try:
        STATE.unlink()
    except FileNotFoundError:
        pass
    try:
        STATE_DIRECTORY.rmdir()
    except OSError:
        pass


def phase_one(source_root: Path, owner_uid: int, reboot: bool) -> None:
    install(source_root, owner_uid)
    make_test_executable()
    add_active_rule()
    add_active_weekly_rule()
    add_v13_state(owner_uid)
    check_extension_policy_link(owner_uid)
    check_domain_block()
    check_domain_block(TEST_WEEKLY_DOMAIN)
    check_domain_block(TEST_POMODORO_DOMAIN)
    check_executable_block()
    check_v13_state(owner_uid)
    check_gui_exit(owner_uid)
    change_time_and_restore()
    tamper_primary_and_restart()
    check_v13_state(owner_uid)
    STATE_DIRECTORY.mkdir(mode=0o700, parents=False, exist_ok=False)
    STATE.write_text(json.dumps({
        "phase": 2,
        "source_root": str(source_root),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
    }), encoding="utf-8")
    STATE.chmod(0o600)
    if not reboot:
        print("Phase 1 passed. Run this command again after the virtual machine reboots.")
        return
    print("Phase 1 passed. The virtual machine will restart now.", flush=True)
    command(["/usr/bin/systemctl", "reboot"], check=False)


def phase_two(source_root: Path, owner_uid: int) -> None:
    wait_for_service()
    status = installed_client().request("status")
    if status.get("clock_trusted") is not False:
        raise AcceptanceError("The clock-tamper latch did not survive the restart.")
    check_domain_block()
    check_domain_block(TEST_WEEKLY_DOMAIN)
    check_domain_block(TEST_POMODORO_DOMAIN)
    check_executable_block()
    check_v13_state(owner_uid)
    cleanup(source_root, strict=True)
    print("Ubuntu acceptance checks passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Ubuntu virtual-machine acceptance checks")
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="stop after phase 1 instead of restarting the virtual machine",
    )
    args = parser.parse_args()
    owner_uid = require_vm()
    source_root = Path(__file__).resolve().parent.parent
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AcceptanceError("The acceptance state is invalid.") from error
        if (
            not isinstance(state, dict)
            or set(state) != {"phase", "source_root", "boot_id"}
            or state["phase"] != 2
            or state["source_root"] != str(source_root)
            or not isinstance(state["boot_id"], str)
        ):
            raise AcceptanceError("The acceptance state has invalid values.")
        current_boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if current_boot == state["boot_id"]:
            raise AcceptanceError("Restart the virtual machine before phase 2.")
        phase_two(source_root, owner_uid)
        return 0
    if INSTALL_MARKER.exists():
        raise AcceptanceError("Remove the existing Distraction Blocker installation first.")
    try:
        phase_one(source_root, owner_uid, not args.no_reboot)
    except Exception:
        cleanup(source_root)
        raise
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(f"Acceptance refused: {error}", file=sys.stderr)
        raise SystemExit(2)
