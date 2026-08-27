#!/usr/bin/env python3
"""Run acceptance checks for the Chromium extension.

Run this script as root in the marked acceptance virtual machine. Run it
after phase 1 of ubuntu_acceptance.py installs the service.

The script:

1. Selects Chrome that can load an unpacked extension. New branded Chrome
   releases reject ``--load-extension``. ``--download`` gets Chrome for
   Testing. An older system Chrome can also work.
2. Creates a temporary user-data directory and copies
   ``extension/chromium/`` into it.
3. Writes the native-messaging host manifest to each path that Chrome can
   use. It removes each file after the check.
4. Creates one URL-path rule through the service socket.
5. Serves a canary page and starts headless Chrome as the desktop user.
   It uses a CDP pipe to check the blocked load and its service report.
6. Checks inactive-tab blocking, tab changes, and service-worker restart.
7. Uses the real Chromium status page to turn inactive-tab blocking on and
   off. Local inactive-tab denials must not enter service statistics.

Website usage is outside this check. Usage rows count permitted loads under
allowance rules. This check drives one denied load.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ubuntu_acceptance import (  # noqa: E402
    AcceptanceError,
    installed_client,
    require_vm,
)

CHROME_CANDIDATES = ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable")
# Breadcrumb: distinct from the Firefox harness (port 8765, rule 6666…)
# so both harnesses can run against one VM without touching each other's
# statistics rows.
CANARY_PORT = 8766
CANARY_PATH = "/canary-chrome"
RULE_ID = "77777777-7777-4777-8777-777777777777"
TARGET_VALUE = f"localhost{CANARY_PATH}"
OPEN_PATH = "/open"
INACTIVE_POLL_SECONDS = 90
STATS_FILE = Path("/var/lib/distraction-blocker/website-statistics.json")
POLL_SECONDS = 150
HOST_MANIFEST_NAME = "org.distraction_blocker.extension.json"
# Branded Chrome 137 dropped --load-extension; newer loads go through CDP.


# Chrome usually stops an idle service worker after about 30 seconds.
WORKER_IDLE_SECONDS = 35


def command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise AcceptanceError(f"{args[0]} failed: {detail}")
    return result


CFT_ROOT = Path("/opt/distraction-blocker-chromium")
CFT_URL = (
    "https://storage.googleapis.com/chrome-for-testing-public/"
    "138.0.7204.94/linux64/chrome-linux64.zip"
)


def chrome_major_version(chrome_bin: Path) -> int:
    result = command([str(chrome_bin), "--version"])
    match = re.search(r"(\d+)\.", result.stdout)
    if not match:
        raise AcceptanceError(f"unreadable Chrome version: {result.stdout!r}")
    return int(match.group(1))


def ensure_chrome(download: bool) -> Path:
    # Breadcrumb: branded Chrome 137+ refuses --load-extension outright, so
    # unpacked sideloading needs a Chrome for Testing build, which keeps the
    # switch. Mirrors the Firefox harness: download only with --download.
    cft_bin = CFT_ROOT / "chrome-linux64" / "chrome"
    if cft_bin.is_file():
        return cft_bin
    if download:
        archive = CFT_ROOT / "chrome-linux64.zip"
        CFT_ROOT.mkdir(parents=True, exist_ok=True)
        print(f"Downloading Chrome for Testing into {archive} ...", flush=True)
        command(["/usr/bin/wget", "-q", "-O", str(archive), CFT_URL])
        command(["/usr/bin/unzip", "-q", "-o", str(archive), "-d", str(CFT_ROOT)])
        if not cft_bin.is_file():
            raise AcceptanceError("Chrome for Testing download failed.")
        return cft_bin
    for candidate in CHROME_CANDIDATES:
        binary = Path(candidate)
        if not binary.is_file():
            continue
        version = chrome_major_version(binary)
        if version <= 136:
            return binary
        raise AcceptanceError(
            f"{binary} is Chrome {version}, which refuses --load-extension. "
            "Rerun with --download to fetch a Chrome for Testing build that "
            "can sideload unpacked extensions."
        )
    raise AcceptanceError(
        "Google Chrome is not installed in the VM; install chrome-stable "
        "first or rerun with --download."
    )


def extension_id(extension_source: Path) -> str:
    # Breadcrumb: Chromium derives the extension id from the manifest "key"
    # (SHA-256 over the DER SPKI, first 16 bytes, each hex digit spelled in
    # the a-p alphabet). This replicates tests/test_extension_build.py::
    # test_chromium_manifest_key_matches_packaged_extension_id exactly; if
    # that computation changes, change this copy too.
    manifest = json.loads(
        (extension_source / "manifest.json").read_text(encoding="utf-8")
    )
    spki = base64.b64decode(manifest["key"])
    digest = hashlib.sha256(spki).hexdigest()[:32]
    return "".join(chr(ord("a") + int(digit, 16)) for digit in digest)


def build_profile(extension_source: Path, account: pwd.struct_passwd) -> tuple[Path, str]:
    # Breadcrumb: the adapter directory needs a current copy of the shared
    # core before packaging; build.py fails loudly on drift.
    command([
        "/usr/bin/python3",
        str(extension_source.parent / "build.py"),
        "--check",
    ])
    profile_root = Path(account.pw_dir) / ".cache" / "distraction-blocker-chromium"
    profile = profile_root / "profile"
    if profile.exists():
        shutil.rmtree(profile)
    extension_copy = profile / "extension"
    extension_copy.mkdir(mode=0o755, parents=True)
    # Breadcrumb: --load-extension and Extensions.loadUnpacked both want an
    # unpacked directory, so a plain copy is enough; skip __pycache__ like
    # the Firefox xpi packing does.
    for item in sorted(extension_source.rglob("*")):
        if item.is_file() and "__pycache__" not in item.parts:
            dest = extension_copy / item.relative_to(extension_source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest)
    expected_id = extension_id(extension_source)
    subprocess.run(
        [
            "/usr/bin/chown",
            "-R",
            f"{account.pw_uid}:{account.pw_gid}",
            str(profile_root),
        ],
        check=True,
    )
    return profile, expected_id


def _write_manifest(source: Path, directory: Path) -> None:
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = directory / HOST_MANIFEST_NAME
    shutil.copyfile(source, target)
    os.chmod(target, 0o644)


def ensure_native_manifest(
    account: pwd.struct_passwd,
    expected_id: str,
    profile: Path | None = None,
) -> list[Path]:
    """Place native messaging manifests for every Chrome flavor.

    Branded Chrome reads ~/.config/google-chrome/NativeMessagingHosts.
    Chromium and Chrome for Testing read the user-data directory.
    The harness removes only the manifests that it writes.
    """
    source = (
        Path(__file__).resolve().parent.parent
        / "packaging"
        / "org.distraction_blocker.chromium.json"
    )
    policy = json.loads(source.read_text(encoding="utf-8"))
    origins = policy.get("allowed_origins", [])
    extensions = policy.get("allowed_extensions", [])
    origin_ok = origins == [f"chrome-extension://{expected_id}/*"]
    extension_ok = extensions == [f"{expected_id}/*"]
    if not (origin_ok and extension_ok):
        raise AcceptanceError(
            "packaging/org.distraction_blocker.chromium.json no longer "
            f"pins chrome-extension://{expected_id} in allowed_origins and "
            f"allowed_extensions; regenerate the extension key pair and "
            "update every copy"
        )
    directories = [
        Path(account.pw_dir)
        / ".config"
        / "google-chrome"
        / "NativeMessagingHosts",
    ]
    if profile is not None:
        directories.append(profile / "NativeMessagingHosts")
    written = []
    for directory in directories:
        target = directory / HOST_MANIFEST_NAME
        if target.is_file():
            continue
        _write_manifest(source, directory)
        os.chown(directory, account.pw_uid, account.pw_gid)
        os.chown(target, account.pw_uid, account.pw_gid)
        written.append(target)
    return written


def create_rule() -> None:
    installed_client().request(
        "put_rule",
        rule={
            "id": RULE_ID,
            "name": "Chromium acceptance",
            "enabled": True,
            "targets": [{"kind": "url_path", "value": TARGET_VALUE}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        },
    )


def remove_rule() -> None:
    client = installed_client()
    client.request("set_enabled", rule_id=RULE_ID, enabled=False)
    client.request("delete_rule", rule_id=RULE_ID)


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        # Breadcrumb: Chrome navigates before the service worker finishes
        # its first policy fetch, so the page reloads every 3 s until a
        # compiled rule starts cancelling it.
        body = (
            b"<!doctype html><meta http-equiv=\"refresh\" content=\"3\">\n"
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        print("CANARY:", self.path, flush=True)


def _recorded_denials() -> dict:
    if not STATS_FILE.exists():
        return {}
    try:
        envelope = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        return {row["value"]: row for row in envelope["payload"]["items"]}
    except (OSError, ValueError, KeyError):
        return {}


def _sandbox_flags() -> list[str]:
    # Breadcrumb: qemu guests often cannot create user namespaces, so every
    # content-process sandbox is disabled for this disposable environment.
    return [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]


def _run_as_desktop_user(
    args: list[str],
    account: pwd.struct_passwd,
    preexec_fn=None,
) -> subprocess.Popen:
    # Breadcrumb: Chrome refuses to run as root, and the extension must
    # reach the service socket as the desktop user anyway; mirrors the
    # Firefox harness launcher.
    return subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            account.pw_name,
            "--",
            "/usr/bin/env",
            f"HOME={account.pw_dir}",
            *args,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=False,
        preexec_fn=preexec_fn,
    )


class _PipeCdp:
    """Minimal NUL-delimited JSON client for --remote-debugging-pipe."""

    def __init__(self, write_fd: int, read_fd: int) -> None:
        self.write_fd = write_fd
        self.read_fd = read_fd
        self._buffer = b""
        self._next_id = 1

    def request(
        self,
        method: str,
        params: dict,
        timeout: float,
        session_id: str | None = None,
    ) -> dict:
        frame = {"id": self._next_id, "method": method, "params": params}
        if session_id is not None:
            frame["sessionId"] = session_id
        message_id = frame["id"]
        self._next_id += 1
        os.write(self.write_fd, json.dumps(frame).encode("utf-8") + b"\0")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            payload = self._next_message(message_id)
            if payload is not None:
                if "error" in payload:
                    raise AcceptanceError(
                        f"{method} refused: {payload['error'].get('message')}"
                    )
                return payload.get("result", {})
            time.sleep(0.1)
        raise AcceptanceError(f"{method} timed out after {timeout:.0f}s")

    def _next_message(self, wanted_id: int) -> dict | None:
        try:
            chunk = os.read(self.read_fd, 65536)
        except BlockingIOError:
            chunk = b""
        self._buffer += chunk
        while b"\0" in self._buffer:
            frame, _, rest = self._buffer.partition(b"\0")
            self._buffer = rest
            payload = json.loads(frame.decode("utf-8"))
            if payload.get("id") == wanted_id:
                return payload
            # Events and replies for other sessions are drained.
        return None

    def close(self) -> None:
        for fd in (self.write_fd, self.read_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def _launch_chrome(
    chrome_bin: Path,
    profile: Path,
    url: str,
    account: pwd.struct_passwd,
) -> tuple[subprocess.Popen, _PipeCdp]:
    # Breadcrumb: fd 3 carries commands to Chrome and fd 4 carries replies;
    # the descriptors are duped into place in the forked child before exec
    # so runuser/env pass them through to the browser.
    to_chrome_read, to_chrome_write = os.pipe()
    from_chrome_read, from_chrome_write = os.pipe()

    def _wire_fds() -> None:  # pragma: no cover - runs in the forked child
        os.dup2(to_chrome_read, 3)
        os.dup2(from_chrome_write, 4)
        os.set_inheritable(3, True)
        os.set_inheritable(4, True)

    args = [str(chrome_bin), *(_sandbox_flags()), "--headless=new"]
    args.append(f"--user-data-dir={profile}")
    # Breadcrumb: Chrome 137 removed --load-extension behind the
    # DisableLoadExtensionCommandLineSwitch feature; re-disabling that
    # feature restores unpacked loading on every current major.
    args.append("--disable-features=DisableLoadExtensionCommandLineSwitch")
    args.append(f"--load-extension={profile / 'extension'}")
    args.append("--remote-debugging-pipe")
    args.append("--enable-unsafe-extension-debugging")
    args.append(url)
    chrome = _run_as_desktop_user(args, account, preexec_fn=_wire_fds)
    os.close(to_chrome_read)
    os.close(from_chrome_write)
    os.set_blocking(from_chrome_read, False)
    return chrome, _PipeCdp(to_chrome_write, from_chrome_read)


def _attach(cdp: _PipeCdp, target_id: str) -> str:
    result = cdp.request(
        "Target.attachToTarget",
        {"targetId": target_id, "flatten": True},
        timeout=15,
    )
    return result["sessionId"]


def _evaluate(cdp: _PipeCdp, session_id: str, expression: str, timeout: float = 15):
    payload = cdp.request(
        "Runtime.evaluate",
        {"expression": expression, "awaitPromise": True, "returnByValue": True},
        timeout=timeout,
        session_id=session_id,
    )
    details = payload.get("exceptionDetails")
    if details:
        text = details.get("exception", {}).get("description") or "unknown error"
        raise AcceptanceError(f"extension evaluation failed: {text}")
    return payload.get("result", {}).get("value")


def _worker_target(cdp: _PipeCdp, expected_id: str, timeout: float = 30) -> dict:
    # Breadcrumb: the MV3 service worker appears as its own CDP target.
    # Every storage, tabs, and DNR call must run inside that worker.
    deadline = time.monotonic() + timeout
    origin = f"chrome-extension://{expected_id}/"
    while time.monotonic() < deadline:
        infos = cdp.request("Target.getTargets", {}, timeout=10).get(
            "targetInfos", []
        )
        workers = [
            info for info in infos
            if info.get("type") == "service_worker"
            and str(info.get("url", "")).startswith(origin)
        ]
        if workers:
            return workers[0]
        time.sleep(0.5)
    raise AcceptanceError("the extension service worker never appeared")


def _worker_session(cdp: _PipeCdp, expected_id: str, timeout: float = 30) -> str:
    return _attach(cdp, _worker_target(cdp, expected_id, timeout)["targetId"])


_TABS_JS = (
    "chrome.tabs.query({}).then((tabs) => tabs.map("
    "(tab) => ({id: tab.id, active: tab.active})))"
)
_DYNAMIC_RULES_JS = "chrome.declarativeNetRequest.getDynamicRules()"
_RULES_JS = "chrome.declarativeNetRequest.getSessionRules()"
_PROBE_JS = (
    'fetch("%(url)s", {mode: "no-cors"}).then(() => "loaded", () => "blocked")'
)
_POPUP_STATE_JS = (
    "(() => {"
    "const box = document.querySelector('#block_inactive');"
    "const state = document.querySelector('#inactive_state');"
    "return box && state ? {checked: box.checked, text: state.textContent} : null;"
    "})()"
)


def check_worker_survival(cdp: _PipeCdp, expected_id: str) -> None:
    """Check that a new service worker keeps the dynamic DNR policy."""
    original = _worker_target(cdp, expected_id)
    worker = _attach(cdp, original["targetId"])
    if _evaluate(cdp, worker, "chrome.runtime.getManifest().manifest_version") != 3:
        raise AcceptanceError("the extension did not run as an MV3 worker")
    cdp.request("Target.detachFromTarget", {"sessionId": worker}, timeout=15)
    time.sleep(WORKER_IDLE_SECONDS)

    origin = f"chrome-extension://{expected_id}/"
    infos = cdp.request("Target.getTargets", {}, timeout=10).get(
        "targetInfos", []
    )
    workers = [
        info for info in infos
        if info.get("type") == "service_worker"
        and str(info.get("url", "")).startswith(origin)
    ]
    if any(info["targetId"] == original["targetId"] for info in workers):
        raise AcceptanceError("the original service worker did not stop")

    wake_target = None
    if workers:
        restarted = workers[0]
    else:
        wake_target = cdp.request(
            "Target.createTarget",
            {"url": f"chrome-extension://{expected_id}/status.html"},
            timeout=15,
        )["targetId"]
        restarted = _worker_target(cdp, expected_id)
    if restarted["targetId"] == original["targetId"]:
        raise AcceptanceError("Chromium reused the stopped worker target")

    worker = _attach(cdp, restarted["targetId"])
    deadline = time.monotonic() + 20
    dynamic_rules = None
    last_worker_error = None
    while time.monotonic() < deadline:
        try:
            dynamic_rules = _evaluate(cdp, worker, _DYNAMIC_RULES_JS)
        except AcceptanceError as error:
            last_worker_error = error
            time.sleep(0.5)
            continue
        if isinstance(dynamic_rules, list) and dynamic_rules:
            break
        time.sleep(0.5)
    else:
        detail = f": {last_worker_error}" if last_worker_error else ""
        raise AcceptanceError(
            f"the new service worker did not find the dynamic policy rules{detail}"
        )
    cdp.request("Target.detachFromTarget", {"sessionId": worker}, timeout=15)
    if wake_target is not None:
        cdp.request("Target.closeTarget", {"targetId": wake_target}, timeout=15)
    print("A new service worker kept the dynamic policy rules.")


def check_tab_transition(
    cdp: _PipeCdp,
    worker: str,
    active_tab_id: int,
    inactive_tab_id: int,
    active_target_id: str,
    inactive_target_id: str,
    probe_js: str,
) -> None:
    """Check that a tab switch moves the session rule to the new background tab."""
    cdp.request(
        "Target.activateTarget", {"targetId": inactive_target_id}, timeout=15,
    )
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while time.monotonic() < deadline:
        rows = _evaluate(cdp, worker, _TABS_JS) or []
        states = {row["id"]: row["active"] for row in rows}
        if (
            states.get(inactive_tab_id) is True
            and states.get(active_tab_id) is False
        ):
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError("the tab transition did not settle")

    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while time.monotonic() < deadline:
        covered = _evaluate(cdp, worker, _RULES_JS) or []
        tab_ids = {
            tab_id
            for rule in covered
            for tab_id in rule.get("condition", {}).get("tabIds", [])
        }
        if active_tab_id in tab_ids and inactive_tab_id not in tab_ids:
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError("the session rule did not follow the tab transition")

    if _evaluate(cdp, _attach(cdp, active_target_id), probe_js, timeout=30) != "blocked":
        raise AcceptanceError("the old background tab was not blocked after the switch")
    if _evaluate(cdp, _attach(cdp, inactive_target_id), probe_js, timeout=30) != "loaded":
        raise AcceptanceError("the new active tab was blocked after the switch")

    cdp.request(
        "Target.activateTarget", {"targetId": active_target_id}, timeout=15,
    )
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while time.monotonic() < deadline:
        rows = _evaluate(cdp, worker, _TABS_JS) or []
        states = {row["id"]: row["active"] for row in rows}
        if (
            states.get(active_tab_id) is True
            and states.get(inactive_tab_id) is False
        ):
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError("the reverse tab transition did not settle")
    print("The session rule followed both tab transitions.")


def check_inactive_tab_blocking(cdp: _PipeCdp, expected_id: str) -> None:
    """Prove background-tab enforcement holds and stays local-only.

    Breadcrumb: background.js flips one session DNR rule scoped to the
    inactive tab ids when storage.local.block_inactive turns true; its
    counters carry the "inactive-tab" label and never travel to the
    service, unlike rule-matched denials.
    """
    stats_before = _recorded_denials()
    worker = _worker_session(cdp, expected_id)
    probe_js = _PROBE_JS % {"url": f"http://localhost:{CANARY_PORT}{OPEN_PATH}"}
    prior_tab_ids = {
        row["id"] for row in (_evaluate(cdp, worker, _TABS_JS) or [])
    }

    # Chrome can leave both new targets inactive behind the canary target.
    # Activate one target before the tab-state query.
    tab_a = cdp.request(
        "Target.createTarget", {"url": "about:blank#a"}, timeout=15,
    )["targetId"]
    tab_b = cdp.request(
        "Target.createTarget", {"url": "about:blank#b"}, timeout=15,
    )["targetId"]
    cdp.request("Target.activateTarget", {"targetId": tab_a}, timeout=15)
    deadline = time.monotonic() + 20
    active_tab_id = None
    inactive_tab_id = None
    rows = []
    while time.monotonic() < deadline:
        rows = _evaluate(cdp, worker, _TABS_JS) or []
        new_rows = [row for row in rows if row.get("id") not in prior_tab_ids]
        active_rows = [row for row in new_rows if row.get("active") is True]
        inactive_rows = [row for row in new_rows if row.get("active") is False]
        if len(active_rows) == 1 and len(inactive_rows) == 1:
            active_tab_id = active_rows[0]["id"]
            inactive_tab_id = inactive_rows[0]["id"]
            break
        time.sleep(0.5)
    if inactive_tab_id is None:
        raise AcceptanceError(
            f"the two probe tabs never settled active/inactive: {rows}"
        )
    active_target_id = tab_a
    inactive_target_id = tab_b

    def _rule_covers(tab_id: int) -> bool:
        for rule in _evaluate(cdp, worker, _RULES_JS) or []:
            if tab_id in (rule.get("condition", {}).get("tabIds") or []):
                return True
        return False

    _evaluate(cdp, worker, "chrome.storage.local.set({block_inactive: true})")
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while not _rule_covers(inactive_tab_id):
        if time.monotonic() >= deadline:
            raise AcceptanceError("the inactive-tab session rule never appeared")
        time.sleep(0.5)

    active_session = _attach(cdp, active_target_id)
    if _evaluate(cdp, active_session, probe_js, timeout=30) != "loaded":
        raise AcceptanceError("an active-tab load of the unblocked probe failed")

    inactive_session = _attach(cdp, inactive_target_id)
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while True:
        if _evaluate(cdp, inactive_session, probe_js, timeout=30) == "blocked":
            break
        if time.monotonic() >= deadline:
            raise AcceptanceError("loads from an inactive tab were never blocked")
        time.sleep(1)

    stored = _evaluate(cdp, worker, "chrome.storage.local.get('denials')") or {}
    labels = [str(key) for key in (stored.get("denials") or {})]
    if not any(label.startswith("inactive-tab \u2192 ") for label in labels):
        raise AcceptanceError(
            "the blocked inactive-tab load stayed unrecorded locally"
        )
    check_tab_transition(
        cdp,
        worker,
        active_tab_id,
        inactive_tab_id,
        active_target_id,
        inactive_target_id,
        probe_js,
    )
    _evaluate(cdp, worker, "chrome.storage.local.set({block_inactive: false})")
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while _rule_covers(inactive_tab_id):
        if time.monotonic() >= deadline:
            raise AcceptanceError("the inactive-tab session rule never cleared")
        time.sleep(0.5)
    while True:
        if _evaluate(cdp, inactive_session, probe_js, timeout=30) == "loaded":
            break
        if time.monotonic() >= deadline:
            raise AcceptanceError(
                "toggling inactive-tab blocking off never restored loads"
            )
        time.sleep(1)

    # Exercise the actual status surface after the request-level check.
    popup_target = cdp.request(
        "Target.createTarget",
        {"url": f"chrome-extension://{expected_id}/status.html"},
        timeout=15,
    )["targetId"]
    popup_session = _attach(cdp, popup_target)
    deadline = time.monotonic() + 20
    popup_state = None
    while time.monotonic() < deadline:
        popup_state = _evaluate(cdp, popup_session, _POPUP_STATE_JS)
        if (
            popup_state
            and popup_state.get("checked") is False
            and popup_state.get("text") == "Background-tab loads are permitted."
        ):
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError(f"the inactive-tab status page did not load: {popup_state}")

    _evaluate(
        cdp,
        popup_session,
        "document.querySelector('#block_inactive').click()",
    )
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while time.monotonic() < deadline:
        popup_state = _evaluate(cdp, popup_session, _POPUP_STATE_JS)
        if (
            _rule_covers(inactive_tab_id)
            and popup_state.get("checked") is True
            and popup_state.get("text") == "Background-tab loads are blocked."
        ):
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError("the status page did not enable inactive-tab blocking")

    _evaluate(
        cdp,
        popup_session,
        "document.querySelector('#block_inactive').click()",
    )
    deadline = time.monotonic() + INACTIVE_POLL_SECONDS
    while time.monotonic() < deadline:
        popup_state = _evaluate(cdp, popup_session, _POPUP_STATE_JS)
        if (
            not _rule_covers(inactive_tab_id)
            and popup_state.get("checked") is False
            and popup_state.get("text") == "Background-tab loads are permitted."
        ):
            break
        time.sleep(0.5)
    else:
        raise AcceptanceError("the status page did not disable inactive-tab blocking")
    cdp.request("Target.closeTarget", {"targetId": popup_target}, timeout=15)

    cdp.request("Target.detachFromTarget", {"sessionId": worker}, timeout=15)

    # Breadcrumb: local-only counts must never reach the service; compare
    # key sets, not raw counts, because the reloading canary page keeps
    # bumping its own rule-matched row during this phase.
    stats_after = _recorded_denials()
    if set(stats_after) != set(stats_before):
        raise AcceptanceError(
            "local inactive-tab activity leaked into the service statistics: "
            f"{sorted(set(stats_after) ^ set(stats_before))}"
        )
    print("Inactive-tab blocking held and stayed out of the service statistics.")


def check_extension_blocks(
    chrome_bin: Path,
    profile: Path,
    account: pwd.struct_passwd,
    expected_id: str,
) -> None:
    before = _recorded_denials()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", CANARY_PORT), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    chrome = None
    cdp = None
    try:
        url = f"http://localhost:{CANARY_PORT}{CANARY_PATH}"
        chrome, cdp = _launch_chrome(chrome_bin, profile, url, account)
        deadline = time.monotonic() + POLL_SECONDS
        denied = False
        while time.monotonic() < deadline:
            if chrome.poll() is not None:
                raise AcceptanceError(
                    f"Chrome exited before extension acceptance (code {chrome.returncode})"
                )
            after = _recorded_denials()
            row = after.get(TARGET_VALUE)
            if row and row["count"] > before.get(TARGET_VALUE, {}).get("count", 0):
                print("Extension blocked the canary and reported the denial.")
                denied = True
                break
            time.sleep(2)
        if not denied:
            raise AcceptanceError(
                "the extension never reported a denial for the canary URL"
            )
        check_inactive_tab_blocking(cdp, expected_id)
        check_worker_survival(cdp, expected_id)
    finally:
        if cdp is not None:
            cdp.close()
        if chrome is not None:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        server.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Chromium extension acceptance in the marked VM"
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="fetch a Chrome for Testing build able to sideload extensions",
    )
    args = parser.parse_args()
    owner_uid = require_vm()
    account = pwd.getpwuid(owner_uid)
    chrome_bin = ensure_chrome(args.download)
    extension_source = Path(__file__).resolve().parent.parent / "extension" / "chromium"
    if not (extension_source / "manifest.json").is_file():
        raise AcceptanceError("the extension source tree is missing")
    profile, expected_id = build_profile(extension_source, account)
    # Breadcrumb: the profile copy must land before Chrome launches, so the
    # flavor-specific lookup inside the user data dir finds it.
    manifest_written = ensure_native_manifest(
        account, expected_id, profile=profile
    )
    create_rule()
    try:
        check_extension_blocks(chrome_bin, profile, account, expected_id)
    except Exception:
        remove_rule()
        for path in manifest_written:
            path.unlink(missing_ok=True)
        raise
    remove_rule()
    for path in manifest_written:
        path.unlink(missing_ok=True)
    print("Chromium extension acceptance passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
