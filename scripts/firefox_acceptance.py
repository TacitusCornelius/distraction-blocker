#!/usr/bin/env python3
"""End-to-end Firefox acceptance for the Distraction Blocker extension.

Run as root inside the marked acceptance virtual machine, after the main
ubuntu_acceptance.py phase 1 has installed the service. The script:

1. Downloads Firefox ESR into /opt when absent (ESR honors
   ``xpinstall.signatures.required = false`` so our unsigned extension can
   be sideloaded persistently) and installs the runtime libraries the
   tarball build needs.
2. Builds a disposable profile with the extension unpacked into it.
3. Creates one URL-path rule through the service socket.
4. Serves a canary on localhost, then starts headless Firefox as the
   desktop user against it.
5. Waits for the extension to cancel the load, report the denial through
   the native messaging host, and for the service to persist it into the
   signed website-statistics file.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ubuntu_acceptance import (  # noqa: E402
    AcceptanceError,
    installed_client,
    require_vm,
)

FIREFOX_ROOT = Path("/opt/distraction-blocker-firefox")
FIREFOX_BIN = FIREFOX_ROOT / "firefox" / "firefox"
PROFILE_ROOT = Path("/home/test/.cache/distraction-blocker-firefox")
EXTENSION_ID = "{e4f1a2b3-9c8d-4e5f-a6b7-8c9d0e1f2a3b}"
ESR_URL = (
    "https://download.mozilla.org/"
    "?product=firefox-esr-latest&os=linux64&lang=en-US"
)
CANARY_PORT = 8765
RULE_ID = "66666666-6666-4666-8666-666666666666"
TARGET_VALUE = "localhost/canary"
STATS_FILE = Path("/var/lib/distraction-blocker/website-statistics.json")
POLL_SECONDS = 150

# Breadcrumb: qemu guests often cannot create user namespaces, so every
# content-process sandbox is disabled for this disposable environment.
FIREFOX_ENV = {
    "MOZ_DISABLE_CONTENT_SANDBOX": "1",
    "MOZ_DISABLE_RDD_SANDBOX": "1",
    "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX": "1",
    "MOZ_DISABLE_GPU_SANDBOX": "1",
}

PREFS = {
    "xpinstall.signatures.required": False,
    "extensions.autoDisableScopes": 0,
    "browser.shell.checkDefaultBrowser": False,
    "browser.aboutwelcome.enabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.enabled": False,
    "app.update.auto": False,
}

RUNTIME_PACKAGES = (
    "libgtk-3-0",
    "libdbus-glib-1-2",
    "libxt6",
    "libasound2t64",
    "libasound2",
)


def command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise AcceptanceError(f"{args[0]} failed: {detail}")
    return result


def ensure_firefox(download: bool) -> Path:
    if FIREFOX_BIN.is_file():
        return FIREFOX_BIN
    if not download:
        raise AcceptanceError(
            f"Firefox ESR is not installed at {FIREFOX_BIN}; pass --download"
        )
    archive = FIREFOX_ROOT / "firefox-esr.tar.xz"
    FIREFOX_ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    print(f"Downloading Firefox ESR into {archive} …", flush=True)
    with urllib.request.urlopen(ESR_URL, timeout=600) as response, archive.open("wb") as sink:
        shutil.copyfileobj(response, sink)
    command(["/usr/bin/tar", "-xJf", str(archive), "-C", str(FIREFOX_ROOT)])
    if not FIREFOX_BIN.is_file():
        raise AcceptanceError("the Firefox ESR archive had no firefox binary")
    # Breadcrumb: the tarball build links GTK, ALSA, and X11 directly; the
    # server cloud image ships none of them. Package names differ between
    # releases, so both ALSA spellings are attempted and failures ignored.
    for package in RUNTIME_PACKAGES:
        command(["/usr/bin/apt-get", "install", "-y", "-q", package], check=False)
    return FIREFOX_BIN


def build_profile(extension_source: Path) -> Path:
    profile = PROFILE_ROOT / "profile"
    if profile.exists():
        shutil.rmtree(profile)
    extensions = profile / "extensions"
    extensions.mkdir(mode=0o755, parents=True)
    # Breadcrumb: an unpacked directory named exactly the add-on ID is a
    # persistent sideload; ESR loads it because signatures are disabled.
    xpi = extensions / f"{EXTENSION_ID}.xpi"
    with zipfile.ZipFile(xpi, "w") as bundle:
        for item in sorted(extension_source.rglob("*")):
            if item.is_file() and "__pycache__" not in item.parts:
                bundle.write(item, item.relative_to(extension_source).as_posix())
    lines = [
        f'user_pref("{name}", {json.dumps(value)});'
        for name, value in PREFS.items()
    ]
    (profile / "prefs.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    test_user = pwd.getpwuid(1000)
    os.chown(PROFILE_ROOT, test_user.pw_uid, test_user.pw_gid)
    subprocess.run(
        ["/usr/bin/chown", "-R", f"{test_user.pw_uid}:{test_user.pw_gid}", str(profile)],
        check=True,
    )
    return profile


def create_rule() -> None:
    installed_client().request(
        "put_rule",
        rule={
            "id": RULE_ID,
            "name": "Firefox acceptance",
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
        body = b"canary\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        # Temporary acceptance probes arrive here as /probe?m=… requests.
        print("CANARY:", self.path, flush=True)


def _recorded_denials() -> dict:
    if not STATS_FILE.exists():
        return {}
    try:
        envelope = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        return {row["value"]: row for row in envelope["payload"]["items"]}
    except (OSError, ValueError, KeyError):
        return {}


def check_extension_blocks(firefox_bin: Path, profile: Path) -> None:
    before = _recorded_denials()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", CANARY_PORT), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    firefox = None
    try:
        account = pwd.getpwuid(1000)
        # Breadcrumb: Firefox refuses to run as root, and the extension must
        # reach the socket as the desktop user anyway.
        firefox = subprocess.Popen(
            [
                "/usr/sbin/runuser",
                "-u",
                account.pw_name,
                "--",
                "/usr/bin/env",
                f"HOME={account.pw_dir}",
                *sum(([k, v] for k, v in FIREFOX_ENV.items()), []),
                str(firefox_bin),
                "-profile",
                str(profile),
                f"http://localhost:{CANARY_PORT}/canary",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + POLL_SECONDS
        while time.monotonic() < deadline:
            after = _recorded_denials()
            row = after.get(TARGET_VALUE)
            if row and row["count"] > before.get(TARGET_VALUE, {}).get("count", 0):
                print("Extension blocked the canary and reported the denial.")
                return
            time.sleep(2)
        raise AcceptanceError(
            "the extension never reported a denial for the canary URL"
        )
    finally:
        if firefox is not None:
            firefox.terminate()
            try:
                firefox.wait(timeout=15)
            except subprocess.TimeoutExpired:
                firefox.kill()
        server.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Firefox extension acceptance in the marked VM"
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="download Firefox ESR when it is not installed",
    )
    args = parser.parse_args()
    require_vm()
    firefox_bin = ensure_firefox(download=args.download)
    extension_source = Path(__file__).resolve().parent.parent / "extension" / "firefox"
    if not (extension_source / "manifest.json").is_file():
        raise AcceptanceError("the extension source tree is missing")
    profile = build_profile(extension_source)
    create_rule()
    try:
        check_extension_blocks(firefox_bin, profile)
    except Exception:
        remove_rule()
        raise
    remove_rule()
    print("Firefox extension acceptance passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
