#!/usr/bin/python3
"""Native messaging host between the browser extension and the service.

The browser starts this file as the logged-in desktop user. It forwards a
small allowlisted command set to the running service over the existing
owner-checked Unix socket, so the extension never gains a privilege the
desktop session does not have.
"""

# distraction-blocker-owned-wrapper-v1
from __future__ import annotations

import json
import struct
import sys

INSTALL_ROOT = "/usr/lib/distraction-blocker"
sys.path.insert(0, INSTALL_ROOT)

from distraction_blocker.rpc import Client  # noqa: E402

SOCKET = "/run/distraction-blocker/control.sock"

# Breadcrumb for reviewers: the allowlist lives in this root-owned file so
# a compromised extension cannot read protected state or change policy.
READONLY_COMMANDS = frozenset({
    "status",
    "list_rules",
    "list_denial_stats",
    "list_website_stats",
})
# Commands that carry payload fields; the field set is still pinned here.
FIELD_COMMANDS = {
    "report_website_denials": frozenset({"command", "entries"}),
    "report_website_usage": frozenset({"command", "entries"}),
    "request_allowance_lease": frozenset({"command", "rule_id", "seconds"}),
    "report_allowance_usage": frozenset({
        "command", "lease_id", "report_id", "start_utc", "end_utc",
    }),
}

def read_message(stream) -> dict | None:
    """Read one length-prefixed JSON message from a binary stream."""
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("@I", header)
    if length == 0 or length > 65536:
        return None
    try:
        request = json.loads(stream.read(length).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return request if isinstance(request, dict) else None


def send_message(stream, message: dict) -> None:
    """Write one length-prefixed JSON message to a binary stream."""
    encoded = json.dumps(
        message, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    stream.write(struct.pack("@I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def handle(request: dict) -> dict:
    command = request.get("command")
    fields = set(request)
    allowed = (
        command in READONLY_COMMANDS
        and fields == {"command"}
        or command in FIELD_COMMANDS
        and fields <= FIELD_COMMANDS[command]
    )
    if not allowed:
        return {
            "ok": False,
            "error": {
                "code": "forbidden",
                "message": "command is not allowed",
            },
        }
    try:
        result = Client(SOCKET).request(**request)
    except Exception as error:  # noqa: BLE001 - the browser sees one JSON shape
        return {
            "ok": False,
            "error": {"code": "host_error", "message": str(error)},
        }
    return {"ok": True, "result": result}


def main() -> int:
    reader = sys.stdin.buffer
    writer = sys.stdout.buffer
    while True:
        request = read_message(reader)
        if request is None:
            return 0
        send_message(writer, handle(request))


if __name__ == "__main__":
    raise SystemExit(main())
