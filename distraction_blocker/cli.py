"""Socket-only public command-line client.

This module imports only the standard library and the small RPC client.  It
never reads protected files and keeps optional GTK and service imports outside
all CLI command paths.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import date, datetime, timezone
import getpass as _getpass
import json
import sys
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .canonical import CanonicalError, canonical_uuid
from .rpc import Client, RpcError

UTC = timezone.utc
DEFAULT_SOCKET = "/run/distraction-blocker/control.sock"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="distraction-blocker")
    parser.add_argument("--json", action="store_true", dest="json_output", help="write one deterministic JSON result")
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text)
        # argparse normally accepts a global option only before the command.
        # Suppressed defaults allow the same global option after the command.
        sub.add_argument("--json", action="store_true", dest="json_output", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        return sub

    command("status", "show service health")
    command("rules", "list rules")
    command("managed-lists", "list managed lists")
    today = command("today", "show the projected schedule for one local day")
    today.add_argument("--date", dest="day", help="local date in YYYY-MM-DD form")
    today.add_argument("--timezone", help="IANA time zone (default: system)")
    focus = command("focus", "start a focus period")
    focus.add_argument("rule_id")
    focus.add_argument("minutes", type=int)
    stats = command("stats", "show denial statistics")
    stats.add_argument("--clear", action="store_true", help="clear statistics after reading them")
    for name, help_text, enabled in (("enable", "enable a rule", True), ("disable", "disable a rule", False)):
        sub = command(name, help_text)
        sub.add_argument("rule_id")
        sub.set_defaults(enabled=enabled)
    delete = command("delete", "delete a rule")
    delete.add_argument("rule_id")
    timed = command("lock-timed", "set a timed lock")
    timed.add_argument("rule_id")
    timed.add_argument("until", nargs="?")
    timed.add_argument("--until", dest="until_option", help="local expiry as ISO date/time")
    timed.add_argument("--timezone", default="UTC", help="IANA time zone for a naive expiry (default: UTC)")
    friction = command("lock-friction", "set a friction lock")
    friction.add_argument("rule_id")
    password = command("lock-password", "set a password lock")
    password.add_argument("rule_id")
    clear = command("clear-lock", "remove a rule lock")
    clear.add_argument("rule_id")
    authorize = command("authorize", "authorize one weakening change")
    authorize.add_argument("rule_id")
    return parser


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _human_lines(command: str, value: Any) -> list[str]:
    if command == "status" and isinstance(value, dict):
        counts = value.get("active_counts", {})
        return [
            f"Service: {'healthy' if value.get('healthy') else 'unhealthy'}",
            f"Clock: {'trusted' if value.get('clock_trusted') else 'not trusted'}",
            f"Active websites: {counts.get('website', 0)}",
            f"Active applications: {counts.get('application', 0)}",
        ]
    if command == "rules" and isinstance(value, list):
        if not value:
            return ["No rules."]
        return [
            (
                f"{item.get('id', '')}  {item.get('name', '')}  "
                f"{'enabled' if item.get('enabled') else 'disabled'}  "
                f"{item.get('schedule', {}).get('kind', 'unknown')}"
            )
            for item in value
        ]
    if command == "managed-lists" and isinstance(value, list):
        if not value:
            return ["No managed lists."]
        return [
            (
                f"{item.get('id', '')}  {item.get('name', '')}  "
                f"{item.get('domain_count', 0)} domains"
            )
            for item in value
        ]
    if command == "today" and isinstance(value, dict):
        lines = [
            f"Date: {value.get('date', '')}",
            f"Time zone: {value.get('timezone', '')}",
        ]
        intervals = value.get("intervals", [])
        if not intervals:
            return [*lines, "No scheduled intervals."]
        return [
            *lines,
            *(
                f"{item.get('start', '')} to {item.get('end', '')}  "
                f"{item.get('rule_name', '')}"
                for item in intervals
            ),
        ]
    if command == "stats" and isinstance(value, dict):
        lines = [f"Dropped events: {value.get('dropped', 0)}"]
        items = value.get("items", [])
        if not items:
            return [*lines, "No application denials."]
        return [
            *lines,
            *(
                f"{item.get('count', 0)}  {item.get('path', '')}  "
                f"last {item.get('last_utc', '')}"
                for item in items
            ),
        ]
    if isinstance(value, dict):
        lines = []
        for key in sorted(value):
            item = value[key]
            if isinstance(item, (dict, list)):
                item = json.dumps(
                    item, ensure_ascii=True, sort_keys=True
                )
            lines.append(f"{key.replace('_', ' ').title()}: {item}")
        return lines or ["Done."]
    if isinstance(value, list):
        return [str(item) for item in value] or ["No results."]
    return [str(value)]


def _write_result(
    command: str,
    value: Any,
    json_output: bool,
    output: Callable[[str], None],
) -> None:
    safe = _json_safe(value)
    if json_output:
        output(json.dumps(
            safe,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ))
        return
    for line in _human_lines(command, safe):
        output(line)


def _utc_expiry(value: str, timezone_name: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("expiry must be an ISO date and time") from error
    if parsed.tzinfo is None:
        try:
            zone = ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError("timezone is not valid") from error
        candidate = parsed.replace(tzinfo=zone, fold=0)
        round_trip = (
            candidate.astimezone(UTC)
            .astimezone(zone)
            .replace(tzinfo=None)
        )
        second = parsed.replace(tzinfo=zone, fold=1)
        if round_trip != parsed:
            raise ValueError("expiry local time does not exist")
        if candidate.utcoffset() != second.utcoffset():
            raise ValueError("expiry local time occurs twice")
        parsed = candidate
    return parsed.astimezone(UTC).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _rule_id(value: str) -> str:
    try:
        return canonical_uuid(value, normalize=True)
    except CanonicalError as error:
        raise ValueError("rule ID is not valid") from error


def _password(value: str) -> str:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError("password is not valid") from error
    if not 8 <= size <= 1024:
        raise ValueError("password must contain 8 to 1024 UTF-8 bytes")
    return value


def _today(
    client: Any,
    arguments: argparse.Namespace,
    now: Callable[[], datetime],
) -> dict[str, Any]:
    from .gui import system_timezone_name

    timezone_name = arguments.timezone or system_timezone_name()
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError("timezone is not valid") from error
    if arguments.day:
        try:
            local_day = date.fromisoformat(arguments.day)
        except ValueError as error:
            raise ValueError("date must be in YYYY-MM-DD form") from error
    else:
        current = now()
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        local_day = current.astimezone(zone).date()
    result = client.request(
        "daily_schedule",
        timezone=timezone_name,
        date=local_day.isoformat(),
    )
    if (
        not isinstance(result, dict)
        or set(result) != {"date", "timezone", "intervals"}
        or not isinstance(result["intervals"], list)
    ):
        raise ValueError("service returned an invalid daily schedule")
    return result


def _execute(
    arguments: argparse.Namespace,
    client: Any,
    input_fn: Callable[[str], str],
    getpass_fn: Callable[[str], str],
    now: Callable[[], datetime],
) -> Any:
    command = arguments.command
    if command == "status":
        return client.request("status")
    if command == "rules":
        return client.request("list_rules")
    if command == "managed-lists":
        return client.request("list_managed_lists")
    if command == "today":
        return _today(client, arguments, now)
    if command == "focus":
        return client.request("start_focus", rule_id=_rule_id(arguments.rule_id), minutes=arguments.minutes)
    if command == "stats":
        result = client.request("list_denial_stats")
        if arguments.clear:
            client.request("clear_denial_stats")
        return result
    if command in {"enable", "disable"}:
        return client.request("set_enabled", rule_id=_rule_id(arguments.rule_id), enabled=arguments.enabled)
    if command == "delete":
        return client.request("delete_rule", rule_id=_rule_id(arguments.rule_id))
    if command == "lock-timed":
        expiry = arguments.until_option or arguments.until
        if not expiry:
            raise ValueError("expiry is required")
        return client.request("set_rule_lock", rule_id=_rule_id(arguments.rule_id), lock={"kind": "timed", "until_utc": _utc_expiry(expiry, arguments.timezone)})
    if command == "lock-password":
        rule_id = _rule_id(arguments.rule_id)
        first = _password(getpass_fn("Password: "))
        confirmation = getpass_fn("Confirm password: ")
        if confirmation != first:
            raise ValueError("password and confirmation do not match")
        return client.request("set_rule_lock", rule_id=rule_id, lock={"kind": "password", "password": first})
    if command == "lock-friction":
        return client.request("set_rule_lock", rule_id=_rule_id(arguments.rule_id), lock={"kind": "friction"})
    if command == "clear-lock":
        return client.request("set_rule_lock", rule_id=_rule_id(arguments.rule_id), lock={"kind": "none"})
    if command == "authorize":
        rule_id = _rule_id(arguments.rule_id)
        challenge = client.request("begin_rule_authorization", rule_id=rule_id)
        if not isinstance(challenge, dict):
            raise ValueError("service returned invalid authorization challenge")
        kind = challenge.get("kind")
        if kind == "friction":
            prompt = challenge.get("prompt")
            if not isinstance(prompt, str):
                raise ValueError("service returned an invalid authorization prompt")
            response = input_fn(f"Type {prompt}: ")
        elif kind == "password":
            response = getpass_fn("Password: ")
        else:
            raise ValueError("service returned an unsupported authorization kind")
        return client.request("complete_rule_authorization", rule_id=rule_id, challenge_id=challenge.get("challenge_id"), response=response)
    raise ValueError("unknown command")


def main(
    argv: Sequence[str] | None = None,
    *,
    client: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
    input_fn: Callable[[str], str] | None = None,
    getpass_fn: Callable[[str], str] | None = None,
    output: Callable[[str], None] | None = None,
    error: Callable[[str], None] | None = None,
    now: Callable[[], datetime] | None = None,
    socket_path: str = DEFAULT_SOCKET,
) -> int:
    """Run one public CLI command and return a process exit code."""
    if client_factory is None:
        client_factory = Client
    if input_fn is None:
        input_fn = input
    if getpass_fn is None:
        getpass_fn = _getpass.getpass
    if output is None:
        output = print
    if error is None:
        error = lambda text: print(text, file=sys.stderr)
    if now is None:
        now = lambda: datetime.now(UTC)
    try:
        arguments = _parser().parse_args(argv)
        active_client = (
            client if client is not None else client_factory(socket_path)
        )
        result = _execute(
            arguments, active_client, input_fn, getpass_fn, now
        )
        _write_result(
            arguments.command,
            result,
            bool(arguments.json_output),
            output,
        )
        return 0
    except (RpcError, OSError, ValueError, TypeError) as exc:
        error(f"distraction-blocker: {exc}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
