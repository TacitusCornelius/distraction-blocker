"""Socket-only public command-line client.

This module imports only the standard library and small data-contract modules.
It never reads protected files. It does not import GTK or the root service.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import date, datetime, timedelta, timezone
import getpass as _getpass
import json
import sys
from uuid import uuid4
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .actions import ACTION_KINDS, new_action
from .canonical import CanonicalError, canonical_uuid
from .model import ManagedList, PolicyProjection, Schedule
from .notifications import (
    block as block_notifications,
    current_state as current_notification_state,
    unblock as unblock_notifications,
)
from .rpc import Client, RpcError
from .transfer import (
    atomic_write_text,
    block_list_preview_text,
    parse_block_list_export,
    parse_domain_text,
    read_block_list_text,
    read_import_text,
    statistics_export_text,
)

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
    managed_lists = command(
        "managed-lists", "list or manage managed lists"
    )
    managed_lists.add_argument(
        "operation", nargs="?", choices=("list", "create", "edit"),
        default="list",
    )
    managed_lists.add_argument("list_id", nargs="?")
    managed_lists.add_argument("--name", help="list name for create or edit")
    managed_lists.add_argument(
        "--domains", action="append",
        help="comma- or newline-separated domains (repeatable)",
    )
    managed_lists.add_argument(
        "--file", dest="domain_file",
        help="UTF-8 domain file, one hostname per line",
    )
    managed_lists.add_argument("--source")
    managed_lists.add_argument("--version")
    managed_lists.add_argument(
        "--license", dest="license_note"
    )
    managed_lists.add_argument(
        "--add", action="append",
        help="domains to add while editing (repeatable)",
    )
    managed_lists.add_argument(
        "--remove", action="append",
        help="domains to remove while editing (repeatable)",
    )
    command("status", "show service health")
    command("rules", "list rules")
    block_list = command(
        "import-block-list", "preview or import a Block List .blocklist.json export"
    )
    block_list.add_argument("path")
    block_list.add_argument(
        "--timezone", default="UTC", help="IANA time zone for scheduled blocks"
    )
    block_list.add_argument(
        "--enable",
        action="store_true",
        help="enable imported rules (default: disabled for review)",
    )
    block_list.add_argument(
        "--apply",
        action="store_true",
        help="write accepted rules to the service after previewing",
    )

    today = command("today", "show the projected schedule for one local day")
    actions = command("actions", "list or manage scheduled workstation actions")
    actions.add_argument(
        "operation", choices=("list", "add", "remove", "enable", "disable")
    )
    actions.add_argument("action_id", nargs="?")
    actions.add_argument("--kind", choices=ACTION_KINDS)
    actions.add_argument("--at", help="one-time local date/time")
    actions.add_argument("--timezone", default="UTC", help="IANA time zone for --at")
    actions.add_argument(
        "--weekdays",
        help="comma-separated weekday numbers (0=Monday through 6=Sunday)",
    )
    actions.add_argument("--start", help="weekly local start time HH:MM")
    actions.add_argument("--end", help="weekly local end time HH:MM")
    actions.add_argument(
        "--confirm-shutdown",
        action="store_true",
        help="confirm that shutdown may power off this workstation",
    )
    notifications = command("notifications", "control desktop notifications")
    notifications.add_argument(
        "operation", choices=("status", "block", "unblock")
    )
    today.add_argument("--date", dest="day", help="local date in YYYY-MM-DD form")
    today.add_argument("--timezone", help="IANA time zone (default: system)")
    focus = command("focus", "start a focus period")
    focus.add_argument("rule_id")
    focus.add_argument("minutes", type=int)
    stats = command("stats", "show denial statistics")
    stats.add_argument("--clear", action="store_true", help="clear statistics after reading them")
    stats.add_argument(
        "--export",
        dest="export_path",
        help="write application and website statistics to this path",
    )
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
    schedule_lock = command("lock-schedule", "set a weekly schedule lock")
    schedule_lock.add_argument("rule_id")
    friction = command("lock-friction", "set a friction lock")
    friction.add_argument("rule_id")
    password = command("lock-password", "set a password lock")
    password.add_argument("rule_id")
    delay = command("lock-delay", "set a Delay lock")
    delay.add_argument("rule_id")
    delay.add_argument("wait_minutes", type=int)
    delay.add_argument("break_minutes", type=int)
    delay_break = command("delay-break", "request a Delay temporary break")
    delay_break.add_argument("rule_id")
    cancel_delay = command("cancel-delay-break", "cancel a pending Delay break")
    cancel_delay.add_argument("rule_id")
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
            f"Active network controls: {counts.get('network', 0)}",
        ]
    if command == "rules" and isinstance(value, dict):
        rules = value["rules"]
        if not rules:
            return ["No rules."]
        return [
            (
                f"{item['id']}  {item['name']}  "
                f"{'enabled' if item['enabled'] else 'disabled'}  "
                f"{item['schedule']['kind']}"
            )
            for item in rules
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
    if command == "import-block-list" and isinstance(value, dict):
        lines = [
            f"Imported blocks: {value.get('accepted_blocks', 0)}",
            f"Exact hostnames: {value.get('accepted_websites', 0)}",
            f"Duplicates: {value.get('duplicates', 0)}",
            f"Unsupported or invalid entries: {len(value.get('issues', []))}",
            f"Applied: {value.get('applied', 0)}",
        ]
        lines.extend(
            f"- {item.get('path', '')}: {item.get('reason', '')}"
            for item in value.get("issues", [])[:32]
            if isinstance(item, dict)
        )
        return lines
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
    if command == "actions" and isinstance(value, (dict, list)):
        items = value if isinstance(value, list) else [value]
        if not items:
            return ["No scheduled actions."]
        return [
            (
                f"{item.get('id', '')}  {item.get('kind', '')}  "
                f"{'enabled' if item.get('enabled') else 'disabled'}  "
                f"{item.get('schedule', {}).get('kind', '')}"
            )
            for item in items
        ]
    if command == "notifications" and isinstance(value, dict):
        return [
            f"Notification banners: {'enabled' if value.get('show_banners') else 'blocked'}",
            (
                "Notifications on lock screen: "
                + ("enabled" if value.get("show_in_lock_screen") else "blocked")
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
    if command == "rules":
        # Breadcrumb: validate before either JSON or human output. This keeps
        # malformed service data out of every CLI presentation path.
        value = PolicyProjection.from_dict(value).to_dict()
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


def _scheduled_action(
    arguments: argparse.Namespace,
    now: Callable[[], datetime],
) -> dict[str, Any] | None:
    if arguments.operation == "list":
        return None
    if arguments.operation in {"enable", "disable"}:
        if not arguments.action_id:
            raise ValueError("action ID is required")
        return {
            "action_id": _rule_id(arguments.action_id),
            "enabled": arguments.operation == "enable",
        }
    if arguments.operation == "remove":
        if not arguments.action_id:
            raise ValueError("action ID is required")
        return {"action_id": _rule_id(arguments.action_id)}
    if arguments.kind is None:
        raise ValueError("action kind is required")
    if arguments.kind == "shutdown" and not arguments.confirm_shutdown:
        raise ValueError("shutdown requires --confirm-shutdown")
    if arguments.at:
        if arguments.weekdays or arguments.start or arguments.end:
            raise ValueError("one-time and weekly schedule fields cannot be combined")
        utc_text = _utc_expiry(arguments.at, arguments.timezone)
        start = datetime.fromisoformat(utc_text.replace("Z", "+00:00"))
        schedule = Schedule.from_dict({
            "kind": "one_time",
            "start_utc": utc_text,
            "end_utc": (start + timedelta(minutes=1)).isoformat().replace(
                "+00:00", "Z"
            ),
        })
    else:
        if not arguments.weekdays or not arguments.start or not arguments.end:
            raise ValueError("weekly actions require --weekdays, --start, and --end")
        try:
            weekdays = [int(item) for item in arguments.weekdays.split(",")]
        except ValueError as error:
            raise ValueError("weekdays must be comma-separated numbers") from error
        schedule = Schedule.from_dict({
            "kind": "weekly",
            "timezone": arguments.timezone,
            "periods": [{
                "weekdays": weekdays,
                "start": arguments.start,
                "end": arguments.end,
            }],
        })
    return new_action(arguments.kind, schedule).to_dict()


def _notification_command(operation: str) -> dict[str, Any]:
    if operation == "block":
        state = block_notifications()
    elif operation == "unblock":
        state = unblock_notifications()
    else:
        state = current_notification_state()
    return {
        "show_banners": state.show_banners,
        "show_in_lock_screen": state.show_in_lock_screen,
    }


def _today(
    client: Any,
    arguments: argparse.Namespace,
    now: Callable[[], datetime],
) -> dict[str, Any]:
    from .schedule_view import system_timezone_name

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


def _block_list_import(arguments: argparse.Namespace, client: Any) -> dict[str, Any]:
    preview = parse_block_list_export(
        read_block_list_text(arguments.path),
        timezone_name=arguments.timezone,
        enabled=arguments.enable,
    )
    applied = 0
    if arguments.apply and preview.rules:
        response = client.request("begin_rule_import")
        import_id = response["import_id"]
        try:
            for offset in range(0, len(preview.rules), 200):
                client.request(
                    "import_rule_chunk",
                    import_id=import_id,
                    rules=[
                        rule.to_dict()
                        for rule in preview.rules[offset : offset + 200]
                    ],
                )
            client.request("commit_rule_import", import_id=import_id)
            applied = len(preview.rules)
        except Exception:
            try:
                client.request("cancel_rule_import", import_id=import_id)
            except Exception:
                pass
            raise
    return {
        "accepted_blocks": preview.accepted_blocks,
        "accepted_websites": preview.accepted_websites,
        "duplicates": preview.duplicates,
        "issues": [
            {"path": issue.path, "text": issue.text, "reason": issue.reason}
            for issue in preview.issues
        ],
        "applied": applied,
    }


def _managed_list_domains(values: Sequence[str] | None, filename: str | None) -> tuple[str, ...]:
    pieces: list[str] = []
    for value in values or ():
        pieces.extend(value.replace(",", "\n").splitlines())
    if filename:
        pieces.append(read_import_text(filename))
    if not pieces:
        raise ValueError("provide --domains or --file")
    preview = parse_domain_text("\n".join(pieces))
    if preview.issues:
        issue = preview.issues[0]
        raise ValueError(
            f"invalid domain on line {issue.line}: {issue.reason}"
        )
    if not preview.domains:
        raise ValueError("the managed list contains no valid domains")
    return preview.domains


def _managed_list_upload(client: Any, managed_list: ManagedList) -> dict[str, Any]:
    metadata = managed_list.to_dict()
    metadata = {
        key: metadata[key]
        for key in ("id", "name", "source", "version", "license")
    }
    begin = client.request("begin_list_import", metadata=metadata)
    if not isinstance(begin, dict) or not isinstance(begin.get("import_id"), str):
        raise ValueError("service returned an invalid list import ID")
    import_id = begin["import_id"]
    try:
        result: Any = None
        for offset in range(0, len(managed_list.domains), 200):
            result = client.request(
                "import_list_chunk",
                import_id=import_id,
                domains=list(managed_list.domains[offset:offset + 200]),
            )
        result = client.request("commit_list_import", import_id=import_id)
        if not isinstance(result, dict):
            raise ValueError("service returned an invalid managed-list result")
        return result
    except Exception:
        try:
            client.request("cancel_list_import", import_id=import_id)
        except Exception:
            pass
        raise


def _read_managed_list_domains(client: Any, list_id: str) -> tuple[str, ...]:
    domains: list[str] = []
    offset = 0
    while True:
        result = client.request(
            "read_managed_list",
            list_id=list_id,
            offset=offset,
            limit=200,
        )
        if (
            not isinstance(result, dict)
            or result.get("id") != list_id
            or not isinstance(result.get("domains"), list)
            or not all(isinstance(item, str) for item in result["domains"])
        ):
            raise ValueError("service returned an invalid managed-list chunk")
        domains.extend(result["domains"])
        next_offset = result.get("next_offset")
        if next_offset is None:
            return tuple(domains)
        if (
            not isinstance(next_offset, int)
            or isinstance(next_offset, bool)
            or next_offset <= offset
        ):
            raise ValueError("service returned an invalid managed-list offset")
        offset = next_offset


def _managed_lists_command(
    arguments: argparse.Namespace,
    client: Any,
    now: Callable[[], datetime],
) -> Any:
    operation = arguments.operation
    if operation == "list":
        if any(
            value is not None
            for value in (
                arguments.list_id,
                arguments.name,
                arguments.domains,
                arguments.domain_file,
                arguments.source,
                arguments.version,
                arguments.license_note,
                arguments.add,
                arguments.remove,
            )
        ):
            raise ValueError("list does not accept edit options")
        return client.request("list_managed_lists")
    if operation == "create":
        if arguments.list_id:
            raise ValueError("create does not accept a list ID")
        if not arguments.name:
            raise ValueError("--name is required for create")
        domains = _managed_list_domains(arguments.domains, arguments.domain_file)
        managed_list = ManagedList.from_dict({
            "id": str(uuid4()),
            "name": arguments.name.strip(),
            "source": arguments.source or "custom",
            "version": arguments.version or "1",
            "license": arguments.license_note or "User-provided domains.",
            "imported_utc": now(),
            "domains": list(domains),
        })
        return _managed_list_upload(client, managed_list)
    if not arguments.list_id:
        raise ValueError("edit requires a list ID")
    list_id = _rule_id(arguments.list_id)
    summaries = client.request("list_managed_lists")
    if not isinstance(summaries, list):
        raise ValueError("service returned invalid managed-list summaries")
    summary = next(
        (item for item in summaries
         if isinstance(item, dict) and item.get("id") == list_id),
        None,
    )
    if summary is None:
        raise ValueError("managed list was not found")
    if not all(isinstance(summary.get(key), str) for key in (
        "name", "source", "version", "license"
    )):
        raise ValueError("service returned invalid managed-list metadata")
    if arguments.domain_file:
        current = _managed_list_domains(None, arguments.domain_file)
    elif arguments.domains is not None:
        current = _managed_list_domains(arguments.domains, None)
    else:
        current = _read_managed_list_domains(client, list_id)
    additions = _managed_list_domains(arguments.add, None) if arguments.add else ()
    removals = _managed_list_domains(arguments.remove, None) if arguments.remove else ()
    roster = (set(current) | set(additions)) - set(removals)
    if not roster:
        raise ValueError("the managed list contains no valid domains")
    managed_list = ManagedList.from_dict({
        "id": list_id,
        "name": (arguments.name or summary["name"]).strip(),
        "source": arguments.source or summary["source"],
        "version": arguments.version or summary["version"],
        "license": arguments.license_note or summary["license"],
        "imported_utc": now(),
        "domains": sorted(roster),
    })
    return _managed_list_upload(client, managed_list)


def _execute(
    arguments: argparse.Namespace,
    client: Any,
    input_fn: Callable[[str], str],
    getpass_fn: Callable[[str], str],
    now: Callable[[], datetime],
) -> Any:
    command = arguments.command
    if command == "import-block-list":
        return _block_list_import(arguments, client)
    if command == "actions":
        if arguments.operation == "list":
            return client.request("list_scheduled_actions")
        fields = _scheduled_action(arguments, now)
        if arguments.operation == "remove":
            return client.request("delete_scheduled_action", **fields)
        if arguments.operation in {"enable", "disable"}:
            return client.request("set_scheduled_action_enabled", **fields)
        return client.request("put_scheduled_action", action=fields)
    if command == "notifications":
        return _notification_command(arguments.operation)
    if command == "status":
        return client.request("status")
    if command == "rules":
        return client.request("list_rules")
    if command == "managed-lists":
        return _managed_lists_command(arguments, client, now)
    if command == "today":
        return _today(client, arguments, now)
    if command == "focus":
        return client.request("start_focus", rule_id=_rule_id(arguments.rule_id), minutes=arguments.minutes)
    if command == "stats":
        result = client.request("list_denial_stats")
        if arguments.export_path:
            website = client.request("list_website_stats")
            atomic_write_text(
                arguments.export_path,
                statistics_export_text(result, website, now()),
            )
        if arguments.clear:
            client.request("clear_denial_stats")
        return result
    if command in {"enable", "disable"}:
        return client.request("set_enabled", rule_id=_rule_id(arguments.rule_id), enabled=arguments.enabled)
    if command == "delete":
        return client.request("delete_rule", rule_id=_rule_id(arguments.rule_id))
    if command == "lock-schedule":
        return client.request(
            "set_rule_lock",
            rule_id=_rule_id(arguments.rule_id),
            lock={"kind": "schedule"},
        )
    if command == "lock-timed":
        expiry = arguments.until_option or arguments.until
        if not expiry:
            raise ValueError("expiry is required")
        return client.request(
            "set_rule_lock",
            rule_id=_rule_id(arguments.rule_id),
            lock={"kind": "timed", "until_utc": _utc_expiry(expiry, arguments.timezone)},
        )
    if command == "lock-delay":
        rule_id = _rule_id(arguments.rule_id)
        if not 1 <= arguments.wait_minutes <= 1440:
            raise ValueError("wait_minutes must be between 1 and 1440")
        if not 1 <= arguments.break_minutes <= 1440:
            raise ValueError("break_minutes must be between 1 and 1440")
        return client.request(
            "set_rule_lock",
            rule_id=rule_id,
            lock={
                "kind": "delay",
                "wait_seconds": arguments.wait_minutes * 60,
                "break_seconds": arguments.break_minutes * 60,
            },
        )
    if command == "delay-break":
        return client.request(
            "request_delay_break",
            rule_id=_rule_id(arguments.rule_id),
        )
    if command == "cancel-delay-break":
        return client.request(
            "cancel_delay_break",
            rule_id=_rule_id(arguments.rule_id),
        )
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
