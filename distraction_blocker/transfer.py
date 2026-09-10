"""Pure import and export contracts for versioned rule data."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterable, Mapping, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from uuid import uuid4

from .model import POLICY_SCHEMA_VERSION, ManagedList, Policy, Rule, Schedule, Target, ValidationError

NATIVE_FORMAT = "distraction-blocker"
# Version 5 adds best-effort proxy and VPN endpoint controls; earlier
# portable files are migrated on import when their targets remain supported.
NATIVE_VERSION = 5
MAX_DOMAIN_IMPORT_BYTES = 4 * 1024 * 1024
MAX_NATIVE_IMPORT_BYTES = 8 * 1024 * 1024
MAX_IMPORT_ENTRIES = 50_000
_HOSTS_SINKS = {"0.0.0.0", "127.0.0.1", "::"}


class TransferError(ValueError):
    """Imported or exported data does not satisfy the file contract."""


@dataclass(frozen=True)
class ImportIssue:
    line: int
    text: str
    reason: str


@dataclass(frozen=True)
class ImportPreview:
    domains: tuple[str, ...]
    duplicates: int
    ignored: int
    issues: tuple[ImportIssue, ...]

    @property
    def accepted(self) -> int:
        return len(self.domains)


@dataclass(frozen=True)
class BlockListIssue:
    """One unsupported or malformed entry in a Block List export."""

    path: str
    text: str
    reason: str


@dataclass(frozen=True)
class BlockListImportPreview:
    rules: tuple[Rule, ...]
    duplicates: int
    issues: tuple[BlockListIssue, ...]

    @property
    def accepted_websites(self) -> int:
        return sum(
            target.kind == "website"
            for rule in self.rules
            for target in rule.targets
        )

    @property
    def accepted_blocks(self) -> int:
        return len(self.rules)


_COLD_TURKEY_FIELDS = {
    "type",
    "lock",
    "lockUnblock",
    "restartUnblock",
    "password",
    "randomTextLength",
    "break",
    "window",
    "users",
    "web",
    "exceptions",
    "apps",
    "schedule",
    "customUsers",
    "blockList",
}


def _bounded_utf8(text: Any, label: str, maximum_bytes: int) -> str:
    if not isinstance(text, str):
        raise TransferError(f"{label} must be UTF-8 text")
    if len(text.encode("utf-8")) > maximum_bytes:
        maximum_mib = maximum_bytes // (1024 * 1024)
        raise TransferError(f"{label} is larger than {maximum_mib} MiB")
    return text


def parse_domain_text(text: str, *, max_entries: int = MAX_IMPORT_ENTRIES) -> ImportPreview:
    """Parse plain domains, comments, and common hosts-file rows."""
    content = _bounded_utf8(text, "domain file", MAX_DOMAIN_IMPORT_BYTES)
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
        raise TransferError("domain entry limit is invalid")
    domains: list[str] = []
    seen: set[str] = set()
    issues: list[ImportIssue] = []
    duplicates = 0
    ignored = 0

    for line_number, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            ignored += 1
            continue
        fields = stripped.split()
        if fields[0] in _HOSTS_SINKS:
            candidates = []
            for field in fields[1:]:
                if field.startswith("#"):
                    break
                candidates.append(field)
            if not candidates:
                issues.append(ImportIssue(line_number, raw_line, "hosts row has no domain"))
                continue
        elif len(fields) == 1:
            candidates = fields
        else:
            issues.append(ImportIssue(line_number, raw_line, "use one domain on each line"))
            continue

        for candidate in candidates:
            try:
                domain = Target.from_dict({"kind": "website", "value": candidate}).value
            except ValidationError as error:
                issues.append(ImportIssue(line_number, candidate, error.message))
                continue
            if domain in seen:
                duplicates += 1
                continue
            if len(domains) >= max_entries:
                raise TransferError("domain file has too many entries")
            seen.add(domain)
            domains.append(domain)

    return ImportPreview(tuple(domains), duplicates, ignored, tuple(issues))


def _block_list_issue(
    issues: list[BlockListIssue], path: str, value: Any, reason: str
) -> None:
    issues.append(BlockListIssue(path, str(value), reason))


def _block_list_endpoint(
    value: Any,
    path: str,
    issues: list[BlockListIssue],
    *,
    maximum_day: int,
) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        _block_list_issue(issues, path, value, "schedule endpoint must be text")
        return None
    fields = value.split(",")
    if len(fields) != 3:
        _block_list_issue(
            issues, path, value, "schedule endpoint must be day,hour,minute"
        )
        return None
    try:
        day, hour, minute = (int(field) for field in fields)
    except ValueError:
        _block_list_issue(
            issues, path, value, "schedule endpoint must be day,hour,minute"
        )
        return None
    if not 0 <= day <= maximum_day or not 0 <= hour <= 23 or not 0 <= minute <= 59:
        _block_list_issue(issues, path, value, "schedule endpoint is out of range")
        return None
    return day, hour, minute

def _block_list_schedule(
    settings: Mapping[str, Any],
    path: str,
    timezone_name: str,
    issues: list[BlockListIssue],
) -> Schedule | None:
    schedule_type = settings.get("type")
    if schedule_type == "continuous":
        return Schedule.from_dict({"kind": "indefinite"})
    if schedule_type != "scheduled":
        _block_list_issue(
            issues, f"{path}.type", schedule_type, "block type is not supported"
        )
        return None
    raw_schedule = settings.get("schedule")
    if not isinstance(raw_schedule, list) or not raw_schedule:
        _block_list_issue(
            issues, f"{path}.schedule", raw_schedule, "scheduled block has no periods"
        )
        return None
    periods: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for index, raw_period in enumerate(raw_schedule):
        period_path = f"{path}.schedule[{index}]"
        if not isinstance(raw_period, Mapping):
            _block_list_issue(
                issues, period_path, raw_period, "schedule period must be an object"
            )
            continue
        start = _block_list_endpoint(
            raw_period.get("startTime"),
            f"{period_path}.startTime",
            issues,
            maximum_day=6,
        )
        end = _block_list_endpoint(
            raw_period.get("endTime"),
            f"{period_path}.endTime",
            issues,
            maximum_day=7,
        )
        if start is None or end is None:
            continue
        start_day, start_hour, start_minute = start
        end_day, end_hour, end_minute = end
        day_delta = end_day - start_day
        start_text = f"{start_hour:02d}:{start_minute:02d}"
        end_text = f"{end_hour:02d}:{end_minute:02d}"
        start_minutes = start_hour * 60 + start_minute
        end_minutes = end_hour * 60 + end_minute
        if day_delta not in (0, 1) or (
            day_delta == 0 and end_minutes <= start_minutes
        ) or (day_delta == 1 and end_minutes > start_minutes):
            _block_list_issue(
                issues,
                period_path,
                raw_period,
                "schedule period spans more than one supported local day",
            )
            continue
        weekday = (start_day - 1) % 7
        key = (weekday, start_text, end_text)
        if key in seen:
            continue
        seen.add(key)
        if raw_period.get("break", "none") not in (None, "", "none"):
            _block_list_issue(
                issues,
                f"{period_path}.break",
                raw_period.get("break"),
                "scheduled breaks are not supported",
            )
        periods.append({
            "weekdays": [weekday],
            "start": start_text,
            "end": end_text,
        })
    if not periods:
        return None
    try:
        return Schedule.from_dict({
            "kind": "weekly",
            "timezone": timezone_name,
            "periods": periods,
        })
    except ValidationError as error:
        _block_list_issue(issues, f"{path}.schedule", raw_schedule, error.message)
        return None


def parse_block_list_export(
    text: str,
    *,
    timezone_name: str = "UTC",
    enabled: bool = False,
) -> BlockListImportPreview:
    """Parse a Block List ``.blocklist.json`` mapping without repairing its JSON.

    Block List exports a mapping of block names to settings. Only exact
    hostnames and representable weekly schedules are imported; every other
    entry is retained in ``issues`` for the confirmation UI.
    """
    content = _bounded_utf8(text, "Block List export", MAX_NATIVE_IMPORT_BYTES)
    try:
        value = json.loads(content)
    except json.JSONDecodeError as error:
        raise TransferError(
            "Block List export is not valid JSON at "
            f"line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(value, Mapping):
        raise TransferError("Block List export must be a JSON object")
    blocks: Mapping[str, Any] = value
    if set(value) == {"blocks"} and isinstance(value["blocks"], Mapping):
        blocks = value["blocks"]
    if not blocks:
        raise TransferError("Block List export contains no blocks")
    if len(blocks) > MAX_IMPORT_ENTRIES:
        raise TransferError("Block List export contains too many blocks")
    if not isinstance(timezone_name, str) or not timezone_name.strip():
        raise TransferError("Block List import time zone is invalid")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise TransferError("Block List import time zone is invalid") from error
    issues: list[BlockListIssue] = []
    rules: list[Rule] = []
    duplicates = 0
    for name, raw_settings in blocks.items():
        path = f"blocks[{name!r}]"
        if not isinstance(name, str) or not name.strip():
            _block_list_issue(issues, path, name, "block name must be non-empty text")
            continue
        if not isinstance(raw_settings, Mapping):
            _block_list_issue(
                issues, path, raw_settings, "block settings must be an object"
            )
            continue
        settings = dict(raw_settings)
        for field in set(settings) - _COLD_TURKEY_FIELDS:
            _block_list_issue(
                issues, f"{path}.{field}", settings[field], "setting is not supported"
            )
        raw_web = settings.get("web", settings.get("blockList"))
        if not isinstance(raw_web, list):
            _block_list_issue(
                issues, f"{path}.web", raw_web, "block website list must be a list"
            )
            raw_web = []
        targets: list[Target] = []
        seen: set[str] = set()
        for index, raw_target in enumerate(raw_web):
            target_path = f"{path}.web[{index}]"
            if not isinstance(raw_target, str):
                _block_list_issue(
                    issues, target_path, raw_target, "website entry must be text"
                )
                continue
            candidate = raw_target.strip()
            if "*" in candidate:
                reason = "wildcard URL rules are not supported"
            elif "://" in candidate or "/" in candidate:
                reason = "URL-path rules are not supported"
            else:
                reason = ""
            if reason:
                _block_list_issue(issues, target_path, candidate, reason)
                continue
            try:
                domain = Target.from_dict({
                    "kind": "website",
                    "value": candidate,
                }).value
            except ValidationError as error:
                _block_list_issue(issues, target_path, candidate, error.message)
                continue
            if domain in seen:
                duplicates += 1
                continue
            seen.add(domain)
            targets.append(Target("website", domain))
        for field, reason in (
            ("exceptions", "website exceptions are not supported"),
            ("apps", "Block List application entries are not supported"),
        ):
            raw_entries = settings.get(field, [])
            if not isinstance(raw_entries, list):
                _block_list_issue(
                    issues, f"{path}.{field}", raw_entries, f"{field} must be a list"
                )
                continue
            for index, entry in enumerate(raw_entries):
                _block_list_issue(
                    issues, f"{path}.{field}[{index}]", entry, reason
                )
        if settings.get("lock", "none") not in (None, "", "none"):
            _block_list_issue(
                issues, f"{path}.lock", settings["lock"], "block locks are not supported"
            )
        if settings.get("break", "none") not in (None, "", "none"):
            _block_list_issue(
                issues, f"{path}.break", settings["break"], "breaks are not supported"
            )
        if settings.get("users") not in (None, "") or settings.get("customUsers"):
            _block_list_issue(
                issues, f"{path}.users", settings.get("users"), "user targeting is not supported"
            )
        schedule = _block_list_schedule(
            settings, path, timezone_name, issues
        )
        if not targets or schedule is None:
            if not targets:
                _block_list_issue(
                    issues, path, name, "block has no supported exact hostnames"
                )
            continue
        try:
            rules.append(Rule.from_dict({
                "id": str(uuid4()),
                "name": name.strip(),
                "enabled": enabled,
                "targets": [target.to_dict() for target in targets],
                "schedule": schedule.to_dict(),
                "revision": 0,
            }))
        except ValidationError as error:
            _block_list_issue(issues, path, name, error.message)
    return BlockListImportPreview(tuple(rules), duplicates, tuple(issues))


def block_list_preview_text(preview: BlockListImportPreview) -> str:
    lines = [
        f"Imported blocks: {preview.accepted_blocks}",
        f"Exact hostnames: {preview.accepted_websites}",
        f"Duplicates: {preview.duplicates}",
        f"Unsupported or invalid entries: {len(preview.issues)}",
    ]
    if preview.issues:
        lines.extend(
            f"- {issue.path}: {issue.reason} ({issue.text})"
            for issue in preview.issues[:32]
        )
        if len(preview.issues) > 32:
            lines.append(f"- … and {len(preview.issues) - 32} more")
    return "\n".join(lines)


def _read_utf8_text(
    path: str | os.PathLike[str],
    *,
    maximum_bytes: int,
    label: str,
) -> str:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise TransferError(f"{label} path must be a regular file")
    try:
        with source.open("rb") as stream:
            data = stream.read(maximum_bytes + 1)
    except OSError as error:
        raise TransferError(f"cannot read {label}") from error
    if len(data) > maximum_bytes:
        maximum_mib = maximum_bytes // (1024 * 1024)
        raise TransferError(f"{label} is larger than {maximum_mib} MiB")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransferError(f"{label} must use UTF-8") from error


def read_import_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_DOMAIN_IMPORT_BYTES, label="import file"
    )


def read_native_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_NATIVE_IMPORT_BYTES, label="native export"
    )



def read_block_list_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_NATIVE_IMPORT_BYTES, label="Block List export"
    )

def domain_export_text(rules: Iterable[Rule], managed_lists: Iterable[ManagedList] = ()) -> str:
    lists = {item.id: item for item in managed_lists}
    domains: set[str] = set()
    for rule in rules:
        for target in rule.targets:
            if target.kind == "website":
                domains.add(target.value)
            elif target.kind == "managed_list":
                item = lists.get(target.value)
                if item is None:
                    raise TransferError("rule refers to an unknown managed list")
                domains.update(item.domains)
    lines = ["# Distraction Blocker domain export", *sorted(domains)]
    return "\n".join(lines) + "\n"


def native_export_text(
    policy: Policy, exported_utc: datetime | None = None
) -> str:
    if not isinstance(policy, Policy):
        raise TransferError("native export policy is invalid")
    exported = exported_utc or datetime.now(timezone.utc)
    if exported.tzinfo is None or exported.utcoffset() != timedelta(0):
        raise TransferError("export time must be aware UTC")
    payload = {
        "format": NATIVE_FORMAT,
        "version": NATIVE_VERSION,
        "exported_utc": exported.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "revision": policy.revision,
        "rules": [rule.to_dict() for rule in policy.rules],
        "managed_lists": [item.to_dict() for item in policy.managed_lists],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def statistics_export_text(
    application: Mapping[str, Any],
    website: Mapping[str, Any],
    exported_utc: datetime | None = None,
) -> str:
    """Serialize the public application and website statistics snapshot."""
    if not isinstance(application, Mapping) or not isinstance(website, Mapping):
        raise TransferError("statistics export data is invalid")
    exported = exported_utc or datetime.now(timezone.utc)
    if exported.tzinfo is None or exported.utcoffset() != timedelta(0):
        raise TransferError("export time must be aware UTC")
    payload = {
        "format": NATIVE_FORMAT,
        "version": 1,
        "kind": "statistics",
        "exported_utc": exported.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "application": dict(application),
        "website": dict(website),
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    ) + "\n"


def parse_native_export(text: str) -> Policy:
    content = _bounded_utf8(text, "native export", MAX_NATIVE_IMPORT_BYTES)
    try:
        value = json.loads(content)
    except json.JSONDecodeError as error:
        raise TransferError(f"native export is not valid JSON at line {error.lineno}, column {error.colno}") from error
    if not isinstance(value, Mapping):
        raise TransferError("native export fields are invalid")
    if value.get("format") != NATIVE_FORMAT:
        raise TransferError("native export format is not supported")
    version = value.get("version")
    if type(version) is not int or version not in {1, 2, 3, 4, NATIVE_VERSION}:
        raise TransferError("native export version is not supported")
    raw_rules = value.get("rules")
    if not isinstance(raw_rules, list):
        raise TransferError("native rules must be a list")
    if version < NATIVE_VERSION:
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, Mapping) or not isinstance(raw_rule.get("targets"), list):
                raise TransferError("native rule targets are invalid")
            for target in raw_rule["targets"]:
                if not isinstance(target, Mapping) or target.get("kind") != "network":
                    continue
                if version < 3 or target.get("value") in {"doh", "proxy", "vpn"}:
                    raise TransferError(
                        "network targets require native format v5"
                        if target.get("value") in {"proxy", "vpn"}
                        else (
                            "DoH network targets require native format v4"
                            if target.get("value") == "doh"
                            else "network targets require native format v3"
                        )
                    )
    expected = {"format", "version", "exported_utc", "rules"} if version == 1 else {"format", "version", "exported_utc", "revision", "rules", "managed_lists"}
    if set(value) != expected:
        raise TransferError("native export fields are invalid")
    exported = value["exported_utc"]
    if not isinstance(exported, str):
        raise TransferError("native export time is invalid")
    try:
        parsed = datetime.fromisoformat(exported.replace("Z", "+00:00"))
    except ValueError as error:
        raise TransferError("native export time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise TransferError("native export time must be UTC")
    policy_data = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "revision": 0 if version == 1 else value["revision"],
        "rules": value["rules"],
        "managed_lists": [] if version == 1 else value["managed_lists"],
    }
    if version == 1:
        # Breadcrumb for reviewers: old native files are converted before strict v2 model parsing.
        converted_rules = []
        for raw_rule in policy_data["rules"]:
            if not isinstance(raw_rule, Mapping):
                raise TransferError("native rule is invalid")
            rule = dict(raw_rule)
            schedule = rule.get("schedule")
            if isinstance(schedule, Mapping) and schedule.get("kind") == "weekly" and "periods" not in schedule:
                if set(schedule) != {"kind", "timezone", "weekdays", "start", "end"}:
                    raise TransferError("old weekly schedule is invalid")
                rule["schedule"] = {"kind": "weekly", "timezone": schedule["timezone"], "periods": [{"weekdays": schedule["weekdays"], "start": schedule["start"], "end": schedule["end"]}]}
            converted_rules.append(rule)
        policy_data["rules"] = converted_rules
    try:
        return Policy.from_dict(policy_data)
    except ValidationError as error:
        raise TransferError(error.message) from error


def atomic_write_text(path: str | os.PathLike[str], text: str, mode: int = 0o600) -> None:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        metadata = os.lstat(destination)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TransferError("export path must be a regular file")
    parent = destination.parent
    if not parent.is_dir():
        raise TransferError("export directory does not exist")
    data = text.encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".distraction-blocker-", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
