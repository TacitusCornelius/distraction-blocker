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

from .model import ManagedList, Policy, Rule, Target, ValidationError

NATIVE_FORMAT = "distraction-blocker"
NATIVE_VERSION = 2
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
    if isinstance(version, bool) or version not in {1, NATIVE_VERSION}:
        raise TransferError("native export version is not supported")
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
    policy_data = {"revision": 0 if version == 1 else value["revision"], "rules": value["rules"], "managed_lists": [] if version == 1 else value["managed_lists"]}
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
