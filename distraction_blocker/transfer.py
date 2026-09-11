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
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from uuid import uuid4

from .control import ControlError, RuleLock
from .model import POLICY_SCHEMA_VERSION, ManagedList, Policy, Rule, Schedule, Target, ValidationError

NATIVE_FORMAT = "distraction-blocker"
# Version 6 adds elapsed-time allowance policy fields; earlier portable
# files are migrated on import when their targets remain supported.
NATIVE_VERSION = 6
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



TARGET_LIST_FORMAT = "distraction-blocker-target-list"
TARGET_LIST_VERSION = 1
TARGET_LIST_SCOPES = frozenset({"targets", "exceptions", "applications"})


@dataclass(frozen=True)
class TargetListPreview:
    """Validated typed target-list contents and managed-list snapshots."""

    scope: str
    targets: tuple[Target, ...]
    managed_lists: tuple[ManagedList, ...] = ()

@dataclass(frozen=True)
class BlockListIssue:
    """One reported Block List setting and its stable category."""

    path: str
    text: str
    reason: str
    category: str = "target"


@dataclass(frozen=True)
class BlockListMappingPreview:
    """Validated application mappings plus issues needing user correction."""

    mappings: tuple[tuple[str, str], ...]
    issues: tuple[BlockListIssue, ...] = ()

    @property
    def mapping_dict(self) -> dict[str, str]:
        return dict(self.mappings)

@dataclass(frozen=True)
class BlockListReviewPreview:
    """Validated explicit lock/break mappings for named imported blocks."""

    reviews: tuple[tuple[str, dict[str, Any]], ...]
    issues: tuple[BlockListIssue, ...] = ()

    @property
    def review_dict(self) -> dict[str, dict[str, Any]]:
        return {name: dict(value) for name, value in self.reviews}


@dataclass(frozen=True)
class BlockListImportPreview:
    rules: tuple[Rule, ...]
    duplicates: int
    issues: tuple[BlockListIssue, ...]
    lock_reviews: tuple[dict[str, Any], ...] = ()

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

    @property
    def accepted(self) -> int:
        return self.accepted_blocks

    @property
    def transformed(self) -> int:
        return sum(
            target.kind != "website"
            for rule in self.rules
            for target in (*rule.targets, *rule.exceptions)
        )

    @property
    def unsupported(self) -> int:
        return len(self.issues)

    def with_issues(
        self, issues: Iterable[BlockListIssue]
    ) -> "BlockListImportPreview":
        return BlockListImportPreview(
            self.rules,
            self.duplicates,
            (*self.issues, *tuple(issues)),
            self.lock_reviews,
        )


_COLD_TURKEY_ISSUE_CATEGORIES = frozenset({
    "format",
    "target",
    "schedule",
    "lock",
    "break",
    "application",
    "user_scope",
    "policy_capability",
})


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
    issues: list[BlockListIssue],
    path: str,
    value: Any,
    reason: str,
    *,
    category: str = "target",
) -> None:
    if category not in _COLD_TURKEY_ISSUE_CATEGORIES:
        raise ValueError(f"unknown Block List issue category: {category}")
    issues.append(BlockListIssue(path, str(value), reason, category))


_YOUTUBE_HOSTS = frozenset({
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com",
    "youtu.be",
})


def _youtube_target(parsed: Any) -> Target | None:
    host = parsed.hostname.lower() if parsed.hostname else ""
    if host not in _YOUTUBE_HOSTS:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    segments = [item for item in parsed.path.split("/") if item]
    if host == "youtu.be":
        if len(segments) == 1 and not parsed.query:
            try:
                return Target.from_dict({
                    "kind": "youtube_video",
                    "value": segments[0],
                })
            except ValidationError:
                return None
        return None
    if parsed.path.rstrip("/") == "/watch":
        query = parse_qs(parsed.query, keep_blank_values=True)
        values = query.get("v")
        if set(query) == {"v"} and values is not None and len(values) == 1:
            try:
                return Target.from_dict({
                    "kind": "youtube_video",
                    "value": values[0],
                })
            except ValidationError:
                return None
        return None
    if parsed.query:
        return None
    if segments and segments[0].startswith("@"):
        if len(segments) > 2 or (
            len(segments) == 2 and segments[1] != "videos"
        ):
            return None
        try:
            return Target.from_dict({
                "kind": "youtube_channel",
                "value": segments[0],
            })
        except ValidationError:
            return None
    if len(segments) == 2 and segments[0] == "channel":
        try:
            return Target.from_dict({
                "kind": "youtube_channel",
                "value": segments[1],
            })
        except ValidationError:
            return None
    if len(segments) == 2 and segments[0] in {"shorts", "embed", "live"}:
        try:
            return Target.from_dict({
                "kind": "youtube_video",
                "value": segments[1],
            })
        except ValidationError:
            return None
    return None


def _block_list_target(
    value: Any,
    path: str,
    issues: list[BlockListIssue],
    *,
    network_available: bool,
    exception: bool = False,
) -> Target | None:
    if isinstance(value, Mapping):
        if set(value) != {"kind", "value"}:
            _block_list_issue(
                issues, path, value, "target object fields are invalid",
                category="format",
            )
            return None
        kind = value.get("kind")
        raw_value = value.get("value")
        if kind == "network" and raw_value == "whole_internet":
            if exception:
                _block_list_issue(
                    issues, path, value,
                    "exceptions require URL-level targets",
                    category="target",
                )
                return None
            if not network_available:
                _block_list_issue(
                    issues, path, value,
                    "whole-internet import requires enabled network controls",
                    category="policy_capability",
                )
                return None
            return Target.from_dict({"kind": "network", "value": raw_value})
        _block_list_issue(
            issues, path, value,
            "structured target form is not supported",
            category="target",
        )
        return None
    if not isinstance(value, str):
        _block_list_issue(
            issues, path, value, "target entry must be text",
            category="target",
        )
        return None
    candidate = value.strip()
    if not candidate:
        _block_list_issue(
            issues, path, value, "target entry must not be empty",
            category="target",
        )
        return None
    if candidate == "whole_internet":
        if exception:
            _block_list_issue(
                issues, path, candidate,
                "exceptions require URL-level targets",
                category="target",
            )
            return None
        if not network_available:
            _block_list_issue(
                issues, path, candidate,
                "whole-internet import requires enabled network controls",
                category="policy_capability",
            )
            return None
        return Target.from_dict({"kind": "network", "value": candidate})
    if candidate.startswith("keyword:"):
        try:
            return Target.from_dict({
                "kind": "url_keyword",
                "value": candidate[8:],
            })
        except ValidationError as error:
            _block_list_issue(
                issues, path, candidate, error.message, category="target"
            )
            return None
    has_scheme = "://" in candidate
    parse_value = candidate if has_scheme else f"https://{candidate}"
    try:
        parsed = urlsplit(parse_value)
    except ValueError:
        parsed = None
    if parsed is None or not parsed.hostname:
        _block_list_issue(
            issues, path, candidate, "target URL is invalid", category="target"
        )
        return None
    if has_scheme and parsed.scheme not in {"http", "https"}:
        _block_list_issue(
            issues, path, candidate,
            "only HTTP and HTTPS URL targets are supported",
            category="target",
        )
        return None
    try:
        port = parsed.port
    except ValueError:
        _block_list_issue(
            issues, path, candidate, "target URL port is invalid",
            category="target",
        )
        return None
    if port is not None:
        _block_list_issue(
            issues, path, candidate,
            "URL ports are not supported by the target model",
            category="target",
        )
        return None
    youtube = _youtube_target(parsed)
    if youtube is not None:
        if exception and youtube.kind not in Target.URL_LIKE_KINDS:
            _block_list_issue(
                issues, path, candidate,
                "exceptions require URL-level targets", category="target"
            )
            return None
        return youtube
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        _block_list_issue(
            issues, path, candidate,
            "URL query, fragment, or credentials are not supported",
            category="target",
        )
        return None
    raw_path = parsed.path
    if "*" in candidate:
        if not candidate.endswith("*") or candidate.count("*") != 1 or "/" not in raw_path:
            _block_list_issue(
                issues, path, candidate,
                "wildcard URL rules are not supported", category="target"
            )
            return None
        target_kind = "url_wildcard"
    elif raw_path not in ("", "/"):
        target_kind = "url_path"
    else:
        target_kind = "website"
    if exception and target_kind == "website":
        _block_list_issue(
            issues, path, candidate,
            "website exceptions are not supported", category="target"
        )
        return None
    normalized = parsed.hostname + (raw_path if target_kind != "website" else "")
    try:
        target = Target.from_dict({
            "kind": target_kind,
            "value": normalized,
        })
    except ValidationError as error:
        _block_list_issue(
            issues, path, candidate, error.message, category="target"
        )
        return None
    if exception and target.kind not in Target.URL_LIKE_KINDS:
        _block_list_issue(
            issues, path, candidate,
            "exceptions require URL-level targets", category="target"
        )
        return None
    return target


def _block_list_endpoint(
    value: Any,
    path: str,
    issues: list[BlockListIssue],
    *,
    maximum_day: int,
) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        _block_list_issue(
            issues, path, value, "schedule endpoint must be text",
            category="schedule",
        )
        return None
    fields = value.split(",")
    if len(fields) != 3:
        _block_list_issue(
            issues, path, value, "schedule endpoint must be day,hour,minute",
            category="schedule",
        )
        return None
    try:
        day, hour, minute = (int(field) for field in fields)
    except ValueError:
        _block_list_issue(
            issues, path, value, "schedule endpoint must be day,hour,minute",
            category="schedule",
        )
        return None
    if not 0 <= day <= maximum_day or not 0 <= hour <= 23 or not 0 <= minute <= 59:
        _block_list_issue(
            issues, path, value, "schedule endpoint is out of range",
            category="schedule",
        )
        return None
    return day, hour, minute


def _block_list_schedule(
    settings: Mapping[str, Any],
    path: str,
    timezone_name: str,
    issues: list[BlockListIssue],
    *,
    duplicate_counter: list[int] | None = None,
) -> Schedule | None:
    schedule_type = settings.get("type")
    if schedule_type == "continuous":
        raw_schedule = settings.get("schedule")
        if raw_schedule not in (None, "", [], {}):
            _block_list_issue(
                issues, f"{path}.schedule", raw_schedule,
                "continuous blocks must not contain scheduled periods",
                category="schedule",
            )
        return Schedule.from_dict({"kind": "indefinite"})
    if schedule_type != "scheduled":
        _block_list_issue(
            issues, f"{path}.type", schedule_type,
            "block type is not supported", category="schedule"
        )
        return None
    raw_schedule = settings.get("schedule")
    if not isinstance(raw_schedule, list) or not raw_schedule:
        _block_list_issue(
            issues, f"{path}.schedule", raw_schedule,
            "scheduled block has no periods", category="schedule"
        )
        return None
    periods: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for index, raw_period in enumerate(raw_schedule):
        period_path = f"{path}.schedule[{index}]"
        if not isinstance(raw_period, Mapping):
            _block_list_issue(
                issues, period_path, raw_period,
                "schedule period must be an object", category="schedule"
            )
            continue
        for field in sorted(
            set(raw_period) - {"startTime", "endTime", "break"}
        ):
            _block_list_issue(
                issues, f"{period_path}.{field}", raw_period[field],
                "schedule period field is not supported",
                category="schedule",
            )
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
                category="schedule",
            )
            continue
        weekday = (start_day - 1) % 7
        key = (weekday, start_text, end_text)
        if key in seen:
            if duplicate_counter is not None:
                duplicate_counter[0] += 1
            continue
        seen.add(key)
        if raw_period.get("break", "none") not in (None, "", "none"):
            _block_list_issue(
                issues,
                f"{period_path}.break",
                raw_period.get("break"),
                "scheduled breaks are not supported",
                category="break",
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
        _block_list_issue(
            issues, f"{path}.schedule", raw_schedule, error.message,
            category="schedule",
        )
        return None


class _BlockListJsonObject(dict):
    def __init__(self, pairs: list[tuple[Any, Any]]) -> None:
        duplicates: list[tuple[Any, Any, Any]] = []
        values: dict[Any, Any] = {}
        for key, value in pairs:
            if key in values:
                duplicates.append((key, values[key], value))
            values[key] = value
        super().__init__(values)
        self.duplicate_pairs = tuple(duplicates)

def _block_list_report_duplicates(
    value: Any,
    path: str,
    issues: list[BlockListIssue],
) -> None:
    if isinstance(value, _BlockListJsonObject):
        for key, _old, new in value.duplicate_pairs:
            duplicate_path = f"{path}.{key}" if path else str(key)
            _block_list_issue(
                issues,
                duplicate_path,
                new,
                "duplicate JSON setting; the later value was retained",
                category="format",
            )
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            _block_list_report_duplicates(child, child_path, issues)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _block_list_report_duplicates(child, f"{path}[{index}]", issues)


def parse_block_list_mapping(text: str) -> BlockListMappingPreview:
    """Parse an explicit JSON application-id to Linux-path mapping file."""
    content = _bounded_utf8(
        text, "Block List mapping", MAX_NATIVE_IMPORT_BYTES
    )
    duplicate_pairs: list[tuple[str, tuple[Any, Any, Any]]] = []
    try:
        value = json.loads(content, object_pairs_hook=_BlockListJsonObject)
    except json.JSONDecodeError as error:
        raise TransferError(
            "Block List mapping is not valid JSON at "
            f"line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(value, Mapping):
        raise TransferError("Block List mapping must be a JSON object")
    issues: list[BlockListIssue] = []
    if isinstance(value, _BlockListJsonObject):
        for key, _old, new in value.duplicate_pairs:
            if key == "applications":
                _block_list_issue(
                    issues,
                    f"mapping[{key!r}]",
                    new,
                    "application mapping wrapper is duplicated; "
                    "the later value was retained",
                    category="application",
                )
    source: Mapping[str, Any] = value
    if "applications" in value:
        source = value["applications"]
        if not isinstance(source, Mapping):
            _block_list_issue(
                issues,
                "applications",
                source,
                "application mappings must be an object",
                category="format",
            )
            return BlockListMappingPreview((), tuple(issues))
        extras = sorted(set(value) - {"applications"})
        for key in extras:
            duplicate_pairs.append((f"mapping[{key!r}]", (key, value[key], None)))
    mappings: list[tuple[str, str]] = []
    invalid: set[str] = set()
    if isinstance(source, _BlockListJsonObject):
        for key, old, new in source.duplicate_pairs:
            path = f"applications[{key!r}]"
            category = "application"
            reason = (
                "application mapping is duplicated"
                if old == new
                else "application mapping conflicts with another value"
            )
            _block_list_issue(
                issues, path, new, reason, category=category
            )
            invalid.add(str(key))
    for key, raw_path in source.items():
        path = f"applications[{key!r}]"
        if not isinstance(key, str) or not key.strip():
            _block_list_issue(
                issues, path, raw_path,
                "application identifier must be non-empty text",
                category="application",
            )
            continue
        if key in invalid:
            continue
        if not isinstance(raw_path, str) or not os.path.isabs(raw_path):
            _block_list_issue(
                issues, path, raw_path,
                "mapped application path must be absolute",
                category="application",
            )
            continue
        try:
            normalized = Target.from_dict({
                "kind": "application", "value": raw_path,
            }).value
        except ValidationError as error:
            _block_list_issue(
                issues, path, raw_path, error.message, category="application"
            )
            continue
        mappings.append((key, normalized))
    for path, (key, value, _unused) in duplicate_pairs:
        _block_list_issue(
            issues, path, value,
            "mapping file contains an unsupported top-level setting",
            category="format",
        )
    return BlockListMappingPreview(tuple(mappings), tuple(issues))


def _block_list_review_lock(
    value: Any,
    path: str,
    issues: list[BlockListIssue],
    *,
    category: str,
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        _block_list_issue(
            issues, path, value, "review lock must be an object",
            category=category,
        )
        return None
    kind = value.get("kind")
    if "rule_id" in value:
        _block_list_issue(
            issues, path, value,
            "review locks must not specify a rule id",
            category=category,
        )
        return None
    if kind == "password":
        _block_list_issue(
            issues, path, value,
            "password locks require a fresh local password",
            category=category,
        )
        return None
    candidate = {"rule_id": "12345678-1234-5678-1234-567812345678", **value}
    try:
        normalized = RuleLock.from_dict(candidate).to_dict()
    except (ControlError, TypeError, ValueError) as error:
        _block_list_issue(
            issues, path, value, str(error), category=category
        )
        return None
    normalized.pop("rule_id", None)
    return normalized


def parse_block_list_review(text: str) -> BlockListReviewPreview:
    """Parse explicit lock/break mappings for named Block List blocks."""
    content = _bounded_utf8(
        text, "Block List review", MAX_NATIVE_IMPORT_BYTES
    )
    try:
        value = json.loads(content, object_pairs_hook=_BlockListJsonObject)
    except json.JSONDecodeError as error:
        raise TransferError(
            "Block List review is not valid JSON at "
            f"line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(value, Mapping):
        raise TransferError("Block List review must be a JSON object")
    blocks: Mapping[str, Any] = value
    if set(value) == {"blocks"} and isinstance(value["blocks"], Mapping):
        blocks = value["blocks"]
    issues: list[BlockListIssue] = []
    _block_list_report_duplicates(value, "reviews", issues)
    reviews: list[tuple[str, dict[str, Any]]] = []
    for name, raw_review in blocks.items():
        path = f"reviews[{name!r}]"
        if not isinstance(name, str) or not name.strip():
            _block_list_issue(
                issues, path, name, "block name must be non-empty text",
                category="format",
            )
            continue
        if not isinstance(raw_review, Mapping):
            _block_list_issue(
                issues, path, raw_review, "review must be an object",
                category="format",
            )
            continue
        unknown = sorted(set(raw_review) - {"lock", "break"})
        for field in unknown:
            _block_list_issue(
                issues, f"{path}.{field}", raw_review[field],
                "review setting is not supported", category="format"
            )
        if "lock" in raw_review and "break" in raw_review:
            _block_list_issue(
                issues, path, raw_review,
                "a review cannot map both lock and break settings",
                category="lock",
            )
            continue
        field = "lock" if "lock" in raw_review else "break"
        if field not in raw_review:
            _block_list_issue(
                issues, path, raw_review,
                "review must contain lock or break", category="format"
            )
            continue
        mapped = _block_list_review_lock(
            raw_review[field], f"{path}.{field}", issues,
            category="break" if field == "break" else "lock",
        )
        if mapped is not None:
            if field == "break" and mapped.get("kind") != "delay":
                _block_list_issue(
                    issues, f"{path}.{field}", raw_review[field],
                    "break reviews require an equivalent delay lock",
                    category="break",
                )
                continue
            reviews.append((name, {field: mapped}))
    return BlockListReviewPreview(tuple(reviews), tuple(issues))


def parse_block_list_export(
    text: str,
    *,
    timezone_name: str = "UTC",
    enabled: bool = False,
    network_available: bool = False,
    application_mappings: Mapping[str, str] | None = None,
    review_mappings: Mapping[str, Mapping[str, Any]] | None = None,
) -> BlockListImportPreview:
    """Parse a Block List ``.blocklist.json`` mapping without repairing its JSON.

    Every source target is either represented exactly, reported with a
    categorized issue, or resolved by an explicit application mapping.
    """
    content = _bounded_utf8(text, "Block List export", MAX_NATIVE_IMPORT_BYTES)
    try:
        value = json.loads(content, object_pairs_hook=_BlockListJsonObject)
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
    if not isinstance(network_available, bool):
        raise TransferError("Block List network capability is invalid")
    if application_mappings is not None and not isinstance(
        application_mappings, Mapping
    ):
        raise TransferError("Block List application mappings are invalid")
    issues: list[BlockListIssue] = []
    _block_list_report_duplicates(value, "blocks", issues)
    rules: list[Rule] = []
    duplicates = [0]
    used_mappings: set[str] = set()
    mapping_values = dict(application_mappings or {})
    if review_mappings is not None and not isinstance(review_mappings, Mapping):
        raise TransferError("Block List review mappings are invalid")
    review_values = dict(review_mappings or {})
    lock_reviews: list[dict[str, Any]] = []
    used_reviews: set[str] = set()
    for name, raw_settings in blocks.items():
        path = f"blocks[{name!r}]"
        if not isinstance(name, str) or not name.strip():
            _block_list_issue(
                issues, path, name, "block name must be non-empty text",
                category="format",
            )
            continue
        if not isinstance(raw_settings, Mapping):
            _block_list_issue(
                issues, path, raw_settings, "block settings must be an object",
                category="format",
            )
            continue
        settings = dict(raw_settings)
        for field in sorted(set(settings) - _COLD_TURKEY_FIELDS):
            _block_list_issue(
                issues, f"{path}.{field}", settings[field],
                "setting is not supported", category="format"
            )
        if "web" in settings and "blockList" in settings and (
            settings["web"] != settings["blockList"]
        ):
            _block_list_issue(
                issues, f"{path}.blockList", settings["blockList"],
                "web and blockList settings conflict", category="format"
            )
        raw_web = settings.get("web", settings.get("blockList"))
        if not isinstance(raw_web, list):
            _block_list_issue(
                issues, f"{path}.web", raw_web,
                "block website list must be a list", category="target"
            )
            raw_web = []
        targets: list[Target] = []
        seen_targets: set[tuple[str, str]] = set()
        for index, raw_target in enumerate(raw_web):
            target = _block_list_target(
                raw_target, f"{path}.web[{index}]", issues,
                network_available=network_available,
            )
            if target is None:
                continue
            key = (target.kind, target.value)
            if key in seen_targets:
                duplicates[0] += 1
                continue
            seen_targets.add(key)
            targets.append(target)

        raw_exceptions = settings.get("exceptions", [])
        exception_targets: list[Target] = []
        exceptions_valid = True
        if not isinstance(raw_exceptions, list):
            _block_list_issue(
                issues, f"{path}.exceptions", raw_exceptions,
                "exceptions must be a list", category="target"
            )
            exceptions_valid = False
        else:
            for index, entry in enumerate(raw_exceptions):
                exception = _block_list_target(
                    entry, f"{path}.exceptions[{index}]", issues,
                    network_available=network_available, exception=True,
                )
                if exception is None:
                    exceptions_valid = False
                    continue
                exception_targets.append(exception)
            if not exceptions_valid:
                exception_targets = []
        raw_apps = settings.get("apps", [])
        if not isinstance(raw_apps, list):
            _block_list_issue(
                issues, f"{path}.apps", raw_apps,
                "apps must be a list", category="application"
            )
        else:
            seen_apps: set[str] = set()
            for index, entry in enumerate(raw_apps):
                app_path = f"{path}.apps[{index}]"
                if not isinstance(entry, str):
                    _block_list_issue(
                        issues, app_path, entry,
                        "application identifier must be text",
                        category="application",
                    )
                    continue
                if entry in seen_apps:
                    duplicates[0] += 1
                    continue
                seen_apps.add(entry)
                mapped_path = mapping_values.get(entry)
                if mapped_path is None:
                    _block_list_issue(
                        issues, app_path, entry,
                        "application mapping is required",
                        category="application",
                    )
                    continue
                used_mappings.add(entry)
                try:
                    target = Target.from_dict({
                        "kind": "application", "value": mapped_path,
                    })
                except ValidationError as error:
                    _block_list_issue(
                        issues, app_path, mapped_path, error.message,
                        category="application",
                    )
                    continue
                key = (target.kind, target.value)
                if key in seen_targets:
                    duplicates[0] += 1
                    continue
                seen_targets.add(key)
                targets.append(target)

        reviewed_lock: tuple[str, dict[str, Any]] | None = None
        review = review_values.get(name)
        if review is not None and not isinstance(review, Mapping):
            _block_list_issue(
                issues, f"reviews[{name!r}]", review,
                "review mapping must be an object", category="format"
            )
            review = None
        lock_value = settings.get("lock", "none")
        break_value = settings.get("break", "none")
        has_lock = lock_value not in (None, "", "none")
        has_break = break_value not in (None, "", "none")
        conflicting_settings = has_lock and has_break
        if conflicting_settings:
            _block_list_issue(
                issues, path, {"lock": lock_value, "break": break_value},
                "a block cannot define both lock and break settings",
                category="lock",
            )
            review = None
        for field, category, reason in (
            ("lock", "lock", "block locks require an explicit review mapping"),
            ("break", "break", "breaks require an explicit review mapping"),
        ):
            if conflicting_settings:
                continue
            raw_value = settings.get(field, "none")
            if raw_value in (None, "", "none"):
                continue
            candidate = review.get(field) if review is not None else None
            if candidate is None:
                _block_list_issue(
                    issues, f"{path}.{field}", raw_value, reason,
                    category=category,
                )
                continue
            mapped = _block_list_review_lock(
                candidate, f"reviews[{name!r}].{field}", issues,
                category=category,
            )
            if mapped is None or (
                field == "break" and mapped.get("kind") != "delay"
            ):
                if mapped is not None and field == "break":
                    _block_list_issue(
                        issues, f"reviews[{name!r}].break", candidate,
                        "break reviews require an equivalent delay lock",
                        category="break",
                    )
                continue
            used_reviews.add(name)
            reviewed_lock = (field, mapped)
        for field, category, reason in (
            ("lockUnblock", "lock", "lock unblock behavior is not supported"),
            ("restartUnblock", "lock", "restart unlock behavior is not supported"),
            ("password", "lock", "Block List passwords cannot be imported"),
            ("randomTextLength", "lock", "Block List friction settings cannot be imported"),
            ("window", "target", "window-title rules are not supported"),
        ):
            raw_value = settings.get(field)
            if raw_value not in (None, "", False, 0, [], {}):
                _block_list_issue(
                    issues, f"{path}.{field}", raw_value, reason,
                    category=category,
                )
        if settings.get("users") not in (None, "") or settings.get("customUsers"):
            _block_list_issue(
                issues, f"{path}.users", settings.get("users"),
                "user targeting is not supported", category="user_scope"
            )
        schedule = _block_list_schedule(
            settings, path, timezone_name, issues,
            duplicate_counter=duplicates,
        )
        if not targets or schedule is None:
            if not targets:
                _block_list_issue(
                    issues, path, name,
                    "block has no supported targets", category="target"
                )
            continue
        try:
            rule = Rule.from_dict({
                "id": str(uuid4()),
                "name": name.strip(),
                "enabled": enabled,
                "targets": [target.to_dict() for target in targets],
                "exceptions": [target.to_dict() for target in exception_targets],
                "schedule": schedule.to_dict(),
                "revision": 0,
            })
            rules.append(rule)
            if reviewed_lock is not None:
                field, mapped = reviewed_lock
                lock_reviews.append({
                    "rule_id": rule.id,
                    "source": field,
                    "lock": mapped,
                })
        except ValidationError as error:
            _block_list_issue(
                issues, path, name, error.message, category="format"
            )
    for name in sorted(set(review_values) - used_reviews):
        _block_list_issue(
            issues, f"reviews[{name!r}]", review_values[name],
            "review mapping does not match an imported lock or break",
            category="format",
        )
    for identifier in sorted(set(mapping_values) - used_mappings):
        _block_list_issue(
            issues, f"applications[{identifier!r}]", mapping_values[identifier],
            "application mapping does not match an exported application",
            category="application",
        )
    return BlockListImportPreview(
        tuple(rules),
        duplicates[0],
        tuple(issues),
        tuple(lock_reviews),
    )


def block_list_preview_text(preview: BlockListImportPreview) -> str:
    lines = [
        f"Accepted rules: {preview.accepted}",
        f"Transformed targets: {preview.transformed}",
        f"Exact hostnames: {preview.accepted_websites}",
        f"Duplicates: {preview.duplicates}",
        f"Unsupported or invalid entries: {preview.unsupported}",
    ]
    if preview.issues:
        lines.extend(
            f"- {issue.path}: [{issue.category}] {issue.reason} ({issue.text})"
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

def read_block_list_mapping_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_NATIVE_IMPORT_BYTES, label="Block List mapping"
    )

def read_block_list_review_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_NATIVE_IMPORT_BYTES, label="Block List review"
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

def target_list_export_text(
    scope: str,
    targets: Iterable[Target],
    managed_lists: Iterable[ManagedList] = (),
) -> str:
    """Serialize one editor pane without losing target kinds."""
    if not isinstance(scope, str) or scope not in TARGET_LIST_SCOPES:
        raise TransferError("target-list export scope is invalid")
    normalized_targets: list[Target] = []
    seen_targets: set[Target] = set()
    for item in targets:
        if not isinstance(item, Target):
            raise TransferError("target-list export targets are invalid")
        try:
            normalized = Target.from_dict(item.to_dict())
        except ValidationError as error:
            raise TransferError(error.message) from error
        if scope == "exceptions" and normalized.kind not in Target.URL_LIKE_KINDS:
            raise TransferError("target-list exceptions must be URL-level")
        if scope == "applications" and normalized.kind != "application":
            raise TransferError("application export contains a non-application")
        if scope == "targets" and normalized.kind == "application":
            raise TransferError("target export contains an application")
        if normalized in seen_targets:
            raise TransferError("target-list export contains duplicate targets")
        seen_targets.add(normalized)
        normalized_targets.append(normalized)
    normalized_lists: list[ManagedList] = []
    seen_lists: set[str] = set()
    for item in managed_lists:
        if not isinstance(item, ManagedList):
            raise TransferError("target-list managed-list snapshots are invalid")
        try:
            normalized = ManagedList.from_dict(item.to_dict())
        except ValidationError as error:
            raise TransferError(error.message) from error
        if normalized.id in seen_lists:
            raise TransferError("target-list export contains duplicate lists")
        seen_lists.add(normalized.id)
        normalized_lists.append(normalized)
    managed_target_ids = {
        item.value
        for item in normalized_targets
        if item.kind == "managed_list"
    }
    if managed_target_ids != seen_lists:
        raise TransferError(
            "target-list managed-list snapshots must match target references"
        )
    payload = {
        "format": TARGET_LIST_FORMAT,
        "version": TARGET_LIST_VERSION,
        "scope": scope,
        "items": [item.to_dict() for item in normalized_targets],
        "managed_lists": [item.to_dict() for item in normalized_lists],
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    ) + "\n"


def parse_target_list_text(
    text: str,
    *,
    expected_scope: str | None = None,
) -> TargetListPreview:
    """Parse a typed editor-pane export using the existing model schema."""
    content = _bounded_utf8(text, "target-list export", MAX_NATIVE_IMPORT_BYTES)
    try:
        value = json.loads(content)
    except json.JSONDecodeError as error:
        raise TransferError(
            "target-list export is not valid JSON at "
            f"line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(value, Mapping):
        raise TransferError("target-list export must be an object")
    if set(value) not in (
        {"format", "version", "scope", "items"},
        {"format", "version", "scope", "items", "managed_lists"},
    ):
        raise TransferError("target-list export fields are invalid")
    if value.get("format") != TARGET_LIST_FORMAT:
        raise TransferError("target-list export format is not supported")
    if value.get("version") != TARGET_LIST_VERSION:
        raise TransferError("target-list export version is not supported")
    scope = value.get("scope")
    if not isinstance(scope, str) or scope not in TARGET_LIST_SCOPES:
        raise TransferError("target-list export scope is invalid")
    if expected_scope is not None and scope != expected_scope:
        raise TransferError(f"target-list export must contain {expected_scope}")
    raw_items = value.get("items")
    if not isinstance(raw_items, list):
        raise TransferError("target-list export items must be a list")
    targets: list[Target] = []
    seen_targets: set[Target] = set()
    try:
        for raw_item in raw_items:
            target = Target.from_dict(raw_item)
            if scope == "exceptions" and target.kind not in Target.URL_LIKE_KINDS:
                raise TransferError("target-list exceptions must be URL-level")
            if scope == "applications" and target.kind != "application":
                raise TransferError("application export contains a non-application")
            if scope == "targets" and target.kind == "application":
                raise TransferError("target export contains an application")
            if target in seen_targets:
                raise TransferError("target-list export contains duplicate targets")
            seen_targets.add(target)
            targets.append(target)
    except ValidationError as error:
        raise TransferError(error.message) from error
    raw_lists = value.get("managed_lists", [])
    if not isinstance(raw_lists, list):
        raise TransferError("target-list managed lists must be a list")
    managed_lists: list[ManagedList] = []
    seen_lists: set[str] = set()
    try:
        for raw_list in raw_lists:
            managed = ManagedList.from_dict(raw_list)
            if managed.id in seen_lists:
                raise TransferError("target-list export contains duplicate lists")
            seen_lists.add(managed.id)
            managed_lists.append(managed)
    except ValidationError as error:
        raise TransferError(error.message) from error
    managed_target_ids = {
        target.value
        for target in targets
        if target.kind == "managed_list"
    }
    if managed_target_ids != seen_lists:
        raise TransferError(
            "target-list managed-list snapshots must match target references"
        )
    return TargetListPreview(scope, tuple(targets), tuple(managed_lists))


def read_target_list_text(path: str | os.PathLike[str]) -> str:
    return _read_utf8_text(
        path, maximum_bytes=MAX_NATIVE_IMPORT_BYTES, label="target-list export"
    )


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
    if type(version) is not int or version not in {1, 2, 3, 4, 5, NATIVE_VERSION}:
        raise TransferError("native export version is not supported")
    raw_rules = value.get("rules")
    if not isinstance(raw_rules, list):
        raise TransferError("native rules must be a list")
    if version < NATIVE_VERSION:
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, Mapping) or not isinstance(raw_rule.get("targets"), list):
                raise TransferError("native rule targets are invalid")
            if version < NATIVE_VERSION and "allowance_time" in raw_rule:
                raise TransferError(
                    "elapsed-time allowances require native format v6"
                )
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
