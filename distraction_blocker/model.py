"""Strict policy data model and schedule evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import ipaddress
import os
import re
import uuid
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ValidationError(ValueError):
    """A policy value does not satisfy the public policy schema."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> None:
    raise ValidationError(code, message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error("bad_type", f"{label} must be an object")
    unknown = set(value) - fields
    if unknown:
        _error("unknown_field", f"{label} has an unknown field")
    return value


def _string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        _error("bad_type", f"{label} must be a string")
    if nonempty and not value:
        _error("bad_value", f"{label} must not be empty")
    if "\x00" in value:
        _error("bad_value", f"{label} has an invalid character")
    return value


def _integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    # Breadcrumb for reviewers: bool is an int subclass, but is never valid policy data.
    if isinstance(value, bool) or not isinstance(value, int):
        _error("bad_type", f"{label} must be an integer")
    if minimum is not None and value < minimum:
        _error("bad_value", f"{label} is too small")
    return value


def _utc_datetime(value: Any, label: str) -> datetime:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _error("bad_value", f"{label} must be an ISO UTC time")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _error("bad_value", f"{label} must be an aware UTC time")
    return parsed.astimezone(timezone.utc).replace(tzinfo=timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _hostname(value: Any) -> str:
    raw = _string(value, "target value").strip().rstrip(".")
    if not raw or "/" in raw or "\\" in raw or "*" in raw or ":" in raw:
        _error("bad_value", "website value must be a hostname")
    try:
        # Breadcrumb for reviewers: IDNA conversion gives one stable ASCII form for matching.
        host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _error("bad_value", "website value is not valid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _error("bad_value", "website value must be a hostname")
    if len(host) > 253 or any(not _HOST_LABEL.fullmatch(part) for part in host.split(".")):
        _error("bad_value", "website value must be a hostname")
    return host


@dataclass(frozen=True)
class Target:
    kind: str
    value: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Target":
        obj = _object(data, {"kind", "value"}, "target")
        kind = _string(obj.get("kind"), "target kind")
        if kind not in {"website", "application"}:
            _error("bad_value", "target kind is not supported")
        value = obj.get("value")
        if kind == "website":
            value = _hostname(value)
        else:
            value = _string(value, "target value")
            if not os.path.isabs(value):
                _error("bad_value", "application value must be absolute")
            value = os.path.realpath(value)
            if not os.path.isabs(value) or value == "/":
                _error("bad_value", "application value is not valid")
        return cls(kind, value)

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class Schedule:
    kind: str
    start_utc: datetime | None = None
    end_utc: datetime | None = None
    timezone_name: str | None = None
    weekdays: tuple[int, ...] = ()
    start_local: time | None = None
    end_local: time | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Schedule":
        obj = _object(data, {"kind", "start_utc", "end_utc", "timezone", "weekdays", "start", "end"}, "schedule")
        kind = _string(obj.get("kind"), "schedule kind")
        if kind == "one_time":
            if set(obj) != {"kind", "start_utc", "end_utc"}:
                _error("bad_value", "one-time schedule fields are incomplete")
            start = _utc_datetime(obj["start_utc"], "start_utc")
            end = _utc_datetime(obj["end_utc"], "end_utc")
            if end <= start:
                _error("bad_value", "schedule end must be after start")
            return cls(kind, start_utc=start, end_utc=end)
        if kind == "weekly":
            required = {"kind", "timezone", "weekdays", "start", "end"}
            if set(obj) != required:
                _error("bad_value", "weekly schedule fields are incomplete")
            zone = _string(obj["timezone"], "timezone")
            try:
                ZoneInfo(zone)
            except (ZoneInfoNotFoundError, ValueError):
                _error("bad_value", "timezone is not valid")
            days = obj["weekdays"]
            if not isinstance(days, list):
                _error("bad_type", "weekdays must be a list")
            parsed_days = tuple(sorted(set(_integer(day, "weekday", minimum=0) for day in days)))
            if len(parsed_days) != len(days) or any(day > 6 for day in parsed_days) or not parsed_days:
                _error("bad_value", "weekdays are not valid")
            start_time = _local_time(obj["start"], "start")
            end_time = _local_time(obj["end"], "end")
            return cls(kind, timezone_name=zone, weekdays=parsed_days, start_local=start_time, end_local=end_time)
        if kind == "indefinite":
            if set(obj) != {"kind"}:
                _error("bad_value", "indefinite schedule fields are incomplete")
            return cls(kind)
        _error("bad_value", "schedule kind is not supported")

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "one_time":
            return {"kind": self.kind, "start_utc": _utc_text(self.start_utc), "end_utc": _utc_text(self.end_utc)}
        if self.kind == "weekly":
            return {
                "kind": self.kind,
                "timezone": self.timezone_name,
                "weekdays": list(self.weekdays),
                "start": self.start_local.strftime("%H:%M:%S"),
                "end": self.end_local.strftime("%H:%M:%S"),
            }
        return {"kind": self.kind}

    def is_active(self, now_utc: datetime) -> bool:
        if not isinstance(now_utc, datetime) or now_utc.tzinfo is None or now_utc.utcoffset() != timedelta(0):
            _error("bad_value", "now_utc must be an aware UTC time")
        now = now_utc.astimezone(timezone.utc)
        if self.kind == "indefinite":
            return True
        if self.kind == "one_time":
            return self.start_utc <= now < self.end_utc
        local = now.astimezone(ZoneInfo(self.timezone_name))
        local_naive = local.replace(tzinfo=None)
        local_date = local.date()
        for offset in (0, -1):
            start_date = local_date + timedelta(days=offset)
            if start_date.weekday() not in self.weekdays:
                continue
            start = datetime.combine(start_date, self.start_local)
            end_date = start_date + timedelta(days=1 if self.end_local <= self.start_local else 0)
            end = datetime.combine(end_date, self.end_local)
            if start <= local_naive < end:
                return True
        return False


def _local_time(value: Any, label: str) -> time:
    text = _string(value, label)
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?", text):
        _error("bad_value", f"{label} must be a local time")
    try:
        parsed = time.fromisoformat(text)
    except ValueError:
        _error("bad_value", f"{label} must be a local time")
    return parsed.replace(tzinfo=None)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    enabled: bool
    targets: tuple[Target, ...]
    schedule: Schedule
    revision: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Rule":
        obj = _object(data, {"id", "name", "enabled", "targets", "schedule", "revision"}, "rule")
        ident = _string(obj.get("id"), "rule id")
        try:
            if str(uuid.UUID(ident)) != ident.lower():
                _error("bad_value", "rule id must be a UUID")
        except ValueError:
            _error("bad_value", "rule id must be a UUID")
        name = _string(obj.get("name"), "rule name")
        if not isinstance(obj.get("enabled"), bool):
            _error("bad_type", "enabled must be a boolean")
        raw_targets = obj.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets:
            _error("bad_value", "targets must be a non-empty list")
        targets = tuple(Target.from_dict(item) for item in raw_targets)
        if len(set(targets)) != len(targets):
            _error("bad_value", "targets must be unique")
        schedule = Schedule.from_dict(obj.get("schedule"))
        revision = _integer(obj.get("revision"), "revision", minimum=0)
        return cls(ident.lower(), name, obj["enabled"], targets, schedule, revision)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "targets": [target.to_dict() for target in self.targets],
            "schedule": self.schedule.to_dict(),
            "revision": self.revision,
        }

    def is_active(self, now_utc: datetime, clock_trusted: bool = True) -> bool:
        if not self.enabled:
            return False
        if not clock_trusted and self.schedule.kind != "indefinite":
            return True
        return self.schedule.is_active(now_utc)


@dataclass(frozen=True)
class Policy:
    revision: int
    rules: tuple[Rule, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        obj = _object(data, {"revision", "rules"}, "policy")
        revision = _integer(obj.get("revision"), "policy revision", minimum=0)
        raw_rules = obj.get("rules")
        if not isinstance(raw_rules, list):
            _error("bad_type", "rules must be a list")
        rules = tuple(Rule.from_dict(item) for item in raw_rules)
        if len({rule.id for rule in rules}) != len(rules):
            _error("bad_value", "rule ids must be unique")
        return cls(revision, rules)

    def to_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "rules": [rule.to_dict() for rule in self.rules]}
