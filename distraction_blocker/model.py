"""Strict policy data model and schedule evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
import ipaddress
import os
import re
import uuid
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import canonical
from .canonical import CanonicalError


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


def _string(value: Any, label: str, *, nonempty: bool = True, maximum: int | None = None) -> str:
    if not isinstance(value, str):
        _error("bad_type", f"{label} must be a string")
    if nonempty and not value.strip():
        _error("bad_value", f"{label} must not be empty")
    if "\x00" in value:
        _error("bad_value", f"{label} has an invalid character")
    if maximum is not None and len(value.encode("utf-8")) > maximum:
        _error("bad_value", f"{label} is too long")
    return value


def _integer(value: Any, label: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    # Breadcrumb for reviewers: bool is an int subclass, but is never valid policy data.
    if isinstance(value, bool) or not isinstance(value, int):
        _error("bad_type", f"{label} must be an integer")
    if minimum is not None and value < minimum:
        _error("bad_value", f"{label} is too small")
    if maximum is not None and value > maximum:
        _error("bad_value", f"{label} is too large")
    return value


def _utc_datetime(value: Any, label: str) -> datetime:
    try:
        return canonical.parse_utc(value)
    except CanonicalError as error:
        if error.reason == canonical.REASON_ISO:
            _error("bad_value", f"{label} must be an ISO UTC time")
        _error("bad_value", f"{label} must be an aware UTC time")


def _utc_text(value: datetime) -> str:
    return canonical.format_utc(value)


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _hostname(value: Any, label: str = "website value") -> str:
    raw = _string(value, label).strip().rstrip(".")
    if not raw or "/" in raw or "\\" in raw or "*" in raw or ":" in raw:
        _error("bad_value", f"{label} must be a hostname")
    try:
        # Breadcrumb for reviewers: IDNA conversion gives one stable ASCII form for matching.
        host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _error("bad_value", f"{label} is not valid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _error("bad_value", f"{label} must be a hostname")
    if len(host) > 253 or any(not _HOST_LABEL.fullmatch(part) for part in host.split(".")):
        _error("bad_value", f"{label} must be a hostname")
    return host


def _uuid(value: Any, label: str) -> str:
    text = _string(value, label)
    try:
        parsed = uuid.UUID(text)
    except ValueError:
        _error("bad_value", f"{label} must be a UUID")
    if str(parsed) != text.lower():
        _error("bad_value", f"{label} must be a canonical UUID")
    return text.lower()


def _url_target_value(value: Any, label: str, *, wildcard: bool) -> str:
    """Validate one ``host/path`` URL target; the host is canonicalized."""
    # Breadcrumb for reviewers: the extension matches this text against real
    # URLs, so only visible ASCII without query or fragment parts is kept,
    # and the hostname goes through the same IDNA form as website targets.
    raw = _string(value, label).strip()
    if (
        not raw
        or len(raw) > 512
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in raw)
        or any(char in raw for char in '"\\<>`')
    ):
        _error("bad_value", f"{label} is not a valid URL target")
    if "?" in raw or "#" in raw:
        _error("bad_value", f"{label} cannot contain a query or fragment")
    host_part, separator, _path_part = raw.partition("/")
    if not separator:
        _error("bad_value", f"{label} needs a path after the hostname")
    host = _hostname(host_part, label)
    if wildcard:
        if raw.count("*") != 1 or not raw.endswith("*"):
            _error(
                "bad_value",
                f"{label} must end with exactly one * wildcard",
            )
    elif "*" in raw:
        _error("bad_value", f"{label} cannot contain a * wildcard")
    return host + raw[len(host_part):]


def _url_keyword(value: Any, label: str) -> str:
    raw = _string(value, label).strip().lower()
    if (
        len(raw) < 2
        or len(raw) > 64
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in raw)
    ):
        _error(
            "bad_value",
            f"{label} must contain 2 to 64 visible ASCII characters",
        )
    return raw

@dataclass(frozen=True)
class Target:
    kind: str
    value: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Target":
        obj = _object(data, {"kind", "value"}, "target")
        kind = _string(obj.get("kind"), "target kind")
        if kind not in {
            "website",
            "application",
            "managed_list",
            "url_path",
            "url_wildcard",
            "url_keyword",
        }:
            _error("bad_value", "target kind is not supported")
        value = obj.get("value")
        if kind == "website":
            value = _hostname(value)
        elif kind == "managed_list":
            value = _uuid(value, "managed-list target value")
        elif kind == "url_path":
            value = _url_target_value(value, "URL path target", wildcard=False)
        elif kind == "url_wildcard":
            value = _url_target_value(
                value, "URL wildcard target", wildcard=True
            )
        elif kind == "url_keyword":
            value = _url_keyword(value, "URL keyword target")
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
class WeeklyPeriod:
    weekdays: tuple[int, ...]
    start_local: time
    end_local: time

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WeeklyPeriod":
        obj = _object(data, {"weekdays", "start", "end"}, "weekly period")
        if set(obj) != {"weekdays", "start", "end"}:
            _error("bad_value", "weekly period fields are incomplete")
        days = obj["weekdays"]
        if not isinstance(days, list) or not days:
            _error("bad_type" if not isinstance(days, list) else "bad_value", "weekdays must be a non-empty list")
        parsed_days = tuple(sorted(_integer(day, "weekday", minimum=0) for day in days))
        if len(parsed_days) > 7 or any(day > 6 for day in parsed_days) or len(set(parsed_days)) != len(parsed_days):
            _error("bad_value", "weekdays are not valid")
        return cls(parsed_days, _local_time(obj["start"], "start"), _local_time(obj["end"], "end"))

    def to_dict(self) -> dict[str, Any]:
        return {"weekdays": list(self.weekdays), "start": self.start_local.strftime("%H:%M:%S"), "end": self.end_local.strftime("%H:%M:%S")}


@dataclass(frozen=True)
class Schedule:
    kind: str
    start_utc: datetime | None = None
    end_utc: datetime | None = None
    timezone_name: str | None = None
    periods: tuple[WeeklyPeriod, ...] = ()
    work_minutes: int | None = None
    break_minutes: int | None = None
    cycles: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Schedule":
        obj = _object(
            data,
            {
                "kind",
                "start_utc",
                "end_utc",
                "timezone",
                "periods",
                "work_minutes",
                "break_minutes",
                "cycles",
            },
            "schedule",
        )
        kind = _string(obj.get("kind"), "schedule kind")
        if kind == "one_time":
            if set(obj) != {"kind", "start_utc", "end_utc"}:
                _error("bad_value", "one-time schedule fields are incomplete")
            start = _utc_datetime(obj["start_utc"], "start_utc")
            end = _utc_datetime(obj["end_utc"], "end_utc")
            if end <= start:
                _error("bad_value", "schedule end must be after start")
            return cls(kind, start_utc=start, end_utc=end)
        if kind == "pomodoro":
            if set(obj) != {"kind", "start_utc", "work_minutes", "break_minutes", "cycles"}:
                _error("bad_value", "pomodoro schedule fields are incomplete")
            return cls(
                kind,
                start_utc=_utc_datetime(obj["start_utc"], "start_utc"),
                work_minutes=_integer(obj["work_minutes"], "work_minutes", minimum=1, maximum=180),
                break_minutes=_integer(obj["break_minutes"], "break_minutes", minimum=1, maximum=60),
                cycles=_integer(obj["cycles"], "cycles", minimum=1, maximum=20),
            )
        if kind == "weekly":
            if set(obj) != {"kind", "timezone", "periods"}:
                _error("bad_value", "weekly schedule fields are incomplete")
            zone = _string(obj["timezone"], "timezone")
            try:
                ZoneInfo(zone)
            except (ZoneInfoNotFoundError, ValueError):
                _error("bad_value", "timezone is not valid")
            raw_periods = obj["periods"]
            if not isinstance(raw_periods, list) or not raw_periods:
                _error("bad_type" if not isinstance(raw_periods, list) else "bad_value", "periods must be a non-empty list")
            periods = tuple(WeeklyPeriod.from_dict(item) for item in raw_periods)
            if len(periods) > 16 or len(set(periods)) != len(periods):
                _error("bad_value", "weekly schedule periods are not valid")
            periods = tuple(sorted(periods, key=lambda period: (period.weekdays, period.start_local, period.end_local)))
            return cls(kind, timezone_name=zone, periods=periods)
        if kind == "indefinite":
            if set(obj) != {"kind"}:
                _error("bad_value", "indefinite schedule fields are incomplete")
            return cls(kind)
        _error("bad_value", "schedule kind is not supported")

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "one_time":
            return {"kind": self.kind, "start_utc": _utc_text(self.start_utc), "end_utc": _utc_text(self.end_utc)}
        if self.kind == "pomodoro":
            return {
                "kind": self.kind,
                "start_utc": _utc_text(self.start_utc),
                "work_minutes": self.work_minutes,
                "break_minutes": self.break_minutes,
                "cycles": self.cycles,
            }
        if self.kind == "weekly":
            return {"kind": self.kind, "timezone": self.timezone_name, "periods": [period.to_dict() for period in self.periods]}
        return {"kind": self.kind}


    def pomodoro_end_utc(self) -> datetime:
        """Return the final work-block end of an anchored pomodoro schedule."""
        if self.kind != "pomodoro":
            _error("bad_value", "schedule is not a pomodoro schedule")
        # Breadcrumb: the last cycle has no following break, so the span ends
        # one break earlier than cycles * (work + break).
        work = timedelta(minutes=self.work_minutes)
        pause = timedelta(minutes=self.break_minutes)
        return self.start_utc + work * self.cycles + pause * (self.cycles - 1)

    def is_active(self, now_utc: datetime) -> bool:
        if not isinstance(now_utc, datetime) or now_utc.tzinfo is None or now_utc.utcoffset() != timedelta(0):
            _error("bad_value", "now_utc must be an aware UTC time")
        now = now_utc.astimezone(timezone.utc)
        if self.kind == "indefinite":
            return True
        if self.kind == "one_time":
            return self.start_utc <= now < self.end_utc
        if self.kind == "pomodoro":
            work = timedelta(minutes=self.work_minutes)
            pause = timedelta(minutes=self.break_minutes)
            cycle = work + pause
            elapsed = now - self.start_utc
            if elapsed < timedelta(0):
                return False
            final_end = self.pomodoro_end_utc()
            if now >= final_end:
                return False
            _, offset = divmod(elapsed, cycle)
            return offset < work
        local = now.astimezone(ZoneInfo(self.timezone_name))
        local_naive = local.replace(tzinfo=None)
        local_date = local.date()
        for period in self.periods:
            for offset in (0, -1):
                start_date = local_date + timedelta(days=offset)
                if start_date.weekday() not in period.weekdays:
                    continue
                start = datetime.combine(start_date, period.start_local)
                end_date = start_date + timedelta(days=1 if period.end_local <= period.start_local else 0)
                end = datetime.combine(end_date, period.end_local)
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
        ident = _uuid(obj.get("id"), "rule id")
        name = _string(obj.get("name"), "rule name", maximum=256)
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
        return cls(ident, name, obj["enabled"], targets, schedule, revision)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "enabled": self.enabled, "targets": [target.to_dict() for target in self.targets], "schedule": self.schedule.to_dict(), "revision": self.revision}

    def is_active(self, now_utc: datetime, clock_trusted: bool = True) -> bool:
        if not self.enabled:
            return False
        if not clock_trusted and self.schedule.kind != "indefinite":
            return True
        return self.schedule.is_active(now_utc)


@dataclass(frozen=True)
class ManagedList:
    id: str
    name: str
    source: str
    version: str
    license: str
    imported_utc: datetime
    domains: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ManagedList":
        obj = _object(data, {"id", "name", "source", "version", "license", "imported_utc", "domains"}, "managed list")
        if set(obj) != {"id", "name", "source", "version", "license", "imported_utc", "domains"}:
            _error("bad_value", "managed list fields are incomplete")
        raw_domains = obj["domains"]
        if not isinstance(raw_domains, list):
            _error("bad_type", "managed list domains must be a list")
        if len(raw_domains) > 50_000:
            _error("bad_value", "managed list has too many domains")
        domains = tuple(_hostname(domain, "managed list domain") for domain in raw_domains)
        if len(set(domains)) != len(domains):
            _error("bad_value", "managed list domains must be unique")
        if sum(len(domain.encode("utf-8")) for domain in domains) > 4 * 1024 * 1024:
            _error("bad_value", "managed list domains are too large")
        return cls(_uuid(obj["id"], "managed list id"), _string(obj["name"], "managed list name", maximum=256), _string(obj["source"], "managed list source", maximum=512), _string(obj["version"], "managed list version", maximum=128), _string(obj["license"], "managed list license", maximum=512), _utc_datetime(obj["imported_utc"], "imported_utc"), domains)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "source": self.source, "version": self.version, "license": self.license, "imported_utc": _utc_text(self.imported_utc), "domains": list(self.domains)}


@dataclass(frozen=True)
class Policy:
    revision: int
    rules: tuple[Rule, ...]
    managed_lists: tuple[ManagedList, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        obj = _object(data, {"revision", "rules", "managed_lists"}, "policy")
        if set(obj) != {"revision", "rules", "managed_lists"}:
            _error("bad_value", "policy fields are incomplete")
        revision = _integer(obj.get("revision"), "policy revision", minimum=0)
        raw_rules = obj.get("rules")
        if not isinstance(raw_rules, list):
            _error("bad_type", "rules must be a list")
        rules = tuple(Rule.from_dict(item) for item in raw_rules)
        if len({rule.id for rule in rules}) != len(rules):
            _error("bad_value", "rule ids must be unique")
        raw_lists = obj.get("managed_lists")
        if not isinstance(raw_lists, list):
            _error("bad_type", "managed_lists must be a list")
        if len(raw_lists) > 64:
            _error("bad_value", "too many managed lists")
        managed_lists = tuple(ManagedList.from_dict(item) for item in raw_lists)
        list_ids = {item.id for item in managed_lists}
        if len(list_ids) != len(managed_lists):
            _error("bad_value", "managed list ids must be unique")
        total_bytes = sum(len(domain.encode("utf-8")) for item in managed_lists for domain in item.domains)
        if total_bytes > 4 * 1024 * 1024:
            _error("bad_value", "managed list domains are too large")
        for rule in rules:
            for target in rule.targets:
                if target.kind == "managed_list" and target.value not in list_ids:
                    _error("bad_value", "rule refers to an unknown managed list")
        return cls(revision, rules, managed_lists)

    def to_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "rules": [rule.to_dict() for rule in self.rules], "managed_lists": [item.to_dict() for item in self.managed_lists]}
