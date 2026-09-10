"""Scheduled workstation actions kept separate from blocking rules."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from .canonical import CanonicalError, canonical_uuid, format_utc, parse_utc
from .model import Schedule, ValidationError

ACTION_KINDS = ("lock", "logout", "shutdown", "notifications")
MAX_SCHEDULED_ACTIONS = 32


def _uuid(value: Any, label: str) -> str:
    try:
        return canonical_uuid(value)
    except CanonicalError as error:
        raise ValidationError("bad_value", f"{label} must be a UUID") from error


def _utc(value: Any, label: str) -> datetime:
    try:
        return parse_utc(value)
    except CanonicalError as error:
        raise ValidationError("bad_value", f"{label} must be an ISO UTC time") from error


def _utc_text(value: datetime) -> str:
    return format_utc(value)


@dataclass(frozen=True)
class ScheduledAction:
    """One independently scheduled workstation action."""

    id: str
    kind: str
    enabled: bool
    schedule: Schedule
    revision: int = 0
    last_fired_utc: datetime | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScheduledAction":
        if not isinstance(data, Mapping):
            raise ValidationError("bad_type", "scheduled action must be an object")
        expected = {"id", "kind", "enabled", "schedule", "revision", "last_fired_utc"}
        if set(data) != expected:
            raise ValidationError("unknown_field", "scheduled action fields are invalid")
        ident = _uuid(data["id"], "scheduled action id")
        kind = data["kind"]
        if not isinstance(kind, str) or kind not in ACTION_KINDS:
            raise ValidationError("bad_value", "scheduled action kind is not supported")
        if not isinstance(data["enabled"], bool):
            raise ValidationError("bad_type", "scheduled action enabled must be a boolean")
        try:
            schedule = Schedule.from_dict(data["schedule"])
        except ValidationError:
            raise
        if schedule.kind not in {"one_time", "weekly"}:
            raise ValidationError(
                "bad_value", "scheduled action needs a one-time or weekly schedule"
            )
        revision = data["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValidationError("bad_value", "scheduled action revision is invalid")
        fired = None if data["last_fired_utc"] is None else _utc(
            data["last_fired_utc"], "last_fired_utc"
        )
        return cls(ident, kind, data["enabled"], schedule, revision, fired)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "enabled": self.enabled,
            "schedule": self.schedule.to_dict(),
            "revision": self.revision,
            "last_fired_utc": (
                None if self.last_fired_utc is None else _utc_text(self.last_fired_utc)
            ),
        }

    def occurrence_at(self, now_utc: datetime) -> datetime | None:
        """Return the current occurrence start when this action is due."""
        if not self.enabled:
            return None
        now = now_utc.astimezone(timezone.utc)
        schedule = self.schedule
        if schedule.kind == "one_time":
            if now < schedule.start_utc:
                return None
            occurrence = schedule.start_utc
        else:
            zone = timezone.utc
            try:
                from zoneinfo import ZoneInfo
                zone = ZoneInfo(schedule.timezone_name)
            except Exception:
                return None
            local_now = now.astimezone(zone)
            local_naive = local_now.replace(tzinfo=None)
            occurrence = None
            for offset in (0, -1):
                local_date = local_now.date() + timedelta(days=offset)
                for period in schedule.periods:
                    if local_date.weekday() not in period.weekdays:
                        continue
                    start = datetime.combine(local_date, period.start_local)
                    end_date = local_date + (
                        timedelta(days=1)
                        if period.end_local <= period.start_local
                        else timedelta()
                    )
                    end = datetime.combine(end_date, period.end_local)
                    if start <= local_naive < end:
                        occurrence = datetime.combine(
                            local_date, period.start_local, zone
                        ).astimezone(timezone.utc)
                        break
                if occurrence is not None:
                    break
            if occurrence is None:
                return None
        if self.last_fired_utc == occurrence:
            return None
        return occurrence


@dataclass(frozen=True)
class ScheduledActionsState:
    items: tuple[ScheduledAction, ...] = ()

    @classmethod
    def empty(cls) -> "ScheduledActionsState":
        return cls()
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScheduledActionsState":
        if not isinstance(data, Mapping) or set(data) != {"version", "items"}:
            raise ValueError("scheduled actions state has an invalid shape")
        if data["version"] != 1 or not isinstance(data["items"], list):
            raise ValueError("scheduled actions state is invalid")
        if len(data["items"]) > MAX_SCHEDULED_ACTIONS:
            raise ValueError("scheduled actions state has too many entries")
        items = tuple(ScheduledAction.from_dict(item) for item in data["items"])
        if len({item.id for item in items}) != len(items):
            raise ValueError("scheduled actions state has duplicate IDs")
        return cls(items)

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "items": [item.to_dict() for item in self.items]}

    def replace(self, action: ScheduledAction) -> "ScheduledActionsState":
        for index, current in enumerate(self.items):
            if current.id == action.id:
                items = list(self.items)
                items[index] = action
                return ScheduledActionsState(tuple(items))
        if len(self.items) >= MAX_SCHEDULED_ACTIONS:
            raise ValueError("scheduled actions state has too many entries")
        return ScheduledActionsState((*self.items, action))

    def without(self, action_id: str) -> "ScheduledActionsState":
        items = tuple(item for item in self.items if item.id != action_id)
        if len(items) == len(self.items):
            raise KeyError(action_id)
        return ScheduledActionsState(items)


def new_action(kind: str, schedule: Schedule) -> ScheduledAction:
    if not isinstance(kind, str) or kind not in ACTION_KINDS:
        raise ValueError("scheduled action kind is not supported")
    if schedule.kind not in {"one_time", "weekly"}:
        raise ValueError("scheduled action needs a one-time or weekly schedule")
    return ScheduledAction(str(uuid4()), kind, True, schedule, 0, None)


__all__ = [
    "ACTION_KINDS",
    "MAX_SCHEDULED_ACTIONS",
    "ScheduledAction",
    "ScheduledActionsState",
    "new_action",
]
