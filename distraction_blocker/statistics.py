"""Bounded, observational application denial statistics.

Breadcrumb: this module owns only in-memory denial observations. It never
participates in policy decisions, so queue overflow and storage errors stay
local to statistics.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from datetime import date, datetime, timedelta, timezone
import re
import os
from pathlib import Path
import queue
import threading
from typing import Any, Iterable, Mapping

from .canonical import (
    REASON_ISO,
    REASON_TYPE,
    REASON_UUID,
    CanonicalError,
    canonical_uuid,
    format_utc,
    parse_utc,
)

MAX_QUEUE_SIZE = 1024
MAX_PATHS = 256
MAX_COUNT = 2**63 - 1
# Breadcrumb: storage refuses a statistics envelope above MAX_STATISTICS_BYTES
# (1 MiB). This smaller state budget guarantees every legal state fits that
# file, even with 256 paths of the maximum 4096-byte length.
MAX_STATE_BYTES = 768 * 1024


def _utc_text(value: datetime | str | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if not isinstance(value, (datetime, str)):
        raise TypeError("statistics time must be an aware UTC datetime or ISO string")
    try:
        return format_utc(value)
    except CanonicalError as error:
        if error.reason == REASON_ISO:
            raise ValueError("statistics time is invalid") from error
        raise ValueError("statistics time must be aware UTC") from error


def _time_key(value: str) -> datetime:
    return parse_utc(value)


def _bounded_absolute_path(value: str | os.PathLike[str]) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError("statistics path must be a path string")
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or not os.path.isabs(raw)
        or len(raw.encode("utf-8")) > 4096
    ):
        raise ValueError("statistics path must be a bounded absolute path")
    return raw


def canonical_path(value: str | os.PathLike[str]) -> str:
    """Return the symlink-resolved path used by persistent rows."""
    return os.path.realpath(_bounded_absolute_path(value))


def _rule_ids(value: Iterable[str] | str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = (value,)
    if isinstance(value, bytes):
        raise TypeError("rule_ids must be a sequence of strings")
    result: set[str] = set()
    for rule_id in value:
        try:
            result.add(canonical_uuid(rule_id))
        except CanonicalError as error:
            if error.reason in (REASON_TYPE, REASON_UUID):
                raise ValueError("rule id must be a UUID") from error
            raise ValueError("rule id must be a canonical UUID") from error
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True)
class DenialStat:
    """One immutable application denial row."""

    path: str
    count: int
    first_utc: str
    last_utc: str
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", canonical_path(self.path))
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise TypeError("statistics count must be an integer")
        if self.count < 1 or self.count > MAX_COUNT:
            raise ValueError("statistics count is out of range")
        first = _utc_text(self.first_utc)
        last = _utc_text(self.last_utc)
        if _time_key(first) > _time_key(last):
            raise ValueError("first statistics time is after last statistics time")
        object.__setattr__(self, "first_utc", first)
        object.__setattr__(self, "last_utc", last)
        object.__setattr__(self, "rule_ids", _rule_ids(self.rule_ids))

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "count": self.count, "first_utc": self.first_utc, "last_utc": self.last_utc, "rule_ids": list(self.rule_ids)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DenialStat":
        if not isinstance(data, Mapping) or set(data) != {"path", "count", "first_utc", "last_utc", "rule_ids"}:
            raise ValueError("statistics row has an invalid shape")
        if not isinstance(data["rule_ids"], list):
            raise ValueError("statistics rule_ids must be a list")
        return cls(data["path"], data["count"], data["first_utc"], data["last_utc"], tuple(data["rule_ids"]))


def _row_bytes(row: "DenialStat") -> int:
    """Return the canonical JSON size of one row inside the signed envelope."""
    payload = json.dumps(
        row.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return len(payload) + 1


def _victim_index(rows: list, victim_key) -> int:
    """Return the index of the row shed first under ``victim_key``."""
    return min(range(len(rows)), key=lambda i: victim_key(rows[i]))


def _bounded_state_items(
    raw_items: Any,
    dropped: int,
    *,
    row_type: type,
    type_error: str,
    capacity_error: str,
    duplicate_error: str,
    row_key,
    victim_key,
    row_bytes,
    budget_error: str,
):
    """Normalize one bounded signed state's rows.

    Breadcrumb: this hosts the single eviction-loop implementation for all
    three signed states; victims shed oldest-first with the row key as tie
    breaker, matching the record() paths that reuse _victim_index.
    """
    if not isinstance(raw_items, tuple):
        raw_items = tuple(raw_items)
    if len(raw_items) > MAX_PATHS:
        raise ValueError(capacity_error)
    if (
        isinstance(dropped, bool)
        or not isinstance(dropped, int)
        or not 0 <= dropped <= MAX_COUNT
    ):
        raise ValueError("statistics dropped count is invalid")
    rows: list[Any] = []
    seen: set[Any] = set()
    for row in raw_items:
        if not isinstance(row, row_type):
            raise TypeError(type_error)
        key = row_key(row)
        if key in seen:
            raise ValueError(duplicate_error)
        seen.add(key)
        rows.append(row)
    rows.sort(key=row_key)
    total = sum(row_bytes(row) for row in rows)
    while total > MAX_STATE_BYTES:
        if len(rows) == 1:
            raise ValueError(budget_error)
        victim = _victim_index(rows, victim_key)
        total -= row_bytes(rows[victim])
        rows.pop(victim)
    return tuple(rows)


class _BoundedState:
    """Shared envelope mapping for bounded signed statistics states.

    Breadcrumb: subclasses keep their public names, wire shapes, and exact
    error text; only row normalization and the ``items``/``dropped`` JSON
    mapping are unified here.
    """

    __slots__ = ()

    def to_dict(self) -> dict[str, Any]:
        return {"items": [row.to_dict() for row in self.items], "dropped": self.dropped}

    @classmethod
    def empty(cls) -> "_BoundedState":
        return cls()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "_BoundedState":
        if not isinstance(data, Mapping) or set(data) != {"items", "dropped"}:
            raise ValueError(cls._shape_error)
        if not isinstance(data["items"], list):
            raise ValueError(cls._items_error)
        return cls(
            tuple(cls._row_type.from_dict(row) for row in data["items"]),
            data["dropped"],
        )


@dataclass(frozen=True, slots=True)
class StatisticsState(_BoundedState):
    """Immutable bounded statistics snapshot."""

    items: tuple[DenialStat, ...] = ()
    dropped: int = 0

    # Envelope-mapping hooks consumed by _BoundedState.
    _row_type = DenialStat
    _shape_error = "statistics state has an invalid shape"
    _items_error = "statistics items must be a list"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "items",
            _bounded_state_items(
                self.items,
                self.dropped,
                row_type=DenialStat,
                type_error="statistics state rows must be DenialStat",
                capacity_error="statistics state has too many paths",
                duplicate_error="statistics state has duplicate paths",
                row_key=lambda row: row.path,
                victim_key=lambda row: (_time_key(row.last_utc), row.path),
                row_bytes=_row_bytes,
                budget_error="statistics row exceeds the state byte budget",
            ),
        )

    def list(self) -> dict[str, Any]:
        return self.to_dict()

    def clear(self) -> "StatisticsState":
        return StatisticsState.empty()

    def add_dropped(self, amount: int) -> "StatisticsState":
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError("dropped amount is invalid")
        return StatisticsState(self.items, min(MAX_COUNT, self.dropped + amount))

    def record(
        self,
        path: str | os.PathLike[str],
        rule_ids: Iterable[str] | str | None = (),
        now: datetime | str | None = None,
    ) -> "StatisticsState":
        """Return a state with one denial merged for ``path``.

        ``rule_ids`` is the complete active-rule set for the denial, not a
        single rule.
        """
        stamp = _utc_text(now)
        canonical = canonical_path(path)
        incoming = _rule_ids(rule_ids)
        index = next((i for i, row in enumerate(self.items) if row.path == canonical), None)
        if index is None:
            row = DenialStat(canonical, 1, stamp, stamp, incoming)
            rows = list(self.items)
            if len(rows) >= MAX_PATHS:
                # Breadcrumb: path is the tie breaker, so equal timestamps evict deterministically.
                victim = _victim_index(rows, lambda row: (_time_key(row.last_utc), row.path))
                rows.pop(victim)
            rows.append(row)
        else:
            old = self.items[index]
            rows = list(self.items)
            rows[index] = DenialStat(
                canonical,
                min(MAX_COUNT, old.count + 1),
                min(old.first_utc, stamp, key=_time_key),
                max(old.last_utc, stamp, key=_time_key),
                old.rule_ids + incoming,
            )
        return StatisticsState(tuple(rows), self.dropped)

    def merge(self, events: Iterable["DenialEvent"], rule_ids: Iterable[str] | str | None = ()) -> "StatisticsState":
        state = self
        for event in events:
            ids = event.rule_ids if event.rule_ids else rule_ids
            state = state.record(event.path, ids, event.at_utc)
        return state


@dataclass(frozen=True, slots=True)
class DenialEvent:
    """Queued denial path and capture time; policy rule IDs stay in service."""

    path: str
    at_utc: str | None
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Breadcrumb: the fanotify worker must not perform filesystem lookup.
        # The service canonicalizes this already absolute path after dequeue.
        object.__setattr__(self, "path", _bounded_absolute_path(self.path))
        if self.at_utc is not None:
            object.__setattr__(self, "at_utc", _utc_text(self.at_utc))
        object.__setattr__(self, "rule_ids", _rule_ids(self.rule_ids))

    @property
    def rule_id(self) -> str | None:
        return self.rule_ids[0] if self.rule_ids else None


class DenialBuffer:
    """A bounded queue whose producer operation is always non-blocking."""

    def __init__(self, maxsize: int = MAX_QUEUE_SIZE):
        if isinstance(maxsize, bool) or not isinstance(maxsize, int) or not 1 <= maxsize <= MAX_QUEUE_SIZE:
            raise ValueError("denial buffer size is invalid")
        self.maxsize = maxsize
        self._queue: queue.Queue[DenialEvent] = queue.Queue(maxsize=maxsize)
        self._dropped = 0
        self._drop_lock = threading.Lock()

    @property
    def dropped(self) -> int:
        with self._drop_lock:
            return self._dropped

    def record(
        self,
        path: str | os.PathLike[str],
        rule_ids: Iterable[str] | str | None = (),
        at_utc: datetime | str | None = None,
    ) -> bool:
        event = DenialEvent(
            path,
            _utc_text(at_utc) if at_utc is not None else None,
            _rule_ids(rule_ids),
        )
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._drop_lock:
                self._dropped = min(MAX_COUNT, self._dropped + 1)
            return False
        return True

    def drain(self, limit: int | None = None) -> list[DenialEvent]:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
            raise ValueError("drain limit is invalid")
        events: list[DenialEvent] = []
        while limit is None or len(events) < limit:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    def drain_into(self, state: StatisticsState | None = None, limit: int | None = None) -> StatisticsState:
        current = StatisticsState.empty() if state is None else state
        if not isinstance(current, StatisticsState):
            raise TypeError("statistics state has an invalid type")
        current = current.merge(self.drain(limit))
        with self._drop_lock:
            dropped = self._dropped
            self._dropped = 0
        return current.add_dropped(dropped)

    def discard(self) -> int:
        """Drop every queued event and the overflow counter.

        Returns how many events and counted drops were discarded. Used by
        clear_denial_stats so pending work cannot resurrect cleared data.
        """
        count = len(self.drain())
        with self._drop_lock:
            count += self._dropped
            self._dropped = 0
        return count

    def __len__(self) -> int:
        return self._queue.qsize()




def validate_report_value(value: Any) -> str:
    """Validate one extension-echoed target value.

    Breadcrumb: the denial and usage report commands must accept exactly the
    same value text the service itself authored, so both paths share this
    bound (printable ASCII, 1..512 bytes).
    """
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(not 0x20 < ord(char) < 0x7F for char in value)
    ):
        raise ValueError("reported target value is invalid")
    return value


@dataclass(frozen=True, slots=True)
class WebsiteDenialStat:
    """One aggregated website-denial row keyed by matched target value.

    The value is the target text the service itself authored (for example
    ``example.com/feed`` or a keyword); the extension only echoes it back.
    """

    value: str
    count: int
    first_utc: str
    last_utc: str
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "value", validate_report_value(self.value))
        except ValueError as error:
            raise ValueError("website denial value is invalid") from error
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise TypeError("statistics count must be an integer")
        if self.count < 1 or self.count > MAX_COUNT:
            raise ValueError("statistics count is out of range")
        first = _utc_text(self.first_utc)
        last = _utc_text(self.last_utc)
        if _time_key(first) > _time_key(last):
            raise ValueError("first statistics time is after last statistics time")
        object.__setattr__(self, "first_utc", first)
        object.__setattr__(self, "last_utc", last)
        object.__setattr__(self, "rule_ids", _rule_ids(self.rule_ids))

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "count": self.count,
            "first_utc": self.first_utc,
            "last_utc": self.last_utc,
            "rule_ids": list(self.rule_ids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WebsiteDenialStat":
        if not isinstance(data, Mapping) or set(data) != {
            "value",
            "count",
            "first_utc",
            "last_utc",
            "rule_ids",
        }:
            raise ValueError("website statistics row has an invalid shape")
        if not isinstance(data["rule_ids"], list):
            raise ValueError("statistics rule_ids must be a list")
        return cls(
            data["value"],
            data["count"],
            data["first_utc"],
            data["last_utc"],
            tuple(data["rule_ids"]),
        )


@dataclass(frozen=True, slots=True)
class WebsiteDenialState(_BoundedState):
    """Bounded snapshot of website denials reported by the extension."""

    items: tuple[WebsiteDenialStat, ...] = ()
    dropped: int = 0

    # Envelope-mapping hooks consumed by _BoundedState.
    _row_type = WebsiteDenialStat
    _shape_error = "website statistics state has an invalid shape"
    _items_error = "website statistics items must be a list"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "items",
            _bounded_state_items(
                self.items,
                self.dropped,
                row_type=WebsiteDenialStat,
                type_error="website rows must be WebsiteDenialStat values",
                capacity_error="website statistics state has too many entries",
                duplicate_error="website statistics state has duplicate values",
                row_key=lambda row: row.value,
                victim_key=lambda row: (_time_key(row.last_utc), row.value),
                row_bytes=_row_bytes,
                budget_error="website statistics row exceeds the state byte budget",
            ),
        )

    def record(
        self,
        value: str,
        rule_id: str,
        now: datetime | str | None = None,
        *,
        times: int = 1,
    ) -> "WebsiteDenialState":
        """Return a state with ``times`` denials merged for ``value``."""
        if isinstance(times, bool) or not isinstance(times, int) or times < 1:
            raise ValueError("denial count is invalid")
        stamp = _utc_text(now)
        index = next(
            (i for i, row in enumerate(self.items) if row.value == value), None
        )
        if index is None:
            if len(self.items) >= MAX_PATHS:
                victim = _victim_index(
                    self.items, lambda row: (_time_key(row.last_utc), row.value)
                )
                remaining = self.items[:victim] + self.items[victim + 1 :]
                return WebsiteDenialState(remaining, self.dropped).record(
                    value, rule_id, stamp, times=times
                )
            row = WebsiteDenialStat(value, times, stamp, stamp, (rule_id,))
            return WebsiteDenialState((*self.items, row), self.dropped)
        old = self.items[index]
        updated = WebsiteDenialStat(
            old.value,
            min(MAX_COUNT, old.count + times),
            min(old.first_utc, stamp, key=_time_key),
            max(old.last_utc, stamp, key=_time_key),
            old.rule_ids + _rule_ids(rule_id),
        )
        rows = list(self.items)
        rows[index] = updated
        return WebsiteDenialState(tuple(rows), self.dropped)



def _usage_day_text(value: Any) -> str:
    """Validate one ``YYYY-MM-DD`` local-day stamp."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("usage day must be YYYY-MM-DD")
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise ValueError("usage day is not a real date") from error
    return value


def _usage_row_bytes(row: "WebsiteUsageStat") -> int:
    """Return the canonical JSON size of one usage row in the envelope."""
    payload = json.dumps(row.to_dict(), sort_keys=True, separators=(",", ":"))
    return len(payload) + 1


@dataclass(frozen=True, slots=True)
class WebsiteUsageStat:
    """One per-rule daily count of permitted main-frame starts.

    The day is the rule's LOCAL date (its schedule time zone), not UTC, so
    a budget resets when the rule's own calendar day turns over.
    """

    rule_id: str
    day: str
    count: int

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "rule_id", canonical_uuid(self.rule_id))
        except CanonicalError as error:
            raise ValueError("usage rule id must be a canonical UUID") from error
        try:
            object.__setattr__(self, "day", _usage_day_text(self.day))
        except ValueError as error:
            raise ValueError(str(error)) from error
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise TypeError("statistics count must be an integer")
        if self.count < 1 or self.count > MAX_COUNT:
            raise ValueError("statistics count is out of range")

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "day": self.day, "count": self.count}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WebsiteUsageStat":
        if not isinstance(data, Mapping) or set(data) != {"rule_id", "day", "count"}:
            raise ValueError("website usage row has an invalid shape")
        return cls(data["rule_id"], data["day"], data["count"])


@dataclass(frozen=True, slots=True)
class WebsiteUsageState(_BoundedState):
    """Bounded snapshot of per-rule daily starts reported by the extension.

    Breadcrumb: row normalization and envelope mapping are shared via
    _BoundedState; the per-rule LOCAL-day semantics stay local to record()
    and fresh().
    """

    items: tuple[WebsiteUsageStat, ...] = ()
    dropped: int = 0

    # Envelope-mapping hooks consumed by _BoundedState.
    _row_type = WebsiteUsageStat
    _shape_error = "website usage state has an invalid shape"
    _items_error = "website usage items must be a list"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "items",
            _bounded_state_items(
                self.items,
                self.dropped,
                row_type=WebsiteUsageStat,
                type_error="website rows must be WebsiteUsageStat values",
                capacity_error="website usage state has too many entries",
                duplicate_error="website usage state has duplicate rows",
                row_key=lambda row: (row.rule_id, row.day),
                victim_key=lambda row: (row.day, row.rule_id),
                row_bytes=_usage_row_bytes,
                budget_error="website usage row exceeds the state byte budget",
            ),
        )

    def record(
        self,
        rule_id: str,
        times: int,
        day: str,
    ) -> "WebsiteUsageState":
        """Return a state with ``times`` starts merged for ``rule_id`` today."""
        day = _usage_day_text(day)
        if isinstance(times, bool) or not isinstance(times, int) or times < 1:
            raise ValueError("usage count is invalid")
        index = next(
            (i for i, item in enumerate(self.items) if item.rule_id == rule_id),
            None,
        )
        if index is None:
            if len(self.items) >= MAX_PATHS:
                victim = _victim_index(
                    self.items, lambda row: (row.day, row.rule_id)
                )
                remaining = self.items[:victim] + self.items[victim + 1 :]
                return WebsiteUsageState(remaining, self.dropped + 1).record(
                    rule_id, times, day
                )
            fresh = WebsiteUsageStat(rule_id, day, min(MAX_COUNT, times))
            return WebsiteUsageState((*self.items, fresh), self.dropped)
        old = self.items[index]
        if old.day == day:
            updated = WebsiteUsageStat(
                old.rule_id, old.day, min(MAX_COUNT, old.count + times)
            )
            rows = list(self.items)
            rows[index] = updated
            return WebsiteUsageState(tuple(rows), self.dropped)
        # Breadcrumb: lazy daily reset. The stored row belongs to a previous
        # local day, so the first report of the new day replaces it.
        replacement = WebsiteUsageStat(old.rule_id, day, min(MAX_COUNT, times))
        rows = list(self.items)
        rows[index] = replacement
        return WebsiteUsageState(tuple(rows), self.dropped)

    def fresh(self, today_for) -> "WebsiteUsageState":
        """Drop rows whose stored day is not the rule's current local day.

        ``today_for`` maps a rule id to its current local ``YYYY-MM-DD``
        string, or None for an unknown rule. Breadcrumb: no timers exist in
        this design; staleness is resolved lazily at every report, load, and
        projection.
        """
        kept = tuple(
            row
            for row in self.items
            if today_for(row.rule_id) is not None
            and _usage_day_text(today_for(row.rule_id)) == row.day
        )
        return WebsiteUsageState(kept, self.dropped)

    def count_for(self, rule_id: str, day: str) -> int:
        """Return today's counted starts, treating stale rows as zero."""
        row = next((item for item in self.items if item.rule_id == rule_id), None)
        if row is None or row.day != day:
            return 0
        return row.count


__all__ = [
    "MAX_COUNT",
    "MAX_PATHS",
    "MAX_QUEUE_SIZE",
    "MAX_STATE_BYTES",
    "DenialBuffer",
    "DenialEvent",
    "DenialStat",
    "StatisticsState",
    "WebsiteDenialState",
    "WebsiteDenialStat",
    "WebsiteUsageState",
    "WebsiteUsageStat",
    "canonical_path",
]
