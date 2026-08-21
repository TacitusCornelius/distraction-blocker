"""Bounded, observational application denial statistics.

Breadcrumb: this module owns only in-memory denial observations. It never
participates in policy decisions, so queue overflow and storage errors stay
local to statistics.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import queue
import threading
import uuid
from typing import Any, Iterable, Mapping

MAX_QUEUE_SIZE = 1024
MAX_PATHS = 256
MAX_COUNT = 2**63 - 1
# Breadcrumb: storage refuses a statistics envelope above MAX_STATISTICS_BYTES
# (1 MiB). This smaller state budget guarantees every legal state fits that
# file, even with 256 paths of the maximum 4096-byte length.
MAX_STATE_BYTES = 768 * 1024


def _utc_text(value: datetime | str | None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("statistics time is invalid") from exc
    else:
        raise TypeError("statistics time must be an aware UTC datetime or ISO string")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("statistics time must be aware UTC")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _time_key(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


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
        if not isinstance(rule_id, str):
            raise TypeError("rule id must be a UUID string")
        try:
            parsed = uuid.UUID(rule_id)
        except ValueError as error:
            raise ValueError("rule id must be a UUID") from error
        normalized = str(parsed)
        if normalized != rule_id.lower():
            raise ValueError("rule id must be a canonical UUID")
        result.add(normalized)
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


@dataclass(frozen=True, slots=True)
class StatisticsState:
    """Immutable bounded statistics snapshot."""

    items: tuple[DenialStat, ...] = ()
    dropped: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            object.__setattr__(self, "items", tuple(self.items))
        if len(self.items) > MAX_PATHS:
            raise ValueError("statistics state has too many paths")
        if (
            isinstance(self.dropped, bool)
            or not isinstance(self.dropped, int)
            or not 0 <= self.dropped <= MAX_COUNT
        ):
            raise ValueError("statistics dropped count is invalid")
        rows: list[DenialStat] = []
        seen: set[str] = set()
        for row in self.items:
            if not isinstance(row, DenialStat):
                raise TypeError("statistics state rows must be DenialStat")
            if row.path in seen:
                raise ValueError("statistics state has duplicate paths")
            seen.add(row.path)
            rows.append(row)
        rows.sort(key=lambda row: row.path)
        total = sum(_row_bytes(row) for row in rows)
        # Breadcrumb: eviction uses the same deterministic key as record(),
        # so an over-budget state sheds its oldest rows instead of failing
        # to persist later.
        while total > MAX_STATE_BYTES:
            if len(rows) == 1:
                raise ValueError("statistics row exceeds the state byte budget")
            victim = min(
                range(len(rows)),
                key=lambda i: (_time_key(rows[i].last_utc), rows[i].path),
            )
            total -= _row_bytes(rows[victim])
            rows.pop(victim)
        object.__setattr__(self, "items", tuple(rows))

    @classmethod
    def empty(cls) -> "StatisticsState":
        return cls()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StatisticsState":
        if not isinstance(data, Mapping) or set(data) != {"items", "dropped"}:
            raise ValueError("statistics state has an invalid shape")
        if not isinstance(data["items"], list):
            raise ValueError("statistics items must be a list")
        return cls(tuple(DenialStat.from_dict(row) for row in data["items"]), data["dropped"])

    def to_dict(self) -> dict[str, Any]:
        return {"items": [row.to_dict() for row in self.items], "dropped": self.dropped}

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
                victim = min(range(len(rows)), key=lambda i: (_time_key(rows[i].last_utc), rows[i].path))
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


__all__ = ["MAX_COUNT", "MAX_PATHS", "MAX_QUEUE_SIZE", "MAX_STATE_BYTES", "DenialBuffer", "DenialEvent", "DenialStat", "StatisticsState", "canonical_path"]
