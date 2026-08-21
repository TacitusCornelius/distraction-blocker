"""Signed, atomic policy and control storage."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any

from .control import ControlState
from .model import Policy, ValidationError
from .statistics import StatisticsState


class StorageError(RuntimeError):
    """Protected policy state is unavailable or invalid."""


@dataclass(frozen=True)
class LoadResult:
    policy: Policy
    controls: ControlState
    high_water_utc: datetime | None
    degraded: bool = False
    clock_untrusted: bool = False


class ProtectedStore:
    VERSION = 3
    KEY_NAME = "hmac.key"
    PRIMARY_NAME = "policy.json"
    BACKUP_NAME = "policy.json.bak"
    STATISTICS_NAME = "statistics.json"
    MAX_POLICY_BYTES = 16 * 1024 * 1024
    MAX_STATISTICS_BYTES = 1024 * 1024

    def __init__(self, directory: str | os.PathLike[str], key_source: Any = None):
        self.directory = Path(directory)
        self._key_source = key_source
        self._key: bytes | None = None

    @property
    def primary_path(self) -> Path:
        return self.directory / self.PRIMARY_NAME

    @property
    def backup_path(self) -> Path:
        return self.directory / self.BACKUP_NAME

    @property
    def statistics_path(self) -> Path:
        return self.directory / self.STATISTICS_NAME

    def initialize(self) -> None:
        if self.directory.exists() and self.directory.is_symlink():
            raise StorageError("storage directory is a symlink")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise StorageError("storage path is not a directory")
        os.chmod(self.directory, 0o700)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        path = self.directory / self.KEY_NAME
        if self._key_source is not None:
            source = self._key_source() if callable(self._key_source) else self._key_source
            if isinstance(source, (str, os.PathLike)):
                source_path = Path(source)
                if source_path.is_symlink() or not source_path.is_file():
                    raise StorageError("key source is not a regular file")
                key = source_path.read_bytes()
            else:
                key = source
            if not isinstance(key, bytes) or len(key) != 32:
                raise StorageError("HMAC key must contain 32 bytes")
            return key
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise StorageError("key path is not a regular file")
            key = path.read_bytes()
            if len(key) != 32:
                raise StorageError("HMAC key must contain 32 bytes")
            os.chmod(path, 0o600)
            return key
        key = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            return self._load_or_create_key()
        os.chmod(path, 0o600)
        self._fsync_directory()
        return key

    def _require_key(self) -> bytes:
        if self._key is None:
            self.initialize()
        assert self._key is not None
        return self._key

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

    @staticmethod
    def _format_utc(value: datetime | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise StorageError("high-water time must be aware UTC")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _parse_utc(value: Any) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise StorageError("high-water time is invalid")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        except ValueError as exc:
            raise StorageError("high-water time is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise StorageError("high-water time is invalid")
        return parsed.astimezone(timezone.utc).replace(tzinfo=timezone.utc)

    def _envelope(self, policy: Policy, controls: ControlState, high_water_utc: datetime | None, clock_untrusted: bool) -> bytes:
        payload = {"policy": policy.to_dict(), "controls": controls.to_dict(), "clock_untrusted": bool(clock_untrusted), "high_water_utc": self._format_utc(high_water_utc)}
        unsigned = {"version": self.VERSION, "payload": payload}
        signature = hmac.new(self._require_key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
        return self._canonical({**unsigned, "hmac": signature})

    def save(self, policy: Policy, controls: ControlState, high_water_utc: datetime | None, clock_untrusted: bool = False) -> None:
        if not isinstance(policy, Policy):
            raise StorageError("policy has an invalid type")
        if not isinstance(controls, ControlState):
            raise StorageError("controls have an invalid type")
        if not isinstance(clock_untrusted, bool):
            raise StorageError("clock state is invalid")
        self.initialize()
        content = self._envelope(policy, controls, high_water_utc, clock_untrusted)
        # Breadcrumb: both files use same-directory replace so a crash cannot expose a partial JSON file.
        self._atomic_write(self.backup_path, content)
        self._atomic_write(self.primary_path, content)

    def _statistics_envelope(self, state: StatisticsState) -> bytes:
        if not isinstance(state, StatisticsState):
            raise StorageError("statistics state has an invalid type")
        unsigned = {"version": 1, "payload": state.to_dict()}
        signature = hmac.new(self._require_key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
        return self._canonical({**unsigned, "hmac": signature})

    def save_statistics(self, state: StatisticsState) -> None:
        """Atomically save observational statistics without touching policy files."""
        self.initialize()
        content = self._statistics_envelope(state)
        if len(content) > self.MAX_STATISTICS_BYTES:
            raise StorageError("statistics file is too large")
        # Breadcrumb: statistics have no backup. Observational data must never rewrite policy backups.
        self._atomic_write(self.statistics_path, content)

    def load_statistics(self) -> StatisticsState:
        """Load signed statistics, or return an empty state when absent."""
        self.initialize()
        path = self.statistics_path
        if not path.exists():
            return StatisticsState.empty()
        if path.is_symlink() or not path.is_file():
            raise StorageError("statistics path is not a regular file")
        if path.stat().st_size > self.MAX_STATISTICS_BYTES:
            raise StorageError("statistics file is too large")
        try:
            envelope = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError("statistics file is invalid") from exc
        if not isinstance(envelope, dict) or set(envelope) != {"version", "payload", "hmac"}:
            raise StorageError("statistics envelope is invalid")
        signature = envelope["hmac"]
        if envelope["version"] != 1 or not isinstance(signature, str) or len(signature) != 64:
            raise StorageError("statistics envelope is invalid")
        unsigned = {"version": envelope["version"], "payload": envelope["payload"]}
        expected = hmac.new(self._require_key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
        # Breadcrumb: compare_digest protects the signed file boundary from timing differences.
        if not hmac.compare_digest(signature, expected):
            raise StorageError("statistics signature is invalid")
        try:
            return StatisticsState.from_dict(envelope["payload"])
        except (TypeError, ValueError, KeyError) as exc:
            raise StorageError("statistics payload is invalid") from exc


    def _atomic_write(self, path: Path, content: bytes) -> None:
        if path.exists() and path.is_symlink():
            raise StorageError("policy path is a symlink")
        fd, temp_name = tempfile.mkstemp(prefix=".policy-", dir=self.directory)
        temp_path = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
            self._fsync_directory()
        except Exception:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            raise

    def _fsync_directory(self) -> None:
        try:
            fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def load(self) -> LoadResult:
        self.initialize()
        errors: list[Exception] = []
        for path, degraded in ((self.primary_path, False), (self.backup_path, True)):
            try:
                return self._load_file(path, degraded)
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, StorageError, ValidationError) as exc:
                errors.append(exc)
        if not self.primary_path.exists() and not self.backup_path.exists():
            return LoadResult(Policy(0, ()), ControlState.empty(), None, False, False)
        raise StorageError("primary and backup policy state are invalid") from errors[-1]

    @staticmethod
    def _migrate_policy(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise StorageError("policy is invalid")
        migrated = dict(data)
        migrated.setdefault("managed_lists", [])
        rules = migrated.get("rules")
        if not isinstance(rules, list):
            raise StorageError("policy rules are invalid")
        converted_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise StorageError("policy rule is invalid")
            converted = dict(rule)
            schedule = converted.get("schedule")
            if isinstance(schedule, dict) and schedule.get("kind") == "weekly" and "periods" not in schedule:
                old = dict(schedule)
                required = {"kind", "timezone", "weekdays", "start", "end"}
                if set(old) != required:
                    raise StorageError("old weekly schedule is invalid")
                converted["schedule"] = {"kind": "weekly", "timezone": old["timezone"], "periods": [{"weekdays": old["weekdays"], "start": old["start"], "end": old["end"]}]}
            converted_rules.append(converted)
        migrated["rules"] = converted_rules
        return migrated

    def _load_file(self, path: Path, degraded: bool) -> LoadResult:
        if path.is_symlink() or not path.is_file():
            raise StorageError("policy path is not a regular file")
        if path.stat().st_size > self.MAX_POLICY_BYTES:
            raise StorageError("policy file is too large")
        raw = path.read_bytes()
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != {"version", "payload", "hmac"}:
            raise StorageError("policy envelope is invalid")
        version = envelope["version"]
        if isinstance(version, bool) or version not in {1, 2, self.VERSION}:
            raise StorageError("policy version is invalid")
        signature = envelope["hmac"]
        if not isinstance(signature, str) or len(signature) != 64:
            raise StorageError("policy signature is invalid")
        unsigned = {"version": version, "payload": envelope["payload"]}
        expected = hmac.new(self._require_key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
        # Breadcrumb: compare_digest avoids a timing leak from attacker-controlled signatures.
        if not hmac.compare_digest(signature, expected):
            raise StorageError("policy signature is invalid")
        payload = envelope["payload"]
        old_fields = {"clock_untrusted", "high_water_utc", "policy"}
        current_fields = old_fields | {"controls"}
        if not isinstance(payload, dict) or set(payload) != (current_fields if version == self.VERSION else old_fields):
            raise StorageError("policy payload is invalid")
        if not isinstance(payload["clock_untrusted"], bool):
            raise StorageError("clock state is invalid")
        policy_data = self._migrate_policy(payload["policy"]) if version == 1 else payload["policy"]
        policy = Policy.from_dict(policy_data)
        controls = ControlState.from_dict(payload["controls"]) if version == self.VERSION else ControlState.empty()
        result = LoadResult(policy, controls, self._parse_utc(payload["high_water_utc"]), degraded, payload["clock_untrusted"])
        if version != self.VERSION:
            # Breadcrumb: verify the old signature first, then write only the converted v3 form.
            self.save(policy, controls, result.high_water_utc, result.clock_untrusted)
        return result
