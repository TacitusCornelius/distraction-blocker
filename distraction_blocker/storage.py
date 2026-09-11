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

from .actions import ScheduledActionsState
from .allowance import AllowanceUsageState
from .canonical import CanonicalError, format_utc, parse_utc
from .control import ControlState, DelayBreakState
from .model import POLICY_SCHEMA_VERSION, Policy, ValidationError
from .statistics import StatisticsState, WebsiteDenialState, WebsiteUsageState


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
    VERSION = 7
    KEY_NAME = "hmac.key"
    PRIMARY_NAME = "policy.json"
    BACKUP_NAME = "policy.json.bak"
    STATISTICS_NAME = "statistics.json"
    WEBSITE_STATISTICS_NAME = "website-statistics.json"
    WEBSITE_USAGE_NAME = "website-usage.json"
    ALLOWANCE_USAGE_NAME = "allowance-usage.json"
    ACTIONS_NAME = "scheduled-actions.json"
    DELAY_BREAKS_NAME = "delay-breaks.json"
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

    @property
    def website_statistics_path(self) -> Path:
        return self.directory / self.WEBSITE_STATISTICS_NAME

    @property
    def website_usage_path(self) -> Path:
        return self.directory / self.WEBSITE_USAGE_NAME
    @property
    def allowance_usage_path(self) -> Path:
        return self.directory / self.ALLOWANCE_USAGE_NAME
    @property
    def delay_breaks_path(self) -> Path:
        return self.directory / self.DELAY_BREAKS_NAME

    def initialize(self) -> None:
        if self.directory.exists() and self.directory.is_symlink():
            raise StorageError("storage directory is a symlink")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise StorageError("storage path is not a directory")
        os.chmod(self.directory, 0o700)
        self._key = self._load_or_create_key()
    @property
    def actions_path(self) -> Path:
        return self.directory / self.ACTIONS_NAME

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
        try:
            return format_utc(value)
        except CanonicalError as error:
            raise StorageError("high-water time must be aware UTC") from error

    @staticmethod
    def _parse_utc(value: Any) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise StorageError("high-water time is invalid")
        try:
            return parse_utc(value)
        except CanonicalError as error:
            raise StorageError("high-water time is invalid") from error

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

    def _statistics_envelope(self, state) -> bytes:
        if not isinstance(
            state,
            (
                StatisticsState,
                WebsiteDenialState,
                WebsiteUsageState,
                AllowanceUsageState,
                ScheduledActionsState,
                DelayBreakState,
            ),
        ):
            raise StorageError("signed state has an invalid type")
        unsigned = {"version": 1, "payload": state.to_dict()}
        signature = hmac.new(
            self._require_key(),
            self._canonical(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return self._canonical({**unsigned, "hmac": signature})
    def _save_signed_state(
        self,
        path: Path,
        state: StatisticsState | WebsiteDenialState | WebsiteUsageState | AllowanceUsageState | ScheduledActionsState | DelayBreakState,
        name: str,
    ) -> None:
        """Atomically save one signed state; ``name`` labels errors."""
        self.initialize()
        content = self._statistics_envelope(state)
        if len(content) > self.MAX_STATISTICS_BYTES:
            raise StorageError(f"{name} file is too large")
        self._atomic_write(path, content)

    def _load_signed_state(self, path: Path, empty, from_payload, name: str):
        """Load one signed statistics state, or an empty state when absent."""
        self.initialize()
        if not path.exists():
            return empty()
        if path.is_symlink() or not path.is_file():
            raise StorageError(f"{name} path is not a regular file")
        if path.stat().st_size > self.MAX_STATISTICS_BYTES:
            raise StorageError(f"{name} file is too large")
        try:
            envelope = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError(f"{name} file is invalid") from exc
        _, payload = self._verify_envelope(envelope, {1}, name)
        try:
            return from_payload(payload)
        except (TypeError, ValueError, KeyError) as exc:
            raise StorageError(f"{name} payload is invalid") from exc

    def save_statistics(self, state: StatisticsState) -> None:
        """Atomically save observational statistics without touching policy files."""
        self._save_signed_state(self.statistics_path, state, "statistics")

    def load_statistics(self) -> StatisticsState:
        """Load signed statistics, or return an empty state when absent."""
        return self._load_signed_state(
            self.statistics_path,
            StatisticsState.empty,
            StatisticsState.from_dict,
            "statistics",
        )

    def save_website_statistics(self, state: WebsiteDenialState) -> None:
        """Atomically save website denials into their own signed file."""
        self._save_signed_state(
            self.website_statistics_path, state, "website statistics"
        )

    def load_website_statistics(self) -> WebsiteDenialState:
        """Load signed website statistics, or an empty state when absent."""
        return self._load_signed_state(
            self.website_statistics_path,
            WebsiteDenialState.empty,
            WebsiteDenialState.from_dict,
            "website statistics",
        )

    def save_website_usage(self, state: WebsiteUsageState) -> None:
        """Atomically save per-rule daily starts into their own signed file."""
        self._save_signed_state(self.website_usage_path, state, "website usage")

    def load_website_usage(self) -> WebsiteUsageState:
        """Load signed website usage, or an empty state when absent."""
        return self._load_signed_state(
            self.website_usage_path,
            WebsiteUsageState.empty,
            WebsiteUsageState.from_dict,
            "website usage",
        )

    def save_allowance_usage(self, state: AllowanceUsageState) -> None:
        """Atomically save the root-owned elapsed allowance ledger."""
        self._save_signed_state(
            self.allowance_usage_path, state, "allowance usage"
        )

    def load_allowance_usage(self) -> AllowanceUsageState:
        """Load the signed elapsed allowance ledger, or an empty state."""
        return self._load_signed_state(
            self.allowance_usage_path,
            AllowanceUsageState.empty,
            AllowanceUsageState.from_dict,
            "allowance usage",
        )

    def save_delay_breaks(self, state: DelayBreakState) -> None:
        """Atomically save root-owned Delay runtime state."""
        self._save_signed_state(
            self.delay_breaks_path, state, "Delay breaks"
        )

    def load_delay_breaks(self) -> DelayBreakState:
        """Load signed Delay runtime state, or return an empty state."""
        return self._load_signed_state(
            self.delay_breaks_path,
            DelayBreakState.empty,
            DelayBreakState.from_dict,
            "Delay breaks",
        )

    def save_scheduled_actions(self, state: ScheduledActionsState) -> None:
        """Atomically save independently scheduled workstation actions."""
        self._save_signed_state(
            self.actions_path, state, "scheduled actions"
        )

    def load_scheduled_actions(self) -> ScheduledActionsState:
        """Load signed scheduled actions, or return an empty state."""
        return self._load_signed_state(
            self.actions_path,
            ScheduledActionsState.empty,
            ScheduledActionsState.from_dict,
            "scheduled actions",
        )


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

    def _verify_envelope(self, envelope: Any, versions: set[int], label: str) -> tuple[int, Any]:
        """Check one signed envelope's shape and HMAC; return version and payload.

        Breadcrumb: compare_digest avoids a timing leak from attacker-controlled
        signatures, and ``label`` keeps each file's error messages distinct.
        """
        if not isinstance(envelope, dict) or set(envelope) != {"version", "payload", "hmac"}:
            raise StorageError(f"{label} envelope is invalid")
        version = envelope["version"]
        if isinstance(version, bool) or version not in versions:
            raise StorageError(f"{label} version is invalid")
        signature = envelope["hmac"]
        if not isinstance(signature, str) or len(signature) != 64:
            raise StorageError(f"{label} signature is invalid")
        unsigned = {"version": version, "payload": envelope["payload"]}
        expected = hmac.new(self._require_key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise StorageError(f"{label} signature is invalid")
        return version, envelope["payload"]

    @staticmethod
    def _migrate_policy(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise StorageError("policy is invalid")
        if "schema_version" in data and (
            type(data["schema_version"]) is not int
            or data["schema_version"] not in {1, 2, 3, 4, 5, 6}
        ):
            raise StorageError("old policy schema version is invalid")
        migrated = dict(data)
        # Verified pre-v5 policies have no elapsed-time allowance fields.
        # Their rule shapes are a strict subset of the current schema, so
        # they can be authenticated and then forced into the current policy
        # schema version.
        migrated["schema_version"] = POLICY_SCHEMA_VERSION
        migrated.setdefault("managed_lists", [])
        rules = migrated.get("rules")
        if not isinstance(rules, list):
            raise StorageError("policy rules are invalid")
        converted_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise StorageError("policy rule is invalid")
            if "allowance_time" in rule:
                raise StorageError(
                    "old policy contains an unsupported elapsed-time allowance"
                )
            converted = dict(rule)
            schedule = converted.get("schedule")
            if isinstance(schedule, dict) and schedule.get("kind") == "weekly" and "periods" not in schedule:
                old = dict(schedule)
                required = {"kind", "timezone", "weekdays", "start", "end"}
                if set(old) != required:
                    raise StorageError("old weekly schedule is invalid")
                converted["schedule"] = {"kind": "weekly", "timezone": old["timezone"], "periods": [{"weekdays": old["weekdays"], "start": old["start"], "end": old["end"]}]}
            # Version 1.8 makes existing websites and managed-list references
            # browser-level by default; system enforcement is opt-in.
            converted.setdefault("system_blocking", False)
            converted.setdefault("system_targets", [])
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
        version, payload = self._verify_envelope(
            envelope,
            {1, 2, 3, 4, 5, 6, self.VERSION},
            "policy",
        )
        old_fields = {"clock_untrusted", "high_water_utc", "policy"}
        current_fields = old_fields | {"controls"}
        has_controls = version >= 3
        if (
            not isinstance(payload, dict)
            or set(payload) != (current_fields if has_controls else old_fields)
        ):
            raise StorageError("policy payload is invalid")
        if not isinstance(payload["clock_untrusted"], bool):
            raise StorageError("clock state is invalid")
        raw_policy = payload["policy"]
        policy_data = raw_policy
        if version != self.VERSION or (
            isinstance(raw_policy, dict)
            and raw_policy.get("schema_version") != POLICY_SCHEMA_VERSION
        ):
            policy_data = self._migrate_policy(raw_policy)
        policy = Policy.from_dict(policy_data)
        controls = (
            ControlState.from_dict(payload["controls"])
            if has_controls
            else ControlState.empty()
        )
        result = LoadResult(
            policy,
            controls,
            self._parse_utc(payload["high_water_utc"]),
            degraded,
            payload["clock_untrusted"],
        )
        if version != self.VERSION or policy_data is not raw_policy:
            # Breadcrumb: verify the old signature first, then write only the
            # converted current form.
            self.save(policy, controls, result.high_water_utc, result.clock_untrusted)
        return result
