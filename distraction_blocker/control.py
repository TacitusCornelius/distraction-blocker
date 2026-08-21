"""Protected rule-lock state.

Control records stay separate from :class:`~distraction_blocker.model.Policy`.
Version 1.3 supports timed, friction, and password locks. A password lock
stores its scrypt parameter values beside the hash.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, Mapping

SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 1024



class ControlError(ValueError):
    """A control value does not satisfy the protected control schema."""


def _utc(value: Any, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        except ValueError as exc:
            raise ControlError(f"{label} must be an ISO UTC time") from exc
    else:
        raise ControlError(f"{label} must be an aware UTC time")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ControlError(f"{label} must be an aware UTC time")
    return parsed.astimezone(timezone.utc).replace(tzinfo=timezone.utc)


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _utc(value, "UTC time").isoformat(timespec="microseconds").replace("+00:00", "Z")


def _rule_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ControlError("rule_id must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ControlError("rule_id must be a UUID") from exc
    normalized = str(parsed)
    if normalized != value.lower():
        raise ControlError("rule_id must be a canonical UUID")
    return normalized


def _password_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ControlError("password must be text")
    encoded = value.encode("utf-8")
    if not PASSWORD_MIN_BYTES <= len(encoded) <= PASSWORD_MAX_BYTES:
        raise ControlError("password must contain 8 to 1024 UTF-8 bytes")
    return encoded

def _password_digest(
    password: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    return hashlib.scrypt(
        _password_bytes(password),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
        maxmem=32 * 1024 * 1024,
    )


def _validated_scrypt_params(n: Any, r: Any, p: Any) -> tuple[int, int, int]:
    """Normalize optional scrypt parameters; absent values take the defaults."""
    if n is None and r is None and p is None:
        return SCRYPT_N, SCRYPT_R, SCRYPT_P
    if n is None or r is None or p is None:
        raise ControlError("password scrypt parameters are incomplete")
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (n, r, p)
    ):
        raise ControlError("password scrypt parameters are invalid")
    if not (
        (1 << 10) <= n <= (1 << 22)
        and n & (n - 1) == 0
        and 1 <= r <= 64
        and 1 <= p <= 8
    ):
        raise ControlError("password scrypt parameters are out of range")
    # Breadcrumb: hashlib.scrypt fails when 128*n*r exceeds maxmem, so this
    # bound keeps every stored hash verifiable with the same memory budget.
    if 128 * n * r > 32 * 1024 * 1024:
        raise ControlError("password scrypt parameters exceed the memory budget")
    return n, r, p


@dataclass(frozen=True)
class RuleLock:
    """An immutable control for one rule."""

    rule_id: str
    kind: str
    until_utc: datetime | None = None
    salt_hex: str | None = None
    digest_hex: str | None = None
    failures: int = 0
    scrypt_n: int | None = None
    scrypt_r: int | None = None
    scrypt_p: int | None = None
    retry_after_utc: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _rule_id(self.rule_id))
        if self.kind == "timed":
            if (
                self.until_utc is None
                or self.salt_hex is not None
                or self.digest_hex is not None
                or self.failures != 0
                or self.retry_after_utc is not None
                or self.scrypt_n is not None
                or self.scrypt_r is not None
                or self.scrypt_p is not None
            ):
                raise ControlError("timed lock fields are invalid")
            object.__setattr__(
                self, "until_utc", _utc(self.until_utc, "until_utc")
            )
        elif self.kind == "friction":
            if any((
                self.until_utc is not None,
                self.salt_hex is not None,
                self.digest_hex is not None,
                self.failures != 0,
                self.retry_after_utc is not None,
                self.scrypt_n is not None,
                self.scrypt_r is not None,
                self.scrypt_p is not None,
            )):
                raise ControlError("friction lock fields are invalid")
        elif self.kind == "password":
            if self.until_utc is not None:
                raise ControlError("password lock fields are invalid")
            try:
                salt = bytes.fromhex(self.salt_hex or "")
                digest = bytes.fromhex(self.digest_hex or "")
            except ValueError as error:
                raise ControlError("password lock hash is invalid") from error
            if len(salt) != 16 or len(digest) != 32:
                raise ControlError("password lock hash is invalid")
            if (
                isinstance(self.failures, bool)
                or not isinstance(self.failures, int)
                or not 0 <= self.failures <= 64
            ):
                raise ControlError("password failure count is invalid")
            retry = self.retry_after_utc
            if retry is not None:
                retry = _utc(retry, "retry_after_utc")
            if self.failures == 0 and retry is not None:
                raise ControlError("password retry state is invalid")
            object.__setattr__(self, "retry_after_utc", retry)
            params = _validated_scrypt_params(
                self.scrypt_n, self.scrypt_r, self.scrypt_p
            )
            object.__setattr__(self, "scrypt_n", params[0])
            object.__setattr__(self, "scrypt_r", params[1])
            object.__setattr__(self, "scrypt_p", params[2])
        else:
            raise ControlError("lock kind is not supported")

    @classmethod
    def timed(cls, rule_id: str, until_utc: datetime) -> "RuleLock":
        return cls(rule_id, "timed", until_utc)

    @classmethod
    def friction(cls, rule_id: str) -> "RuleLock":
        return cls(rule_id, "friction")

    @classmethod
    def password_lock(
        cls,
        rule_id: str,
        password: str,
        *,
        salt: bytes | None = None,
    ) -> "RuleLock":
        actual_salt = secrets.token_bytes(16) if salt is None else salt
        if not isinstance(actual_salt, bytes) or len(actual_salt) != 16:
            raise ControlError("password salt is invalid")
        digest = _password_digest(password, actual_salt)
        return cls(
            rule_id,
            "password",
            salt_hex=actual_salt.hex(),
            digest_hex=digest.hex(),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleLock":
        if not isinstance(data, Mapping):
            raise ControlError("lock must be an object")
        kind = data.get("kind")
        if kind == "timed":
            if set(data) != {"rule_id", "kind", "until_utc"}:
                raise ControlError("timed lock fields are invalid")
            return cls.timed(data["rule_id"], data["until_utc"])
        if kind == "friction":
            if set(data) != {"rule_id", "kind"}:
                raise ControlError("friction lock fields are invalid")
            return cls.friction(data["rule_id"])
        if kind == "password":
            base = {
                "rule_id",
                "kind",
                "salt_hex",
                "digest_hex",
                "failures",
                "retry_after_utc",
            }
            # Breadcrumb: records written before parameter persistence lack
            # the three scrypt keys, so both shapes load.
            extended = base | {"scrypt_n", "scrypt_r", "scrypt_p"}
            if set(data) not in (base, extended):
                raise ControlError("password lock fields are invalid")
            return cls(
                data["rule_id"],
                "password",
                salt_hex=data["salt_hex"],
                digest_hex=data["digest_hex"],
                failures=data["failures"],
                retry_after_utc=data["retry_after_utc"],
                scrypt_n=data.get("scrypt_n"),
                scrypt_r=data.get("scrypt_r"),
                scrypt_p=data.get("scrypt_p"),
            )
        raise ControlError("lock kind is not supported")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "kind": self.kind,
        }
        if self.kind == "timed":
            result["until_utc"] = _utc_text(self.until_utc)
        elif self.kind == "password":
            result.update({
                "salt_hex": self.salt_hex,
                "digest_hex": self.digest_hex,
                "failures": self.failures,
                "retry_after_utc": _utc_text(self.retry_after_utc),
                "scrypt_n": self.scrypt_n,
                "scrypt_r": self.scrypt_r,
                "scrypt_p": self.scrypt_p,
            })
        return result

    def is_effective(
        self,
        now_utc: datetime,
        *,
        clock_trusted: bool = True,
        root: bool = False,
    ) -> bool:
        if not isinstance(clock_trusted, bool):
            raise ControlError("clock_trusted must be a boolean")
        if not isinstance(root, bool):
            raise ControlError("root must be a boolean")
        if root:
            return False
        if self.kind in {"friction", "password"}:
            return True
        if not clock_trusted:
            # Breadcrumb: an untrusted clock must not weaken a persisted lock.
            return True
        return _utc(now_utc, "now_utc") < self.until_utc

    def retry_seconds(self, now_utc: datetime) -> int:
        if self.kind != "password" or self.retry_after_utc is None:
            return 0
        remaining = (
            self.retry_after_utc - _utc(now_utc, "now_utc")
        ).total_seconds()
        return max(0, int(remaining + 0.999999))

    def verify_password(self, password: str) -> bool:
        if self.kind != "password":
            raise ControlError("lock does not use a password")
        actual = _password_digest(
            password,
            bytes.fromhex(self.salt_hex or ""),
            n=self.scrypt_n,
            r=self.scrypt_r,
            p=self.scrypt_p,
        )
        return hmac.compare_digest(
            actual, bytes.fromhex(self.digest_hex or "")
        )

    def with_password_failure(self, now_utc: datetime) -> "RuleLock":
        if self.kind != "password":
            raise ControlError("lock does not use a password")
        failures = min(64, self.failures + 1)
        delay = 1 << min(failures, 6)
        return RuleLock(
            self.rule_id,
            "password",
            salt_hex=self.salt_hex,
            digest_hex=self.digest_hex,
            scrypt_n=self.scrypt_n,
            scrypt_r=self.scrypt_r,
            scrypt_p=self.scrypt_p,
            failures=failures,
            retry_after_utc=_utc(now_utc, "now_utc")
            + timedelta(seconds=delay),
        )

    def with_password_success(self) -> "RuleLock":
        if self.kind != "password":
            raise ControlError("lock does not use a password")
        return RuleLock(
            self.rule_id,
            "password",
            salt_hex=self.salt_hex,
            digest_hex=self.digest_hex,
            scrypt_n=self.scrypt_n,
            scrypt_r=self.scrypt_r,
            scrypt_p=self.scrypt_p,
        )

    def to_summary(
        self,
        now_utc: datetime,
        *,
        clock_trusted: bool = True,
        root: bool = False,
    ) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "locked": self.is_effective(
                now_utc,
                clock_trusted=clock_trusted,
                root=root,
            ),
            "until_utc": (
                _utc_text(self.until_utc)
                if self.kind == "timed"
                else None
            ),
            "retry_after_utc": (
                _utc_text(self.retry_after_utc)
                if self.kind == "password"
                else None
            ),
        }




@dataclass(frozen=True)
class ControlState:
    """Immutable lock state kept beside, but never inside, a policy."""

    locks: tuple[RuleLock, ...] = ()

    def __post_init__(self) -> None:
        try:
            locks = tuple(self.locks)
        except TypeError as exc:
            raise ControlError("locks must be an iterable of RuleLock values") from exc
        if any(not isinstance(lock, RuleLock) for lock in locks):
            raise ControlError("locks must contain RuleLock values")
        if len({lock.rule_id for lock in locks}) != len(locks):
            raise ControlError("a rule cannot have multiple lock records")
        object.__setattr__(self, "locks", tuple(sorted(locks, key=lambda lock: lock.rule_id)))

    @classmethod
    def empty(cls) -> "ControlState":
        return cls()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ControlState":
        if not isinstance(data, Mapping) or set(data) != {"locks"}:
            raise ControlError("control state fields are invalid")
        locks = data["locks"]
        if not isinstance(locks, list):
            raise ControlError("control state locks must be a list")
        return cls(tuple(RuleLock.from_dict(item) for item in locks))

    def to_dict(self) -> dict[str, Any]:
        return {"locks": [lock.to_dict() for lock in self.locks]}

    def lock_for(self, rule_id: str) -> RuleLock | None:
        ident = _rule_id(rule_id)
        return next((lock for lock in self.locks if lock.rule_id == ident), None)

    def effective(
        self,
        rule_id: str,
        now_utc: datetime,
        clock_trusted: bool = True,
        *,
        root: bool = False,
    ) -> bool:
        if not isinstance(clock_trusted, bool):
            raise ControlError("clock_trusted must be a boolean")
        if not isinstance(root, bool):
            raise ControlError("root must be a boolean")
        lock = self.lock_for(rule_id)
        return lock is not None and lock.is_effective(
            now_utc,
            clock_trusted=clock_trusted,
            root=root,
        )

    def effective_lock(
        self,
        rule_id: str,
        now_utc: datetime,
        *,
        clock_trusted: bool = True,
        root: bool = False,
    ) -> RuleLock | None:
        lock = self.lock_for(rule_id)
        if lock is not None and lock.is_effective(now_utc, clock_trusted=clock_trusted, root=root):
            return lock
        return None

    def summaries(
        self,
        now_utc: datetime,
        *,
        clock_trusted: bool = True,
        root: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(lock.to_summary(now_utc, clock_trusted=clock_trusted, root=root) for lock in self.locks)

    def with_locks(self, locks: tuple[RuleLock, ...] | list[RuleLock]) -> "ControlState":
        return ControlState(tuple(locks))
