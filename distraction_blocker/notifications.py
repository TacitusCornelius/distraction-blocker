"""Best-effort GNOME notification suppression for the current desktop user."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any


_SCHEMA_VERSION = 1
_SCHEMA = "org.gnome.desktop.notifications"
_KEYS = ("show-banners", "show-in-lock-screen")


class NotificationControlError(RuntimeError):
    """The desktop notification backend could not be controlled."""


@dataclass(frozen=True)
class NotificationState:
    show_banners: bool
    show_in_lock_screen: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": _SCHEMA_VERSION,
            "show_banners": self.show_banners,
            "show_in_lock_screen": self.show_in_lock_screen,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "NotificationState":
        if not isinstance(value, dict) or set(value) != {
            "version", "show_banners", "show_in_lock_screen"
        }:
            raise ValueError("notification state is invalid")
        if value["version"] != _SCHEMA_VERSION or not all(
            isinstance(value[key], bool)
            for key in ("show_banners", "show_in_lock_screen")
        ):
            raise ValueError("notification state is invalid")
        return cls(value["show_banners"], value["show_in_lock_screen"])


def state_path() -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return root / "distraction-blocker" / "notifications.json"


def _gsettings(operation: str, key: str, value: str | None = None) -> str:
    command = ["/usr/bin/gsettings", operation, _SCHEMA, key]
    if value is not None:
        command.append(value)
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NotificationControlError(
            "GNOME notification settings are unavailable"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise NotificationControlError(
            "GNOME notification settings rejected the request"
            + (f": {detail}" if detail else "")
        )
    return result.stdout.strip()


def _read_bool(key: str) -> bool:
    raw = _gsettings("get", key).lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise NotificationControlError("GNOME returned an invalid notification setting")


def current_state() -> NotificationState:
    return NotificationState(*(_read_bool(key) for key in _KEYS))

def _write_saved(state: NotificationState) -> None:
    destination = state_path()
    parent = destination.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise NotificationControlError("notification preference directory is unsafe")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise NotificationControlError("notification preference path is unsafe")
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(
                json.dumps(
                    state.to_dict(), sort_keys=True, separators=(",", ":")
                )
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def _read_saved(source: Path | None = None) -> NotificationState | None:
    source = state_path() if source is None else source
    if source.is_symlink() or not source.is_file():
        return None
    try:
        return NotificationState.from_dict(json.loads(source.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise NotificationControlError("saved notification settings are invalid") from error


def block() -> NotificationState:
    """Disable notification banners and lock-screen notifications."""
    saved = _read_saved()
    if saved is None:
        saved = current_state()
        _write_saved(saved)
    for key in _KEYS:
        _gsettings("set", key, "false")
    return current_state()


def restore_saved_state(path: Path) -> NotificationState:
    """Restore a saved preference file, including during system uninstall."""
    saved = _read_saved(path)
    if saved is None:
        return current_state()
    for key, value in zip(_KEYS, (saved.show_banners, saved.show_in_lock_screen)):
        _gsettings("set", key, "true" if value else "false")
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    return current_state()


def unblock() -> NotificationState:
    """Restore values captured by :func:`block`, if any."""
    return restore_saved_state(state_path())


__all__ = [
    "NotificationControlError",
    "NotificationState",
    "block",
    "current_state",
    "restore_saved_state",
    "state_path",
]
