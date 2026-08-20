"""User-owned GUI preferences. No service state is stored here."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

THEMES = ("system", "light", "dark")
PREFERENCE_VERSION = 1


def preference_path() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    root = Path(configured) if configured else Path.home() / ".config"
    return root / "distraction-blocker" / "preferences.json"


def load_theme(path: str | os.PathLike[str] | None = None) -> str:
    source = Path(path) if path is not None else preference_path()
    try:
        if source.is_symlink() or not source.is_file():
            return "system"
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "system"
    if not isinstance(value, dict) or set(value) != {"version", "theme"}:
        return "system"
    if (
        isinstance(value["version"], bool)
        or value["version"] != PREFERENCE_VERSION
        or value["theme"] not in THEMES
    ):
        return "system"
    return value["theme"]


def save_theme(theme: str, path: str | os.PathLike[str] | None = None) -> None:
    if theme not in THEMES:
        raise ValueError("theme is not supported")
    destination = Path(path) if path is not None else preference_path()
    parent = destination.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise OSError("preference directory is not safe")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        metadata = os.lstat(destination)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("preference path is not a regular file")
    data = json.dumps(
        {"version": PREFERENCE_VERSION, "theme": theme},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".preferences-", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
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
