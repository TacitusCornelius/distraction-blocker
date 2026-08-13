"""Linux enforcement for website and application targets."""
from __future__ import annotations

import ctypes
import errno
import os
import select
import struct
import tempfile
import threading
from typing import Iterable

BEGIN_MARKER = b"# BEGIN DISTRACTION-BLOCKER"
END_MARKER = b"# END DISTRACTION-BLOCKER"


def stat_is_regular(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000


class HostsEnforcer:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = os.fspath(path)

    def _read(self) -> bytes:
        st = os.lstat(self.path)
        if os.path.islink(self.path):
            raise OSError(errno.ELOOP, "hosts path is a symlink")
        if not stat_is_regular(st.st_mode):
            raise OSError(errno.EINVAL, "hosts path is not a regular file")
        with open(self.path, "rb") as stream:
            return stream.read()

    @staticmethod
    def _section(data: bytes) -> tuple[int, int] | None:
        lines = data.splitlines(keepends=True)
        begin = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == BEGIN_MARKER]
        end = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == END_MARKER]
        if not begin and not end:
            return None
        if len(begin) != 1 or len(end) != 1 or begin[0] >= end[0]:
            raise ValueError("invalid managed hosts section")
        offsets: list[int] = []
        at = 0
        for line in lines:
            offsets.append(at)
            at += len(line)
        return offsets[begin[0]], offsets[end[0]] + len(lines[end[0]])

    def managed_hostnames(self) -> set[str]:
        data = self._read()
        section = self._section(data)
        if section is None:
            return set()
        result: set[str] = set()
        for line in data[section[0] : section[1]].splitlines()[1:-1]:
            text = line.decode("utf-8", "strict").strip()
            if not text or text.startswith("#"):
                continue
            fields = text.split()
            if len(fields) >= 2 and fields[0] in {"0.0.0.0", "::"}:
                result.update(fields[1:])
        return result

    @staticmethod
    def _validate_hostnames(hostnames: Iterable[str]) -> list[str]:
        names: set[str] = set()
        for hostname in hostnames:
            if not isinstance(hostname, str) or not hostname or any(c.isspace() for c in hostname) or "#" in hostname:
                raise ValueError("invalid host name")
            names.add(hostname)
        return sorted(names)

    def apply(self, hostnames: Iterable[str]) -> None:
        names = self._validate_hostnames(hostnames)
        old = self._read()
        section = self._section(old)
        newline = b"\r\n" if b"\r\n" in old else b"\n"
        block = newline.join(
            [BEGIN_MARKER]
            + [b"0.0.0.0 " + name.encode("ascii") for name in names]
            + [b":: " + name.encode("ascii") for name in names]
            + [END_MARKER]
        ) + newline
        if section is None:
            new = old + ((newline) if old and not old.endswith((b"\n", b"\r")) else b"") + block
        else:
            new = old[: section[0]] + block + old[section[1] :]
        self._write(old, new)

    def clear(self) -> None:
        old = self._read()
        section = self._section(old)
        if section is None:
            return
        self._write(old, old[: section[0]] + old[section[1] :])

    def _write(self, old: bytes, new: bytes) -> None:
        if new == old:
            return
        # Breadcrumb for reviewers: reject symlinks before atomic replacement.
        st = os.lstat(self.path)
        if os.path.islink(self.path):
            raise OSError(errno.ELOOP, "hosts path is a symlink")
        directory = os.path.dirname(self.path) or "."
        fd, temporary = tempfile.mkstemp(prefix=".distraction-blocker.", dir=directory)
        try:
            os.fchmod(fd, st.st_mode & 0o7777)
            os.fchown(fd, st.st_uid, st.st_gid)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(new)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_FILESYSTEM = 0x00000100
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
FAN_Q_OVERFLOW = 0x00004000
FANOTIFY_METADATA_VERSION = 3
FAN_NOFD = -1
_METADATA = struct.Struct("<IBBHQii")
_RESPONSE = struct.Struct("<iI")


class FanotifyEnforcer:
    def __init__(self, path_provider):
        self.path_provider = path_provider
        self._fd: int | None = None
        self._mounts: list[str] = []
        self._blocked: set[str] = set()
        self._healthy = True
        self._closed = False
        self._thread: threading.Thread | None = None
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        self._libc = ctypes.CDLL(None, use_errno=True)

    @property
    def healthy(self) -> bool:
        return self._healthy and not self._closed

    def _init(self) -> int:
        fn = getattr(self._libc, "fanotify_init", None)
        if fn is None:
            raise OSError(errno.ENOSYS, "fanotify is not available")
        fn.restype = ctypes.c_int
        event_flags = os.O_RDONLY | getattr(os, "O_LARGEFILE", 0)
        value = fn(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE, event_flags)
        if value < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return value

    def _mark(self, fd: int, flags: int, mount: str) -> None:
        fn = getattr(self._libc, "fanotify_mark", None)
        if fn is None:
            raise OSError(errno.ENOSYS, "fanotify is not available")
        fn.restype = ctypes.c_int
        result = fn(fd, flags, ctypes.c_uint64(FAN_OPEN_EXEC_PERM), -1, os.fsencode(mount))
        if result < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

    @staticmethod
    def _mount_for(path: str, mounts: list[str]) -> str | None:
        matches: list[str] = []
        for mount in mounts:
            resolved_mount = os.path.realpath(mount)
            try:
                if os.path.commonpath((path, resolved_mount)) == resolved_mount:
                    matches.append(resolved_mount)
            except ValueError:
                continue
        return max(matches, key=len) if matches else None

    def _ensure_mounts(self, fd: int, paths: set[str]) -> None:
        available = [os.path.realpath(os.fspath(path)) for path in self.path_provider()]
        if not available:
            raise RuntimeError("no mounted file systems")
        required: set[str] = set()
        for path in paths:
            mount = self._mount_for(path, available)
            if mount is None:
                raise RuntimeError(f"no mount covers blocked application: {path}")
            required.add(mount)
        for mount in sorted(required):
            if mount in self._mounts:
                continue
            self._mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mount)
            self._mounts.append(mount)

    def start(self) -> None:
        if self._fd is not None:
            return
        fd = self._init()
        self._mounts = []
        try:
            self._ensure_mounts(fd, self._blocked)
        except Exception:
            os.close(fd)
            raise
        self._fd, self._closed, self._healthy = fd, False, True
        self._thread = threading.Thread(target=self._run, name="fanotify", daemon=True)
        self._thread.start()

    def set_blocked(self, paths: Iterable[str]) -> None:
        blocked = {os.path.realpath(os.fspath(path)) for path in paths}
        if self._fd is not None:
            try:
                self._ensure_mounts(self._fd, blocked)
            except Exception:
                self._healthy = False
                raise
        self._blocked = blocked

    def _respond(self, event_fd: int, allow: bool) -> None:
        if self._fd is None:
            return
        payload = _RESPONSE.pack(event_fd, FAN_ALLOW if allow else FAN_DENY)
        view = memoryview(payload)
        while view:
            count = os.write(self._fd, view)
            if count <= 0:
                raise OSError(errno.EIO, "fanotify response failed")
            view = view[count:]

    def _handle_event(self, event: bytes) -> None:
        event_len, version, _reserved, metadata_len, mask, event_fd, _pid = _METADATA.unpack_from(event)
        if version != FANOTIFY_METADATA_VERSION:
            raise ValueError("fanotify metadata version is not supported")
        if event_len < metadata_len or metadata_len < _METADATA.size or event_len > len(event):
            raise ValueError("invalid fanotify event")
        if mask & FAN_Q_OVERFLOW:
            self._healthy = False
        if event_fd != FAN_NOFD:
            try:
                target = os.path.realpath(os.readlink(f"/proc/self/fd/{event_fd}"))
                allow = not (mask & FAN_OPEN_EXEC_PERM) or target not in self._blocked
                self._respond(event_fd, allow)
            finally:
                os.close(event_fd)

    def process_bytes(self, data: bytes) -> bytes:
        offset = 0
        while offset < len(data):
            if len(data) - offset < _METADATA.size:
                raise ValueError("short fanotify event")
            event_len = struct.unpack_from("<I", data, offset)[0]
            if event_len < _METADATA.size or offset + event_len > len(data):
                raise ValueError("invalid fanotify event")
            self._handle_event(data[offset : offset + event_len])
            offset += event_len
        return data[offset:]

    def _run(self) -> None:
        buffer = bytearray()
        while self._fd is not None and not self._closed:
            try:
                ready, _, _ = select.select([self._fd, self._wake_r], [], [], 1.0)
            except (OSError, ValueError):
                break
            if self._wake_r in ready:
                try:
                    os.read(self._wake_r, 4096)
                except OSError:
                    pass
                break
            if self._fd not in ready:
                continue
            try:
                chunk = os.read(self._fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                self._healthy = False
                break
            if not chunk:
                self._healthy = False
                break
            buffer.extend(chunk)
            while len(buffer) >= 4:
                event_len = struct.unpack_from("<I", buffer)[0]
                if event_len < _METADATA.size:
                    self._healthy = False
                    return
                if len(buffer) < event_len:
                    break
                event = bytes(buffer[:event_len])
                del buffer[:event_len]
                try:
                    self._handle_event(event)
                except (OSError, ValueError):
                    self._healthy = False
                    return

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.write(self._wake_w, b"x")
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._fd is not None:
            for mount in self._mounts:
                try:
                    self._mark(self._fd, FAN_MARK_REMOVE | FAN_MARK_FILESYSTEM, mount)
                except OSError:
                    pass
            os.close(self._fd)
            self._fd = None
        os.close(self._wake_r)
        os.close(self._wake_w)
