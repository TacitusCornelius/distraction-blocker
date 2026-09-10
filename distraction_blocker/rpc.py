"""Bounded, owner-checked Unix socket RPC."""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
from typing import Any

MAX_MESSAGE = 65536


class RpcError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")

def _response_bytes(result: dict[str, Any]) -> bytes:
    return json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def response_fits(result: dict[str, Any]) -> bool:
    return len(_response_bytes(result)) <= MAX_MESSAGE




class RpcServer:
    def __init__(self, service, socket_path: str | os.PathLike[str], owner_uid: int):
        self.service = service
        self.socket_path = os.fspath(socket_path)
        self.owner_uid = int(owner_uid)
        self._socket: socket.socket | None = None
        self._closed = False

    def _peer_uid(self, connection: socket.socket) -> int:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        if len(raw) != struct.calcsize("3i"):
            raise OSError("invalid peer credentials")
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid

    def _response(self, result: dict[str, Any]) -> bytes:
        return _response_bytes(result)

    def _read_request(self, connection: socket.socket) -> dict[str, Any]:
        data = bytearray()
        while len(data) <= MAX_MESSAGE:
            chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
        if len(data) > MAX_MESSAGE:
            raise RpcError("too_large", "request is too large")
        if data.count(b"\n") != 1 or not data.endswith(b"\n"):
            raise RpcError("malformed", "request must be one JSON line")
        line = bytes(data[:-1])
        if not line:
            raise RpcError("malformed", "request is empty")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RpcError("malformed", "request is not valid JSON") from None
        if not isinstance(value, dict):
            raise RpcError("malformed", "request must be an object")
        return value

    def _serve_connection(self, connection: socket.socket) -> None:
        connection.settimeout(1.0)
        try:
            try:
                peer_uid = self._peer_uid(connection)
            except OSError:
                peer_uid = -1
            if peer_uid not in {self.owner_uid, 0}:
                response = {"ok": False, "error": {"code": "forbidden", "message": "peer is not allowed"}}
            else:
                try:
                    request = self._read_request(connection)
                    response = self.service.dispatch(peer_uid, request)
                except RpcError as error:
                    response = {"ok": False, "error": {"code": error.code, "message": error.message}}
                except Exception as error:
                    # A policy mutation may fail after its enforcement-side
                    # checks (for example while preparing SafeSearch). Keep
                    # the daemon alive and return one bounded RPC error.
                    response = {"ok": False, "error": {"code": "service_error", "message": str(error)}}
            if not response_fits(response):
                response = {
                    "ok": False,
                    "error": {
                        "code": "response_too_large",
                        "message": "response is too large",
                    },
                }
            payload = self._response(response)
            try:
                connection.sendall(payload)
            except OSError:
                # Breadcrumb for reviewers: an allowed peer can close before the reply.
                pass
        finally:
            connection.close()

    def serve_forever(self) -> None:
        if self._socket is not None:
            raise RuntimeError("RPC server is already running")
        parent = os.path.dirname(self.socket_path) or "."
        os.makedirs(parent, mode=0o755, exist_ok=True)
        try:
            st = os.lstat(self.socket_path)
            if stat.S_ISLNK(st.st_mode):
                raise OSError("socket path is a symlink")
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)
            os.chown(self.socket_path, self.owner_uid, os.getgid())
            server.listen(16)
            server.settimeout(1.0)
            self._socket = server
            self._closed = False
            while not self._closed:
                self.service.tick()
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._closed:
                        break
                    raise
                self._serve_connection(connection)
        finally:
            self._socket = None
            server.close()
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass

    def close(self) -> None:
        self._closed = True
        if self._socket is not None:
            self._socket.close()
            self._socket = None


class Client:
    def __init__(self, socket_path: str | os.PathLike[str] = "/run/distraction-blocker/control.sock"):
        self.socket_path = os.fspath(socket_path)

    def request(self, command: str, **fields: Any) -> Any:
        if not isinstance(command, str) or not command:
            raise RpcError("bad_request", "command is required")
        request = {"command": command, **fields}
        payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        if len(payload) > MAX_MESSAGE:
            raise RpcError("too_large", "request is too large")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(self.socket_path)
            connection.sendall(payload)
            data = bytearray()
            while len(data) <= MAX_MESSAGE:
                chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in chunk:
                    break
            if len(data) > MAX_MESSAGE or data.count(b"\n") != 1 or not data.endswith(b"\n"):
                raise RpcError("malformed", "response is malformed")
            try:
                response = json.loads(bytes(data[:-1]).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RpcError("malformed", "response is not valid JSON") from None
            if not isinstance(response, dict) or set(response) != {"ok", "result"} and set(response) != {"ok", "error"}:
                raise RpcError("malformed", "response is malformed")
            if response.get("ok") is True:
                return response["result"]
            error = response.get("error")
            if not isinstance(error, dict) or set(error) != {"code", "message"}:
                raise RpcError("malformed", "response error is malformed")
            raise RpcError(str(error["code"]), str(error["message"]))
        except OSError as error:
            raise RpcError("connection", "cannot connect to service") from error
        finally:
            connection.close()
