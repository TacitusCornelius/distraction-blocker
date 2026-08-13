"""Root service for policy reconciliation and command dispatch."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import stat
import time
from datetime import datetime, timezone
from typing import Any

from .model import Policy, Rule, ValidationError


class BlockerService:
    def __init__(self, store, clock, hosts, applications):
        self.store = store
        self.clock = clock
        self.hosts = hosts
        self.applications = applications
        self.policy: Policy | None = None
        self._started = False
        self._healthy = True
        self._last_checkpoint = time.monotonic()
        self._last_clock_trusted = bool(getattr(clock, "trusted", True))
        self._degraded = False

    @property
    def healthy(self) -> bool:
        app_health = getattr(self.applications, "healthy", True)
        return self._healthy and bool(app_health)

    def _now(self) -> datetime:
        now = self.clock.now()
        if not isinstance(now, datetime):
            raise RuntimeError("clock returned an invalid time")
        return now.astimezone(timezone.utc)

    def _active_targets(self, policy: Policy | None = None) -> tuple[set[str], set[str], list[Rule]]:
        active: list[Rule] = []
        website: set[str] = set()
        application: set[str] = set()
        selected = policy if policy is not None else self.policy
        if selected is None:
            return website, application, active
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        for rule in selected.rules:
            if not rule.is_active(now, clock_trusted=trusted):
                continue
            active.append(rule)
            for target in rule.targets:
                if target.kind == "website":
                    website.add(target.value)
                elif target.kind == "application":
                    application.add(target.value)
        return website, application, active

    def _reconcile(self, policy: Policy | None = None) -> None:
        websites, applications, _ = self._active_targets(policy)
        self.hosts.apply(websites)
        self.applications.set_blocked(applications)
        if not getattr(self.applications, "healthy", True):
            self._healthy = False

    def start(self) -> None:
        if self._started:
            return
        self.store.initialize()
        loaded = self.store.load()
        self.policy = getattr(loaded, "policy", loaded)
        self._degraded = bool(getattr(loaded, "degraded", False))
        if not isinstance(self.policy, Policy):
            self.policy = Policy.from_dict(self.policy)
        # Breadcrumb for reviewers: website state and fanotify marks apply before RPC starts.
        self._reconcile()
        self.applications.start()
        self._reconcile()
        self._started = True

    def tick(self) -> None:
        if not self._started:
            raise RuntimeError("service is not started")
        self._reconcile()
        if not self.healthy:
            raise RuntimeError("application enforcement is unhealthy")
        clock_trusted = bool(getattr(self.clock, "trusted", True))
        current = time.monotonic()
        clock_became_untrusted = self._last_clock_trusted and not clock_trusted
        if clock_became_untrusted or current - self._last_checkpoint >= 60:
            checkpoint = getattr(self.clock, "checkpoint", None)
            if checkpoint is not None:
                checkpoint()
            self._last_checkpoint = current
        self._last_clock_trusted = clock_trusted

    @staticmethod
    def _error(code: str, message: str) -> dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    @staticmethod
    def _ok(result: Any) -> dict[str, Any]:
        return {"ok": True, "result": result}

    @staticmethod
    def _fields(request: Any, command: str, required: set[str]) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("command") != command:
            return None
        if set(request) != {"command"} | required:
            return None
        return {name: request[name] for name in required}

    def _save(self, policy: Policy) -> None:
        revision = getattr(policy, "revision", 0)
        policy = Policy(revision=revision + 1, rules=policy.rules)
        from .rpc import response_fits

        listed = self._ok([rule.to_dict() for rule in policy.rules])
        if not response_fits(listed):
            raise ValidationError("too_large", "policy is too large for the service protocol")
        self._reconcile(policy)
        self.store.save(policy, self._now(), not bool(getattr(self.clock, "trusted", True)))
        self.policy = policy

    @staticmethod
    def _rule_active(rule: Rule, now: datetime, trusted: bool) -> bool:
        return rule.is_active(now, clock_trusted=trusted)

    def _weakened_active_change(self, old: Rule, new: Rule) -> str | None:
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        if not self._rule_active(old, now, trusted):
            return None
        if not new.enabled:
            return "active rule cannot be disabled"
        old_targets = {(target.kind, target.value) for target in old.targets}
        new_targets = {(target.kind, target.value) for target in new.targets}
        if not old_targets <= new_targets:
            return "active rule cannot remove targets"
        if old.schedule.kind != new.schedule.kind:
            return "active rule cannot shorten schedule"
        if old.schedule.kind == "one_time":
            if new.schedule.start_utc > old.schedule.start_utc or new.schedule.end_utc < old.schedule.end_utc:
                return "active rule cannot shorten schedule"
        elif old.schedule.to_dict() != new.schedule.to_dict():
            return "active weekly schedule cannot be changed"
        return None

    def _put_rule(self, raw: Any) -> dict[str, Any]:
        candidate = Rule.from_dict(raw)
        if self.policy is None:
            raise RuntimeError("service is not started")
        rules = list(self.policy.rules)
        for index, old in enumerate(rules):
            if old.id == candidate.id:
                reason = self._weakened_active_change(old, candidate)
                if reason:
                    return self._error("active_rule", reason)
                rules[index] = candidate
                self._save(Policy(self.policy.revision, tuple(rules)))
                return self._ok(candidate.to_dict())
        rules.append(candidate)
        self._save(Policy(self.policy.revision, tuple(rules)))
        return self._ok(candidate.to_dict())

    def dispatch(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not self._started:
            return self._error("not_ready", "service is not ready")
        if not isinstance(request, dict) or not isinstance(request.get("command"), str):
            return self._error("bad_request", "command is required")
        command = request["command"]
        if command in {"put_rule", "delete_rule", "set_enabled"} and not self.healthy:
            return self._error("unhealthy", "enforcement is not healthy")
        if command == "status":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            websites, applications, _ = self._active_targets()
            return self._ok({"healthy": self.healthy, "clock_trusted": bool(getattr(self.clock, "trusted", True)), "clock_reason": str(getattr(self.clock, "reason", "")), "active_targets": {"website": sorted(websites), "application": sorted(applications)}})
        if command == "list_rules":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            return self._ok([rule.to_dict() for rule in self.policy.rules])
        if command == "put_rule":
            if set(request) != {"command", "rule"}:
                return self._error("bad_request", "unknown command field")
            try:
                return self._put_rule(request["rule"])
            except ValidationError as error:
                return self._error(error.code, error.message)
        if command == "delete_rule":
            if set(request) != {"command", "rule_id"} or not isinstance(request.get("rule_id"), str):
                return self._error("bad_request", "rule_id is required")
            for rule in self.policy.rules:
                if rule.id == request["rule_id"]:
                    now = self._now()
                    if rule.is_active(now, bool(getattr(self.clock, "trusted", True))):
                        return self._error("active_rule", "active rule must be disabled before deletion")
                    rules = tuple(item for item in self.policy.rules if item.id != rule.id)
                    self._save(Policy(self.policy.revision, rules))
                    return self._ok({"deleted": rule.id})
            return self._error("not_found", "rule was not found")
        if command == "set_enabled":
            if set(request) != {"command", "rule_id", "enabled"} or not isinstance(request.get("rule_id"), str) or not isinstance(request.get("enabled"), bool):
                return self._error("bad_request", "rule_id and enabled are required")
            for index, rule in enumerate(self.policy.rules):
                if rule.id == request["rule_id"]:
                    if not request["enabled"] and rule.schedule.kind != "indefinite" and rule.is_active(self._now(), bool(getattr(self.clock, "trusted", True))):
                        return self._error("active_rule", "active rule cannot be disabled")
                    data = rule.to_dict()
                    data["enabled"] = request["enabled"]
                    data["revision"] = rule.revision + 1
                    replacement = Rule.from_dict(data)
                    rules = list(self.policy.rules)
                    rules[index] = replacement
                    self._save(Policy(self.policy.revision, tuple(rules)))
                    return self._ok(replacement.to_dict())
            return self._error("not_found", "rule was not found")
        if command == "clear_clock_latch":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            if uid != 0:
                return self._error("forbidden", "root access is required")
            clear_latch = getattr(self.clock, "clear_latch", None)
            if clear_latch is None:
                return self._error("unavailable", "clock recovery is not available")
            try:
                recovered = clear_latch()
            except RuntimeError as error:
                return self._error("clock_untrusted", str(error))
            return self._ok({"clock_trusted": True, "time_utc": recovered.isoformat()})
        return self._error("bad_request", "unknown command")


_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")


def _decode_mount_path(value: str) -> str:
    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _mounts() -> list[str]:
    mounts: list[str] = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) > 4:
                mounts.append(_decode_mount_path(fields[4]))
    return sorted(set(mounts))


def _system_time_synchronized() -> bool:
    try:
        result = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "yes"


def _read_owner_uid(data_dir: str) -> int:
    path = os.path.join(data_dir, "owner.uid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise ValueError("owner UID file is not protected")
        if metadata.st_mode & 0o077:
            raise ValueError("owner UID file permissions are not protected")
        raw = os.read(fd, 32)
        if os.read(fd, 1):
            raise ValueError("owner UID file is too large")
    finally:
        os.close(fd)
    owner_uid = int(raw.strip())
    if owner_uid <= 0 or owner_uid > 2**31 - 1:
        raise ValueError("owner UID is not valid")
    return owner_uid


def main(argv=None) -> int:
    if os.geteuid() != 0:
        print("The service requires root.")
        return 1
    from .clock import TrustedClock
    from .enforcement import FanotifyEnforcer, HostsEnforcer
    from .rpc import RpcServer
    from .storage import ProtectedStore

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="/var/lib/distraction-blocker")
    parser.add_argument("--hosts", default="/etc/hosts")
    parser.add_argument("--socket", default="/run/distraction-blocker/control.sock")
    parser.add_argument("--owner-uid", type=int)
    args = parser.parse_args(argv)
    try:
        owner_uid = args.owner_uid if args.owner_uid is not None else _read_owner_uid(args.data_dir)
    except (OSError, ValueError):
        print("The service needs a protected owner UID file.")
        return 1
    if owner_uid <= 0:
        print("The service needs the configured user UID.")
        return 1
    store = ProtectedStore(args.data_dir)
    store.initialize()
    state: dict[str, Any] = {"service": None}

    def write_clock(high_water, latch):
        current = state["service"]
        if current is not None and current.policy is not None:
            store.save(current.policy, high_water, latch)

    clock = TrustedClock(store.load, write_clock, _system_time_synchronized)
    hosts = HostsEnforcer(args.hosts)
    applications = FanotifyEnforcer(_mounts)
    service = BlockerService(store, clock, hosts, applications)
    state["service"] = service
    service.start()
    server = RpcServer(service, args.socket, owner_uid)
    try:
        server.serve_forever()
    finally:
        server.close()
        applications.close()
    return 0
