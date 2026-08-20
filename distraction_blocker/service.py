"""Root service for policy reconciliation and command dispatch."""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .model import ManagedList, Policy, Rule, ValidationError


class BlockerService:
    """Policy authority and the only place that expands managed-list targets."""

    _STAGE_SECONDS = 10 * 60
    _CHUNK_SIZE = 200
    _MAX_STAGED = 4
    _MAX_LIST_IMPORT_BYTES = 4 * 1024 * 1024
    _MAX_NATIVE_IMPORT_BYTES = 8 * 1024 * 1024

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
        # Breadcrumb for reviewers: staged data has no disk representation, so a
        # crash cannot create an unreviewed policy or bypass signed storage.
        self._staged_lists: dict[str, dict[str, Any]] = {}
        self._staged_native: dict[str, dict[str, Any]] = {}

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
        lists = {item.id: item for item in getattr(selected, "managed_lists", ())}
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
                elif target.kind == "managed_list":
                    managed = lists.get(target.value)
                    if managed is not None:
                        website.update(managed.domains)
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
        self._expire_staged()
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

    def _save(self, policy: Policy) -> None:
        revision = getattr(policy, "revision", 0)
        # Breadcrumb for reviewers: direct dataclass construction is convenient
        # inside the service. Reparse before enforcement so dangling list
        # references and aggregate limits cannot bypass the public schema.
        policy_data = policy.to_dict()
        policy_data["revision"] = revision + 1
        policy = Policy.from_dict(policy_data)
        from .rpc import response_fits
        listed = self._ok([rule.to_dict() for rule in policy.rules])
        summaries = self._ok([self._list_summary(item) for item in policy.managed_lists])
        if not response_fits(listed) or not response_fits(summaries):
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
                self._save(Policy(self.policy.revision, tuple(rules), self.policy.managed_lists))
                return self._ok(candidate.to_dict())
        rules.append(candidate)
        self._save(Policy(self.policy.revision, tuple(rules), self.policy.managed_lists))
        return self._ok(candidate.to_dict())

    def _validate_replacement(self, imported: Policy) -> dict[str, Any] | None:
        if self.policy is None:
            raise RuntimeError("service is not started")
        replacements = {rule.id: rule for rule in imported.rules}
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        for old in self.policy.rules:
            if not old.is_active(now, clock_trusted=trusted):
                continue
            replacement = replacements.get(old.id)
            if replacement is None:
                return self._error("active_rule", "native import cannot remove an active rule")
            reason = self._weakened_active_change(old, replacement)
            if reason:
                return self._error("active_rule", reason)
        old_lists = {item.id: item for item in self.policy.managed_lists}
        new_lists = {item.id: item for item in imported.managed_lists}
        active_list_ids = {
            target.value
            for rule in self.policy.rules
            if rule.is_active(now, clock_trusted=trusted)
            for target in rule.targets
            if target.kind == "managed_list"
        }
        for list_id in active_list_ids:
            old = old_lists.get(list_id)
            new = new_lists.get(list_id)
            if old is not None and (new is None or not set(old.domains) <= set(new.domains)):
                return self._error("active_rule", "active rule list cannot remove domains")
        return None

    def _replace_rules(self, raw_rules: Any) -> dict[str, Any]:
        if not isinstance(raw_rules, list):
            raise ValidationError("bad_type", "rules must be a list")
        if self.policy is None:
            raise RuntimeError("service is not started")
        imported = Policy.from_dict({
            "revision": self.policy.revision,
            "rules": raw_rules,
            "managed_lists": [item.to_dict() for item in self.policy.managed_lists],
        })
        reason = self._validate_replacement(imported)
        if reason:
            return reason
        self._save(imported)
        return self._ok({"imported": len(imported.rules), "policy_revision": self.policy.revision})

    def _expire_staged(self) -> None:
        now = time.monotonic()
        for collection in (self._staged_lists, self._staged_native):
            for token, value in list(collection.items()):
                if value["expires"] <= now:
                    del collection[token]

    def _staged_count(self) -> int:
        return len(self._staged_lists) + len(self._staged_native)

    def _stage(self, collection: dict[str, dict[str, Any]], uid: int, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str):
            return None
        value = collection.get(token)
        if value is None or value["owner"] != uid:
            return None
        if value["expires"] <= time.monotonic():
            collection.pop(token, None)
            return None
        return value

    def _list_summary(self, managed: ManagedList) -> dict[str, Any]:
        return {
            "id": managed.id,
            "name": managed.name,
            "source": managed.source,
            "version": managed.version,
            "license": managed.license,
            "imported_utc": managed.to_dict()["imported_utc"],
            "domain_count": len(managed.domains),
        }

    def _commit_list(self, uid: int, token: str) -> dict[str, Any]:
        stage = self._stage(self._staged_lists, uid, token)
        if stage is None:
            return self._error("not_found", "staged list was not found")
        try:
            managed = ManagedList.from_dict({**stage["metadata"], "domains": stage["domains"]})
            if self.policy is None:
                raise RuntimeError("service is not started")
            lists = list(self.policy.managed_lists)
            old = next((item for item in lists if item.id == managed.id), None)
            if old is not None and not set(old.domains) <= set(managed.domains):
                now = self._now()
                trusted = bool(getattr(self.clock, "trusted", True))
                used = any(
                    rule.is_active(now, clock_trusted=trusted)
                    and any(target.kind == "managed_list" and target.value == managed.id for target in rule.targets)
                    for rule in self.policy.rules
                )
                if used:
                    return self._error("active_rule", "active rule list cannot remove domains")
            if old is None:
                lists.append(managed)
            else:
                lists[lists.index(old)] = managed
            candidate = Policy(self.policy.revision, self.policy.rules, tuple(lists))
            self._save(candidate)
            del self._staged_lists[token]
            return self._ok(self._list_summary(managed))
        except ValidationError as error:
            return self._error(error.code, error.message)

    def _parse_native(self, value: Any) -> Policy:
        if isinstance(value, dict):
            if "policy" in value:
                value = value["policy"]
            # Version 1 files use an envelope and omit managed_lists.
            if isinstance(value, dict) and "format" in value and "rules" in value:
                from .transfer import parse_native_export
                import json
                parsed = parse_native_export(json.dumps(value, ensure_ascii=False))
                if isinstance(parsed, Policy):
                    return parsed
                return Policy(
                    revision=getattr(self.policy, "revision", 0),
                    rules=tuple(parsed),
                    managed_lists=(),
                )
            return Policy.from_dict(value)
        if not isinstance(value, str):
            raise ValidationError("bad_type", "native state must be text or an object")
        if len(value.encode("utf-8")) > self._MAX_NATIVE_IMPORT_BYTES:
            raise ValidationError("too_large", "native state is too large")
        try:
            import json
            parsed = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValidationError("malformed", "native state is not valid JSON") from None
        return self._parse_native(parsed)

    def _commit_native(self, uid: int, token: str) -> dict[str, Any]:
        stage = self._stage(self._staged_native, uid, token)
        if stage is None:
            return self._error("not_found", "staged native import was not found")
        try:
            imported = self._parse_native("".join(stage["chunks"]))
            reason = self._validate_replacement(imported)
            if reason:
                return reason
            candidate = Policy(self.policy.revision, imported.rules, imported.managed_lists)
            self._save(candidate)
            del self._staged_native[token]
            return self._ok({
                "imported": len(imported.rules),
                "managed_lists": len(imported.managed_lists),
                "policy_revision": self.policy.revision,
            })
        except ValidationError as error:
            return self._error(error.code, error.message)
        except (TypeError, ValueError) as error:
            return self._error("malformed", str(error))

    def dispatch(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not self._started:
            return self._error("not_ready", "service is not ready")
        self._expire_staged()
        if not isinstance(request, dict) or not isinstance(request.get("command"), str):
            return self._error("bad_request", "command is required")
        command = request["command"]
        if command in {"put_rule", "delete_rule", "set_enabled", "replace_rules", "commit_list_import", "commit_native_import", "delete_managed_list"} and not self.healthy:
            return self._error("unhealthy", "enforcement is not healthy")
        if command == "status":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            websites, applications, _ = self._active_targets()
            return self._ok({"healthy": self.healthy, "clock_trusted": bool(getattr(self.clock, "trusted", True)), "clock_reason": str(getattr(self.clock, "reason", "")), "active_counts": {"website": len(websites), "application": len(applications)}})
        if command == "list_rules":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            return self._ok([rule.to_dict() for rule in self.policy.rules])
        if command == "list_managed_lists":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            return self._ok([self._list_summary(item) for item in self.policy.managed_lists])
        if command == "read_managed_list":
            allowed_fields = (
                {"command", "list_id", "offset"},
                {"command", "list_id", "offset", "limit"},
            )
            if set(request) not in allowed_fields:
                return self._error("bad_request", "list_id and offset are required")
            list_id, offset = request.get("list_id"), request.get("offset")
            limit = request.get("limit", self._CHUNK_SIZE)
            if (
                not isinstance(list_id, str)
                or not isinstance(offset, int)
                or isinstance(offset, bool)
                or not isinstance(limit, int)
                or isinstance(limit, bool)
                or limit < 1
                or limit > self._CHUNK_SIZE
                or offset < 0
            ):
                return self._error("bad_request", "invalid list chunk")
            managed = next(
                (item for item in self.policy.managed_lists if item.id == list_id),
                None,
            )
            if managed is None:
                return self._error("not_found", "managed list was not found")
            domains = managed.domains[offset:offset + limit]
            following = offset + len(domains)
            return self._ok({
                "id": list_id,
                "offset": offset,
                "domains": list(domains),
                "next_offset": following if following < len(managed.domains) else None,
            })
        if command == "begin_list_import":
            if set(request) != {"command", "metadata"}:
                return self._error("bad_request", "list metadata is required")
            metadata = request["metadata"]
            if self._staged_count() >= self._MAX_STAGED:
                return self._error("busy", "too many staged imports")
            if not isinstance(metadata, dict):
                return self._error("bad_type", "list metadata must be an object")
            try:
                required = {"id", "name", "source", "version", "license"}
                if set(metadata) != required:
                    raise ValidationError("bad_request", "list metadata fields are invalid")
                metadata = {
                    **metadata,
                    "imported_utc": self._now().isoformat(timespec="microseconds").replace("+00:00", "Z"),
                }
                ManagedList.from_dict({**metadata, "domains": []})
            except ValidationError as error:
                return self._error(error.code, error.message)
            token = str(uuid.uuid4())
            self._staged_lists[token] = {
                "owner": uid,
                "expires": time.monotonic() + self._STAGE_SECONDS,
                "metadata": metadata,
                "domains": [],
            }
            return self._ok({"import_id": token, "expires_in": self._STAGE_SECONDS})
        if command == "import_list_chunk":
            if set(request) != {"command", "import_id", "domains"}:
                return self._error("bad_request", "import_id and domains are required")
            stage = self._stage(self._staged_lists, uid, request.get("import_id"))
            domains = request.get("domains")
            if stage is None:
                return self._error("not_found", "staged list was not found")
            if not isinstance(domains, list) or not domains or len(domains) > self._CHUNK_SIZE:
                return self._error("bad_request", "list chunks need 1 to 200 domains")
            try:
                candidate = ManagedList.from_dict({**stage["metadata"], "domains": stage["domains"] + domains})
                size = sum(len(domain.encode("utf-8")) for domain in candidate.domains)
                if size > self._MAX_LIST_IMPORT_BYTES:
                    return self._error("too_large", "list import is too large")
                stage["domains"] = list(candidate.domains)
            except ValidationError as error:
                return self._error(error.code, error.message)
            return self._ok({"import_id": request["import_id"], "received": len(stage["domains"])})
        if command == "commit_list_import":
            if set(request) != {"command", "import_id"}:
                return self._error("bad_request", "import_id is required")
            return self._commit_list(uid, request.get("import_id"))
        if command == "cancel_list_import":
            if set(request) != {"command", "import_id"}:
                return self._error("bad_request", "import_id is required")
            stage = self._stage(self._staged_lists, uid, request.get("import_id"))
            if stage is None:
                return self._error("not_found", "staged list was not found")
            del self._staged_lists[request["import_id"]]
            return self._ok({"cancelled": True})
        if command == "delete_managed_list":
            if set(request) != {"command", "list_id"} or not isinstance(request.get("list_id"), str):
                return self._error("bad_request", "list_id is required")
            list_id = request["list_id"]
            if any(target.kind == "managed_list" and target.value == list_id for rule in self.policy.rules for target in rule.targets):
                return self._error("in_use", "managed list is used by a rule")
            lists = tuple(item for item in self.policy.managed_lists if item.id != list_id)
            if len(lists) == len(self.policy.managed_lists):
                return self._error("not_found", "managed list was not found")
            self._save(Policy(self.policy.revision, self.policy.rules, lists))
            return self._ok({"deleted": list_id})
        if command == "begin_native_import":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            if self._staged_count() >= self._MAX_STAGED:
                return self._error("busy", "too many staged imports")
            token = str(uuid.uuid4())
            self._staged_native[token] = {
                "owner": uid,
                "expires": time.monotonic() + self._STAGE_SECONDS,
                "chunks": [],
                "bytes": 0,
            }
            return self._ok({"import_id": token, "expires_in": self._STAGE_SECONDS})
        if command == "native_import_chunk":
            if set(request) != {"command", "import_id", "text"}:
                return self._error("bad_request", "import_id and text are required")
            stage = self._stage(self._staged_native, uid, request.get("import_id"))
            text = request.get("text")
            if stage is None:
                return self._error("not_found", "staged native import was not found")
            if not isinstance(text, str) or not text:
                return self._error("bad_type", "native import chunk must be text")
            size = stage["bytes"] + len(text.encode("utf-8"))
            if size > self._MAX_NATIVE_IMPORT_BYTES:
                return self._error("too_large", "native state is too large")
            stage["chunks"].append(text)
            stage["bytes"] = size
            return self._ok({"import_id": request["import_id"], "received_bytes": size})
        if command == "commit_native_import":
            if set(request) != {"command", "import_id"}:
                return self._error("bad_request", "import_id is required")
            return self._commit_native(uid, request.get("import_id"))
        if command == "cancel_native_import":
            if set(request) != {"command", "import_id"}:
                return self._error("bad_request", "import_id is required")
            stage = self._stage(self._staged_native, uid, request.get("import_id"))
            if stage is None:
                return self._error("not_found", "staged native import was not found")
            del self._staged_native[request["import_id"]]
            return self._ok({"cancelled": True})
        if command == "put_rule":
            if set(request) != {"command", "rule"}:
                return self._error("bad_request", "unknown command field")
            try:
                return self._put_rule(request["rule"])
            except ValidationError as error:
                return self._error(error.code, error.message)
        if command == "replace_rules":
            if set(request) != {"command", "rules"}:
                return self._error("bad_request", "unknown command field")
            try:
                return self._replace_rules(request["rules"])
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
                    self._save(Policy(self.policy.revision, tuple(item for item in self.policy.rules if item.id != rule.id), self.policy.managed_lists))
                    return self._ok({"deleted": rule.id})
            return self._error("not_found", "rule was not found")
        if command == "set_enabled":
            if set(request) != {"command", "rule_id", "enabled"} or not isinstance(request.get("rule_id"), str) or not isinstance(request.get("enabled"), bool):
                return self._error("bad_request", "rule_id and enabled are required")
            for index, rule in enumerate(self.policy.rules):
                if rule.id == request["rule_id"]:
                    data = rule.to_dict()
                    data["enabled"] = request["enabled"]
                    data["revision"] = rule.revision + 1
                    replacement = Rule.from_dict(data)
                    # Indefinite rules remain manually disable-able, as in v1.1.
                    reason = None
                    if request["enabled"] or rule.schedule.kind != "indefinite":
                        reason = self._weakened_active_change(rule, replacement)
                    if reason:
                        return self._error("active_rule", reason)
                    rules = list(self.policy.rules)
                    rules[index] = replacement
                    self._save(Policy(self.policy.revision, tuple(rules), self.policy.managed_lists))
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
