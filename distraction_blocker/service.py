"""Root service for policy reconciliation and command dispatch."""
from __future__ import annotations

import argparse
import hmac
import os
import re
import stat
import subprocess
import secrets
import sys
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from .control import ControlError, ControlState, RuleLock
from .model import ManagedList, Policy, Rule, ValidationError
from .schedule_view import ScheduleViewError, project_daily_schedule
from .statistics import DenialBuffer, StatisticsState


def _authorization_now() -> float:
    """Return elapsed time that includes Linux system suspend."""
    # CLOCK_BOOTTIME prevents a short grant from surviving a long suspend.
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class BlockerService:
    """Policy authority and the only place that expands managed-list targets."""

    _STAGE_SECONDS = 10 * 60
    _CHUNK_SIZE = 200
    _MAX_STAGED = 4
    _MAX_LIST_IMPORT_BYTES = 4 * 1024 * 1024
    _AUTH_SECONDS = 60
    _CHALLENGE_SECONDS = 2 * 60
    _MAX_AUTHORIZATIONS = 32
    _FRICTION_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    _MAX_NATIVE_IMPORT_BYTES = 8 * 1024 * 1024

    def __init__(self, store, clock, hosts, applications, denial_buffer=None):
        self.store = store
        self.clock = clock
        self.hosts = hosts
        self.applications = applications
        self.denial_buffer = (
            denial_buffer
            if denial_buffer is not None
            else getattr(applications, "denial_buffer", None)
        )
        if self.denial_buffer is None:
            self.denial_buffer = DenialBuffer()
        set_buffer = getattr(applications, "set_denial_buffer", None)
        if set_buffer is not None:
            set_buffer(self.denial_buffer)
        self.policy: Policy | None = None
        self.controls = ControlState.empty()
        self._statistics = StatisticsState.empty()
        self._statistics_dirty = False
        self._last_statistics_persist = time.monotonic()
        self._last_statistics_error: str | None = None
        self._active_application_rules: dict[str, tuple[str, ...]] = {}
        self._started = False
        self._closed = False
        self._healthy = True
        self._last_checkpoint = time.monotonic()
        self._last_clock_trusted = bool(getattr(clock, "trusted", True))
        self._degraded = False
        # Breadcrumb for reviewers: staged data has no disk representation, so a
        # crash cannot create an unreviewed policy or bypass signed storage.
        self._challenges: dict[str, dict[str, Any]] = {}
        self._grants: dict[tuple[int, str], float] = {}
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

    def _application_rule_map(
        self, active: Iterable[Rule]
    ) -> dict[str, tuple[str, ...]]:
        mapping: dict[str, set[str]] = {}
        for rule in active:
            for target in rule.targets:
                if target.kind != "application":
                    continue
                path = os.path.realpath(os.path.abspath(os.fspath(target.value)))
                mapping.setdefault(path, set()).add(rule.id)
        return {
            path: tuple(sorted(rule_ids))
            for path, rule_ids in mapping.items()
        }

    def _publish_application_rule_map(
        self, mapping: dict[str, tuple[str, ...]]
    ) -> None:
        self._active_application_rules = mapping
        setter = getattr(self.applications, "set_rule_ids_provider", None)
        if setter is not None:
            setter(lambda path: self._active_application_rules.get(
                os.path.realpath(os.path.abspath(os.fspath(path))), ()
            ))

    def _load_statistics(self) -> None:
        loader = getattr(self.store, "load_statistics", None)
        if loader is None:
            return
        try:
            loaded = loader()
            if loaded is None:
                return
            if isinstance(loaded, dict):
                loaded = StatisticsState.from_dict(loaded)
            if not isinstance(loaded, StatisticsState):
                raise TypeError("statistics loader returned an invalid state")
            self._statistics = loaded
        except Exception:
            # Statistics are observational. A bad stats file cannot degrade
            # policy health or change a fanotify decision.
            self._statistics = StatisticsState.empty()

    @staticmethod
    def _event_path(event) -> str:
        return os.path.realpath(os.path.abspath(os.fspath(
            getattr(event, "path", event)
        )))

    def _drain_statistics(self) -> None:
        drain = getattr(self.denial_buffer, "drain", None)
        if drain is None:
            return
        try:
            drained = drain()
        except Exception:
            return
        events = drained
        dropped_hint = 0
        if (
            isinstance(drained, tuple)
            and len(drained) == 2
            and isinstance(drained[1], int)
        ):
            events, dropped_hint = drained
        state = self._statistics
        try:
            for event in events:
                path = self._event_path(event)
                event_rule_ids = getattr(event, "rule_ids", ())
                if isinstance(event_rule_ids, str):
                    rule_ids = {event_rule_ids}
                else:
                    rule_ids = {
                        item for item in event_rule_ids
                        if isinstance(item, str)
                    }
                if not rule_ids:
                    rule_ids = set(
                        self._active_application_rules.get(path, ())
                    )
                stamp = getattr(event, "at_utc", None) or self._now()
                state = state.record(path, tuple(sorted(rule_ids)), stamp)
            # drain_into(limit=0) atomically reads and resets overflow without
            # consuming any additional events after the queue drain above.
            drain_into = getattr(self.denial_buffer, "drain_into", None)
            if drain_into is not None:
                try:
                    state = drain_into(state, limit=0)
                except TypeError:
                    state = drain_into(state)
            elif dropped_hint or getattr(self.denial_buffer, "dropped", 0):
                state = state.add_dropped(
                    dropped_hint or int(getattr(self.denial_buffer, "dropped", 0))
                )
        except Exception:
            # A statistics implementation failure is never enforcement failure.
            return
        if state != self._statistics:
            self._statistics = state
            self._statistics_dirty = True

    def _persist_statistics(self, force: bool = False) -> None:
        if not self._statistics_dirty:
            return
        if not force and time.monotonic() - self._last_statistics_persist < 5:
            return
        saver = getattr(self.store, "save_statistics", None)
        if saver is None:
            return
        try:
            saver(self._statistics)
        except Exception as error:
            # Statistics are observational, but silent permanent loss hid
            # real faults. Report each distinct failure once and throttle
            # retries; the state stays dirty so close() tries again.
            message = f"{type(error).__name__}: {error}"
            if message != self._last_statistics_error:
                print(
                    f"distraction-blocker: statistics persist failed: {message}",
                    file=sys.stderr,
                    flush=True,
                )
                self._last_statistics_error = message
            self._last_statistics_persist = time.monotonic()
            return
        self._statistics_dirty = False
        self._last_statistics_error = None
        self._last_statistics_persist = time.monotonic()
    def _statistics_result(self) -> dict[str, Any]:
        result = self._statistics.to_dict()
        # Breadcrumb: the state is path-bounded, and this second bound keeps
        # the normal RPC frame below MAX_MESSAGE for unusually long paths.
        from .rpc import response_fits
        while result["items"] and not response_fits(self._ok(result)):
            result["items"].pop()
        return result

    @property
    def statistics(self) -> StatisticsState:
        return self._statistics

    def _reconcile(self, policy: Policy | None = None) -> None:
        websites, applications, active = self._active_targets(policy)
        self._publish_application_rule_map(self._application_rule_map(active))
        self.hosts.apply(websites)
        self.applications.set_blocked(applications)
        if not getattr(self.applications, "healthy", True):
            self._healthy = False

    def start(self) -> None:
        if self._started:
            return
        self.store.initialize()
        self._load_statistics()
        loaded = self.store.load()
        self.policy = getattr(loaded, "policy", loaded)
        self.controls = getattr(loaded, "controls", ControlState.empty())
        self._degraded = bool(getattr(loaded, "degraded", False))
        if not isinstance(self.policy, Policy):
            self.policy = Policy.from_dict(self.policy)
        if not isinstance(self.controls, ControlState):
            self.controls = ControlState.from_dict(self.controls)
        known_rules = {rule.id for rule in self.policy.rules}
        if any(lock.rule_id not in known_rules for lock in self.controls.locks):
            raise RuntimeError("protected lock refers to an unknown rule")
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
        # Breadcrumb: only this main-thread tick drains and aggregates events.
        self._drain_statistics()
        self._persist_statistics()
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

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._started:
            self._drain_statistics()
            self._persist_statistics(force=True)
        close_applications = getattr(self.applications, "close", None)
        if close_applications is not None:
            try:
                close_applications()
            except Exception:
                # Fanotify cleanup must not hide a successful stats flush.
                pass

    @staticmethod
    def _error(code: str, message: str) -> dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    @staticmethod
    def _ok(result: Any) -> dict[str, Any]:
        return {"ok": True, "result": result}

    def _validate_control_refs(
        self, policy: Policy, controls: ControlState
    ) -> None:
        rule_ids = {rule.id for rule in policy.rules}
        if any(lock.rule_id not in rule_ids for lock in controls.locks):
            raise ControlError("protected lock refers to an unknown rule")

    def _save(
        self, policy: Policy, controls: ControlState | None = None
    ) -> None:
        revision = getattr(policy, "revision", 0)
        # Breadcrumb for reviewers: direct dataclass construction is convenient
        # inside the service. Reparse before enforcement so dangling list
        # references and aggregate limits cannot bypass the public schema.
        policy_data = policy.to_dict()
        policy_data["revision"] = revision + 1
        policy = Policy.from_dict(policy_data)
        selected_controls = controls if controls is not None else self.controls
        self._validate_control_refs(policy, selected_controls)
        from .rpc import response_fits
        listed = self._ok([rule.to_dict() for rule in policy.rules])
        summaries = self._ok([self._list_summary(item) for item in policy.managed_lists])
        if not response_fits(listed) or not response_fits(summaries):
            raise ValidationError("too_large", "policy is too large for the service protocol")
        # Breadcrumb for reviewers: persist before exposing a weaker live
        # policy. A failed signed write must leave enforcement unchanged.
        self.store.save(
            policy,
            selected_controls,
            self._now(),
            not bool(getattr(self.clock, "trusted", True)),
        )
        self.policy = policy
        self.controls = selected_controls
        self._reconcile(policy)

    def _save_controls(self, controls: ControlState) -> None:
        if self.policy is None:
            raise RuntimeError("service is not started")
        self._validate_control_refs(self.policy, controls)
        self.store.save(
            self.policy,
            controls,
            self._now(),
            not bool(getattr(self.clock, "trusted", True)),
        )
        self.controls = controls

    @staticmethod
    def _rule_active(rule: Rule, now: datetime, trusted: bool) -> bool:
        return rule.is_active(now, clock_trusted=trusted)

    @staticmethod
    def _weakened_change(old: Rule, new: Rule) -> bool:
        old_targets = {(target.kind, target.value) for target in old.targets}
        new_targets = {(target.kind, target.value) for target in new.targets}
        return (
            old.enabled and not new.enabled
            or not old_targets <= new_targets
            or old.schedule.to_dict() != new.schedule.to_dict()
        )

    def _has_grant(self, uid: int, rule_id: str) -> bool:
        expires = self._grants.get((uid, rule_id), 0.0)
        if expires <= _authorization_now():
            self._grants.pop((uid, rule_id), None)
            return False
        return True

    def _consume_grants(
        self, uid: int, rule_ids: set[str] | tuple[str, ...] | list[str]
    ) -> None:
        for rule_id in set(rule_ids):
            self._grants.pop((uid, rule_id), None)

    def _lock_refusal(
        self, uid: int, rule_ids: set[str] | tuple[str, ...] | list[str]
    ) -> dict[str, Any] | None:
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        for rule_id in sorted(set(rule_ids)):
            lock = self.controls.effective_lock(
                rule_id,
                now,
                clock_trusted=trusted,
                root=uid == 0,
            )
            if lock is None:
                continue
            if lock.kind != "timed" and self._has_grant(uid, rule_id):
                continue
            if lock.kind == "timed":
                until = lock.to_dict()["until_utc"]
                return self._error(
                    "timed_lock",
                    f"rule is protected by a timed lock until {until}",
                )
            return self._error(
                "authorization_required",
                "rule needs one-time authorization before this change",
            )
        return None

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
            return "active recurring schedule cannot be changed"
        return None

    def _put_rule(self, uid: int, raw: Any) -> dict[str, Any]:
        candidate = Rule.from_dict(raw)
        if self.policy is None:
            raise RuntimeError("service is not started")
        rules = list(self.policy.rules)
        for index, old in enumerate(rules):
            if old.id == candidate.id:
                reason = self._weakened_active_change(old, candidate)
                if reason:
                    return self._error("active_rule", reason)
                weakened = self._weakened_change(old, candidate)
                if weakened:
                    refusal = self._lock_refusal(uid, {old.id})
                    if refusal:
                        return refusal
                rules[index] = candidate
                self._save(
                    Policy(
                        self.policy.revision,
                        tuple(rules),
                        self.policy.managed_lists,
                    )
                )
                if weakened:
                    self._consume_grants(uid, {old.id})
                return self._ok(candidate.to_dict())
        rules.append(candidate)
        self._save(
            Policy(
                self.policy.revision,
                tuple(rules),
                self.policy.managed_lists,
            )
        )
        return self._ok(candidate.to_dict())

    def _validate_replacement(
        self, uid: int, imported: Policy
    ) -> dict[str, Any] | None:
        if self.policy is None:
            raise RuntimeError("service is not started")
        replacements = {rule.id: rule for rule in imported.rules}
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        for old in self.policy.rules:
            replacement = replacements.get(old.id)
            if old.is_active(now, clock_trusted=trusted):
                if replacement is None:
                    return self._error(
                        "active_rule",
                        "native import cannot remove an active rule",
                    )
                reason = self._weakened_active_change(old, replacement)
                if reason:
                    return self._error("active_rule", reason)
            if replacement is None or self._weakened_change(old, replacement):
                refusal = self._lock_refusal(uid, {old.id})
                if refusal:
                    return refusal
        old_lists = {item.id: item for item in self.policy.managed_lists}
        new_lists = {item.id: item for item in imported.managed_lists}
        for list_id, old in old_lists.items():
            new = new_lists.get(list_id)
            if new is not None and set(old.domains) <= set(new.domains):
                continue
            referencing = {
                rule.id
                for rule in self.policy.rules
                if any(
                    target.kind == "managed_list"
                    and target.value == list_id
                    for target in rule.targets
                )
            }
            if any(
                rule.id in referencing
                and rule.is_active(now, clock_trusted=trusted)
                for rule in self.policy.rules
            ):
                return self._error(
                    "active_rule",
                    "active rule list cannot remove domains",
                )
            refusal = self._lock_refusal(uid, referencing)
            if refusal:
                return refusal
        return None

    def _replacement_grant_ids(self, imported: Policy) -> set[str]:
        if self.policy is None:
            raise RuntimeError("service is not started")
        replacements = {rule.id: rule for rule in imported.rules}
        result = {
            old.id
            for old in self.policy.rules
            if (
                replacements.get(old.id) is None
                or self._weakened_change(old, replacements[old.id])
            )
        }
        new_lists = {item.id: item for item in imported.managed_lists}
        for old_list in self.policy.managed_lists:
            new_list = new_lists.get(old_list.id)
            if (
                new_list is not None
                and set(old_list.domains) <= set(new_list.domains)
            ):
                continue
            result.update(
                rule.id
                for rule in self.policy.rules
                if any(
                    target.kind == "managed_list"
                    and target.value == old_list.id
                    for target in rule.targets
                )
            )
        return result

    def _replace_rules(self, uid: int, raw_rules: Any) -> dict[str, Any]:
        if not isinstance(raw_rules, list):
            raise ValidationError("bad_type", "rules must be a list")
        if self.policy is None:
            raise RuntimeError("service is not started")
        imported = Policy.from_dict({
            "revision": self.policy.revision,
            "rules": raw_rules,
            "managed_lists": [
                item.to_dict() for item in self.policy.managed_lists
            ],
        })
        reason = self._validate_replacement(uid, imported)
        if reason:
            return reason
        grant_ids = self._replacement_grant_ids(imported)
        remaining_ids = {rule.id for rule in imported.rules}
        controls = self.controls.with_locks([
            lock for lock in self.controls.locks
            if lock.rule_id in remaining_ids
        ])
        self._save(imported, controls)
        self._consume_grants(uid, grant_ids)
        return self._ok({
            "imported": len(imported.rules),
            "policy_revision": self.policy.revision,
        })
    def _expire_staged(self) -> None:
        staged_now = time.monotonic()
        authorization_now = _authorization_now()
        for collection in (self._staged_lists, self._staged_native):
            for token, value in list(collection.items()):
                if value["expires"] <= staged_now:
                    del collection[token]
        for challenge_id, challenge in list(self._challenges.items()):
            if challenge["expires"] <= authorization_now:
                del self._challenges[challenge_id]
        for key, expires in list(self._grants.items()):
            if expires <= authorization_now:
                del self._grants[key]

    def _begin_rule_authorization(
        self, uid: int, rule_id: Any
    ) -> dict[str, Any]:
        if not isinstance(rule_id, str):
            return self._error("bad_request", "rule_id is required")
        if self.policy is None or not any(
            rule.id == rule_id for rule in self.policy.rules
        ):
            return self._error("not_found", "rule was not found")
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        lock = self.controls.effective_lock(
            rule_id,
            now,
            clock_trusted=trusted,
            root=uid == 0,
        )
        if lock is None:
            return self._error("not_locked", "rule has no effective lock")
        if lock.kind == "timed":
            return self._lock_refusal(uid, {rule_id})
        if lock.kind == "password":
            if not trusted:
                return self._error(
                    "clock_untrusted",
                    "password authorization needs a trusted clock",
                )
            retry = lock.retry_seconds(now)
            if retry:
                retry_at = lock.to_summary(now)["retry_after_utc"]
                return self._error(
                    "rate_limited",
                    f"password retry is available after {retry_at}",
                )
        if len(self._challenges) >= self._MAX_AUTHORIZATIONS:
            return self._error("busy", "too many authorization challenges")
        prompt = (
            "".join(
                secrets.choice(self._FRICTION_ALPHABET)
                for _index in range(12)
            )
            if lock.kind == "friction"
            else None
        )
        challenge_id = str(uuid.uuid4())
        self._challenges[challenge_id] = {
            "owner": uid,
            "rule_id": rule_id,
            "kind": lock.kind,
            "prompt": prompt,
            "expires": _authorization_now() + self._CHALLENGE_SECONDS,
        }
        return self._ok({
            "rule_id": rule_id,
            "kind": lock.kind,
            "challenge_id": challenge_id,
            "prompt": prompt,
            "expires_in": self._CHALLENGE_SECONDS,
        })

    def _complete_rule_authorization(
        self,
        uid: int,
        rule_id: Any,
        challenge_id: Any,
        response: Any,
    ) -> dict[str, Any]:
        if not all(
            isinstance(value, str)
            for value in (rule_id, challenge_id, response)
        ):
            return self._error(
                "bad_request",
                "rule_id, challenge_id, and response are required",
            )
        challenge = self._challenges.pop(challenge_id, None)
        if (
            challenge is None
            or challenge["owner"] != uid
            or challenge["rule_id"] != rule_id
            or challenge["expires"] <= _authorization_now()
        ):
            return self._error(
                "not_found", "authorization challenge was not found"
            )
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        lock = self.controls.effective_lock(
            rule_id,
            now,
            clock_trusted=trusted,
            root=uid == 0,
        )
        if lock is None or lock.kind != challenge["kind"]:
            return self._error(
                "not_locked", "rule lock changed before authorization"
            )
        if lock.kind == "friction":
            if not hmac.compare_digest(
                response.encode("utf-8"),
                (challenge["prompt"] or "").encode("utf-8"),
            ):
                return self._error(
                    "incorrect_response",
                    "authorization text did not match",
                )
        elif lock.kind == "password":
            if not trusted:
                return self._error(
                    "clock_untrusted",
                    "password authorization needs a trusted clock",
                )
            if lock.retry_seconds(now):
                return self._error(
                    "rate_limited",
                    "password retry delay is still active",
                )
            try:
                correct = lock.verify_password(response)
            except ControlError:
                correct = False
            replacement = (
                lock.with_password_success()
                if correct
                else lock.with_password_failure(now)
            )
            locks = [
                replacement if item.rule_id == rule_id else item
                for item in self.controls.locks
            ]
            self._save_controls(self.controls.with_locks(locks))
            if not correct:
                retry_at = replacement.to_summary(now)[
                    "retry_after_utc"
                ]
                return self._error(
                    "invalid_password",
                    f"password was not accepted; retry after {retry_at}",
                )
        else:
            return self._error(
                "bad_value", "lock kind is not supported"
            )
        if len(self._grants) >= self._MAX_AUTHORIZATIONS:
            return self._error("busy", "too many authorization grants")
        self._grants[(uid, rule_id)] = (
            _authorization_now() + self._AUTH_SECONDS
        )
        return self._ok({
            "rule_id": rule_id,
            "authorized": True,
            "expires_in": self._AUTH_SECONDS,
        })


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
            grant_ids: set[str] = set()
            lists = list(self.policy.managed_lists)
            old = next((item for item in lists if item.id == managed.id), None)
            if old is not None and not set(old.domains) <= set(managed.domains):
                now = self._now()
                trusted = bool(getattr(self.clock, "trusted", True))
                referencing = {
                    rule.id
                    for rule in self.policy.rules
                    if any(
                        target.kind == "managed_list"
                        and target.value == managed.id
                        for target in rule.targets
                    )
                }
                used = any(
                    rule.id in referencing
                    and rule.is_active(now, clock_trusted=trusted)
                    for rule in self.policy.rules
                )
                if used:
                    return self._error(
                        "active_rule",
                        "active rule list cannot remove domains",
                    )
                refusal = self._lock_refusal(uid, referencing)
                if refusal:
                    return refusal
                grant_ids = referencing
            if old is None:
                lists.append(managed)
            else:
                lists[lists.index(old)] = managed
            candidate = Policy(self.policy.revision, self.policy.rules, tuple(lists))
            self._save(candidate)
            self._consume_grants(uid, grant_ids)
            del self._staged_lists[token]
            return self._ok(self._list_summary(managed))
        except ValidationError as error:
            return self._error(error.code, error.message)

    def _start_focus(
        self, rule_id: Any, minutes: Any
    ) -> dict[str, Any]:
        if (
            not isinstance(rule_id, str)
            or isinstance(minutes, bool)
            or not isinstance(minutes, int)
            or not 1 <= minutes <= 1440
        ):
            return self._error(
                "bad_request",
                "rule_id and 1 to 1440 minutes are required",
            )
        if self.policy is None:
            raise RuntimeError("service is not started")
        source = next(
            (rule for rule in self.policy.rules if rule.id == rule_id),
            None,
        )
        if source is None:
            return self._error("not_found", "source rule was not found")
        now = self._now()
        focus = Rule.from_dict({
            "id": str(uuid.uuid4()),
            "name": f"Focus: {source.name}",
            "enabled": True,
            "targets": [
                target.to_dict() for target in source.targets
            ],
            "schedule": {
                "kind": "one_time",
                "start_utc": now.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
                "end_utc": (
                    now + timedelta(minutes=minutes)
                ).isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
            },
            "revision": 0,
        })
        rules = (*self.policy.rules, focus)
        self._save(
            Policy(
                self.policy.revision,
                rules,
                self.policy.managed_lists,
            )
        )
        return self._ok(focus.to_dict())

    def _daily_schedule(
        self, timezone_name: Any, day_text: Any
    ) -> dict[str, Any]:
        if not isinstance(timezone_name, str) or not isinstance(
            day_text, str
        ):
            return self._error(
                "bad_request", "timezone and date are required"
            )
        try:
            local_day = date.fromisoformat(day_text)
        except ValueError:
            return self._error(
                "bad_value", "date must be in YYYY-MM-DD form"
            )
        try:
            intervals = project_daily_schedule(
                self.policy.rules, local_day, timezone_name
            )
        except (ScheduleViewError, ValidationError, ValueError) as error:
            return self._error("bad_value", str(error))
        if len(intervals) > 512:
            return self._error(
                "too_large", "daily schedule has too many intervals"
            )
        result = {
            "date": day_text,
            "timezone": timezone_name,
            "intervals": [
                {
                    "rule_id": item.rule_id,
                    "rule_name": item.rule_name,
                    "start": item.start_local.isoformat(),
                    "end": item.end_local.isoformat(),
                }
                for item in intervals
            ],
        }
        from .rpc import response_fits
        if not response_fits(self._ok(result)):
            return self._error(
                "too_large", "daily schedule response is too large"
            )
        return self._ok(result)

    def _parse_native(self, value: Any) -> Policy:
        if isinstance(value, dict):
            if "policy" in value:
                value = value["policy"]
            # Version 1 files use an envelope and omit managed_lists.
            if (
                isinstance(value, dict)
                and "format" in value
                and "rules" in value
            ):
                from .transfer import parse_native_export
                import json
                parsed = parse_native_export(
                    json.dumps(value, ensure_ascii=False)
                )
                if isinstance(parsed, Policy):
                    return parsed
                return Policy(
                    revision=getattr(self.policy, "revision", 0),
                    rules=tuple(parsed),
                    managed_lists=(),
                )
            return Policy.from_dict(value)
        if not isinstance(value, str):
            raise ValidationError(
                "bad_type", "native state must be text or an object"
            )
        if len(value.encode("utf-8")) > self._MAX_NATIVE_IMPORT_BYTES:
            raise ValidationError(
                "too_large", "native state is too large"
            )
        try:
            import json
            parsed = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValidationError(
                "malformed", "native state is not valid JSON"
            ) from None
        return self._parse_native(parsed)


    def _commit_native(self, uid: int, token: str) -> dict[str, Any]:
        stage = self._stage(self._staged_native, uid, token)
        if stage is None:
            return self._error("not_found", "staged native import was not found")
        try:
            imported = self._parse_native("".join(stage["chunks"]))
            reason = self._validate_replacement(uid, imported)
            if reason:
                return reason
            candidate = Policy(
                self.policy.revision,
                imported.rules,
                imported.managed_lists,
            )
            grant_ids = self._replacement_grant_ids(imported)
            remaining_ids = {rule.id for rule in candidate.rules}
            controls = self.controls.with_locks([
                lock for lock in self.controls.locks
                if lock.rule_id in remaining_ids
            ])
            self._save(candidate, controls)
            self._consume_grants(uid, grant_ids)
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

    def _set_rule_lock(
        self, uid: int, rule_id: Any, raw_lock: Any
    ) -> dict[str, Any]:
        if not isinstance(rule_id, str):
            return self._error("bad_request", "rule_id is required")
        if self.policy is None:
            raise RuntimeError("service is not started")
        if not any(rule.id == rule_id for rule in self.policy.rules):
            return self._error("not_found", "rule was not found")
        if not isinstance(raw_lock, dict) or not isinstance(
            raw_lock.get("kind"), str
        ):
            return self._error("bad_request", "lock is required")
        current = self.controls.lock_for(rule_id)
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        current_effective = (
            current is not None
            and current.is_effective(
                now,
                clock_trusted=trusted,
                root=uid == 0,
            )
        )
        authorization_used = False
        kind = raw_lock["kind"]
        if kind == "none":
            if set(raw_lock) != {"kind"}:
                return self._error("bad_request", "lock fields are invalid")
            refusal = self._lock_refusal(uid, {rule_id})
            if refusal:
                return refusal
            authorization_used = current_effective
            replacement = None
        elif kind == "timed":
            if set(raw_lock) != {"kind", "until_utc"}:
                return self._error("bad_request", "lock fields are invalid")
            if not trusted:
                return self._error(
                    "clock_untrusted",
                    "a timed lock needs a trusted clock",
                )
            try:
                replacement = RuleLock.from_dict({
                    "rule_id": rule_id,
                    "kind": "timed",
                    "until_utc": raw_lock["until_utc"],
                })
            except ControlError as error:
                return self._error("bad_value", str(error))
            if replacement.until_utc <= now:
                return self._error(
                    "bad_value",
                    "timed lock expiry must be in the future",
                )
            if replacement.until_utc > now + timedelta(days=366):
                return self._error(
                    "bad_value",
                    "timed lock cannot exceed 366 days",
                )
            if current_effective:
                if current.kind == "timed":
                    if replacement.until_utc < current.until_utc:
                        return self._lock_refusal(uid, {rule_id})
                else:
                    refusal = self._lock_refusal(uid, {rule_id})
                    if refusal:
                        return refusal
                    authorization_used = True
        elif kind == "friction":
            if set(raw_lock) != {"kind"}:
                return self._error("bad_request", "lock fields are invalid")
            replacement = RuleLock.friction(rule_id)
            if current_effective and current.kind != "friction":
                refusal = self._lock_refusal(uid, {rule_id})
                if refusal:
                    return refusal
                authorization_used = True
        elif kind == "password":
            if set(raw_lock) != {"kind", "password"}:
                return self._error("bad_request", "lock fields are invalid")
            try:
                replacement = RuleLock.password_lock(
                    rule_id, raw_lock["password"]
                )
            except ControlError as error:
                return self._error("bad_value", str(error))
            if current_effective:
                refusal = self._lock_refusal(uid, {rule_id})
                if refusal:
                    return refusal
                authorization_used = True
        else:
            return self._error("bad_value", "lock kind is not supported")
        locks = [
            lock for lock in self.controls.locks
            if lock.rule_id != rule_id
        ]
        if replacement is not None:
            locks.append(replacement)
        controls = self.controls.with_locks(locks)
        self._save_controls(controls)
        if authorization_used:
            self._consume_grants(uid, {rule_id})
        if replacement is None:
            return self._ok({
                "rule_id": rule_id,
                "kind": "none",
                "locked": False,
                "until_utc": None,
                "retry_after_utc": None,
            })
        return self._ok(
            replacement.to_summary(now, clock_trusted=trusted)
        )

    def dispatch(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not self._started:
            return self._error("not_ready", "service is not ready")
        self._expire_staged()
        if not isinstance(request, dict) or not isinstance(request.get("command"), str):
            return self._error("bad_request", "command is required")
        command = request["command"]
        if command in {"put_rule", "delete_rule", "set_enabled", "replace_rules", "commit_list_import", "commit_native_import", "delete_managed_list", "set_rule_lock", "start_focus"} and not self.healthy:
            return self._error("unhealthy", "enforcement is not healthy")
        if command == "status":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            websites, applications, _ = self._active_targets()
            return self._ok({"healthy": self.healthy, "clock_trusted": bool(getattr(self.clock, "trusted", True)), "clock_reason": str(getattr(self.clock, "reason", "")), "active_counts": {"website": len(websites), "application": len(applications)}})
        if command == "start_focus":
            if set(request) != {"command", "rule_id", "minutes"}:
                return self._error(
                    "bad_request", "rule_id and minutes are required"
                )
            return self._start_focus(
                request["rule_id"], request["minutes"]
            )
        if command == "daily_schedule":
            if set(request) != {"command", "timezone", "date"}:
                return self._error(
                    "bad_request", "timezone and date are required"
                )
            return self._daily_schedule(
                request["timezone"], request["date"]
            )
        if command == "list_rules":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            return self._ok([rule.to_dict() for rule in self.policy.rules])
        if command == "list_locks":
            if set(request) != {"command"}:
                return self._error(
                    "bad_request", "unknown command field"
                )
            return self._ok(list(self.controls.summaries(
                self._now(),
                clock_trusted=bool(
                    getattr(self.clock, "trusted", True)
                ),
            )))
        if command == "list_denial_stats":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            return self._ok(self._statistics_result())
        if command == "clear_denial_stats":
            if set(request) != {"command"}:
                return self._error("bad_request", "unknown command field")
            self._statistics = self._statistics.clear()
            discard = getattr(self.denial_buffer, "discard", None)
            if discard is not None:
                # Breadcrumb: queued events would otherwise reappear on the
                # next tick and resurrect the data this command just cleared.
                discard()
            self._statistics_dirty = True
            self._persist_statistics(force=True)
            return self._ok({"cleared": True})
        if command == "set_rule_lock":
            if set(request) != {"command", "rule_id", "lock"}:
                return self._error(
                    "bad_request", "rule_id and lock are required"
                )
            return self._set_rule_lock(
                uid, request["rule_id"], request["lock"]
            )
        if command == "begin_rule_authorization":
            if set(request) != {"command", "rule_id"}:
                return self._error(
                    "bad_request", "rule_id is required"
                )
            return self._begin_rule_authorization(
                uid, request["rule_id"]
            )
        if command == "complete_rule_authorization":
            required = {
                "command",
                "rule_id",
                "challenge_id",
                "response",
            }
            if set(request) != required:
                return self._error(
                    "bad_request",
                    "authorization response fields are required",
                )
            return self._complete_rule_authorization(
                uid,
                request["rule_id"],
                request["challenge_id"],
                request["response"],
            )
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
                return self._put_rule(uid, request["rule"])
            except ValidationError as error:
                return self._error(error.code, error.message)
        if command == "replace_rules":
            if set(request) != {"command", "rules"}:
                return self._error("bad_request", "unknown command field")
            try:
                return self._replace_rules(uid, request["rules"])
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
                    refusal = self._lock_refusal(uid, {rule.id})
                    if refusal:
                        return refusal
                    controls = self.controls.with_locks([
                        lock for lock in self.controls.locks
                        if lock.rule_id != rule.id
                    ])
                    self._save(
                        Policy(
                            self.policy.revision,
                            tuple(
                                item for item in self.policy.rules
                                if item.id != rule.id
                            ),
                            self.policy.managed_lists,
                        ),
                        controls,
                    )
                    self._consume_grants(uid, {rule.id})
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
                    if rule.enabled and not replacement.enabled:
                        refusal = self._lock_refusal(uid, {rule.id})
                        if refusal:
                            return refusal
                    rules = list(self.policy.rules)
                    rules[index] = replacement
                    weakened = rule.enabled and not replacement.enabled
                    self._save(
                        Policy(
                            self.policy.revision,
                            tuple(rules),
                            self.policy.managed_lists,
                        )
                    )
                    if weakened:
                        self._consume_grants(uid, {rule.id})
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
            store.save(current.policy, current.controls, high_water, latch)

    clock = TrustedClock(store.load, write_clock, _system_time_synchronized)
    hosts = HostsEnforcer(args.hosts)
    denial_buffer = DenialBuffer()
    applications = FanotifyEnforcer(_mounts, denial_buffer)
    service = BlockerService(
        store, clock, hosts, applications, denial_buffer
    )
    state["service"] = service
    service.start()
    server = RpcServer(service, args.socket, owner_uid)
    try:
        server.serve_forever()
    finally:
        server.close()
        service.close()
    return 0
