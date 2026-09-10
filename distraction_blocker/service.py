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
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Any, Iterable

from .canonical import format_utc
from .control import ControlError, ControlState, RuleLock
from .model import (
    POLICY_SCHEMA_VERSION,
    ManagedList,
    Policy,
    PolicyProjection,
    Rule,
    Target,
    ValidationError,
)
from .schedule_view import ScheduleViewError, project_daily_schedule, system_timezone_name
from .statistics import DenialBuffer, StatisticsState, WebsiteDenialState, WebsiteUsageState, validate_report_value
from .storage import StorageError

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

    def __init__(self, store, clock, hosts, applications, denial_buffer=None, *, network=None):
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
        # Breadcrumb: FakeApplications in the tests has no denial_buffer
        # attribute until this call, so the fallback read above must stay.
        applications.set_denial_buffer(self.denial_buffer)
        # Breadcrumb: the network enforcer is an explicit opt-in. ``None``
        # (or ``available`` False) means network controls are unavailable,
        # never silently unenforced; the service then performs no network
        # side effects at all and refuses to persist network targets.
        self.network = network
        self._active_network: frozenset[str] = frozenset()
        self.policy: Policy | None = None
        self.controls = ControlState.empty()
        self._statistics = StatisticsState.empty()
        self._website_statistics = WebsiteDenialState.empty()
        self._website_usage = WebsiteUsageState.empty()
        self._cached_system_zone_name: str | None = None
        self._statistics_dirty = False
        self._last_statistics_persist = time.monotonic()
        self._last_statistics_error: str | None = None
        self._active_application_rules: dict[str, tuple[str, ...]] = {}
        self._started = False
        self._closed = False
        self._healthy = True
        self._last_checkpoint = time.monotonic()
        self._last_clock_trusted = bool(clock.trusted)
        self._degraded = False
        # Breadcrumb for reviewers: staged data has no disk representation, so a
        # crash cannot create an unreviewed policy or bypass signed storage.
        self._challenges: dict[str, dict[str, Any]] = {}
        self._grants: dict[tuple[int, str], float] = {}
        self._staged_lists: dict[str, dict[str, Any]] = {}
        self._staged_native: dict[str, dict[str, Any]] = {}

    @property
    def healthy(self) -> bool:
        if not self._healthy:
            return False
        if not bool(getattr(self.applications, "healthy", True)):
            return False
        network = self.network
        if network is None or not bool(getattr(network, "available", False)):
            # Breadcrumb (fail-closed): an unavailable enforcer with an
            # ACTIVE network policy means the persisted fence may be the
            # only protection left, so the service must report unhealthy.
            return not bool(self._active_network)
        return bool(getattr(network, "healthy", True))

    def _now(self) -> datetime:
        now = self.clock.now()
        if not isinstance(now, datetime):
            raise RuntimeError("clock returned an invalid time")
        return now.astimezone(timezone.utc)

    def _active_targets(
        self, policy: Policy | None = None
    ) -> tuple[set[str], set[str], frozenset[str], list[Rule]]:
        active: list[Rule] = []
        website: set[str] = set()
        application: set[str] = set()
        network: set[str] = set()
        selected = policy if policy is not None else self.policy
        if selected is None:
            return website, application, frozenset(), active
        lists = {item.id: item for item in getattr(selected, "managed_lists", ())}
        now = self._now()
        trusted = bool(getattr(self.clock, "trusted", True))
        # Breadcrumb (allowance seam): a budget-exhausted rule stays
        # ACTIVE-BLOCKING regardless of schedule or exceptions until its
        # local day resets, so its targets join the blocked set here.
        exhausted = self._exhausted_rule_ids(selected)
        for rule in selected.rules:
            if not rule.enabled:
                continue
            if rule.id not in exhausted and not rule.is_active(now, clock_trusted=trusted):
                continue
            active.append(rule)
            for target in rule.targets:
                if target.kind == "website":
                    website.add(target.value)
                elif target.kind == "application":
                    application.add(target.value)
                elif target.kind == "network":
                    network.add(target.value)
                elif target.kind == "managed_list":
                    managed = lists.get(target.value)
                    if managed is not None:
                        website.update(managed.domains)
        return website, application, frozenset(network), active

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
        try:
            loaded = self.store.load_statistics()
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

    def _load_website_statistics(self) -> None:
        try:
            loaded = self.store.load_website_statistics()
            if isinstance(loaded, WebsiteDenialState):
                self._website_statistics = loaded
        except Exception:
            # Observational data can never degrade policy health.
            self._website_statistics = WebsiteDenialState.empty()

    def _load_website_usage(self) -> None:
        try:
            loaded = self.store.load_website_usage()
            if isinstance(loaded, WebsiteUsageState):
                # Breadcrumb: lazy day reset — stale rows count as zero and
                # are pruned here so no timer is ever needed.
                self._website_usage = loaded.fresh(self._usage_day_for_rule_id)
        except Exception:
            # Observational data can never degrade policy health.
            self._website_usage = WebsiteUsageState.empty()

    def _system_zone_name(self) -> str:
        """Return the cached IANA name of the host time zone."""
        if self._cached_system_zone_name is None:
            try:
                self._cached_system_zone_name = system_timezone_name()
            except ScheduleViewError:
                # Breadcrumb: an unresolvable host zone must never break
                # reporting; UTC keeps day bucketing deterministic.
                self._cached_system_zone_name = "UTC"
        return self._cached_system_zone_name

    def _rule_zone_name(self, rule: Rule | None) -> str:
        """Resolve one rule's day-bucket zone from its own schedule."""
        if (
            rule is not None
            and rule.schedule.kind == "weekly"
            and rule.schedule.timezone_name
        ):
            return rule.schedule.timezone_name
        return self._system_zone_name()

    def _local_day_text(self, zone_name: str) -> str:
        try:
            zone = ZoneInfo(zone_name)
        except (ZoneInfoNotFoundError, ValueError):
            zone = timezone.utc
        return self._now().astimezone(zone).date().isoformat()

    def _usage_day_for_rule_id(
        self, rule_id: str, policy: Policy | None = None
    ) -> str | None:
        selected = policy if policy is not None else self.policy
        rule = next(
            (
                item
                for item in selected.rules
                if item.id == rule_id
                and item.allowance_starts is not None
                and all(
                    target.kind in Target.URL_LIKE_KINDS
                    for target in item.targets
                )
            ),
            None,
        ) if selected is not None else None
        if rule is None:
            return None
        return self._local_day_text(self._rule_zone_name(rule))

    def _pruned_website_usage(
        self, policy: Policy | None = None
    ) -> WebsiteUsageState:
        return self._website_usage.fresh(
            lambda rule_id: self._usage_day_for_rule_id(rule_id, policy)
        )

    def _exhausted_rule_ids(
        self,
        policy: Policy | None = None,
        *,
        usage: WebsiteUsageState | None = None,
    ) -> frozenset[str]:
        """Return enabled rules whose counted starts used up their budget.

        Breadcrumb (allowance seam): these ids drive three views that must
        agree — list_rules projection, daily-schedule projection, and
        website-target blocking in _active_targets.
        """
        selected = policy if policy is not None else self.policy
        if selected is None:
            return frozenset()
        current_usage = (
            usage
            if usage is not None
            else self._pruned_website_usage(selected)
        )
        exhausted: set[str] = set()
        for rule in selected.rules:
            if not rule.enabled or rule.allowance_starts is None:
                continue
            day = self._local_day_text(self._rule_zone_name(rule))
            if current_usage.count_for(rule.id, day) >= rule.allowance_starts:
                exhausted.add(rule.id)
        return frozenset(exhausted)

    def _policy_projection(
        self, policy: Policy | None = None
    ) -> dict[str, Any]:
        """Build the one strict projection shared by RPC and size checks."""
        selected = policy if policy is not None else self.policy
        if selected is None:
            raise RuntimeError("service is not started")
        return PolicyProjection.from_policy(
            selected, self._exhausted_rule_ids(selected)
        ).to_dict()


    @staticmethod
    def _event_path(event) -> str:
        return os.path.realpath(os.path.abspath(os.fspath(
            getattr(event, "path", event)
        )))

    def _drain_statistics(self) -> None:
        # Breadcrumb: denial_buffer is always a DenialBuffer — constructed
        # here when not injected — and DenialBuffer.drain returns a list.
        try:
            events = self.denial_buffer.drain()
        except Exception:
            return
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
            state = self.denial_buffer.drain_into(state, limit=0)
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
        try:
            self.store.save_statistics(self._statistics)
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
        websites, applications, network, active = self._active_targets(policy)
        self._publish_application_rule_map(self._application_rule_map(active))
        self.hosts.apply(websites)
        self.applications.set_blocked(applications)
        if not getattr(self.applications, "healthy", True):
            self._healthy = False
        self._reconcile_network(network)

    def _reconcile_network(self, controls: frozenset[str]) -> None:
        self._active_network = controls
        if self.network is None or not self.network.available:
            if controls:
                self._healthy = False
                raise StorageError("active network controls require network enablement")
            return
        try:
            self.network.reconcile(controls)
            if not self.network.healthy:
                raise StorageError("network enforcement is unhealthy")
        except Exception:
            self._healthy = False
            raise

    def start(self) -> None:
        if self._started:
            return
        self.store.initialize()
        self._load_statistics()
        self._load_website_statistics()
        loaded = self.store.load()
        self.policy = getattr(loaded, "policy", loaded)
        self.controls = getattr(loaded, "controls", ControlState.empty())
        self._degraded = bool(getattr(loaded, "degraded", False))
        if not isinstance(self.policy, Policy):
            self.policy = Policy.from_dict(self.policy)
        if not isinstance(self.controls, ControlState):
            self.controls = ControlState.from_dict(self.controls)
        # Breadcrumb: usage staleness resolves per-rule time zones, so the
        # load must wait until the policy (and its rules) is in memory.
        self._load_website_usage()
        try:
            # Validate the complete persisted policy, not only currently
            # active targets. A future network rule must never become
            # impossible to enforce after the service reports healthy.
            self._assert_network_supported(self.policy)
        except ValidationError as error:
            self._healthy = False
            raise StorageError(error.message) from error
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
            raise RuntimeError("enforcement is unhealthy")
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

    def _assert_network_supported(self, policy: Policy) -> None:
        # Breadcrumb: network targets are root-policy data. A service
        # without an opted-in enforcer must not persist a policy whose
        # network rules it cannot enforce; presence gates the save even
        # while a rule's schedule is inactive, because the rule may fire.
        if self.network is not None and bool(getattr(self.network, "available", False)):
            return
        for rule in policy.rules:
            if any(target.kind == "network" for target in rule.targets):
                raise ValidationError(
                    "network_unavailable",
                    "network enforcement is not enabled",
                )

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
        self._assert_network_supported(policy)
        selected_controls = controls if controls is not None else self.controls
        self._validate_control_refs(policy, selected_controls)
        projection = self._policy_projection(policy)
        summaries = self._ok(
            [self._list_summary(item) for item in policy.managed_lists]
        )
        from .rpc import response_fits
        if not response_fits(self._ok(projection)) or not response_fits(summaries):
            raise ValidationError(
                "too_large", "policy is too large for the service protocol"
            )
        # Breadcrumb for reviewers (fail-closed ordering): persist before
        # exposing a weaker live policy, and install the stronger union of
        # old and new active network controls BEFORE the signed write. A
        # failed save or failed union reconcile leaves the old stronger
        # enforcement in place; it is never removed here.
        if self.network is not None and bool(getattr(self.network, "available", False)):
            old_network = self._active_targets()[2]
            new_network = self._active_targets(policy)[2]
            if old_network or new_network:
                try:
                    self.network.reconcile(frozenset(old_network | new_network))
                    if not self.network.healthy:
                        raise StorageError("network enforcement is unhealthy")
                except Exception as error:
                    self._healthy = False
                    raise StorageError(
                        "network reconcile failed before policy save"
                    ) from error
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
        self._assert_network_supported(self.policy)
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
    def _weakened_allowance(old: Rule, new: Rule) -> bool:
        # Breadcrumb: an allowance increase, including None to a finite
        # allowance, is a weakening under the policy change contract.
        return (
            old.allowance_starts is None
            and new.allowance_starts is not None
        ) or (
            old.allowance_starts is not None
            and new.allowance_starts is not None
            and new.allowance_starts > old.allowance_starts
        )

    @staticmethod
    def _weakened_change(old: Rule, new: Rule) -> bool:
        old_targets = {(target.kind, target.value) for target in old.targets}
        new_targets = {(target.kind, target.value) for target in new.targets}
        old_exceptions = {
            (target.kind, target.value) for target in old.exceptions
        }
        new_exceptions = {
            (target.kind, target.value) for target in new.exceptions
        }
        return (
            old.enabled and not new.enabled
            or not old_targets <= new_targets
            or not new_exceptions <= old_exceptions
            or old.schedule.to_dict() != new.schedule.to_dict()
            or BlockerService._weakened_allowance(old, new)
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

    def _finalize_weakening(
        self,
        policy: Policy,
        uid: int,
        grant_ids: set[str] | tuple[str, ...] | list[str],
        controls: ControlState | None = None,
    ) -> None:
        """Persist a policy-weakening change, then burn its authorization grants.

        Breadcrumb: callers MUST settle _lock_refusal or _validate_replacement
        BEFORE this helper; it saves immediately and consumes grants.
        """
        self._save(policy, controls)
        self._consume_grants(uid, grant_ids)

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
        if self._weakened_allowance(old, new):
            return "active rule allowance cannot be weakened"
        old_targets = {(target.kind, target.value) for target in old.targets}
        new_targets = {(target.kind, target.value) for target in new.targets}
        if not old_targets <= new_targets:
            return "active rule cannot remove targets"
        if old.schedule.kind != new.schedule.kind:
            return "active rule cannot shorten schedule"
        if old.schedule.kind == "one_time":
            if (
                new.schedule.start_utc > old.schedule.start_utc
                or new.schedule.end_utc < old.schedule.end_utc
            ):
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

    def _referencing_rule_ids(self, list_id: str) -> set[str]:
        """Return ids of rules whose targets reference this managed list."""
        if self.policy is None:
            raise RuntimeError("service is not started")
        return {
            rule.id
            for rule in self.policy.rules
            if any(
                target.kind == "managed_list"
                and target.value == list_id
                for target in rule.targets
            )
        }

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
            referencing = self._referencing_rule_ids(list_id)
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
            result.update(self._referencing_rule_ids(old_list.id))
        return result

    def _replace_rules(self, uid: int, raw_rules: Any) -> dict[str, Any]:
        if not isinstance(raw_rules, list):
            raise ValidationError("bad_type", "rules must be a list")
        if self.policy is None:
            raise RuntimeError("service is not started")
        imported = Policy.from_dict({
            "schema_version": POLICY_SCHEMA_VERSION,
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
        self._finalize_weakening(imported, uid, grant_ids, controls)
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
                referencing = self._referencing_rule_ids(managed.id)
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
            self._finalize_weakening(candidate, uid, grant_ids)
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
                "start_utc": format_utc(now),
                "end_utc": format_utc(now + timedelta(minutes=minutes)),
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
                self.policy.rules,
                local_day,
                timezone_name,
                exhausted_rule_ids=self._exhausted_rule_ids(),
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
            self._finalize_weakening(candidate, uid, grant_ids, controls)
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

    # Command dispatch table. Each entry maps a command name to the allowed
    # request field sets, the exact bad_request message used when the fields
    # do not match, and the handler owning the command body.
    # Breadcrumb: these messages are wire-contract strings; tests assert them
    # byte-for-byte, so never reword them.
    _COMMANDS = {
        "status": ((frozenset({"command"}),), "unknown command field", "_cmd_status"),
        "start_focus": ((frozenset({"command", "rule_id", "minutes"}),), "rule_id and minutes are required", "_cmd_start_focus"),
        "daily_schedule": ((frozenset({"command", "timezone", "date"}),), "timezone and date are required", "_cmd_daily_schedule"),
        "list_rules": ((frozenset({"command"}),), "unknown command field", "_cmd_list_rules"),
        "list_locks": ((frozenset({"command"}),), "unknown command field", "_cmd_list_locks"),
        "list_denial_stats": ((frozenset({"command"}),), "unknown command field", "_cmd_list_denial_stats"),
        "clear_denial_stats": ((frozenset({"command"}),), "unknown command field", "_cmd_clear_denial_stats"),
        "set_rule_lock": ((frozenset({"command", "rule_id", "lock"}),), "rule_id and lock are required", "_cmd_set_rule_lock"),
        "begin_rule_authorization": ((frozenset({"command", "rule_id"}),), "rule_id is required", "_cmd_begin_rule_authorization"),
        "complete_rule_authorization": ((frozenset({"command", "rule_id", "challenge_id", "response"}),), "authorization response fields are required", "_cmd_complete_rule_authorization"),
        "list_managed_lists": ((frozenset({"command"}),), "unknown command field", "_cmd_list_managed_lists"),
        "read_managed_list": (
            (
                frozenset({"command", "list_id", "offset"}),
                frozenset({"command", "list_id", "offset", "limit"}),
            ),
            "list_id and offset are required",
            "_cmd_read_managed_list",
        ),
        "begin_list_import": ((frozenset({"command", "metadata"}),), "list metadata is required", "_cmd_begin_list_import"),
        "import_list_chunk": ((frozenset({"command", "import_id", "domains"}),), "import_id and domains are required", "_cmd_import_list_chunk"),
        "commit_list_import": ((frozenset({"command", "import_id"}),), "import_id is required", "_cmd_commit_list_import"),
        "cancel_list_import": ((frozenset({"command", "import_id"}),), "import_id is required", "_cmd_cancel_list_import"),
        "delete_managed_list": ((frozenset({"command", "list_id"}),), "list_id is required", "_cmd_delete_managed_list"),
        "begin_native_import": ((frozenset({"command"}),), "unknown command field", "_cmd_begin_native_import"),
        "native_import_chunk": ((frozenset({"command", "import_id", "text"}),), "import_id and text are required", "_cmd_native_import_chunk"),
        "commit_native_import": ((frozenset({"command", "import_id"}),), "import_id is required", "_cmd_commit_native_import"),
        "cancel_native_import": ((frozenset({"command", "import_id"}),), "import_id is required", "_cmd_cancel_native_import"),
        "put_rule": ((frozenset({"command", "rule"}),), "unknown command field", "_cmd_put_rule"),
        "replace_rules": ((frozenset({"command", "rules"}),), "unknown command field", "_cmd_replace_rules"),
        "delete_rule": ((frozenset({"command", "rule_id"}),), "rule_id is required", "_cmd_delete_rule"),
        "set_enabled": ((frozenset({"command", "rule_id", "enabled"}),), "rule_id and enabled are required", "_cmd_set_enabled"),
        "clear_clock_latch": ((frozenset({"command"}),), "unknown command field", "_cmd_clear_clock_latch"),
        # Breadcrumb: website statistics are observational, so reporting and
        # listing stay available even when enforcement is unhealthy.
        "list_website_stats": ((frozenset({"command"}),), "unknown command field", "_cmd_list_website_stats"),
        "report_website_denials": ((frozenset({"command", "entries"}),), "entries is required", "_cmd_report_website_denials"),
        "report_website_usage": ((frozenset({"command", "entries"}),), "entries is required", "_cmd_report_website_usage"),

    }
    def _cmd_list_rules(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        # Breadcrumb: the same projection is returned and size-checked by
        # _save, so an accepted policy always fits the RPC response frame.
        return self._ok(self._policy_projection())

    # Refused while enforcement is unhealthy. The gate runs before field
    # validation, exactly as the previous if-chain ordered it.
    _UNHEALTHY_COMMANDS = frozenset({
        "put_rule", "delete_rule", "set_enabled", "replace_rules",
        "commit_list_import", "commit_native_import",
        "delete_managed_list", "set_rule_lock", "start_focus",
    })

    def dispatch(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not self._started:
            return self._error("not_ready", "service is not ready")
        self._expire_staged()
        if not isinstance(request, dict) or not isinstance(request.get("command"), str):
            return self._error("bad_request", "command is required")
        command = request["command"]
        entry = self._COMMANDS.get(command)
        if entry is None:
            return self._error("bad_request", "unknown command")
        allowed, message, handler = entry
        if command in self._UNHEALTHY_COMMANDS and not self.healthy:
            return self._error("unhealthy", "enforcement is not healthy")
        if set(request) not in allowed:
            return self._error("bad_request", message)
        return getattr(self, handler)(uid, request)

    def _cmd_status(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        websites, applications, network, _ = self._active_targets()
        return self._ok({"healthy": self.healthy, "clock_trusted": bool(getattr(self.clock, "trusted", True)), "clock_reason": str(getattr(self.clock, "reason", "")), "active_counts": {"website": len(websites), "application": len(applications), "network": len(network)}})

    def _cmd_start_focus(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._start_focus(
            request["rule_id"], request["minutes"]
        )

    def _cmd_daily_schedule(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._daily_schedule(
            request["timezone"], request["date"]
        )


    def _cmd_list_locks(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._ok(list(self.controls.summaries(
            self._now(),
            clock_trusted=bool(
                getattr(self.clock, "trusted", True)
            ),
        )))

    def _cmd_list_denial_stats(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._ok(self._statistics_result())

    def _cmd_clear_denial_stats(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        self._statistics = self._statistics.clear()
        discard = getattr(self.denial_buffer, "discard", None)
        if discard is not None:
            # Breadcrumb: queued events would otherwise reappear on the
            # next tick and resurrect the data this command just cleared.
            discard()
        self._statistics_dirty = True
        self._persist_statistics(force=True)
        return self._ok({"cleared": True})

    def _cmd_set_rule_lock(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._set_rule_lock(
            uid, request["rule_id"], request["lock"]
        )

    def _cmd_list_website_stats(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        result = self._website_statistics.to_dict()
        # Additive projection: today's per-rule usage versus its allowance.
        usage = self._pruned_website_usage()
        exhausted = self._exhausted_rule_ids(usage=usage)
        usage_rows = []
        for rule in self.policy.rules:
            day = self._local_day_text(self._rule_zone_name(rule))
            count = usage.count_for(rule.id, day)
            if rule.allowance_starts is None and count == 0:
                continue
            usage_rows.append({
                "rule_id": rule.id,
                "day": day,
                "count": count,
                "allowance_starts": rule.allowance_starts,
                "budget_exhausted": rule.id in exhausted,
            })
        result["usage"] = usage_rows
        from .rpc import response_fits
        while result["items"] and not response_fits(self._ok(result)):
            result["items"].pop()
        if not response_fits(self._ok(result)):
            return self._error(
                "too_large", "website statistics response is too large"
            )
        return self._ok(result)

    def _cmd_report_website_usage(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        entries = request["entries"]
        if not isinstance(entries, list) or not entries or len(entries) > 128:
            return self._error(
                "bad_request", "entries must be a list of 1 to 128 items"
            )
        state = self._pruned_website_usage()
        try:
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {
                    "rule_id",
                    "value",
                    "count",
                }:
                    raise ValidationError("bad_value", "entry fields are invalid")
                rule_id = entry["rule_id"]
                value = entry["value"]
                count = entry["count"]
                if (
                    isinstance(rule_id, bool)
                    or not isinstance(rule_id, str)
                    or isinstance(value, bool)
                    or not isinstance(value, str)
                    or isinstance(count, bool)
                    or not isinstance(count, int)
                ):
                    raise ValidationError("bad_type", "entry types are invalid")
                day = self._usage_day_for_rule_id(rule_id)
                if day is None:
                    raise ValidationError(
                        "bad_value",
                        "rule ID is not eligible for website usage",
                    )
                # Breadcrumb: validate the whole batch before assigning state,
                # so an unknown row cannot evict a real allowance counter.
                try:
                    validate_report_value(value)
                    state = state.record(rule_id, count, day)
                except (TypeError, ValueError) as error:
                    raise ValidationError("bad_value", str(error)) from error
        except ValidationError as error:
            return self._error(error.code, error.message)
        accepted = len(state.items)
        dropped = state.dropped
        self._website_usage = state
        try:
            self.store.save_website_usage(state)
        except Exception:
            # Observational writes never block or fail the report.
            pass
        # Breadcrumb: the report may push a rule past its allowance, so
        # enforcement re-projects immediately instead of waiting for tick().
        self._reconcile()
        return self._ok({"accepted": accepted, "dropped": dropped})

    def _cmd_report_website_denials(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        entries = request["entries"]
        if not isinstance(entries, list) or not entries or len(entries) > 128:
            return self._error(
                "bad_request", "entries must be a list of 1 to 128 items"
            )
        stamp = self._now()
        state = self._website_statistics
        try:
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {
                    "rule_id",
                    "value",
                    "count",
                }:
                    raise ValidationError("bad_value", "entry fields are invalid")
                rule_id = entry["rule_id"]
                value = entry["value"]
                count = entry["count"]
                if (
                    isinstance(rule_id, bool)
                    or not isinstance(rule_id, str)
                    or isinstance(value, bool)
                    or not isinstance(value, str)
                    or isinstance(count, bool)
                    or not isinstance(count, int)
                ):
                    raise ValidationError("bad_type", "entry types are invalid")
                # Breadcrumb: record() revalidates the value bounds and the
                # canonical UUID form, so a hostile client cannot widen the
                # signed statistics file beyond its budget.
                try:
                    state = state.record(value, rule_id, stamp, times=count)
                except (TypeError, ValueError) as error:
                    raise ValidationError("bad_value", str(error)) from error
        except ValidationError as error:
            return self._error(error.code, error.message)
        accepted = len(state.items)
        dropped = state.dropped
        self._website_statistics = state
        try:
            self.store.save_website_statistics(state)
        except Exception:
            # Observational writes never block or fail the report.
            pass
        return self._ok({"accepted": accepted, "dropped": dropped})

    def _cmd_begin_rule_authorization(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._begin_rule_authorization(
            uid, request["rule_id"]
        )

    def _cmd_complete_rule_authorization(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._complete_rule_authorization(
            uid,
            request["rule_id"],
            request["challenge_id"],
            request["response"],
        )

    def _cmd_list_managed_lists(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._ok([self._list_summary(item) for item in self.policy.managed_lists])

    def _cmd_read_managed_list(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
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

    def _cmd_begin_list_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
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
                "imported_utc": format_utc(self._now()),
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

    def _cmd_import_list_chunk(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
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

    def _cmd_commit_list_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._commit_list(uid, request.get("import_id"))

    def _cmd_cancel_list_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        stage = self._stage(self._staged_lists, uid, request.get("import_id"))
        if stage is None:
            return self._error("not_found", "staged list was not found")
        del self._staged_lists[request["import_id"]]
        return self._ok({"cancelled": True})

    # The field-set half of the original compound guard lives in _COMMANDS;
    # the list_id type check below completes it with the same message.
    def _cmd_delete_managed_list(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request.get("list_id"), str):
            return self._error("bad_request", "list_id is required")
        list_id = request["list_id"]
        if any(target.kind == "managed_list" and target.value == list_id for rule in self.policy.rules for target in rule.targets):
            return self._error("in_use", "managed list is used by a rule")
        lists = tuple(item for item in self.policy.managed_lists if item.id != list_id)
        if len(lists) == len(self.policy.managed_lists):
            return self._error("not_found", "managed list was not found")
        self._save(Policy(self.policy.revision, self.policy.rules, lists))
        return self._ok({"deleted": list_id})

    def _cmd_begin_native_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
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

    def _cmd_native_import_chunk(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
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

    def _cmd_commit_native_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        return self._commit_native(uid, request.get("import_id"))

    def _cmd_cancel_native_import(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        stage = self._stage(self._staged_native, uid, request.get("import_id"))
        if stage is None:
            return self._error("not_found", "staged native import was not found")
        del self._staged_native[request["import_id"]]
        return self._ok({"cancelled": True})

    def _cmd_put_rule(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._put_rule(uid, request["rule"])
        except ValidationError as error:
            return self._error(error.code, error.message)

    def _cmd_replace_rules(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._replace_rules(uid, request["rules"])
        except ValidationError as error:
            return self._error(error.code, error.message)

    # The field-set half of the original compound guard lives in _COMMANDS;
    # the rule_id type check below completes it with the same message.
    def _cmd_delete_rule(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request.get("rule_id"), str):
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
                self._finalize_weakening(
                    Policy(
                        self.policy.revision,
                        tuple(
                            item for item in self.policy.rules
                            if item.id != rule.id
                        ),
                        self.policy.managed_lists,
                    ),
                    uid,
                    {rule.id},
                    controls,
                )
                return self._ok({"deleted": rule.id})
        return self._error("not_found", "rule was not found")

    # The field-set half of the original compound guard lives in _COMMANDS;
    # the rule_id/enabled type checks below complete it with the same message.
    def _cmd_set_enabled(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request.get("rule_id"), str) or not isinstance(request.get("enabled"), bool):
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

    def _cmd_clear_clock_latch(self, uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if uid != 0:
            return self._error("forbidden", "root access is required")
        # Breadcrumb: the clock is injectable, so a substitute without
        # clear_latch must read as "unavailable" instead of raising
        # AttributeError past _serve_connection and stopping the service.
        clear_latch = getattr(self.clock, "clear_latch", None)
        if not callable(clear_latch):
            return self._error("unavailable", "clock recovery is not available")
        try:
            recovered = clear_latch()
        except RuntimeError as error:
            return self._error("clock_untrusted", str(error))
        return self._ok({"clock_trusted": True, "time_utc": recovered.isoformat()})


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
    from .network_enforcement import NetworkEnforcer
    from .rpc import RpcServer
    from .storage import ProtectedStore

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="/var/lib/distraction-blocker")
    parser.add_argument("--hosts", default="/etc/hosts")
    parser.add_argument("--socket", default="/run/distraction-blocker/control.sock")
    parser.add_argument("--owner-uid", type=int)
    args = parser.parse_args(argv)
    try:
        if args.owner_uid is not None:
            # Breadcrumb for reviewers: --owner-uid is an operator override
            # that skips every protection _read_owner_uid enforces on the
            # owner.uid file (root-owned regular file, mode 0600, <=32 bytes).
            # main() already requires root, so we only mirror the value checks
            # _read_owner_uid applies to the parsed number: positive and
            # within 1..2**31-1. The file path stays the default.
            owner_uid = args.owner_uid
            if owner_uid <= 0 or owner_uid > 2**31 - 1:
                print("The service needs the configured user UID.")
                return 1
        else:
            owner_uid = _read_owner_uid(args.data_dir)
    except (OSError, ValueError):
        print("The service needs a protected owner UID file.")
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
    # Breadcrumb: main always wires the real network enforcer. Availability is
    # an explicit operator opt-in the enforcer reads from its data dir marker,
    # so an absent marker means no network side effects, never silent bypass.
    network = NetworkEnforcer(owner_uid, data_dir=args.data_dir)
    service = BlockerService(
        store, clock, hosts, applications, denial_buffer, network=network
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
