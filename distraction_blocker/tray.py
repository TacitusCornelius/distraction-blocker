"""Optional GTK 3/Ayatana tray client for the long-running service."""
from __future__ import annotations

import importlib
import subprocess
from types import ModuleType
from typing import Callable

from .notifications import (
    NotificationControlError,
    block as block_notifications,
    current_state as current_notification_state,
    unblock as unblock_notifications,
)
from .rpc import Client, RpcError


class TrayUnavailableError(RuntimeError):
    """The optional system-tray bindings are not installed."""


def _load_modules(importer: Callable[[str], ModuleType] = importlib.import_module):
    try:
        gi = importer("gi")
        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            indicator = importer("gi.repository.AyatanaAppIndicator3")
        except (AttributeError, ImportError, ValueError):
            gi.require_version("AppIndicator3", "0.1")
            indicator = importer("gi.repository.AppIndicator3")
        return importer("gi.repository.Gtk"), indicator
    except (AttributeError, ImportError, ModuleNotFoundError, ValueError) as error:
        raise TrayUnavailableError(
            "System tray support is unavailable. Install "
            "gir1.2-ayatanaappindicator3-0.1 and python3-gi."
        ) from error


def run_tray(
    *,
    client_factory: Callable[[], Client] = Client,
    gui_command: tuple[str, ...] = (
        "/usr/bin/python3",
        "-I",
        "/usr/lib/distraction-blocker/gui_entry.py",
        "gui",
    ),
) -> int:
    """Run the tray menu until the user selects Quit."""
    Gtk, AppIndicator = _load_modules()
    indicator = AppIndicator.Indicator.new(
        "distraction-blocker", "preferences-system-privacy", AppIndicator.IndicatorStatus.ACTIVE
    )
    menu = Gtk.Menu()
    status_item = Gtk.MenuItem(label="Service: loading")
    status_item.set_sensitive(False)
    menu.append(status_item)
    menu.append(Gtk.SeparatorMenuItem())

    open_item = Gtk.MenuItem(label="Open Distraction Blocker")
    open_item.connect("activate", lambda *_args: subprocess.Popen(gui_command))
    menu.append(open_item)

    notification_item = Gtk.MenuItem(label="Block notifications")
    menu.append(notification_item)
    rules_root = Gtk.MenuItem(label="Rules")
    rules_menu = Gtk.Menu()
    rules_root.set_submenu(rules_menu)
    menu.append(rules_root)

    actions_root = Gtk.MenuItem(label="Scheduled actions")
    actions_menu = Gtk.Menu()
    actions_root.set_submenu(actions_menu)
    menu.append(actions_root)

    def refill(
        target: object,
        entries: list[tuple[str, Callable[[], None]]],
        empty_label: str,
    ) -> None:
        for child in target.get_children():
            target.remove(child)
        if not entries:
            empty = Gtk.MenuItem(label=empty_label)
            empty.set_sensitive(False)
            target.append(empty)
        else:
            for label, activate in entries:
                item = Gtk.MenuItem(label=label)
                item.connect("activate", lambda *_args, callback=activate: callback())
                target.append(item)
        target.show_all()

    def refresh() -> None:
        try:
            status = client_factory().request("status")
            healthy = bool(status.get("healthy")) if isinstance(status, dict) else False
            status_item.set_label(f"Service: {'healthy' if healthy else 'unhealthy'}")
        except RpcError:
            status_item.set_label("Service: unavailable")
        try:
            projection = client_factory().request("list_rules")
            raw_rules = projection.get("rules", []) if isinstance(projection, dict) else []
            rule_entries = []
            for rule in raw_rules if isinstance(raw_rules, list) else []:
                if not isinstance(rule, dict):
                    continue
                rule_id = rule.get("id")
                if not isinstance(rule_id, str):
                    continue
                enabled = bool(rule.get("enabled"))
                rule_entries.append(
                    (
                        f"{rule.get('name', rule_id[:8])}: "
                        f"{'disable' if enabled else 'enable'}",
                        lambda rule_id=rule_id, enabled=enabled: (
                            client_factory().request(
                                "set_enabled",
                                rule_id=rule_id,
                                enabled=not enabled,
                            ),
                            refresh(),
                        ),
                    )
                )
            refill(rules_menu, rule_entries, "No rules")
        except (RpcError, AttributeError, TypeError):
            refill(rules_menu, [], "Rules unavailable")
        try:
            raw_actions = client_factory().request("list_scheduled_actions")
            action_entries = []
            for action in raw_actions if isinstance(raw_actions, list) else []:
                if not isinstance(action, dict):
                    continue
                action_id = action.get("id")
                if not isinstance(action_id, str):
                    continue
                enabled = bool(action.get("enabled"))
                action_entries.append(
                    (
                        f"{action.get('kind', 'action')}: "
                        f"{'disable' if enabled else 'enable'}",
                        lambda action_id=action_id, enabled=enabled: (
                            client_factory().request(
                                "set_scheduled_action_enabled",
                                action_id=action_id,
                                enabled=not enabled,
                            ),
                            refresh(),
                        ),
                    )
                )
            refill(actions_menu, action_entries, "No scheduled actions")
        except (RpcError, AttributeError, TypeError):
            refill(actions_menu, [], "Actions unavailable")
        try:
            state = current_notification_state()
            notification_item.set_label(
                "Restore notifications" if not state.show_banners else "Block notifications"
            )
        except NotificationControlError:
            notification_item.set_label("Notifications unavailable")

    def toggle_notifications(_item: object) -> None:
        try:
            state = current_notification_state()
            (unblock_notifications if not state.show_banners else block_notifications)()
            refresh()
        except NotificationControlError:
            notification_item.set_label("Notifications unavailable")

    notification_item.connect("activate", toggle_notifications)
    quit_item = Gtk.MenuItem(label="Quit tray")
    quit_item.connect("activate", lambda *_args: Gtk.main_quit())
    menu.append(quit_item)
    menu.show_all()
    indicator.set_menu(menu)
    refresh()
    Gtk.main()
    return 0


__all__ = ["TrayUnavailableError", "run_tray"]
