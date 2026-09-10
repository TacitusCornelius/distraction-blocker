from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import stat
import tempfile
import unittest

from distraction_blocker.model import ManagedList, Policy, Rule
from distraction_blocker.transfer import (
    TransferError,
    atomic_write_text,
    domain_export_text,
    native_export_text,
    parse_domain_text,
    parse_native_export,
    read_import_text,
    read_native_text,
)

RULE_ID = "12345678-1234-5678-1234-567812345678"
LIST_ID = "11111111-1111-4111-8111-111111111111"


def make_rule(domains=("example.com",), enabled=True, managed=False):
    targets = ([{"kind": "managed_list", "value": LIST_ID}] if managed else [{"kind": "website", "value": domain} for domain in domains])
    targets.append({"kind": "application", "value": "/usr/bin/true"})
    return Rule.from_dict({"id": RULE_ID, "name": "Portable", "enabled": enabled, "targets": targets, "schedule": {"kind": "indefinite"}, "revision": 2})


def make_list():
    return ManagedList.from_dict({"id": LIST_ID, "name": "Imported", "source": "test", "version": "1", "license": "Test", "imported_utc": "2026-01-01T00:00:00Z", "domains": ["z.example", "a.example"]})


class DomainImportTests(unittest.TestCase):
    def test_previews_plain_hosts_duplicate_and_invalid_rows(self):
        preview = parse_domain_text("# source\n\nExample.COM\n0.0.0.0 second.example example.com # note\n127.0.0.1\n*wildcard.example*\ntwo.example extra.example\n")
        self.assertEqual(preview.domains, ("example.com", "second.example"))
        self.assertEqual(preview.duplicates, 1)
        self.assertEqual(preview.ignored, 2)
        self.assertEqual(len(preview.issues), 3)
        self.assertEqual([item.line for item in preview.issues], [5, 6, 7])

    def test_normalizes_idna_and_rejects_ip_address(self):
        preview = parse_domain_text("Exämple.COM.\n192.0.2.1\n")
        self.assertEqual(preview.domains, ("xn--exmple-cua.com",))
        self.assertEqual(len(preview.issues), 1)

    def test_reads_only_regular_bounded_utf8_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "domains.txt"
            source.write_text("example.com\n", encoding="utf-8")
            self.assertEqual(read_import_text(source), "example.com\n")
            link = root / "link.txt"
            link.symlink_to(source)
            with self.assertRaisesRegex(TransferError, "regular file"):
                read_import_text(link)

    def test_native_reader_has_room_for_complete_policy_export(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "backup.json"
            content = "x" * (4 * 1024 * 1024 + 1)
            source.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(TransferError, "4 MiB"):
                read_import_text(source)
            self.assertEqual(read_native_text(source), content)



class ExportTests(unittest.TestCase):
    def test_domain_export_expands_lists_and_excludes_apps(self):
        rule = make_rule(managed=True)
        self.assertEqual(domain_export_text((rule,), (make_list(),)), "# Distraction Blocker domain export\na.example\nz.example\n")

    def test_native_export_round_trips_complete_policy(self):
        rule = make_rule()
        policy = Policy(4, (rule,), (make_list(),))
        text = native_export_text(policy, datetime(2026, 8, 13, 12, tzinfo=timezone.utc))
        value = json.loads(text)
        self.assertEqual(value["format"], "distraction-blocker")
        self.assertEqual(value["version"], 5)
        self.assertEqual(parse_native_export(text), policy)

    def test_native_v1_import_converts_to_empty_lists(self):
        rule = make_rule()
        value = {"format": "distraction-blocker", "version": 1, "exported_utc": "2026-08-13T12:00:00Z", "rules": [rule.to_dict()]}
        imported = parse_native_export(json.dumps(value))
        self.assertEqual(imported.rules, (rule,))
        self.assertEqual(imported.managed_lists, ())

    def test_native_round_trip_keeps_url_targets(self):
        rule = Rule.from_dict({
            "id": "12345678-1234-5678-1234-567812345678",
            "name": "URL",
            "enabled": True,
            "targets": [
                {"kind": "url_path", "value": "example.com/feed"},
                {"kind": "url_wildcard", "value": "example.com/vid/*"},
                {"kind": "url_keyword", "value": "casino"},
            ],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        policy = Policy(0, (rule,))
        text = native_export_text(policy, datetime(2026, 8, 13, 12, tzinfo=timezone.utc))
        self.assertEqual(parse_native_export(text), policy)

    def test_native_round_trip_keeps_network_targets(self):
        rule = Rule.from_dict({
            "id": RULE_ID,
            "name": "Network",
            "enabled": True,
            "targets": [
                {"kind": "network", "value": "safe_search"},
                {"kind": "website", "value": "example.test"},
            ],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        policy = Policy(0, (rule,))
        text = native_export_text(policy, datetime(2026, 8, 13, 12, tzinfo=timezone.utc))
        self.assertEqual(json.loads(text)["version"], 5)
        self.assertEqual(parse_native_export(text), policy)

    def test_native_v2_import_refuses_network_targets(self):
        # Breadcrumb: network targets are a native format v3 addition; a v2
        # export carrying them is forged or mixed-version and must be
        # refused rather than parsed.
        rule = Rule.from_dict({
            "id": RULE_ID,
            "name": "Network",
            "enabled": True,
            "targets": [{"kind": "network", "value": "safe_search"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        value = {
            "format": "distraction-blocker",
            "version": 2,
            "exported_utc": "2026-08-13T12:00:00Z",
            "revision": 0,
            "rules": [rule.to_dict()],
            "managed_lists": [],
        }
        with self.assertRaisesRegex(TransferError, "network"):
            parse_native_export(json.dumps(value))

    def test_native_v3_import_refuses_doh_targets(self):
        rule = Rule.from_dict({
            "id": RULE_ID,
            "name": "DoH",
            "enabled": True,
            "targets": [{"kind": "network", "value": "doh"}],
            "schedule": {"kind": "indefinite"},
            "revision": 0,
        })
        value = {
            "format": "distraction-blocker",
            "version": 3,
            "exported_utc": "2026-08-13T12:00:00Z",
            "revision": 0,
            "rules": [rule.to_dict()],
            "managed_lists": [],
        }
        with self.assertRaisesRegex(TransferError, "DoH"):
            parse_native_export(json.dumps(value))

    def test_native_v4_import_refuses_proxy_and_vpn_targets(self):
        for control in ("proxy", "vpn"):
            with self.subTest(control=control):
                rule = Rule.from_dict({
                    "id": RULE_ID,
                    "name": "Network",
                    "enabled": True,
                    "targets": [{"kind": "network", "value": control}],
                    "schedule": {"kind": "indefinite"},
                    "revision": 0,
                })
                value = {
                    "format": "distraction-blocker",
                    "version": 4,
                    "exported_utc": "2026-08-13T12:00:00Z",
                    "revision": 0,
                    "rules": [rule.to_dict()],
                    "managed_lists": [],
                }
                with self.assertRaisesRegex(TransferError, "v5"):
                    parse_native_export(json.dumps(value))
    def test_native_import_refuses_malformed_or_unknown_data(self):
        with self.assertRaisesRegex(TransferError, "line 1"):
            parse_native_export('{"format":"distraction-blocker"')
        value = json.loads(native_export_text(Policy(0, (make_rule(),), ())))
        value["extra"] = True
        with self.assertRaisesRegex(TransferError, "fields"):
            parse_native_export(json.dumps(value))

    def test_native_export_requires_complete_policy(self):
        with self.assertRaisesRegex(TransferError, "policy"):
            native_export_text((make_rule(),))


    def test_atomic_export_uses_owner_only_mode_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "backup.json"
            atomic_write_text(destination, "data\n")
            self.assertEqual(destination.read_text(encoding="utf-8"), "data\n")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            target = root / "target"
            target.write_text("keep", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(TransferError, "regular file"):
                atomic_write_text(link, "replace")
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
