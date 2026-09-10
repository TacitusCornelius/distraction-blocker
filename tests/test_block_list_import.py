from __future__ import annotations

import json
from datetime import time
import tempfile
import unittest
from pathlib import Path

from distraction_blocker.cli import main
from distraction_blocker.transfer import (
    TransferError,
    block_list_preview_text,
    parse_block_list_export,
)


class BlockListImporterTests(unittest.TestCase):
    def test_imports_exact_hostnames_and_maps_weekly_schedule(self) -> None:
        payload = {
            "Focus": {
                "type": "scheduled",
                "web": [
                    "Example.COM",
                    "example.com",
                    "*.social.example",
                    "https://example.net/path",
                ],
                "exceptions": ["docs.example"],
                "apps": ["win10:Calculator.exe", "title:Mail"],
                "schedule": [
                    {
                        "startTime": "1,09,00",
                        "endTime": "1,17,00",
                        "break": "none",
                    }
                ],
            }
        }
        preview = parse_block_list_export(json.dumps(payload), timezone_name="UTC")
        self.assertEqual(preview.accepted_blocks, 1)
        self.assertEqual(preview.accepted_websites, 1)
        self.assertEqual(preview.duplicates, 1)
        rule = preview.rules[0]
        self.assertFalse(rule.enabled)
        self.assertEqual(rule.name, "Focus")
        self.assertEqual(rule.schedule.kind, "weekly")
        self.assertEqual(rule.schedule.timezone_name, "UTC")
        self.assertEqual(rule.schedule.periods[0].weekdays, (0,))
        self.assertEqual(rule.schedule.periods[0].start_local, time(9, 0))
        self.assertEqual(len(preview.issues), 5)
        rendered = block_list_preview_text(preview)
        self.assertIn("wildcard URL rules are not supported", rendered)
        self.assertIn("website exceptions are not supported", rendered)

    def test_continuous_blocks_can_be_explicitly_enabled(self) -> None:
        payload = {"Always": {"type": "continuous", "web": ["example.com"]}}
        preview = parse_block_list_export(json.dumps(payload), enabled=True)
        self.assertTrue(preview.rules[0].enabled)
        self.assertEqual(preview.rules[0].schedule.kind, "indefinite")

    def test_invalid_start_day_is_reported_and_other_settings_are_scanned(self) -> None:
        payload = {
            "Focus": {
                "type": "scheduled",
                "web": ["example.com"],
                "apps": ["Calculator.exe"],
                "schedule": [
                    {"startTime": "7,09,00", "endTime": "7,17,00"}
                ],
            }
        }
        preview = parse_block_list_export(json.dumps(payload))
        self.assertFalse(preview.rules)
        self.assertTrue(
            any("schedule endpoint is out of range" in issue.reason for issue in preview.issues)
        )
        self.assertTrue(
            any("application" in issue.reason.lower() for issue in preview.issues)
        )

    def test_invalid_website_field_does_not_hide_other_unsupported_entries(self) -> None:
        payload = {
            "Focus": {
                "type": "continuous",
                "web": "example.com",
                "exceptions": ["docs.example"],
                "apps": ["Calculator.exe"],
            }
        }
        preview = parse_block_list_export(json.dumps(payload))
        reasons = {issue.reason for issue in preview.issues}
        self.assertIn("block website list must be a list", reasons)
        self.assertIn("website exceptions are not supported", reasons)
        self.assertTrue(any("application" in reason.lower() for reason in reasons))

    def test_malformed_json_is_rejected_without_repair(self) -> None:
        with self.assertRaisesRegex(TransferError, "line 1"):
            parse_block_list_export('{"Focus":{"type":"continuous"}')

    def test_cli_preview_is_non_destructive_and_apply_is_explicit(self) -> None:
        payload = {"Focus": {"type": "continuous", "web": ["example.com"]}}
        class FakeClient:
            def __init__(self) -> None:
                self.calls = []

            def request(self, command, **fields):
                self.calls.append((command, fields))
                if command == "begin_rule_import":
                    return {"import_id": "import-id"}
                return {}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "focus.blocklist.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            preview_client = FakeClient()
            self.assertEqual(
                main(
                    ["import-block-list", str(path)],
                    client=preview_client,
                    output=lambda _text: None,
                ),
                0,
            )
            self.assertEqual(preview_client.calls, [])
            apply_client = FakeClient()
            self.assertEqual(
                main(
                    ["import-block-list", str(path), "--apply", "--enable"],
                    client=apply_client,
                    output=lambda _text: None,
                ),
                0,
            )
            self.assertEqual(
                [call[0] for call in apply_client.calls],
                ["begin_rule_import", "import_rule_chunk", "commit_rule_import"],
            )
            self.assertTrue(apply_client.calls[1][1]["rules"][0]["enabled"])


if __name__ == "__main__":
    unittest.main()
