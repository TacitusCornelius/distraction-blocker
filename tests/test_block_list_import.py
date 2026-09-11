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
    parse_block_list_mapping,
    parse_block_list_review,
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
        self.assertEqual(len(preview.issues), 4)
        self.assertEqual(
            [(target.kind, target.value) for target in rule.targets],
            [("website", "example.com"), ("url_path", "example.net/path")],
        )
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

    def test_maps_supported_url_and_youtube_forms_without_wildcard_expansion(self) -> None:
        payload = {
            "URLs": {
                "type": "continuous",
                "web": [
                    "example.com/path",
                    "example.com/path/*",
                    "keyword:casino",
                    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                    "youtube.com/@examplehandle/videos",
                ],
                "exceptions": [
                    "example.com/allowed",
                    "https://youtube.com/channel/" + "UC" + "a" * 22,
                ],
            }
        }
        preview = parse_block_list_export(json.dumps(payload))
        self.assertFalse(preview.issues)
        self.assertEqual(
            [(target.kind, target.value) for target in preview.rules[0].targets],
            [
                ("url_path", "example.com/path"),
                ("url_wildcard", "example.com/path/*"),
                ("url_keyword", "casino"),
                ("youtube_video", "dQw4w9WgXcQ"),
                ("youtube_channel", "@examplehandle"),
            ],
        )
        self.assertEqual(
            [(target.kind, target.value) for target in preview.rules[0].exceptions],
            [
                ("url_path", "example.com/allowed"),
                ("youtube_channel", "UC" + "a" * 22),
            ],
        )

    def test_rejects_ambiguous_url_variants_without_coercion(self) -> None:
        preview = parse_block_list_export(json.dumps({
            "URLs": {
                "type": "continuous",
                "web": [
                    "https://example.com:8443/path",
                    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1",
                    "https://youtu.be/dQw4w9WgXcQ",
                ],
            }
        }))
        self.assertEqual(
            [(target.kind, target.value) for target in preview.rules[0].targets],
            [("youtube_video", "dQw4w9WgXcQ")],
        )
        self.assertEqual(len(preview.issues), 2)

    def test_youtube_mapping_rejects_metadata_and_arbitrary_suffixes(self) -> None:
        preview = parse_block_list_export(json.dumps({
            "URLs": {
                "type": "continuous",
                "web": [
                    "https://youtube.com/watch?v=dQw4w9WgXcQ#fragment",
                    "https://user:pass@youtube.com/watch?v=dQw4w9WgXcQ",
                    "https://youtube.com/@examplehandle/not-videos",
                    "https://youtube.com/@examplehandle/videos",
                ],
            }
        }))
        self.assertEqual(
            [(target.kind, target.value) for target in preview.rules[0].targets],
            [
                ("url_path", "youtube.com/@examplehandle/not-videos"),
                ("youtube_channel", "@examplehandle"),
            ],
        )
        self.assertEqual(len(preview.issues), 2)

    def test_whole_internet_requires_network_capability_and_apps_need_mapping(self) -> None:
        payload = {
            "Network": {
                "type": "continuous",
                "web": ["whole_internet"],
                "apps": ["win10:Calculator.exe"],
            }
        }
        unavailable = parse_block_list_export(json.dumps(payload))
        self.assertFalse(unavailable.rules)
        self.assertEqual(
            {issue.category for issue in unavailable.issues},
            {"policy_capability", "application", "target"},
        )
        mapping = parse_block_list_mapping(
            json.dumps({"applications": {"win10:Calculator.exe": "/usr/bin/true"}})
        )
        available = parse_block_list_export(
            json.dumps(payload),
            network_available=True,
            application_mappings=mapping.mapping_dict,
        )
        self.assertFalse(available.issues)
        self.assertEqual(
            {target.kind for target in available.rules[0].targets},
            {"network", "application"},
        )

    def test_schedule_fields_are_not_silently_discarded(self) -> None:
        preview = parse_block_list_export(json.dumps({
            "Continuous": {
                "type": "continuous",
                "web": ["example.com"],
                "schedule": [
                    {"startTime": "1,09,00", "endTime": "1,10,00"}
                ],
            },
            "Scheduled": {
                "type": "scheduled",
                "web": ["example.net"],
                "schedule": [
                    {
                        "startTime": "1,09,00",
                        "endTime": "1,10,00",
                        "unrecognized": True,
                    }
                ],
            },
        }))
        self.assertEqual(len(preview.rules), 2)
        self.assertTrue(any(
            issue.path == "blocks['Continuous'].schedule"
            and issue.category == "schedule"
            for issue in preview.issues
        ))
        self.assertTrue(any(
            issue.path == "blocks['Scheduled'].schedule[0].unrecognized"
            and issue.category == "schedule"
            for issue in preview.issues
        ))

    def test_lock_review_maps_only_existing_delay_contract(self) -> None:
        review = parse_block_list_review(json.dumps({
            "Focus": {
                "break": {
                    "kind": "delay",
                    "wait_seconds": 60,
                    "break_seconds": 120,
                }
            }
        }))
        self.assertFalse(review.issues)
        preview = parse_block_list_export(
            json.dumps({
                "Focus": {
                    "type": "continuous",
                    "web": ["example.com"],
                    "break": "scheduled",
                }
            }),
            review_mappings=review.review_dict,
        )
        self.assertFalse(preview.issues)
        self.assertEqual(preview.lock_reviews[0]["source"], "break")
        self.assertEqual(
            preview.lock_reviews[0]["lock"]["break_seconds"], 120
        )

    def test_duplicate_export_settings_are_reported_with_source_path(self) -> None:
        preview = parse_block_list_export(
            '{"Focus":{"type":"continuous","web":["example.com"],'
            '"web":["example.net"]}}'
        )
        self.assertEqual(
            [(target.kind, target.value) for target in preview.rules[0].targets],
            [("website", "example.net")],
        )
        self.assertTrue(any(
            issue.category == "format"
            and "blocks.Focus.web" in issue.path
            for issue in preview.issues
        ))

    def test_duplicate_and_invalid_application_mappings_stay_as_issues(self) -> None:
        preview = parse_block_list_mapping(
            '{"applications":{"Calculator":"/usr/bin/true",'
            '"Calculator":"/usr/bin/false","Other":"relative/path"}}'
        )
        self.assertEqual(preview.mappings, ())
        self.assertEqual(
            {issue.category for issue in preview.issues},
            {"application"},
        )

    def test_duplicate_application_wrappers_are_reported(self) -> None:
        preview = parse_block_list_mapping(
            '{"applications":{"A":"/tmp/block-list-true"},'
            '"applications":{"B":"/tmp/block-list-false"}}'
        )
        self.assertEqual(
            preview.mapping_dict,
            {"B": "/tmp/block-list-false"},
        )
        self.assertTrue(any(
            issue.category == "application"
            and "wrapper is duplicated" in issue.reason
            for issue in preview.issues
        ))

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

    def test_cli_apply_passes_explicit_mappings_and_review_locks(self) -> None:
        payload = {
            "Focus": {
                "type": "continuous",
                "apps": ["win10:Calculator.exe"],
                "lock": "scheduled",
            }
        }

        class FakeClient:
            def __init__(self) -> None:
                self.calls = []

            def request(self, command, **fields):
                self.calls.append((command, fields))
                if command == "begin_rule_import":
                    return {"import_id": "import-id"}
                return {}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_path = root / "focus.blocklist.json"
            mapping_path = root / "mapping.json"
            review_path = root / "review.json"
            export_path.write_text(json.dumps(payload), encoding="utf-8")
            mapping_path.write_text(json.dumps({
                "applications": {"win10:Calculator.exe": "/usr/bin/true"}
            }), encoding="utf-8")
            review_path.write_text(json.dumps({
                "Focus": {"lock": {"kind": "schedule"}}
            }), encoding="utf-8")
            client = FakeClient()
            self.assertEqual(
                main(
                    [
                        "import-block-list",
                        str(export_path),
                        "--mapping-file",
                        str(mapping_path),
                        "--review-file",
                        str(review_path),
                        "--apply",
                    ],
                    client=client,
                    output=lambda _text: None,
                ),
                0,
            )
            self.assertEqual(
                client.calls[0][1]["locks"][0]["kind"], "schedule"
            )
            self.assertEqual(
                client.calls[1][1]["rules"][0]["targets"][0],
                {"kind": "application", "value": "/usr/bin/gnutrue"},
            )

if __name__ == "__main__":
    unittest.main()
