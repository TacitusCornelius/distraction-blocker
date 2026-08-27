/**
 * Unit coverage for the shared website-allowance accounting helpers.
 * Run: node --test extension/tests/
 */
"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const {
  COUNTER_MAX,
  bump_bounded,
  bump_usage,
  decode_usage_key,
  is_allowance_rule,
  merge_usage,
  merge_labels,
  partition_rules,
  prune_usage,
  restore_usage,
  retire_usage,
  usage_entries,
  usage_key,
  usage_snapshot,
} = await import(join(root, "core", "usage.js"));

test("is_allowance_rule accepts only integer allowance_starts >= 1", () => {
  assert.equal(is_allowance_rule({ allowance_starts: 1 }), true);
  assert.equal(is_allowance_rule({ allowance_starts: 50 }), true);
  assert.equal(is_allowance_rule({}), false);
  assert.equal(is_allowance_rule({ allowance_starts: 0 }), false);
  assert.equal(is_allowance_rule({ allowance_starts: -3 }), false);
  assert.equal(is_allowance_rule({ allowance_starts: 2.5 }), false);
  assert.equal(is_allowance_rule({ allowance_starts: "5" }), false);
  assert.equal(is_allowance_rule(null), false);
});

test("exhausted allowance rules move to enforced rules", () => {
  const { enforced, allowance } = partition_rules([
    { id: "open", allowance_starts: 2 },
    { id: "spent", allowance_starts: 2, budget_exhausted: true },
  ]);
  assert.deepEqual(enforced.map((rule) => rule.id), ["spent"]);
  assert.deepEqual(allowance.map((rule) => rule.id), ["open"]);
});

test("partition_rules splits by the allowance flag only", () => {
  const rules = [
    { id: "plain", enabled: true, targets: [] },
    { id: "budgeted", enabled: true, targets: [], allowance_starts: 10 },
    { id: "off-budget", enabled: false, targets: [], allowance_starts: 1 },
    { id: "zero", enabled: true, targets: [], allowance_starts: 0 },
  ];
  const { enforced, allowance } = partition_rules(rules);
  assert.deepEqual(
    enforced.map((rule) => rule.id),
    ["plain", "zero"],
  );
  // Partitioning ignores `enabled`; compile()/compile_dnr() filter that
  // downstream - a disabled allowance rule still belongs to this half.
  assert.deepEqual(
    allowance.map((rule) => rule.id),
    ["budgeted", "off-budget"],
  );
  assert.deepEqual(partition_rules(null), { enforced: [], allowance: [] });
});

test("bump_usage accumulates per rule_id and value", () => {
  const counts = new Map();
  bump_usage(counts, "r1", "a.com/feed");
  bump_usage(counts, "r1", "a.com/feed");
  bump_usage(counts, "r1", "a.com/other");
  assert.deepEqual([...counts], [["r1\u0000a.com/feed", 2], ["r1\u0000a.com/other", 1]]);
});

test("usage keys decode and restore from session rows", () => {
  assert.deepEqual(decode_usage_key(usage_key("rule-1", "example.com/path")), {
    rule_id: "rule-1",
    value: "example.com/path",
  });
  assert.equal(decode_usage_key("bad-key"), null);
  const counts = new Map();
  restore_usage(counts, [
    [usage_key("rule-1", "a"), 2],
    [usage_key("rule-1", "a"), 3],
    ["bad-key", 9],
    [usage_key("rule-2", "b"), 0],
  ]);
  assert.deepEqual([...counts], [
    ["rule-1\u0000a", 5],
  ]);
  assert.deepEqual(usage_snapshot(counts), { "rule-1 \u2192 a": 5 });
});

test("bounded counters evict FIFO keys and saturate values", () => {
  const counts = new Map();
  for (let i = 0; i < 256; i += 1) {
    bump_bounded(counts, `url-${i}`);
  }
  bump_bounded(counts, "url-0");
  assert.equal(counts.size, 256);
  assert.equal(counts.get("url-0"), 2);
  bump_bounded(counts, "url-256");
  assert.equal(counts.size, 256);
  assert.equal(counts.has("url-0"), false);
  assert.equal(counts.has("url-1"), true);
  bump_bounded(counts, "url-257");
  assert.equal(counts.has("url-1"), false);
  assert.equal(counts.has("url-2"), true);
  const saturated = new Map();
  bump_bounded(saturated, "url", COUNTER_MAX);
  bump_bounded(saturated, "url");
  assert.equal(saturated.get("url"), COUNTER_MAX);
});

test("prune_usage removes stale values and exhausted rules", () => {
  const counts = new Map([
    [usage_key("open", "keep"), 2],
    [usage_key("open", "stale"), 3],
    [usage_key("spent", "keep"), 4],
    [usage_key("gone", "keep"), 5],
  ]);
  prune_usage(counts, [
    {
      id: "open",
      allowance_starts: 2,
      targets: [{ kind: "url_path", value: "keep" }],
    },
    {
      id: "spent",
      allowance_starts: 2,
      budget_exhausted: true,
      targets: [{ kind: "url_path", value: "keep" }],
    },
  ]);
  assert.deepEqual([...counts], [[usage_key("open", "keep"), 2]]);
});

test("usage_entries builds report entries and caps at the limit", () => {
  const counts = new Map();
  for (let i = 0; i < 130; i += 1) {
    bump_usage(counts, "rule", `value-${i}`);
  }
  const entries = usage_entries(counts, 128);
  assert.equal(entries.length, 128);
  assert.deepEqual(entries[0], {
    rule_id: "rule",
    value: "value-0",
    count: 1,
  });
  // The unsent tail stays available for the next cycle.
  assert.equal(usage_entries(counts).length, 128);
  assert.deepEqual(usage_entries(new Map()), []);
});

test("retire_usage subtracts reported counts and drops emptied keys", () => {
  const counts = new Map();
  bump_usage(counts, "r1", "a", 5);
  bump_usage(counts, "r1", "b", 2);
  retire_usage(counts, [{ rule_id: "r1", value: "a", count: 5 }]);
  assert.deepEqual([...counts], [["r1\u0000b", 2]]);
  retire_usage(counts, [{ rule_id: "r1", value: "b", count: 1 }]);
  assert.deepEqual([...counts], [["r1\u0000b", 1]]);
});

test("merge_usage re-adds report-shaped entries (retry and restore)", () => {
  const counts = new Map();
  merge_usage(counts, [
    { rule_id: "r1", value: "a", count: 3 },
    { rule_id: "r1", value: "a", count: 2 },
    { rule_id: "bad", value: "x", count: 0 }, // never positive: ignored
  ]);
  assert.deepEqual([...counts], [["r1\u0000a", 5]]);
});

// Breadcrumb: Firefox compiles the shared core to classic scripts (MV2
// persistent background); build.py --check owns that contract. Chromium
// keeps verbatim module copies.
test("chromium core is byte-identical to the shared source", () => {
  for (const name of ["engine.js", "usage.js"]) {
    const source = readFileSync(join(root, "core", name));
    const copy = join(root, "chromium", "core", name);
    try {
      assert.equal(
        readFileSync(copy).equals(source),
        true,
        `chromium core ${name} stale`,
      );
    } catch (error) {
      if (error.code === "ENOENT") continue; // adapter not started yet
      throw error;
    }
  }
});

test("merge_labels restores record_state snapshots into counters", () => {
  const counts = new Map();
  merge_labels(counts, {
    "rule-1 \u2192 example.com": 4,
    "rule-2 \u2192 youtube.com/embed": 1,
  });
  assert.deepEqual([...counts], [
    ["rule-1\u0000example.com", 4],
    ["rule-2\u0000youtube.com/embed", 1],
  ]);
});

test("merge_labels skips junk labels and blocked prefixes", () => {
  const counts = new Map();
  merge_labels(
    counts,
    {
      "inactive-tab \u2192 http://x": 7, // local-only: must not come back
      "rule-1 \u2192 a.example": 2,
      "no-separator": 5,
      "rule-3 \u2192 b.example": 0,
      "rule-4 \u2192 c.example": -1,
      "rule-5 \u2192 d.example": "3",
    },
    ["inactive-tab"],
  );
  assert.deepEqual([...counts], [["rule-1\u0000a.example", 2]]);
});

test("merge_labels merges into existing counters", () => {
  const counts = new Map([["rule-1\u0000a.example", 2]]);
  merge_labels(counts, { "rule-1 \u2192 a.example": 3 });
  assert.equal(counts.get("rule-1\u0000a.example"), 5);
});
