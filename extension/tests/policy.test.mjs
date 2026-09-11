"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { expand_managed_lists, rules_from_policy } from "../core/policy.js";

const current = {
  schema_version: 6,
  revision: 7,
  rules: [{ id: "rule-1" }],
};

test("policy parser returns rules from the current schema", () => {
  assert.equal(rules_from_policy(current), current.rules);
});

test("policy parser rejects missing, unknown, and invalid outer values", () => {
  // Breadcrumb: adapters keep the last valid matcher after these errors.
  const invalid = [
    null,
    [],
    { revision: 7, rules: [] },
    { ...current, schema_version: 1 },
    { ...current, schema_version: 7 },
    { ...current, revision: -1 },
    { ...current, revision: true },
    { ...current, rules: {} },
    { ...current, extra: true },
  ];
  for (const value of invalid) {
    assert.throws(() => rules_from_policy(value));
  }
});


test("managed-list expansion is complete before browser compilation", async () => {
  const policy = {
    schema_version: 6,
    revision: 4,
    rules: [{
      id: "rule-1",
      enabled: true,
      targets: [
        { kind: "managed_list", value: "list-1" },
        { kind: "website", value: "direct.example" },
      ],
    }],
  };
  const calls = [];
  const expanded = await expand_managed_lists(policy, async (id, offset) => {
    calls.push([id, offset]);
    return {
      ok: true,
      result: {
        id,
        offset,
        revision: 4,
        domains: offset === 0 ? ["list.example"] : [],
        next_offset: null,
      },
    };
  });
  assert.deepEqual(calls, [["list-1", 0]]);
  assert.deepEqual(expanded.rules[0].targets, [
    { kind: "website", value: "list.example" },
    { kind: "website", value: "direct.example" },
  ]);
});