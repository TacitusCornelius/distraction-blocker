"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { rules_from_policy } from "../core/policy.js";

const current = {
  schema_version: 5,
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
    { ...current, schema_version: 6 },
    { ...current, revision: -1 },
    { ...current, revision: true },
    { ...current, rules: {} },
    { ...current, extra: true },
  ];
  for (const value of invalid) {
    assert.throws(() => rules_from_policy(value));
  }
});
