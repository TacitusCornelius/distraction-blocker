/**
 * DNR emitter conformance: the Chromium rule set must block and pass the
 * exact same fixture URLs as the Firefox matcher. Run:
 * node --test extension/tests/
 */
"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const { compile_dnr, rule_to_regexp } = await import(
  join(root, "core", "dnr.js")
);
const conformance = JSON.parse(
  readFileSync(join(root, "core", "conformance.json"), "utf-8"),
);

function compiled_regexes(policy_name) {
  return compile_dnr(conformance.policies[policy_name]).map((entry) => ({
    rule_id: entry.rule_id,
    regexp: rule_to_regexp(entry.rule),
  }));
}

for (const [index, case_] of conformance.cases.entries()) {
  if (case_["not-a-url"]) {
    continue; // DNR regexes only see well-formed request URLs.
  }
  test(`dnr conformance ${index}: ${case_.policy} ${case_.url.slice(0, 60)}`, () => {
    const regexes = compiled_regexes(case_.policy);
    const hit = regexes.find((entry) => entry.regexp.test(case_.url));
    const blocked = hit !== undefined;
    const expected_blocked = case_.expect !== null;
    assert.equal(
      blocked,
      expected_blocked,
      `expected blocked=${expected_blocked} for ${case_.url}`,
    );
    if (blocked && expected_blocked) {
      assert.equal(hit.rule_id, case_.expect.rule_id);
    }
  });
}

test("dnr rules are deterministic and uniquely numbered", () => {
  const first = compile_dnr(conformance.policies.mixed);
  const second = compile_dnr(conformance.policies.mixed);
  assert.deepEqual(second, first);
  const ids = new Set(first.map((entry) => entry.rule.id));
  assert.equal(ids.size, first.length);
  for (const entry of first) {
    assert.equal(entry.rule.action.type, "block");
    assert.ok(entry.rule.condition.regexFilter.length > 0);
  }
});
