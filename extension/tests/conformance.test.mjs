/**
 * Conformance suite for the shared extension core.
 *
 * Every browser adapter must satisfy these same fixtures; the drift test
 * additionally proves each adapter's copied core is byte-identical to the
 * source. Run: node --test extension/tests/
 */
"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const { compile, describe_url, split_target } = await import(
  join(root, "core", "engine.js")
);
const conformance = JSON.parse(
  readFileSync(join(root, "core", "conformance.json"), "utf-8"),
);

test("split_target lowercases the host and keeps the path verbatim", () => {
  assert.deepEqual(split_target("Example.COM/Feed"), {
    host: "example.com",
    path: "/Feed",
  });
  assert.equal(split_target("no-slash"), null);
});

test("describe_url parses and normalizes a request URL", () => {
  const url = describe_url("https://USER@Example.COM:443/Feed?x=1");
  assert.equal(url.host, "example.com");
  assert.equal(url.path, "/Feed");
  assert.ok(url.href.includes("/feed?x=1"));
  assert.equal(describe_url("not a url"), null);
});

for (const [index, case_] of conformance.cases.entries()) {
  test(`conformance ${index}: ${case_.policy} ${case_.url.slice(0, 60)}`, () => {
    const match = compile(conformance.policies[case_.policy]);
    const verdict = case_.expect === null && case_["not-a-url"]
      ? null
      : (() => {
          // The matcher itself decides how to interpret malformed URLs;
          // feed it verbatim like webRequest would.
          if (case_["not-a-url"]) return null;
          const hit = match(case_.url);
          return hit ? { rule_id: hit.rule_id } : null;
        })();
    const expected = case_.expect === null
      ? null
      : { rule_id: case_.expect.rule_id };
    assert.deepEqual(verdict, expected);
  });
}

test("conformance fixtures are complete and well-formed", () => {
  assert.ok(Array.isArray(conformance.cases) && conformance.cases.length >= 10);
  for (const case_ of conformance.cases) {
    assert.ok(conformance.policies[case_.policy], `unknown policy ${case_.policy}`);
    assert.ok("expect" in case_);
  }
});

// Breadcrumb: Firefox compiles the shared core to classic scripts (MV2
// persistent background), so its copies intentionally differ from the
// module sources; build.py --check is the authority for that contract.
// Chromium keeps verbatim module copies.
test("chromium core is byte-identical to the shared source", () => {
  const source = readFileSync(join(root, "core", "engine.js"));
  const copy = join(root, "chromium", "core", "engine.js");
  assert.equal(readFileSync(copy).equals(source), true, "chromium core stale");
});
