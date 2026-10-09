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

const { compile_dnr, compile_inactive_tab_rule, rule_to_regexp } = await import(
  join(root, "core", "dnr.js")
);
const conformance = JSON.parse(
  readFileSync(join(root, "core", "conformance.json"), "utf-8"),
);
const { compile } = await import(join(root, "core", "engine.js"));

function compiled_regexes(policy_name) {
  return compile_dnr(conformance.policies[policy_name]).map((entry) => ({
    rule_id: entry.rule_id,
    priority: entry.rule.priority,
    action: entry.rule.action.type,
    regexp: rule_to_regexp(entry.rule),
  }));
}

for (const [index, case_] of conformance.cases.entries()) {
  if (case_["not-a-url"]) {
    continue; // DNR regexes only see well-formed request URLs.
  }
  test(`dnr conformance ${index}: ${case_.policy} ${case_.url.slice(0, 60)}`, () => {
    const matches = compiled_regexes(case_.policy)
      .filter((entry) => entry.regexp.test(case_.url))
      .sort((left, right) => right.priority - left.priority);
    const hit = matches[0];
    const blocked = hit?.action === "block";
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

test("inactive-tab rule targets only normalized tab ids", () => {
  const rule = compile_inactive_tab_rule([9, -1, 3, 9, 2.5], 5001);
  assert.equal(rule.id, 5001);
  assert.equal(rule.action.type, "block");
  assert.deepEqual(rule.condition.tabIds, [3, 9]);
  assert.deepEqual(new Set(rule.condition.resourceTypes), new Set([
    "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
    "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket",
    "webtransport", "webbundle", "other",
  ]));
  assert.equal(rule_to_regexp(rule).test("https://example.test/path"), true);
  assert.equal(rule_to_regexp(rule).test("file:///tmp/example"), false);
});

test("inactive-tab rule is absent without target tabs", () => {
  assert.equal(compile_inactive_tab_rule([], 5001), null);
  assert.equal(compile_inactive_tab_rule(undefined, 5001), null);
});
test("URL exceptions emit higher-priority allow rules", () => {
  const entries = compile_dnr([{
    id: "broad",
    enabled: true,
    targets: [{ kind: "url_wildcard", value: "example.com/*" }],
    exceptions: [{ kind: "url_path", value: "example.com/allowed" }],
  }]);
  assert.deepEqual(
    entries.map((entry) => [entry.rule.action.type, entry.rule.priority]),
    [["block", 1], ["allow", 2]],
  );
  assert.equal(rule_to_regexp(entries[0].rule).test("https://example.com/blocked"), true);
  assert.equal(rule_to_regexp(entries[1].rule).test("https://example.com/allowed"), true);
  const browser_wide = compile_dnr([{
    id: "all-web",
    enabled: true,
    targets: [{ kind: "browser_all", value: "all" }],
    exceptions: [{ kind: "url_path", value: "example.com/allowed" }],
  }]);
  const websocket_block = browser_wide.find(
    (entry) => entry.rule.action.type === "block",
  );
  const websocket_exception = browser_wide.find(
    (entry) => entry.rule.action.type === "allow",
  );
  assert.equal(rule_to_regexp(websocket_block.rule).test("wss://example.com/allowed"), true);
  assert.equal(rule_to_regexp(websocket_exception.rule).test("wss://example.com/allowed"), true);
  assert.equal(websocket_exception.rule.priority, 2);
});

test("website DNR patterns are exact hostnames and allow ports", () => {
  const entries = compile_dnr([{
    id: "website",
    enabled: true,
    targets: [{ kind: "website", value: "example.com" }],
  }]);
  const regexp = rule_to_regexp(entries[0].rule);
  assert.equal(regexp.test("https://example.com/path"), true);
  assert.equal(regexp.test("http://EXAMPLE.COM:8443/"), true);
  assert.equal(regexp.test("https://sub.example.com/"), false);
  assert.equal(regexp.test("https://example.com.evil/"), false);
  assert.equal(regexp.test("wss://example.com/socket"), false);
});

test("browser-wide target blocks web and WebSocket URLs, not network controls", () => {
  const entries = compile_dnr([{
    id: "all-web",
    enabled: true,
    targets: [{ kind: "browser_all", value: "all" }],
  }]);
  assert.equal(entries.length, 1);
  const rule = entries[0].rule;
  const regexp = rule_to_regexp(rule);
  assert.equal(regexp.test("http://one.example/path"), true);
  assert.equal(regexp.test("https://another.example:8443/"), true);
  assert.equal(regexp.test("ws://socket.example/connect"), true);
  assert.equal(regexp.test("wss://socket.example/connect"), true);
  assert.equal(regexp.test("file:///tmp/page.html"), false);
  assert.equal(regexp.test("ftp://example.com/file"), false);
  assert.ok(rule.condition.resourceTypes.includes("main_frame"));
  assert.ok(rule.condition.resourceTypes.includes("websocket"));

  const network = compile_dnr([{
    id: "network-only",
    enabled: true,
    targets: [{ kind: "network", value: "whole_internet" }],
  }]);
  assert.deepEqual(network, []);
});

test("DNR compilation enforces regex-rule capacity before installation", () => {
  const policy_for = (count) => [{
    id: "large",
    enabled: true,
    targets: Array.from({ length: count }, (_, index) => ({
      kind: "url_keyword",
      value: `keyword-${index}`,
    })),
  }];
  assert.equal(compile_dnr(policy_for(999)).length, 999);
  assert.throws(
    () => compile_dnr(policy_for(1000)),
    /999-rule regex capacity/,
  );
});
test("YouTube video IDs keep case-sensitive parity with Firefox", () => {
  const rules = [{
    id: "video",
    enabled: true,
    targets: [{ kind: "youtube_video", value: "dQw4w9WgXcQ" }],
  }];
  const dnr = compile_dnr(rules);
  assert.equal(compile(rules)("https://youtube.com/watch?v=DQW4WWGXcQ"), null);
  assert.equal(
    rule_to_regexp(dnr[0].rule).test("https://youtube.com/watch?v=DQW4WWGXcQ"),
    false,
  );
});

