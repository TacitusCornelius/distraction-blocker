/**
 * Unit tests for the URL rule matcher. Run: node --test extension/firefox/
 */
"use strict";

import test from "node:test";
import assert from "node:assert/strict";

import { compile, describe_url, split_target } from "./engine.js";

const RULES = [
  {
    id: "path-rule",
    enabled: true,
    targets: [{ kind: "url_path", value: "example.com/feed" }],
  },
  {
    id: "wild-rule",
    enabled: true,
    targets: [
      { kind: "url_wildcard", value: "example.com/vid/*" },
      { kind: "url_path", value: "Example.ORG/root" },
    ],
  },
  {
    id: "word-rule",
    enabled: true,
    targets: [{ kind: "url_keyword", value: "casino" }],
  },
  {
    id: "disabled",
    enabled: false,
    targets: [{ kind: "url_path", value: "example.com/off" }],
  },
];

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

test("url_path matches hostname case-insensitively and path exactly", () => {
  const match = compile(RULES);
  assert.equal(match("https://example.com/feed").rule_id, "path-rule");
  assert.equal(match("https://EXAMPLE.com/feed").rule_id, "path-rule");
  assert.equal(match("https://example.com/feed/extra"), null);
  assert.equal(match("https://example.com/feeds"), null);
});

test("url_wildcard matches by prefix and stays inside its host", () => {
  const match = compile(RULES);
  assert.equal(
    match("https://example.com/vid/98765432").rule_id,
    "wild-rule",
  );
  // Breadcrumb: the star is terminal, so only the prefix is required.
  assert.equal(match("https://example.com/vid/").rule_id, "wild-rule");
  assert.equal(match("https://example.org/vid/x"), null);
});

test("url_keyword matches anywhere in the full URL", () => {
  const match = compile(RULES);
  assert.equal(
    match("https://search.example.net/q?click=casino+bonus").rule_id,
    "word-rule",
  );
});

test("disabled rules never match", () => {
  const match = compile(RULES);
  assert.equal(match("https://example.com/off"), null);
});

test("empty or absent rule lists block nothing", () => {
  assert.equal(compile([])("https://example.com/feed"), null);
  assert.equal(compile(null)("https://example.com/feed"), null);
});

test("compile tolerates malformed rule entries", () => {
  const match = compile([{ id: "bad" }, { id: "ok", enabled: true, targets: [] }]);
  assert.equal(match("https://example.com/feed"), null);
});
