import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

function event() {
  const listeners = [];
  return {
    addListener(listener) {
      listeners.push(listener);
    },
    listeners,
  };
}

test("Firefox blocks HTTP requests before the first policy response", async () => {
  const runtime = {
    onInstalled: event(),
    onStartup: event(),
    onMessage: event(),
    getURL(path) {
      return `moz-extension://test/${path}`;
    },
    connectNative() {
      return nativePort;
    },
  };
  const nativePort = {
    onMessage: event(),
    onDisconnect: event(),
    postMessage() {},
    disconnect() {},
  };
  const webRequest = { onBeforeRequest: event() };
  const browser = {
    runtime,
    alarms: { create() {}, onAlarm: event() },
    storage: {
      local: {
        get() {
          return Promise.resolve({});
        },
        set() {
          return Promise.resolve();
        },
      },
      onChanged: event(),
    },
    webRequest,
    tabs: { get: async () => ({ active: true }) },
  };
  const context = vm.createContext({
    browser,
    console,
    Date,
    Promise,
    URL,
    URLSearchParams,
    setTimeout,
  });
  const coreFiles = ["usage.js", "policy.js", "engine.js", "dnr.js", "allowance.js"];
  const source = [
    ...coreFiles.map((file) =>
      readFileSync(new URL(`../firefox/core/${file}`, import.meta.url), "utf8"),
    ),
    readFileSync(new URL("../firefox/background.js", import.meta.url), "utf8"),
  ].join("\n");
  vm.runInContext(source, context);

  assert.equal(webRequest.onBeforeRequest.listeners.length, 1);
  const listener = webRequest.onBeforeRequest.listeners[0];
  const startup_result = await listener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/",
  });
  const startup_page = new URL(startup_result.redirectUrl);
  assert.equal(startup_page.pathname, "/blocked.html");
  assert.equal(startup_page.searchParams.get("rule"), "Policy is not ready");

  const applied = vm.runInContext(
    `apply_policy(${JSON.stringify({
      schema_version: 5,
      revision: 1,
      rules: [{
        id: "test-rule",
        name: "Test extension rule",
        enabled: true,
        targets: [{ kind: "url_path", value: "example.com/blocked" }],
      }],
    })})`,
    context,
  );
  assert.equal(applied, true);
  const result = await listener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked",
  });
  const page = new URL(result.redirectUrl);
  assert.equal(page.pathname, "/blocked.html");
  assert.equal(page.searchParams.get("rule"), "Test extension rule");
  assert.equal(page.searchParams.get("url"), "https://example.com/blocked");
});
