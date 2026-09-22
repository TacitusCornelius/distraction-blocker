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
    postMessage() {
      for (const listener of nativePort.onDisconnect.listeners) {
        listener();
      }
    },
    disconnect() {},
  };
  const webRequest = { onBeforeRequest: event() };
  const updates = [];
  let currentTabUrl = "https://example.com/";
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
    tabs: {
      get: async () => ({ id: 7, active: true, url: currentTabUrl }),
      update: async (tabId, details) => {
        updates.push({ tabId, details });
        currentTabUrl = details.url;
        return { id: tabId, url: details.url };
      },
    },
  };
  const context = vm.createContext({
    browser,
    console,
    Date,
    Promise,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
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
      schema_version: 6,
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
  currentTabUrl = "https://example.com/blocked";
  vm.runInContext(
    `active_tab_id = 7; active_tab_url = "https://example.com/blocked";`,
    context,
  );
  await vm.runInContext("redirect_active_tab_if_blocked()", context);
  assert.equal(updates.length, 1);
  assert.equal(updates[0].tabId, 7);
  const forced_page = new URL(updates[0].details.url);
  assert.equal(forced_page.pathname, "/blocked.html");
  assert.equal(forced_page.searchParams.get("rule"), "Test extension rule");
  assert.equal(forced_page.searchParams.get("url"), "https://example.com/blocked");
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

test("Firefox restores cached policy before handling startup requests", async () => {
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
    postMessage() {
      for (const listener of nativePort.onDisconnect.listeners) {
        listener();
      }
    },
    disconnect() {},
  };
  const webRequest = { onBeforeRequest: event() };
  const snapshot = {
    schema_version: 6,
    revision: 7,
    rules: [{
      id: "cached-rule",
      name: "Cached rule",
      enabled: true,
      targets: [{ kind: "url_path", value: "example.com/blocked" }],
    }],
  };
  const browser = {
    runtime,
    alarms: { create() {}, onAlarm: event() },
    storage: {
      local: {
        get() {
          return Promise.resolve({ policy_snapshot: snapshot });
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
    clearTimeout,
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

  const listener = webRequest.onBeforeRequest.listeners[0];
  const allowed = await listener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/",
  });
  assert.equal(allowed.redirectUrl, undefined);
  const blocked = await listener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked",
  });
  const page = new URL(blocked.redirectUrl);
  assert.equal(page.searchParams.get("rule"), "Cached rule");
});
