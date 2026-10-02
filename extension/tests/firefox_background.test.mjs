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

test("Firefox seeds the allowance tracker from the browser's current idle state", async () => {
  const rule_id = "33333333-3333-4333-8333-333333333333";
  const runtime = {
    onInstalled: event(),
    onStartup: event(),
    onMessage: event(),
    getURL(path) {
      return `moz-extension://test/${path}`;
    },
    connectNative() {
      const port = {
        onMessage: event(),
        onDisconnect: event(),
        postMessage(message) {
          const now = new Date();
          const response = message.command === "request_allowance_lease"
            ? {
                ok: true,
                result: {
                  rule_id,
                  lease_id: "lease",
                  start_utc: now.toISOString(),
                  end_utc: new Date(now.getTime() + 30_000).toISOString(),
                },
              }
            : { ok: true, result: {} };
          queueMicrotask(() => {
            for (const listener of port.onMessage.listeners) listener(response);
          });
        },
        disconnect() {},
      };
      return port;
    },
  };
  const browser = {
    runtime,
    alarms: { create() {}, onAlarm: event() },
    storage: {
      local: {
        get: () => Promise.resolve({}),
        set: () => Promise.resolve(),
      },
      onChanged: event(),
    },
    idle: {
      onStateChanged: event(),
      queryState: async () => "active",
    },
    webRequest: { onBeforeRequest: event() },
    tabs: {
      onActivated: event(),
      onUpdated: event(),
      onRemoved: event(),
      get: async () => ({ id: 7, active: true }),
      query: async () => [],
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
    queueMicrotask,
  });
  const coreFiles = ["usage.js", "policy.js", "engine.js", "dnr.js", "allowance.js"];
  const source = [
    ...coreFiles.map((file) =>
      readFileSync(new URL(`../firefox/core/${file}`, import.meta.url), "utf8"),
    ),
    readFileSync(new URL("../firefox/background.js", import.meta.url), "utf8"),
  ].join("\n");
  vm.runInContext(source, context);
  const acquired = await vm.runInContext(`(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    await allowance_tracker.set_active_tab(7, { rule_id: "${rule_id}" });
    await allowance_tracker.set_focused(true);
    return allowance_tracker.has_lease("${rule_id}");
  })()`, context);
  assert.equal(acquired, true);
});

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
  const host_requests = [];
  let status_response = {
    ok: true,
    result: {
      active: true,
      remaining_seconds: 0,
      window_seconds: null,
      daily_cap_seconds: null,
    },
  };
  const nativePort = {
    onMessage: event(),
    onDisconnect: event(),
    postMessage(message) {
      host_requests.push(message);
      if (message.command === "allowance_status") {
        for (const listener of nativePort.onMessage.listeners) {
          listener(status_response);
        }
        return;
      }
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
  const timed_rule_id = "timed-rule";
  assert.equal(await vm.runInContext(
    `apply_policy(${JSON.stringify({
      schema_version: 6,
      revision: 2,
      rules: [{
        id: timed_rule_id,
        name: "Social Media Evenings",
        enabled: true,
        targets: [{ kind: "url_path", value: "example.com/blocked.html" }],
        allowance_time: {
          periods: [{ mode: "fixed_window", quota_seconds: 600, window_seconds: 3600 }],
          daily_cap_seconds: 3600,
        },
        budget_exhausted: true,
      }],
    })})`,
    context,
  ), true);
  const exhausted_page = new URL(await listener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked.html",
  }).then((result) => result.redirectUrl));
  assert.equal(exhausted_page.searchParams.get("rule_id"), timed_rule_id);
  const status = await vm.runInContext(
    `allowance_status_for_url(${JSON.stringify(exhausted_page.href)})`,
    context,
  );
  assert.equal(status.ok, true);
  assert.equal(status.result.remaining_seconds, 0);
  assert.equal(status.result.rule_name, "Social Media Evenings");
  assert.equal(host_requests.at(-1).command, "allowance_status");
  assert.equal(host_requests.at(-1).rule_id, timed_rule_id);
  const public_blocked_path_status = await vm.runInContext(
    `allowance_status_for_url("https://example.com/blocked.html", ${JSON.stringify(timed_rule_id)})`,
    context,
  );
  assert.equal(public_blocked_path_status.result.remaining_seconds, 0);

  assert.equal(await vm.runInContext(
    `apply_policy(${JSON.stringify({
      schema_version: 6,
      revision: 3,
      rules: [
        {
          id: "strict-rule",
          name: "Strict",
          enabled: true,
          targets: [{ kind: "url_path", value: "example.com/blocked.html" }],
        },
        {
          id: timed_rule_id,
          name: "Social Media Evenings",
          enabled: true,
          targets: [{ kind: "url_path", value: "example.com/blocked.html" }],
          allowance_time: {
            periods: [{ mode: "fixed_window", quota_seconds: 600, window_seconds: 3600 }],
            daily_cap_seconds: 3600,
          },
        },
      ],
    })})`,
    context,
  ), true);
  const before_overlap_status = host_requests.length;
  const overlap_status = await vm.runInContext(
    `allowance_status_for_url("https://example.com/blocked.html")`,
    context,
  );
  assert.equal(overlap_status.result, null);
  assert.equal(host_requests.length, before_overlap_status);
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
