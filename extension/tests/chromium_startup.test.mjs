import assert from "node:assert/strict";
import { compile_dnr } from "../core/dnr.js";
import { test } from "node:test";

function event() {
  const listeners = [];
  return {
    addListener(listener) {
      listeners.push(listener);
    },
    listeners,
  };
}

test("Chromium attributes DNR matches seen during worker startup", async () => {
  globalThis.setTimeout = () => ({ unref() {} });
  const policy = {
    schema_version: 6,
    revision: 1,
    rules: [{
      id: "old",
      enabled: true,
      targets: [{ kind: "url_path", value: "example.com/blocked" }],
    }],
  };
  const dynamicRules = compile_dnr(policy.rules).map((entry) => entry.rule);
  const session = {
    match_totals: [],
    usage_totals: [],
  };
  let releasePolicy;
  const policyReady = new Promise((resolve) => {
    releasePolicy = resolve;
  });
  let requestListener;
  let messageListener;
  const local = {};
  const nativePort = {
    onMessage: event(),
    onDisconnect: event(),
    postMessage() {},
    disconnect() {},
  };
  const browserEvents = {
    onInstalled: event(),
    onStartup: event(),
    onAlarm: event(),
    onChanged: event(),
    onActivated: event(),
    onCreated: event(),
    onRemoved: event(),
    onReplaced: event(),
    onAttached: event(),
    onDetached: event(),
  };
  globalThis.chrome = {
    runtime: {
      lastError: null,
      onInstalled: browserEvents.onInstalled,
      onStartup: browserEvents.onStartup,
      onMessage: {
        addListener(listener) {
          messageListener = listener;
        },
      },
      connectNative() {
        return nativePort;
      },
    },
    alarms: {
      onAlarm: browserEvents.onAlarm,
      create() {},
    },
    storage: {
      session: {
        get(key) {
          if (key === "policy_snapshot") {
            return policyReady.then((snapshot) => ({ policy_snapshot: snapshot }));
          }
          return Promise.resolve({ [key]: session[key] });
        },
        set(values) {
          Object.assign(session, values);
          return Promise.resolve();
        },
      },
      local: {
        get() {
          return Promise.resolve(local);
        },
        set(values) {
          Object.assign(local, values);
          return Promise.resolve();
        },
      },
      onChanged: browserEvents.onChanged,
    },
    tabs: {
      query: async () => [],
      onActivated: browserEvents.onActivated,
      onCreated: browserEvents.onCreated,
      onRemoved: browserEvents.onRemoved,
      onReplaced: browserEvents.onReplaced,
      onAttached: browserEvents.onAttached,
      onDetached: browserEvents.onDetached,
    },
    declarativeNetRequest: {
      getDynamicRules: async () => dynamicRules,
      updateDynamicRules: async ({ removeRuleIds, addRules }) => {
        for (const id of removeRuleIds) {
          const index = dynamicRules.findIndex((rule) => rule.id === id);
          if (index >= 0) dynamicRules.splice(index, 1);
        }
        dynamicRules.push(...addRules);
      },
      updateSessionRules: async () => {},
    },
    webRequest: {
      onBeforeRequest: {
        addListener(listener) {
          requestListener = listener;
        },
      },
    },
  };

  await import("../chromium/background.js?startup-regression");
  requestListener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked",
  });
  releasePolicy({ rules: policy.rules });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  const status = {};
  messageListener({}, {}, (value) => Object.assign(status, value));
  assert.equal(status.denials["old → example.com/blocked"], 1);
});
