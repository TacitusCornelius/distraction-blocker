"use strict";

import test from "node:test";
import assert from "node:assert/strict";

function event() {
  return { addListener() {} };
}

function policy(id, value, revision) {
  const targets = Array.isArray(value)
    ? value
    : [{ kind: "url_path", value }];
  return {
    schema_version: 1,
    revision,
    rules: [{
      id,
      enabled: true,
      targets,
    }],
  };
}

test("Chromium keeps the old policy state when DNR rejects a replacement", async () => {
  const dynamicRules = [];
  const session = {};
  const local = {};
  let getFailure = false;
  let updateFailure = false;
  let sessionUpdateFailure = true;
  let hostResponse = {
    ok: false,
    error: { code: "test_host", message: "not configured" },
  };
  let reportRequest;
  let webRequestListener;
  let messageListener;

  globalThis.setTimeout = () => ({ unref() {} });
  globalThis.chrome = {
    runtime: {
      lastError: null,
      onInstalled: event(),
      onStartup: event(),
      onMessage: {
        addListener(listener) {
          messageListener = listener;
        },
      },
      connectNative() {
        let onMessage;
        return {
          onMessage: { addListener(listener) { onMessage = listener; } },
          onDisconnect: { addListener() {} },
          disconnect() {},
          postMessage(message) {
            if (message.command === "report_website_denials") {
              reportRequest = message;
            }
            queueMicrotask(() => onMessage?.(
              message.command === "report_website_denials"
                ? hostResponse
                : {
                    ok: false,
                    error: { code: "test_host", message: "not configured" },
                  },
            ));
          },
        };
      },
    },
    alarms: { onAlarm: event(), create() {} },
    storage: {
      session: {
        get(key) {
          return Promise.resolve({ [key]: session[key] });
        },
        set(values) {
          Object.assign(session, values);
          return Promise.resolve();
        },
      },
      local: {
        get() { return Promise.resolve(local); },
        set(values) {
          Object.assign(local, values);
          return Promise.resolve();
        },
      },
      onChanged: event(),
    },
    tabs: {
      query() { return Promise.resolve([]); },
      onActivated: event(),
      onCreated: event(),
      onRemoved: event(),
      onReplaced: event(),
      onAttached: event(),
      onDetached: event(),
    },
    declarativeNetRequest: {
      getDynamicRules() {
        if (getFailure) {
          return Promise.reject(new Error("get rejected"));
        }
        return Promise.resolve(dynamicRules.map((rule) => structuredClone(rule)));
      },
      updateDynamicRules({ removeRuleIds, addRules }) {
        if (updateFailure) {
          return Promise.reject(new Error("update rejected"));
        }
        for (const id of removeRuleIds) {
          const index = dynamicRules.findIndex((rule) => rule.id === id);
          if (index >= 0) dynamicRules.splice(index, 1);
        }
        dynamicRules.push(...addRules.map((rule) => structuredClone(rule)));
        return Promise.resolve();
      },
      updateSessionRules() {
        if (sessionUpdateFailure) {
          return Promise.reject(new Error("session update rejected"));
        }
        return Promise.resolve();
      },
    },
    webRequest: {
      onBeforeRequest: {
        addListener(listener) { webRequestListener = listener; },
      },
    },
  };

  const { apply_policy, report_matches } = await import("../chromium/background.js");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(local.inactive_ok, false);
  assert.match(local.inactive_error, /session update rejected/);
  sessionUpdateFailure = false;

  assert.equal(
    await apply_policy(policy("old", "example.com/blocked", 1)),
    true,
  );
  await webRequestListener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked",
  });
  assert.equal(dynamicRules.length, 1);
  const oldRule = structuredClone(dynamicRules[0]);

  getFailure = true;
  assert.equal(
    await apply_policy(policy("new", "new.example/blocked", 2)),
    false,
  );
  assert.deepEqual(dynamicRules, [oldRule]);
  assert.equal(local.policy_ok, false);
  assert.match(local.last_error, /get rejected/);

  getFailure = false;
  updateFailure = true;
  assert.equal(
    await apply_policy(policy("new", "new.example/blocked", 2)),
    false,
  );
  assert.deepEqual(dynamicRules, [oldRule]);
  await webRequestListener({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/blocked",
  });
  assert.equal(local.policy_ok, false);
  assert.match(local.last_error, /update rejected/);
  assert.equal(local.denials["new → new.example/blocked"], undefined);

  const status = {};
  messageListener({}, {}, (value) => Object.assign(status, value));
  assert.equal(status.policy_ok, false);
  assert.equal(status.denials["old → example.com/blocked"], 2);
  updateFailure = false;
  const overlap = {
    schema_version: 1,
    revision: 3,
    rules: [
      {
        id: "allow",
        enabled: true,
        allowance_starts: 2,
        targets: [{ kind: "url_path", value: "overlap.example/blocked" }],
      },
      {
        id: "enforced",
        enabled: true,
        targets: [{ kind: "url_path", value: "overlap.example/blocked" }],
      },
    ],
  };
  assert.equal(await apply_policy(overlap), true);
  await webRequestListener({
    tabId: 7,
    type: "main_frame",
    url: "https://overlap.example/blocked",
  });
  const overlapStatus = {};
  messageListener({}, {}, (value) => Object.assign(overlapStatus, value));
  assert.equal(
    overlapStatus.denials["enforced → overlap.example/blocked"],
    1,
  );
  assert.equal(
    local.usage?.["allow → overlap.example/blocked"],
    undefined,
  );

  const exhausted = {
    schema_version: 1,
    revision: 4,
    rules: [{
      id: "spent",
      enabled: true,
      allowance_starts: 2,
      budget_exhausted: true,
      targets: [{ kind: "url_path", value: "spent.example/blocked" }],
    }],
  };
  assert.equal(await apply_policy(exhausted), true);
  assert.equal(dynamicRules.length, 1);
  await webRequestListener({
    tabId: 7,
    type: "main_frame",
    url: "https://spent.example/blocked",
  });
  const exhaustedStatus = {};
  messageListener({}, {}, (value) => Object.assign(exhaustedStatus, value));
  assert.equal(
    exhaustedStatus.denials["spent → spent.example/blocked"],
    1,
  );
  assert.equal(
    exhaustedStatus.denials["enforced → overlap.example/blocked"],
    1,
  );
  const bulkTargets = Array.from({ length: 129 }, (_, index) => ({
    kind: "url_path",
    value: `bulk-${index}.example/blocked`,
  }));
  assert.equal(await apply_policy(policy("bulk", bulkTargets, 3)), true);
  for (let index = 0; index < bulkTargets.length; index += 1) {
    await webRequestListener({
      tabId: 7,
      type: "main_frame",
      url: `https://bulk-${index}.example/blocked`,
    });
  }
  hostResponse = { ok: true, result: null };
  await report_matches();
  assert.equal(reportRequest.entries.length, 128);
  assert.equal(
    local.denials["bulk → bulk-128.example/blocked"],
    1,
  );
});
