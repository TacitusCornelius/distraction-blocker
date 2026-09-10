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
  const context = vm.createContext({ browser, console, Date, Promise, setTimeout });
  const coreFiles = ["usage.js", "policy.js", "engine.js", "dnr.js"];
  const source = [
    ...coreFiles.map((file) =>
      readFileSync(new URL(`../firefox/core/${file}`, import.meta.url), "utf8"),
    ),
    readFileSync(new URL("../firefox/background.js", import.meta.url), "utf8"),
  ].join("\n");
  vm.runInContext(source, context);

  assert.equal(webRequest.onBeforeRequest.listeners.length, 1);
  const result = await webRequest.onBeforeRequest.listeners[0]({
    tabId: 7,
    type: "main_frame",
    url: "https://example.com/",
  });
  assert.equal(result.cancel, true);
});
