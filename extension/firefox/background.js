/**
 * Background event page: policy link and request blocking.
 *
 * Policy flows one way. The service authors rules; this script fetches them
 * through the root-owned native messaging host, compiles them with
 * engine.compile, and cancels matching loads. Denied loads are batched and
 * reported back as observational statistics.
 */
"use strict";

/* global browser, compile */

const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_MS = 5 * 60 * 1000;

let match = compile([]);
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
const pending_denials = new Map(); // "rule_id\u0000value" -> count

function record_state(error) {
  last_error = error;
  try {
    browser.storage.local.set({
      policy_ok: error === null,
      last_error,
      last_refresh_ms,
      denials: Object.fromEntries(
        [...pending_denials].map(([key, count]) => [
          key.replaceAll("\u0000", " → "),
          count,
        ]),
      ),
    });
  } catch {
    // A closed event page loses nothing that matters; the next refresh rewrites it.
  }
}

function apply_rules(rules) {
  if (!Array.isArray(rules)) {
    record_state("The service returned an invalid rule list.");
    return;
  }
  match = compile(rules);
  last_error = null;
  record_state(null);
}

/** Send one native-messaging request and resolve with its response. */
function host_request(message) {
  return new Promise((resolve) => {
    const port = browser.runtime.connectNative(HOST_NAME);
    port.onMessage.addListener((response) => {
      port.disconnect();
      resolve(response);
    });
    port.onDisconnect.addListener(() => {
      resolve({
        ok: false,
        error: {
          code: "host_error",
          message:
            browser.runtime.lastError?.message ??
            "the native messaging host went away",
        },
      });
    });
    port.postMessage(message);
  });
}

async function flush_denials() {
  if (pending_denials.size === 0) {
    return;
  }
  const entries = [];
  for (const [key, count] of pending_denials.splice(0)) {
    const cut = key.indexOf("\u0000");
    entries.push({
      rule_id: key.slice(0, cut),
      value: key.slice(cut + 1),
      count,
    });
  }
  // Breadcrumb: cap each report so one message stays far below the native
  // messaging frame limit.
  const response = await host_request({
    command: "report_website_denials",
    entries: entries.slice(0, 128),
  });
  if (!(response && response.ok)) {
    // Put the counts back so a transient failure is not lost silently.
    for (const entry of entries) {
      const key = `${entry.rule_id}\u0000${entry.value}`;
      pending_denials.set(key, (pending_denials.get(key) ?? 0) + entry.count);
    }
    record_state(
      `Denial report refused: ${response.error.code}: ${response.error.message}`,
    );
  }
}

async function refresh() {
  await flush_denials();
  const response = await host_request({ command: "list_rules" });
  last_refresh_ms = Date.now();
  if (response && response.ok) {
    // The service returns the full enabled-and-disabled list; the compiler
    // keeps disabled rules out of enforcement.
    apply_rules(response.result);
  } else {
    record_state(
      response && response.error
        ? `${response.error.code}: ${response.error.message}`
        : "The native messaging host returned no response.",
    );
  }
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId === -1 || !details.url.startsWith("http")) {
      return {};
    }
    const hit = match(details.url);
    if (hit === null) {
      return {};
    }
    const key = `${hit.rule_id}\u0000${hit.value}`;
    pending_denials.set(key, (pending_denials.get(key) ?? 0) + 1);
    record_state(null);
    return { cancel: true };
  },
  { urls: ["<all_urls>"] },
  ["blocking"],
);

browser.runtime.onMessage.addListener((_message) => {
  return Promise.resolve({
    policy_ok: last_error === null,
    last_error,
    last_refresh_ms,
    denials: Object.fromEntries(
      [...pending_denials].map(([key, count]) => [
        key.replaceAll("\u0000", " → "),
        count,
      ]),
    ),
  });
});

refresh();
setInterval(refresh, REFRESH_MS);
