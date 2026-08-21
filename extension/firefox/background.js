/**
 * Background event page: policy link and request blocking.
 *
 * Policy flows one way. The service authors rules; this script fetches them
 * through the root-owned native messaging host, compiles them with
 * engine.compile, and cancels matching loads. Statistics stay local until a
 * later phase adds reporting.
 */
"use strict";

/* global browser, compile */

const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_MS = 5 * 60 * 1000;

let match = compile([]);
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
let denial_counts = new Map(); // rule_id -> denied load count

function record_state(error) {
  last_error = error;
  try {
    browser.storage.local.set({
      policy_ok: error === null,
      last_error,
      last_refresh_ms,
      denials: Object.fromEntries(denial_counts),
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

function refresh() {
  const port = browser.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener((response) => {
    port.disconnect();
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
  });
  port.onDisconnect.addListener(() => {
    if (browser.runtime.lastError) {
      record_state(
        `Native host disconnected: ${browser.runtime.lastError.message}`,
      );
    }
  });
  port.postMessage({ command: "list_rules" });
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
    denial_counts.set(hit.rule_id, (denial_counts.get(hit.rule_id) ?? 0) + 1);
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
    denials: Object.fromEntries(denial_counts),
    rules: match && typeof match.rule_list !== "undefined" ? match.rule_list : undefined,
  });
});

refresh();
setInterval(refresh, REFRESH_MS);
