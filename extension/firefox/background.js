/**
 * Background event page: policy link, request blocking, tab blocking.
 *
 * Policy flows one way. The service authors rules; this script fetches them
 * through the root-owned native messaging host, compiles them with
 * engine.compile, and cancels matching loads. Denied loads are batched and
 * reported back as observational statistics. Inactive-tab blocking is a
 * local toggle; its counts never reach the service.
 */
"use strict";

// Breadcrumb: the manifest declares this page as a module, so engine.js
// must be imported explicitly - module scopes are not shared globals.
import { compile } from "../core/engine.js";

const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_MS = 60 * 1000;
const CANARY_PORT = 8765;
const INACTIVE_KEY = "inactive-tab";

let match = compile([]);
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
let block_inactive = false;
const pending_denials = new Map(); // "rule_id\u0000value" -> count

// Breadcrumb: MV3 event pages do not reliably load at browser startup
// unless a startup event is handled, so pin the policy refresh to them.
browser.runtime.onStartup.addListener(() => {
  refresh();
});
browser.runtime.onInstalled.addListener(() => {
  refresh();
});

browser.storage.local.get("block_inactive").then((stored) => {
  block_inactive = stored.block_inactive === true;
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && "block_inactive" in changes) {
    block_inactive = changes.block_inactive.newValue === true;
  }
});

function denial_snapshot() {
  return Object.fromEntries(
    [...pending_denials].map(([key, count]) => [
      key.replaceAll("\u0000", " → "),
      count,
    ]),
  );
}

function record_state(error) {
  try {
    browser.storage.local.set({
      policy_ok: error === null,
      last_error,
      last_refresh_ms,
      denials: denial_snapshot(),
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
    let port;
    try {
      port = browser.runtime.connectNative(HOST_NAME);
    } catch (error) {
      resolve({ ok: false, error: { code: "host_error", message: String(error) } });
      return;
    }
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
  // Only rule-matched denials travel to the service; inactive-tab counts are
  // local because they carry no rule ID.
  const reportable = [...pending_denials].filter(
    ([key]) => !key.startsWith(INACTIVE_KEY),
  );
  if (reportable.length === 0) {
    return;
  }
  const entries = reportable.map(([key, count]) => {
    const cut = key.indexOf("\u0000");
    return { rule_id: key.slice(0, cut), value: key.slice(cut + 1), count };
  });
  pending_denials.clear();
  // Breadcrumb: cap each report so one message stays far below the native
  // messaging frame limit.
  const response = await host_request({
    command: "report_website_denials",
    entries: entries.slice(0, 128),
  });
  if (!(response && response.ok)) {
    for (const entry of entries) {
      const key = `${entry.rule_id}\u0000${entry.value}`;
      pending_denials.set(
        key,
        (pending_denials.get(key) ?? 0) + entry.count,
      );
    }
    record_state(
      `Denial report refused: ${response.error.code}: ${response.error.message}`,
    );
  } else {
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

/** True when the tab holding this request is not the visible tab. */
async function tab_is_inactive(tabId) {
  try {
    const tab = await browser.tabs.get(tabId);
    return tab.active === false;
  } catch {
    return false;
  }
}

browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId === -1 || !details.url.startsWith("http")) {
      return {};
    }
    const hit = match(details.url);
    if (hit !== null) {
      const key = `${hit.rule_id}\u0000${hit.value}`;
      pending_denials.set(key, (pending_denials.get(key) ?? 0) + 1);
      record_state(null);
      return { cancel: true };
    }
    if (block_inactive && (await tab_is_inactive(details.tabId))) {
      const key = `${INACTIVE_KEY}\u0000${details.url.slice(0, 200)}`;
      pending_denials.set(key, (pending_denials.get(key) ?? 0) + 1);
      record_state(null);
      return { cancel: true };
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"],
);

browser.runtime.onMessage.addListener((_message) => {
  return Promise.resolve({
    policy_ok: last_error === null,
    last_error,
    last_refresh_ms,
    block_inactive,
    denials: denial_snapshot(),
  });
});

refresh();
setInterval(refresh, REFRESH_MS);
