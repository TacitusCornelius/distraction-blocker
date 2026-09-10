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

// Breadcrumb: Firefox uses a persistent MV2 background page. The alarm
// still refreshes policy after install and browser start.
const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_ALARM = "policy-refresh";
const REFRESH_MINUTES = 1;
const INACTIVE_KEY = "inactive-tab";

let match = compile([]);
let policy_ready = false;
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
let block_inactive = false;

const pending_denials = new Map(); // encoded rule_id/value -> count
const inactive_denials = new Map(); // URL -> local-only count

// Breadcrumb: allowance rules are permitted, not blocked - their
// top-of-page starts count toward a budget the service enforces later.
let match_allowance = compile([]);
const pending_usage = new Map(); // encoded rule_id/value -> permitted starts

// Breadcrumb: onInstalled/onStartup/alarm ticks can overlap; serialize
// refreshes so interleaved host_request/apply_rules pairs never race.
let refresh_queue = Promise.resolve();
function queue_refresh() {
  refresh_queue = refresh_queue.then(refresh).catch((err) => {
    console.error("refresh failed", err);
  });
}
// Breadcrumb: the MV2 background stays alive, so it does not need an
// event-page timer. The alarms API still refreshes policy on a fixed period.
browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});
browser.runtime.onStartup.addListener(() => {
  browser.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) {
    queue_refresh();
  }
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
  const out = usage_snapshot(pending_denials);
  for (const [url, count] of inactive_denials) {
    out[`${INACTIVE_KEY} → ${url}`] = count;
  }
  return out;
}

function record_state(error) {
  // Breadcrumb: callers pass the new state; without this assignment every
  // failure kept surfacing as the stale startup sentinel.
  if (error !== undefined) {
    last_error = error;
  }
  try {
    browser.storage.local.set({
      policy_ok: error === null,
      last_error,
      last_refresh_ms,
      denials: denial_snapshot(),
      usage: usage_snapshot(pending_usage),
    });
  } catch {
    // A closed event page loses nothing that matters; the next refresh rewrites it.
  }
}

function apply_policy(policy) {
  let rules;
  try {
    rules = rules_from_policy(policy);
  } catch (error) {
    policy_ready = false;
    record_state(String(error.message ?? error));
    return false;
  }
  // Breadcrumb: partition before compiling. Enforced rules keep blocking;
  // allowance rules permit starts until their budget is exhausted.
  const { enforced, allowance } = partition_rules(rules);
  match = compile(enforced);
  match_allowance = compile(allowance);
  prune_usage(pending_usage, rules);
  // Breadcrumb: Firefox has no persisted DNR equivalent. Once compilation
  // succeeds, requests can leave the startup fail-closed state.
  policy_ready = true;
  last_error = null;
  record_state(null);
  return true;
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
  // Only rule-matched denials travel to the service. Inactive-tab counts stay
  // local because they carry no service rule ID.
  const entries = usage_entries(pending_denials, 128);
  if (entries.length === 0) {
    return;
  }
  const response = await host_request({
    command: "report_website_denials",
    entries,
  });
  if (!(response && response.ok)) {
    const detail = response?.error
      ? `${response.error.code}: ${response.error.message}`
      : "the native messaging host returned no response";
    record_state(`Denial report refused: ${detail}`);
    return;
  }
  retire_usage(pending_denials, entries);
  record_state(null);
}

async function flush_usage() {
  if (pending_usage.size === 0) {
    return;
  }
  const entries = usage_entries(pending_usage, 128);
  const response = await host_request({
    command: "report_website_usage",
    entries,
  });
  if (!(response && response.ok)) {
    const detail = response?.error
      ? `${response.error.code}: ${response.error.message}`
      : "the native messaging host returned no response";
    // Breadcrumb: nothing left the map yet, so the counts are simply
    // retried on the next cycle; record_state keeps them on disk.
    record_state(`Usage report refused: ${detail}`);
    return;
  }
  retire_usage(pending_usage, entries);
  record_state(null);
}

async function refresh() {
  await state_ready;
  const response = await host_request({ command: "list_rules" });
  last_refresh_ms = Date.now();
  if (response && response.ok) {
    // The schema parser accepts the policy before either matcher changes.
    if (apply_policy(response.result)) {
      await flush_denials();
      await flush_usage();
    }
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

const state_ready = browser.storage.local.get(["denials", "usage"]).then((stored) => {
  merge_labels(pending_denials, stored?.denials, [INACTIVE_KEY]);
  merge_labels(pending_usage, stored?.usage);
  const prefix = `${INACTIVE_KEY} → `;
  for (const [label, count] of Object.entries(stored?.denials ?? {})) {
    if (label.startsWith(prefix)) {
      bump_bounded(inactive_denials, label.slice(prefix.length), count);
    }
  }
});

browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId === -1 || !details.url.startsWith("http")) {
      return {};
    }
    if (!policy_ready) {
      return { cancel: true };
    }
    const hit = match(details.url);
    if (hit !== null) {
      bump_usage(pending_denials, hit.rule_id, hit.value);
      record_state(null);
      return { cancel: true };
    }
    // Breadcrumb: reaching here means no enforced rule matched, so this
    // load cannot have been blocked. A permitted main-frame start under an
    // allowance rule is exactly one unit of usage; sub_frame loads never
    // count as starts.
    if (details.type === "main_frame") {
      const allowed = match_allowance(details.url);
      if (allowed !== null) {
        bump_usage(pending_usage, allowed.rule_id, allowed.value);
        record_state(null);
      }
    }
    if (block_inactive && (await tab_is_inactive(details.tabId))) {
      const url = details.url.slice(0, 200);
      bump_bounded(inactive_denials, url);
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

queue_refresh();
