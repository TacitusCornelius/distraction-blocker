/**
 * Chromium service worker: policy link and declarative blocking.
 *
 * The service authors rules; this worker fetches them through the
 * root-owned native messaging host, compiles them with core/dnr.js into
 * dynamic declarativeNetRequest rules, and reports matched-load counts
 * back as observational statistics. Dynamic rules persist across service
 * worker suspensions, so enforcement never depends on this script staying
 * alive.
 */
"use strict";

import { compile_dnr, compile_inactive_tab_rule } from "./core/dnr.js";
import { AllowanceTracker } from "./core/allowance.js";
// Breadcrumb: observational attribution only. DNR does the blocking; this
// matcher just attributes observed loads so denial counts match Firefox.
import { compile } from "./core/engine.js";
import { rules_from_policy } from "./core/policy.js";
import {
  bump_bounded,
  bump_usage,
  COUNTER_MAX,
  decode_usage_key,
  is_time_allowance_rule,
  partition_rules,
  prune_usage,
  restore_usage,
  retire_usage,
  usage_entries,
  usage_key,
  usage_snapshot,
} from "./core/usage.js";

const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_ALARM = "policy-refresh";
const REFRESH_MINUTES = 1;
const INACTIVE_KEY = "inactive-tab";
// Session and dynamic DNR rule ids use separate namespaces. Reserve one
// session id for the browser-local inactive-tab rule.
const INACTIVE_RULE_ID = 1;
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
/** Stable encoded rule/value -> { count, reported } pending denial totals. */
const match_totals = new Map();
/** DNR numeric id -> stable match key for new observations. */
const rule_meta = new Map();

// Breadcrumb: shared usage helpers own the stable encoded keys for
// permitted starts. Dynamic DNR rule IDs remain separate and temporary.
const usage_totals = new Map();
const USAGE_KEY = "usage_totals";
let usage_backup_scheduled = false;

const TOTALS_KEY = "match_totals";
const POLICY_KEY = "policy_snapshot";
const ALLOWANCE_REPORTS_KEY = "allowance_reports";
const TIMED_BLOCK_BASE = 1000000;
let attribution_initialized = false;
let attribution_paused = false;
let startup_observations = [];
let totals_backup_scheduled = false;
let match_enforced = null;
let match_allowance = null;
let match_time_allowance = null;
let active_tab_id = null;
let active_tab_url = null;
let allowance_timer = null;
let timed_policy_rules = new Map();
let timed_available_rules = new Set();
let timed_block_ids = new Map();
// Session rule updates share the lifecycle queue below.
const allowance_tracker = new AllowanceTracker({
  request_lease: (rule_id, seconds) =>
    host_request({ command: "request_allowance_lease", rule_id, seconds }),
  report_usage: ({ lease_id, report_id, start_utc, end_utc }) =>
    host_request({
      command: "report_allowance_usage",
      lease_id,
      report_id,
      start_utc,
      end_utc,
    }),
  on_exhausted: (rule_id) => {
    timed_available_rules.delete(rule_id);
    queue_timed_rule_block(rule_id, true);
    queue_refresh();
    schedule_allowance_pulse();
  },
  on_unavailable: (rule_id) => {
    timed_available_rules.delete(rule_id);
    queue_timed_rule_block(rule_id, true);
    schedule_allowance_pulse();
  },
  on_available: (rule_id) => {
    timed_available_rules.add(rule_id);
    queue_timed_rule_block(rule_id, false);
  },
  on_pending_changed: (reports) => {
    chrome.storage.session
      .set({ [ALLOWANCE_REPORTS_KEY]: reports.map((report) => ({ ...report })) })
      .catch(() => {});
  },
});
let block_inactive = false;
let inactive_error = null;
let inactive_tab_ids = new Set();
const inactive_denials = new Map();

// Breadcrumb: the service worker dies after ~30s idle. Stable pending keys
// stay in storage.session, so policy changes cannot mislabel old denials.
function schedule_totals_backup() {
  if (totals_backup_scheduled) {
    return;
  }
  totals_backup_scheduled = true;
  setTimeout(() => {
    totals_backup_scheduled = false;
    chrome.storage.session
      .set({ [TOTALS_KEY]: [...match_totals.entries()] })
      .catch(() => {});
  }, 5000);
}

function schedule_usage_backup() {
  if (usage_backup_scheduled) {
    return;
  }
  usage_backup_scheduled = true;
  setTimeout(() => {
    usage_backup_scheduled = false;
    chrome.storage.session
      .set({ [USAGE_KEY]: [...usage_totals.entries()] })
      .catch(() => {});
  }, 5000);
}

const totals_ready = chrome.storage.session
  .get(TOTALS_KEY)
  .then((stored) => {
    const plain = stored && stored[TOTALS_KEY];
    if (Array.isArray(plain)) {
      for (const [key, totals] of plain) {
        const decoded = decode_usage_key(key);
        if (
          decoded === null ||
          !totals ||
          !Number.isInteger(totals.count) ||
          totals.count < 0 ||
          !Number.isInteger(totals.reported) ||
          totals.reported < 0
        ) {
          continue;
        }
        match_totals.set(key, {
          count: totals.count,
          reported: Math.min(totals.count, totals.reported),
        });
      }
    }
  })
  .catch(() => {});

const usage_ready = chrome.storage.session
  .get(USAGE_KEY)
  .then((stored) => {
    restore_usage(usage_totals, stored && stored[USAGE_KEY]);
  })
  .catch(() => {});

const allowance_reports_ready = chrome.storage.session
  .get(ALLOWANCE_REPORTS_KEY)
  .then((stored) => {
    allowance_tracker.restore_pending(
      stored && stored[ALLOWANCE_REPORTS_KEY],
    );
  })
  .catch(() => {});

function restore_policy_snapshot(stored) {
  const snapshot = stored && stored[POLICY_KEY];
  if (!snapshot || !Array.isArray(snapshot.rules)) {
    return false;
  }
  try {
    const { enforced, allowance } = partition_rules(snapshot.rules);
    const timed_allowance = allowance.filter(is_time_allowance_rule);
    const compiled = compile_dnr(enforced);
    match_enforced = compile(enforced);
    match_allowance = compile(allowance);
    match_time_allowance = compile(timed_allowance);
    timed_policy_rules = new Map(
      timed_allowance.map((rule) => [rule.id, rule]),
    );
    timed_available_rules.clear();
    queue_timed_blocks(timed_allowance);
    rule_meta.clear();
    for (const entry of compiled) {
      rule_meta.set(entry.rule.id, {
        rule_id: entry.rule_id,
        value: entry.value,
        key: usage_key(entry.rule_id, entry.value),
      });
    }
    return true;
  } catch {
    return false;
  }
}

const attribution_ready = chrome.storage.session
  .get(POLICY_KEY)
  .then(async (stored) => {
    const restored = restore_policy_snapshot(stored);
    await Promise.all([totals_ready, usage_ready, allowance_reports_ready]);
    await session_rule_queue;
    attribution_initialized = true;
    // Requests observed before restoration cannot be attributed safely
    // unless the persisted policy describes the dynamic DNR rules.
    if (restored) {
      drain_startup_observations();
    } else {
      startup_observations = [];
    }
  })
  .catch(() => {
    attribution_initialized = true;
    startup_observations = [];
  });
// Breadcrumb: onInstalled/onStartup/alarm ticks can overlap; serialize
// refreshes so interleaved getDynamicRules/updateDynamicRules pairs never
// race on the same DNR rule ids.
let refresh_queue = Promise.resolve();
function queue_refresh() {
  refresh_queue = refresh_queue.then(refresh).catch((err) => {
    console.error("refresh failed", err);
  });
}

// Browser lifecycle events can overlap while updateSessionRules is pending.
// One queue keeps inactive and timed rules from racing each other.
let session_rule_queue = Promise.resolve();
function queue_inactive_refresh() {
  session_rule_queue = session_rule_queue
    .then(refresh_inactive_tabs)
    .catch((error) => {
      inactive_error = String(error);
      chrome.storage.local.set({
        inactive_ok: false,
        inactive_error,
      }).catch(() => {});
    });
}

async function refresh_inactive_tabs() {
  const tabs = block_inactive ? await chrome.tabs.query({}) : [];
  const tab_ids = tabs
    .filter((tab) => tab.active === false)
    .map((tab) => tab.id);
  const rule = compile_inactive_tab_rule(tab_ids, INACTIVE_RULE_ID);
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [INACTIVE_RULE_ID],
    addRules: rule === null ? [] : [rule],
  });
  inactive_tab_ids = new Set(rule?.condition.tabIds ?? []);
  inactive_error = null;
  chrome.storage.local.set({
    inactive_ok: true,
    inactive_error: null,
  }).catch(() => {});
}

function rebuild_timed_blocks() {
  const entries = compile_dnr([...timed_policy_rules.values()]);
  const remove_rule_ids = [...timed_block_ids.values()].flat();
  const add_rules = [];
  const next_ids = new Map();
  for (const [index, entry] of entries.entries()) {
    const id = TIMED_BLOCK_BASE + index;
    if (!timed_available_rules.has(entry.rule_id)) {
      add_rules.push({ ...entry.rule, id });
      const ids = next_ids.get(entry.rule_id) ?? [];
      ids.push(id);
      next_ids.set(entry.rule_id, ids);
    }
  }
  return chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: remove_rule_ids,
    addRules: add_rules,
  }).then(() => {
    timed_block_ids = next_ids;
  });
}

function queue_timed_blocks(rules) {
  timed_policy_rules = new Map(rules.map((rule) => [rule.id, rule]));
  timed_available_rules.clear();
  session_rule_queue = session_rule_queue
    .then(rebuild_timed_blocks)
    .catch((error) => {
      record_state(`Timed allowance blocking update failed: ${String(error)}`);
    });
  return session_rule_queue;
}

function queue_timed_rule_block(rule_id, blocked) {
  if (!timed_policy_rules.has(rule_id)) {
    return;
  }
  if (blocked) {
    timed_available_rules.delete(rule_id);
  } else {
    timed_available_rules.add(rule_id);
  }
  session_rule_queue = session_rule_queue
    .then(rebuild_timed_blocks)
    .catch((error) => {
      record_state(`Timed allowance blocking update failed: ${String(error)}`);
    });
}

chrome.storage.local.get(["block_inactive", "denials"]).then((stored) => {
  block_inactive = stored.block_inactive === true;
  const prefix = `${INACTIVE_KEY} → `;
  if (stored.denials && typeof stored.denials === "object") {
    for (const [label, count] of Object.entries(stored.denials)) {
      if (label.startsWith(prefix)) {
        bump_bounded(
          inactive_denials,
          label.slice(prefix.length),
          count,
        );
      }
    }
  }
  queue_inactive_refresh();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && "block_inactive" in changes) {
    block_inactive = changes.block_inactive.newValue === true;
    queue_inactive_refresh();
  }
});

for (const event of [
  chrome.tabs.onActivated,
  chrome.tabs.onCreated,
  chrome.tabs.onRemoved,
  chrome.tabs.onReplaced,
  chrome.tabs.onAttached,
  chrome.tabs.onDetached,
]) {
  event.addListener(() => {
    if (block_inactive) {
      queue_inactive_refresh();
    }
  });
}

function record_state(error) {
  last_error = error;
  chrome.storage.local.set({
    policy_ok: error === null,
    last_error,
    last_refresh_ms,
    denials: denial_snapshot(),
    usage: usage_snapshot(usage_totals),
  }).catch(() => {});
}

function denial_snapshot() {
  const out = {};
  for (const [key, totals] of match_totals) {
    const decoded = decode_usage_key(key);
    if (decoded !== null) {
      out[`${decoded.rule_id} → ${decoded.value}`] =
        totals.count - totals.reported;
    }
  }
  for (const [url, count] of inactive_denials) {
    out[`${INACTIVE_KEY} → ${url}`] = count;
  }
  return out;
}

function dnr_id_for(rule_id, value) {
  for (const [dnr_id, meta] of rule_meta) {
    if (meta.rule_id === rule_id && meta.value === value) {
      return dnr_id;
    }
  }
  return null;
}

/** Send one native-messaging request and resolve with its response. */
function host_request(message) {
  return new Promise((resolve) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST_NAME);
    } catch (error) {
      resolve({
        ok: false,
        error: { code: "host_error", message: String(error) },
      });
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
            chrome.runtime.lastError?.message ??
            "the native messaging host went away",
        },
      });
    });
    port.postMessage(message);
  });
}

function schedule_allowance_pulse() {
  if (allowance_timer !== null) {
    return;
  }
  allowance_timer = setTimeout(async () => {
    allowance_timer = null;
    try {
      await allowance_tracker.pulse();
    } finally {
      if (allowance_tracker.needs_pulse) {
        schedule_allowance_pulse();
      }
    }
  }, 5000);
  allowance_timer.unref?.();
}

function update_allowance_url(tab_id, url) {
  if (tab_id !== active_tab_id) {
    return;
  }
  active_tab_url = typeof url === "string" ? url : null;
  void allowance_tracker.set_tab_match(
    tab_id,
    typeof url === "string" && match_time_allowance !== null
      ? match_time_allowance(url)
      : null,
  );
  schedule_allowance_pulse();
}

async function sync_active_tab(tab_id) {
  try {
    await allowance_reports_ready;
    const tab = await chrome.tabs.get(tab_id);
    if (tab && tab.id === tab_id) {
      active_tab_id = tab_id;
      active_tab_url = typeof tab.url === "string" ? tab.url : null;
      await allowance_tracker.set_active_tab(
        tab_id,
        active_tab_url && match_time_allowance !== null
          ? match_time_allowance(active_tab_url)
          : null,
      );
      schedule_allowance_pulse();
    }
  } catch {
    if (active_tab_id === tab_id) {
      active_tab_id = null;
      active_tab_url = null;
      void allowance_tracker.set_active_tab(null, null);
    }
  }
}

async function sync_active_window() {
  try {
    await allowance_reports_ready;
    if (chrome.windows?.getLastFocused) {
      const window = await chrome.windows.getLastFocused();
      await allowance_tracker.set_focused(window?.focused === true);
    } else {
      await allowance_tracker.set_focused(false);
    }
    const tabs = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true,
    });
    const tab = tabs[0];
    if (tab?.id !== undefined) {
      await sync_active_tab(tab.id);
    }
  } catch {
    // A browser shutdown can invalidate a query; the next lifecycle event retries.
  }
}

export async function apply_policy(policy) {
  await attribution_ready;
  let rules;
  try {
    rules = rules_from_policy(policy);
  } catch (error) {
    record_state(String(error.message ?? error));
    return false;
  }

  const { enforced, allowance } = partition_rules(rules);
  const timed_allowance = allowance.filter(is_time_allowance_rule);
  let next_match_enforced;
  let next_match_allowance;
  let next_match_time_allowance;
  let compiled;
  try {
    // Breadcrumb: compile every matcher before touching the active state.
    // A bad policy must not replace a working policy with a partial one.
    next_match_enforced = compile(enforced);
    next_match_allowance = compile(allowance);
    next_match_time_allowance = compile(timed_allowance);
    compiled = compile_dnr(enforced);
  } catch (error) {
    record_state(`Policy compile failed: ${String(error.message ?? error)}`);
    return false;
  }

  let existing;
  attribution_paused = true;
  try {
    existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: compiled.map((entry) => entry.rule),
    });
  } catch (error) {
    attribution_paused = false;
    drain_startup_observations();
    // Breadcrumb: local state changes happen only after both DNR calls pass.
    // DNR keeps its old rules when the replacement request is rejected.
    record_state(`DNR policy update failed: ${String(error.message ?? error)}`);
    return false;
  }

  const next_rule_meta = new Map();
  for (const entry of compiled) {
    next_rule_meta.set(entry.rule.id, {
      rule_id: entry.rule_id,
      value: entry.value,
      key: usage_key(entry.rule_id, entry.value),
    });
  }

  // DNR accepted the set, so now commit matchers and metadata. Timed rules
  // start blocked; a successful lease removes only its rule's session block.
  prune_usage(usage_totals, rules);
  allowance_tracker.reset();
  match_enforced = next_match_enforced;
  match_allowance = next_match_allowance;
  match_time_allowance = next_match_time_allowance;
  await queue_timed_blocks(timed_allowance);
  if (active_tab_id !== null && active_tab_url !== null) {
    update_allowance_url(active_tab_id, active_tab_url);
  }
  rule_meta.clear();
  for (const [dnr_id, meta] of next_rule_meta) {
    rule_meta.set(dnr_id, meta);
  }
  chrome.storage.session
    .set({ [POLICY_KEY]: { rules } })
    .catch(() => {});
  attribution_paused = false;
  drain_startup_observations();
  last_error = null;
  record_state(null);
  return true;
}

async function refresh() {
  await totals_ready;
  await usage_ready;
  await allowance_reports_ready;
  const response = await host_request({ command: "list_rules" });
  if (response && response.ok) {
    last_refresh_ms = Date.now();
    if (await apply_policy(response.result)) {
      await report_matches();
      await report_usage();
      await allowance_tracker.pulse();
    }
  } else {
    record_state(
      response && response.error
        ? `${response.error.code}: ${response.error.message}`
        : "The native messaging host returned no response.",
    );
  }
}

export async function report_matches() {
  if (match_totals.size === 0) {
    return;
  }
  const entries = [];
  for (const [key, totals] of match_totals) {
    const decoded = decode_usage_key(key);
    if (decoded === null) {
      continue;
    }
    const pending = totals.count - totals.reported;
    if (pending > 0) {
      entries.push({
        ...decoded,
        count: Math.min(pending, 600),
        key,
      });
    }
  }
  if (entries.length === 0) {
    return;
  }
  // Breadcrumb: cap each report so one message stays far below the native
  // messaging frame limit. Only this sent prefix advances reported.
  const sent_entries = entries.slice(0, 128);
  const response = await host_request({
    command: "report_website_denials",
    entries: sent_entries.map(({ key: _key, ...entry }) => entry),
  });
  if (!(response && response.ok)) {
    const detail = response?.error
      ? `${response.error.code}: ${response.error.message}`
      : "the native messaging host returned no response";
    record_state(`Denial report refused: ${detail}`);
    return;
  }
  for (const entry of sent_entries) {
    const totals = match_totals.get(entry.key);
    if (!totals) {
      continue;
    }
    const reported = Math.min(
      totals.count,
      totals.reported + entry.count,
    );
    if (reported >= totals.count) {
      match_totals.delete(entry.key);
    } else {
      totals.reported = reported;
    }
  }
  chrome.storage.session
    .set({ [TOTALS_KEY]: [...match_totals.entries()] })
    .catch(() => {});
  record_state(null);
}

export async function report_usage() {
  if (usage_totals.size === 0) {
    return;
  }
  const entries = usage_entries(usage_totals, 128);
  const response = await host_request({
    command: "report_website_usage",
    entries,
  });
  if (!(response && response.ok)) {
    const detail = response?.error
      ? `${response.error.code}: ${response.error.message}`
      : "the native messaging host returned no response";
    // Breadcrumb: counters untouched on refusal, so the same delta is
    // retried next cycle; entries past the cap never left the map either.
    record_state(`Usage report refused: ${detail}`);
    return;
  }
  retire_usage(usage_totals, entries);
  // Breadcrumb: flush immediately so a suspension right after a report
  // cannot restore pre-report counts and double-report.
  chrome.storage.session
    .set({ [USAGE_KEY]: [...usage_totals.entries()] })
    .catch(() => {});
  record_state(null);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) {
    queue_refresh();
  }
  void allowance_tracker.pulse();
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});
chrome.tabs.onActivated?.addListener(({ tabId }) => {
  active_tab_id = tabId;
  active_tab_url = null;
  void allowance_tracker.set_active_tab(tabId, null);
  void sync_active_tab(tabId);
});
chrome.tabs.onUpdated?.addListener((tabId, changeInfo) => {
  if (typeof changeInfo.url === "string") {
    update_allowance_url(tabId, changeInfo.url);
  }
});
chrome.tabs.onRemoved?.addListener((tabId) => {
  if (tabId === active_tab_id) {
    active_tab_id = null;
    active_tab_url = null;
    void allowance_tracker.set_active_tab(null, null);
  }
});
chrome.windows?.onFocusChanged?.addListener((windowId) => {
  const none = chrome.windows?.WINDOW_ID_NONE ?? -1;
  void allowance_tracker.set_focused(windowId !== none);
  if (windowId !== none) {
    void sync_active_window();
  }
});
chrome.idle?.onStateChanged?.addListener((state) => {
  void allowance_tracker.set_idle(state !== "active");
});
void sync_active_window();

// Breadcrumb: observation only (no "blocking") — DNR enforces. Denial
// counting here matches Firefox: a scope hit covered by rule_meta is about
// to be blocked by that DNR rule, so it is one denial.
function show_block_page(details, hit = null) {
  if (details.type !== "main_frame") {
    return;
  }
  const page = new URL(chrome.runtime.getURL("blocked.html"));
  page.searchParams.set(
    "rule",
    hit?.name || hit?.rule_id || "Policy is not ready",
  );
  page.searchParams.set("url", details.url);
  try {
    Promise.resolve(
      chrome.tabs.update(details.tabId, { url: page.href }),
    ).catch(() => {});
  } catch {
    // The tab can disappear while a blocked request is being observed.
  }
}

function observe_request(details) {
  const enforced_hit =
    match_enforced === null ? null : match_enforced(details.url);
  if (enforced_hit !== null) {
    const dnr_id = dnr_id_for(enforced_hit.rule_id, enforced_hit.value);
    if (dnr_id !== null) {
      const meta = rule_meta.get(dnr_id);
      const key = meta?.key ?? usage_key(
        enforced_hit.rule_id,
        enforced_hit.value,
      );
      const totals = match_totals.get(key) ?? { count: 0, reported: 0 };
      totals.count = Math.min(COUNTER_MAX, totals.count + 1);
      match_totals.set(key, totals);
      schedule_totals_backup();
      if (details.type === "main_frame") {
        update_allowance_url(details.tabId, null);
        show_block_page(details, enforced_hit);
      }
      return;
    }
  }
  if (details.type === "main_frame") {
    const timed = match_time_allowance === null
      ? null
      : match_time_allowance(details.url);
    if (timed !== null && !timed_available_rules.has(timed.rule_id)) {
      show_block_page(details, timed);
    }
    if (timed === null && match_allowance !== null) {
      const allowed = match_allowance(details.url);
      if (allowed !== null) {
        bump_usage(usage_totals, allowed.rule_id, allowed.value);
        schedule_usage_backup();
      }
    }
  }
  // Breadcrumb: the session DNR rule performs the block. This listener
  // records only local status data and never reports it to the service.
  if (
    block_inactive &&
    inactive_tab_ids.has(details.tabId) &&
    details.url.startsWith("http")
  ) {
    const url = details.url.slice(0, 200);
    if (details.type === "main_frame") {
      show_block_page(details);
    }
    chrome.storage.local.set({ denials: denial_snapshot() }).catch(() => {});
  }
}

function drain_startup_observations() {
  const observations = startup_observations;
  startup_observations = [];
  for (const details of observations) {
    observe_request(details);
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId === -1) {
      return;
    }
    if (!attribution_initialized || attribution_paused) {
      // The persisted DNR rules can block while the worker rehydrates its
      // matcher, and a replacement can briefly expose the new rules before
      // this worker commits their metadata. Keep a bounded event tail.
      if (startup_observations.length < 256) {
        startup_observations.push({
          tabId: details.tabId,
          type: details.type,
          url: details.url,
        });
      }
      return;
    }
    observe_request(details);
  },
  { urls: ["<all_urls>"] },
);

chrome.runtime.onMessage.addListener((_message, _sender, sendResponse) => {
  sendResponse({
    policy_ok: last_error === null,
    last_error,
    last_refresh_ms,
    block_inactive,
    inactive_ok: inactive_error === null,
    inactive_error,
    denials: denial_snapshot(),
  });
  return false;
});
queue_refresh();
