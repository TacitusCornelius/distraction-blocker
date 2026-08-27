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
// Breadcrumb: observational attribution only. DNR does the blocking; this
// matcher just attributes observed loads so denial counts match Firefox.
import { compile } from "./core/engine.js";
import { rules_from_policy } from "./core/policy.js";
import {
  bump_bounded,
  bump_usage,
  COUNTER_MAX,
  decode_usage_key,
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
let totals_backup_scheduled = false;
let match_enforced = null;
let match_allowance = null;
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

// Breadcrumb: onInstalled/onStartup/alarm ticks can overlap; serialize
// refreshes so interleaved getDynamicRules/updateDynamicRules pairs never
// race on the same DNR rule ids.
let refresh_queue = Promise.resolve();
function queue_refresh() {
  refresh_queue = refresh_queue.then(refresh).catch((err) => {
    console.error("refresh failed", err);
  });
}

// Breadcrumb: tab events can overlap while updateSessionRules is pending.
// Serialize full tab snapshots so the last event always wins.
let inactive_refresh_queue = Promise.resolve();
function queue_inactive_refresh() {
  inactive_refresh_queue = inactive_refresh_queue
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

export async function apply_policy(policy) {
  let rules;
  try {
    rules = rules_from_policy(policy);
  } catch (error) {
    record_state(String(error.message ?? error));
    return false;
  }

  const { enforced, allowance } = partition_rules(rules);
  let next_match_enforced;
  let next_match_allowance;
  let compiled;
  try {
    // Breadcrumb: compile every matcher before touching the active state.
    // A bad policy must not replace a working policy with a partial one.
    next_match_enforced = compile(enforced);
    next_match_allowance = compile(allowance);
    compiled = compile_dnr(enforced);
  } catch (error) {
    record_state(`Policy compile failed: ${String(error.message ?? error)}`);
    return false;
  }

  let existing;
  try {
    existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: compiled.map((entry) => entry.rule),
    });
  } catch (error) {
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

  // Breadcrumb: DNR accepted the set, so now commit matchers and metadata.
  // Stable pending totals stay queued, even when a rule leaves the policy.
  prune_usage(usage_totals, rules);
  match_enforced = next_match_enforced;
  match_allowance = next_match_allowance;
  rule_meta.clear();
  for (const [dnr_id, meta] of next_rule_meta) {
    rule_meta.set(dnr_id, meta);
  }
  last_error = null;
  record_state(null);
  return true;
}

async function refresh() {
  await totals_ready;
  await usage_ready;
  const response = await host_request({ command: "list_rules" });
  if (response && response.ok) {
    last_refresh_ms = Date.now();
    if (await apply_policy(response.result)) {
      await report_matches();
      await report_usage();
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

async function report_usage() {
  if (usage_totals.size === 0) {
    return;
  }
  const entries = usage_entries(usage_totals, 128);
  const response = await host_request({
    command: "report_website_usage",
    entries,
  });
  if (!(response && response.ok)) {
    // Breadcrumb: counters untouched on refusal, so the same delta is
    // retried next cycle; entries past the cap never left the map either.
    record_state(
      `Usage report refused: ${response.error.code}: ${response.error.message}`,
    );
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
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  queue_refresh();
});

// Breadcrumb: observation only (no "blocking") — DNR enforces. Denial
// counting here matches Firefox: a scope hit covered by rule_meta is about
// to be blocked by that DNR rule, so it is one denial.
// A scope hit with NO DNR coverage was permitted; for main_frame loads
// under an allowance rule that is one unit of usage. The enforced-matcher
// guard keeps overlapping policies honest: if any enforced target also
// matches, DNR blocked this load and it must not count as usage.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId === -1) {
      return;
    }
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
        return;
      }
    }
    if (details.type === "main_frame" && match_allowance !== null) {
      const allowed = match_allowance(details.url);
      if (allowed !== null) {
        bump_usage(usage_totals, allowed.rule_id, allowed.value);
        schedule_usage_backup();
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
      bump_bounded(inactive_denials, url);
      chrome.storage.local.set({ denials: denial_snapshot() }).catch(() => {});
    }
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
