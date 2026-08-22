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

import { compile_dnr } from "./core/dnr.js";

const HOST_NAME = "org.distraction_blocker.extension";
const REFRESH_ALARM = "policy-refresh";
const REFRESH_MINUTES = 1;

let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
/** DNR numeric id -> { rule_id, value, count, reported } */
const match_totals = new Map();
/** DNR numeric id -> { rule_id, value } for reporting attribution */
const rule_meta = new Map();

function record_state(error) {
  last_error = error;
  chrome.storage.local.set({
    policy_ok: error === null,
    last_error,
    last_refresh_ms,
    denials: denial_snapshot(),
  }).catch(() => {});
}

function denial_snapshot() {
  const out = {};
  for (const [dnr_id, totals] of match_totals) {
    const meta = rule_meta.get(dnr_id);
    if (meta) {
      out[`${meta.rule_id} → ${meta.value}`] =
        totals.count - totals.reported;
    }
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

async function apply_policy(rules) {
  if (!Array.isArray(rules)) {
    record_state("The service returned an invalid rule list.");
    return;
  }
  const compiled = compile_dnr(rules);
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((rule) => rule.id),
    addRules: compiled.map((entry) => entry.rule),
  });
  rule_meta.clear();
  for (const entry of compiled) {
    rule_meta.set(entry.rule.id, {
      rule_id: entry.rule_id,
      value: entry.value,
    });
  }
  // Breadcrumb: a rule set change can retire tracked rules; keep totals
  // only for ids that still exist so counts stay attributable.
  for (const dnr_id of [...match_totals.keys()]) {
    if (!rule_meta.has(dnr_id)) {
      match_totals.delete(dnr_id);
    }
  }
  last_error = null;
  record_state(null);
}

async function refresh() {
  await report_matches();
  const response = await host_request({ command: "list_rules" });
  last_refresh_ms = Date.now();
  if (response && response.ok) {
    await apply_policy(response.result);
  } else {
    record_state(
      response && response.error
        ? `${response.error.code}: ${response.error.message}`
        : "The native messaging host returned no response.",
    );
  }
}

async function report_matches() {
  if (match_totals.size === 0 || rule_meta.size === 0) {
    return;
  }
  const entries = [];
  const rolled_back = [];
  for (const [dnr_id, totals] of match_totals) {
    const meta = rule_meta.get(dnr_id);
    if (!meta) {
      continue;
    }
    const pending = totals.count - totals.reported;
    if (pending > 0) {
      entries.push({
        rule_id: meta.rule_id,
        value: meta.value,
        count: Math.min(pending, 600),
        dnr_id,
      });
    }
  }
  if (entries.length === 0) {
    return;
  }
  // Breadcrumb: cap each report so one message stays far below the native
  // messaging frame limit.
  const response = await host_request({
    command: "report_website_denials",
    entries: entries.slice(0, 128).map(({ dnr_id, ...entry }) => entry),
  });
  if (!(response && response.ok)) {
    // Roll the unsent portions back; the next cycle retries.
    for (const entry of entries) {
      const totals = match_totals.get(entry.dnr_id);
      if (totals) {
        totals.reported -= entry.count;
      }
    }
    record_state(
      `Denial report refused: ${response.error.code}: ${response.error.message}`,
    );
    return;
  }
  for (const entry of entries) {
    match_totals.get(entry.dnr_id).reported += entry.count;
  }
  record_state(null);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) {
    refresh().catch(() => {});
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  refresh().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_MINUTES });
  refresh().catch(() => {});
});

chrome.runtime.onMessage.addListener((_message, _sender, sendResponse) => {
  sendResponse({
    policy_ok: last_error === null,
    last_error,
    last_refresh_ms,
    denials: denial_snapshot(),
  });
  return false;
});

refresh().catch(() => {});
