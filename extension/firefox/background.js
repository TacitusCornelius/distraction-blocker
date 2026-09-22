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
const ALLOWANCE_REPORTS_KEY = "allowance_reports";
const POLICY_KEY = "policy_snapshot";
const STARTUP_REFRESH_WAIT_MS = 2000;
let match = compile([]);
let match_time_allowance = compile([]);
let policy_ready = false;
let last_error = "No policy loaded yet.";
let last_refresh_ms = 0;
let block_inactive = false;
let active_tab_id = null;
let active_tab_url = null;
let allowance_timer = null;

const pending_denials = new Map(); // encoded rule_id/value -> count
const inactive_denials = new Map(); // URL -> local-only count

// Timed allowance starts are tracked by leases, not legacy start counters.
let match_allowance = compile([]);
const pending_usage = new Map(); // encoded rule_id/value -> permitted starts
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
  on_exhausted: () => {
    queue_refresh();
    schedule_allowance_pulse();
  },
  on_unavailable: () => {
    schedule_allowance_pulse();
  },
  on_pending_changed: (reports) => {
    browser.storage.local
      .set({ [ALLOWANCE_REPORTS_KEY]: reports.map((report) => ({ ...report })) })
      .catch(() => {});
  },
});

// Breadcrumb: onInstalled/onStartup/alarm ticks can overlap; serialize
// refreshes so interleaved host_request/apply_rules pairs never race.
let initial_refresh = Promise.resolve();
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
  void allowance_tracker.pulse();
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
function install_matchers(rules) {
  // Breadcrumb: partition before compiling. Enforced rules keep blocking;
  // allowance rules permit starts until their budget is exhausted.
  const { enforced, allowance } = partition_rules(rules);
  const timed_allowance = allowance.filter(is_time_allowance_rule);
  match = compile(enforced);
  match_allowance = compile(allowance);
  match_time_allowance = compile(timed_allowance);
  prune_usage(pending_usage, rules);
  if (active_tab_id !== null && active_tab_url !== null) {
    update_allowance_url(active_tab_id, active_tab_url);
  }
}

function restore_policy_snapshot(stored) {
  const snapshot = stored && stored[POLICY_KEY];
  if (!snapshot || typeof snapshot !== "object") {
    return false;
  }
  try {
    const rules = rules_from_policy(snapshot);
    install_matchers(rules);
    policy_ready = true;
    last_error = null;
    record_state(null);
    return true;
  } catch {
    return false;
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
  try {
    install_matchers(rules);
  } catch (error) {
    policy_ready = false;
    record_state(`Policy compile failed: ${String(error.message ?? error)}`);
    return false;
  }
  // Breadcrumb: Firefox has no persisted DNR equivalent. Persist the
  // complete expanded browser policy so startup can avoid a blanket block
  // while the authoritative service refresh is in flight.
  browser.storage.local
    .set({
      [POLICY_KEY]: {
        schema_version: policy.schema_version,
        revision: policy.revision,
        rules,
      },
    })
    .catch(() => {});
  // Once compilation succeeds, requests can leave the startup fail-closed
  // state.
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

async function update_allowance_url(tab_id, url) {
  if (tab_id !== active_tab_id) {
    return false;
  }
  active_tab_url = typeof url === "string" ? url : null;
  await allowance_tracker.set_tab_match(
    tab_id,
    typeof url === "string" && match_time_allowance !== null
      ? match_time_allowance(url)
      : null,
  );
  schedule_allowance_pulse();
  return true;
}
async function sync_active_tab(tab_id) {
  await state_ready;
  try {
    const tab = await browser.tabs.get(tab_id);
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
  await state_ready;
  try {
    let focused = false;
    if (browser.windows?.getLastFocused) {
      const window = await browser.windows.getLastFocused();
      focused = window?.focused === true;
    }
    await allowance_tracker.set_focused(focused);
    const tabs = await browser.tabs.query({
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
  const response = await host_request({ command: "list_active_rules" });
  last_refresh_ms = Date.now();
  if (response && response.ok) {
    try {
      const expanded = await expand_managed_lists(
        response.result,
        (list_id, offset) =>
          host_request({
            command: "read_managed_list",
            list_id,
            offset,
            limit: 200,
          }),
      );
      // The schema parser accepts the complete policy before either matcher
      // changes.
      if (apply_policy(expanded)) {
        await flush_denials();
        await flush_usage();
        await allowance_tracker.pulse();
        await redirect_active_tab_if_blocked();
      }
    } catch (error) {
      record_state(`Managed-list policy load failed: ${String(error.message ?? error)}`);
    }
  } else {
    record_state(
      response && response.error
        ? `${response.error.code}: ${response.error.message}`
        : "The native messaging host returned no response.",
    );
  }
}
async function redirect_active_tab_if_blocked() {
  if (
    active_tab_id === null ||
    typeof active_tab_url !== "string" ||
    !active_tab_url.startsWith("http")
  ) {
    return;
  }
  const raw_url = active_tab_url;
  const hit = match(raw_url);
  if (hit === null) {
    return;
  }
  try {
    const tab = await browser.tabs.get(active_tab_id);
    if (
      !tab ||
      tab.id !== active_tab_id ||
      tab.url !== raw_url
    ) {
      return;
    }
    await browser.tabs.update(active_tab_id, {
      url: block_page_url(raw_url, hit),
    });
  } catch {
    // The active tab can disappear during a policy refresh.
  }
}


/** True when the tab holding this request is not the visible tab. */
const state_ready = browser.storage.local
  .get(["denials", "usage", ALLOWANCE_REPORTS_KEY, POLICY_KEY])
  .then((stored) => {
    merge_labels(pending_denials, stored?.denials, [INACTIVE_KEY]);
    merge_labels(pending_usage, stored?.usage);
    allowance_tracker.restore_pending(stored?.[ALLOWANCE_REPORTS_KEY]);
    const prefix = `${INACTIVE_KEY} → `;
    for (const [label, count] of Object.entries(stored?.denials ?? {})) {
      if (label.startsWith(prefix)) {
        bump_bounded(inactive_denials, label.slice(prefix.length), count);
      }
    }
    restore_policy_snapshot(stored);
  });
browser.tabs.onActivated?.addListener(({ tabId }) => {
  active_tab_id = tabId;
  active_tab_url = null;
  void allowance_tracker.set_active_tab(tabId, null);
  void sync_active_tab(tabId);
});
browser.tabs.onUpdated?.addListener((tabId, changeInfo) => {
  if (typeof changeInfo.url === "string") {
    update_allowance_url(tabId, changeInfo.url);
  }
});
browser.tabs.onRemoved?.addListener((tabId) => {
  if (tabId === active_tab_id) {
    active_tab_id = null;
    active_tab_url = null;
    void allowance_tracker.set_active_tab(null, null);
  }
});
browser.windows?.onFocusChanged?.addListener((windowId) => {
  const none = browser.windows?.WINDOW_ID_NONE ?? -1;
  void allowance_tracker.set_focused(windowId !== none);
  if (windowId !== none) {
    void sync_active_window();
  }
});
browser.idle?.onStateChanged?.addListener((state) => {
  void allowance_tracker.set_idle(state !== "active");
});
void sync_active_window();


function block_page_url(raw_url, hit = null) {
  const page = new URL(browser.runtime.getURL("blocked.html"));
  page.searchParams.set(
    "rule",
    hit?.name || hit?.rule_id || "Policy is not ready",
  );
  page.searchParams.set("url", raw_url);
  return page.href;
}

function block_result(details, hit = null) {
  if (details.type !== "main_frame") {
    return { cancel: true };
  }
  return { redirectUrl: block_page_url(details.url, hit) };
}

async function wait_for_initial_refresh() {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(resolve, STARTUP_REFRESH_WAIT_MS);
  });
  await Promise.race([initial_refresh, timeout]);
  clearTimeout(timer);
}

browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId === -1 || !details.url.startsWith("http")) {
      return {};
    }
    await state_ready;
    await wait_for_initial_refresh();
    if (!policy_ready) {
      return block_result(details);
    }
    const hit = match(details.url);
    if (hit !== null) {
      if (details.type === "main_frame") {
        await update_allowance_url(details.tabId, null);
      }
      bump_usage(pending_denials, hit.rule_id, hit.value);
      record_state(null);
      return block_result(details, hit);
    }
    const timed = match_time_allowance(details.url);
    if (details.type === "main_frame") {
      await update_allowance_url(details.tabId, details.url);
    }
    if (timed !== null && !allowance_tracker.has_lease(timed.rule_id)) {
      if (allowance_tracker.is_exhausted(timed.rule_id)) {
        bump_usage(pending_denials, timed.rule_id, timed.value);
        record_state(null);
      }
      return block_result(details, timed);
    }
    if (details.type === "main_frame" && timed === null) {
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
      return block_result(details);
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
initial_refresh = refresh_queue;
