/**
 * Status popup: report policy state and set the browser-local inactive-tab
 * toggle. This page never changes service rules.
 */
"use strict";

// Breadcrumb: chrome.* is the Chromium global; alias it so the popup
// code can use one name on both browsers.
const browser = chrome;

const checkbox = document.getElementById("block_inactive");
const inactive_state = document.getElementById("inactive_state");

function show_inactive_state(state) {
  if (state.inactive_ok === false) {
    inactive_state.textContent = `Not enforcing: ${state.inactive_error}`;
    inactive_state.className = "bad";
  } else {
    inactive_state.textContent = state.block_inactive
      ? "Background-tab loads are blocked."
      : "Background-tab loads are permitted.";
    inactive_state.className = state.block_inactive ? "ok" : "";
  }
}

browser.storage.local.get("block_inactive").then((stored) => {
  checkbox.checked = stored.block_inactive === true;
});

checkbox.addEventListener("change", () => {
  browser.storage.local.set({ block_inactive: checkbox.checked });
});

// Breadcrumb: the worker writes inactive_ok only after the atomic DNR
// replacement. Update the text from that result, not from the click alone.
browser.storage.onChanged.addListener((changes, area) => {
  if (
    area === "local" &&
    ["block_inactive", "inactive_ok", "inactive_error"].some(
      (key) => key in changes,
    )
  ) {
    browser.storage.local.get([
      "block_inactive",
      "inactive_ok",
      "inactive_error",
    ]).then((stored) => {
      show_inactive_state({
        block_inactive: stored.block_inactive === true,
        inactive_ok: stored.inactive_ok !== false,
        inactive_error: stored.inactive_error ?? null,
      });
    });
  }
});

browser.runtime.sendMessage({ topic: "status" }).then((state) => {
  const marker = document.getElementById("state");
  if (state.policy_ok) {
    marker.textContent = "Enforcing rules from the service.";
    marker.className = "ok";
  } else {
    marker.textContent = `Not enforcing: ${state.last_error}`;
    marker.className = "bad";
  }
  show_inactive_state(state);
  if (state.last_refresh_ms > 0) {
    document.getElementById("refresh").textContent = new Date(
      state.last_refresh_ms,
    ).toLocaleTimeString();
  }
  // Breadcrumb: the live variables can lag the recorded truth when the
  // event page restarts; storage holds every recorded state change.
  browser.storage.local.get().then((recorded) => {
    const note = document.getElementById("recorded");
    if (note) {
      note.textContent = JSON.stringify(recorded).slice(0, 400);
    }
  });

  const list = document.getElementById("denials");
  list.replaceChildren();
  const entries = Object.entries(state.denials ?? {});
  const denied_count = entries.reduce(
    (total, [, count]) => total + (Number.isInteger(count) ? count : 0),
    0,
  );
  document.getElementById("denial-count").textContent = String(denied_count);
  if (entries.length === 0) {
    const item = document.createElement("li");
    item.textContent = "none yet";
    list.append(item);
    return;
  }
  for (const [label, count] of entries) {
    const item = document.createElement("li");
    item.textContent = `${label}: ${count} denied load(s)`;
    list.append(item);
  }
});

function allowance_text(result) {
  const duration = (seconds) => {
    if (seconds === null || seconds === undefined) return "unlimited";
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    return minutes ? (rest ? `${minutes}m ${rest}s` : `${minutes}m`) : `${rest}s`;
  };
  if (!result) return "No timed allowance applies to the active tab.";
  if (!result.active) return `${result.rule_name}: allowance is outside its scheduled period.`;
  const lines = [
    `${result.rule_name}: ${duration(result.remaining_seconds)} remaining in the current allowance.`,
  ];
  if (result.window_seconds !== null) {
    const reset = Math.max(
      0,
      Math.ceil((Date.parse(result.window_end_utc) - Date.now()) / 1000),
    );
    lines.push(
      `Rolling window: ${duration(result.period_budget_seconds)} per ${duration(result.window_seconds)}; ${duration(result.period_remaining_seconds)} remaining; refills in ${duration(reset)}.`,
    );
  }
  if (result.daily_cap_seconds !== null) {
    lines.push(`Daily cap: ${duration(result.daily_remaining_seconds)} remaining.`);
  }
  if (result.lease_remaining_seconds !== null) {
    lines.push(`Usage timer: running (${duration(result.lease_remaining_seconds)} until renewal).`);
  } else {
    lines.push("Usage timer: not running.");
  }
  return lines.join("\n");
}

browser.runtime.sendMessage({ topic: "allowance_status" })
  .then((response) => {
    document.getElementById("allowance-status").textContent =
      response?.ok
        ? allowance_text(response.result)
        : "Timed allowance status is currently unavailable.";
  })
  .catch(() => {
    document.getElementById("allowance-status").textContent =
      "Timed allowance status is currently unavailable.";
  });
