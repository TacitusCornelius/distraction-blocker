"use strict";

const params = new URLSearchParams(window.location.search);
const rule = params.get("rule")?.trim() || "an active Distraction Blocker rule";
const requested = params.get("url")?.trim() || "";

document.getElementById("rule-name").textContent = rule;
if (requested) {
  const requested_element = document.getElementById("requested");
  requested_element.textContent = `Requested page: ${requested}`;
  requested_element.hidden = false;
}

document.getElementById("back").addEventListener("click", () => {
  history.back();
});

function allowance_text(result) {
  const duration = (seconds) => {
    if (seconds === null || seconds === undefined) return "unlimited";
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    return minutes ? (rest ? `${minutes}m ${rest}s` : `${minutes}m`) : `${rest}s`;
  };
  if (!result) return "No timed allowance applies to this page.";
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
    lines.push(
      `Daily cap: ${duration(result.daily_remaining_seconds)} remaining.`,
    );
  }
  if (result.lease_remaining_seconds !== null) {
    lines.push(
      `Usage timer: running (${duration(result.lease_remaining_seconds)} until renewal).`,
    );
  } else {
    lines.push("Usage timer: not running.");
  }
  return lines.join("\n");
}

const extension_api = globalThis.browser ?? globalThis.chrome;
extension_api.runtime.sendMessage({
  topic: "allowance_status",
  url: requested,
}).then((response) => {
  document.getElementById("allowance-status").textContent =
    response?.ok
      ? allowance_text(response.result)
      : "Timed allowance status is currently unavailable.";
}).catch(() => {
  document.getElementById("allowance-status").textContent =
    "Timed allowance status is currently unavailable.";
});
