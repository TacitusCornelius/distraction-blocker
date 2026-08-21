/**
 * Status popup: report observed policy state only. The service stays the
 * authority; this page never changes rules.
 */
"use strict";

browser.runtime.sendMessage({ topic: "status" }).then((state) => {
  const marker = document.getElementById("state");
  if (state.policy_ok) {
    marker.textContent = "Enforcing rules from the service.";
    marker.className = "ok";
  } else {
    marker.textContent = `Not enforcing: ${state.last_error}`;
    marker.className = "bad";
  }
  if (state.last_refresh_ms > 0) {
    document.getElementById("refresh").textContent = new Date(
      state.last_refresh_ms,
    ).toLocaleTimeString();
  }
  const list = document.getElementById("denials");
  list.replaceChildren();
  const entries = Object.entries(state.denials ?? {});
  if (entries.length === 0) {
    const item = document.createElement("li");
    item.textContent = "none yet";
    list.append(item);
    return;
  }
  for (const [rule_id, count] of entries) {
    const item = document.createElement("li");
    item.textContent = `${rule_id}: ${count} denied load(s)`;
    list.append(item);
  }
});
