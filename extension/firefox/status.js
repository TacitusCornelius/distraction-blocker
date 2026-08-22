/**
 * Status popup: report observed policy state only. The service stays the
 * authority; this page never changes rules.
 */
"use strict";

/* global browser */

const checkbox = document.getElementById("block_inactive");

browser.storage.local.get("block_inactive").then((stored) => {
  checkbox.checked = stored.block_inactive === true;
});

checkbox.addEventListener("change", () => {
  browser.storage.local.set({ block_inactive: checkbox.checked });
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
