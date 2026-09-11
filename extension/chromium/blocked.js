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
