import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

function element() {
  return {
    textContent: "",
    hidden: true,
    listeners: {},
    addEventListener(name, listener) {
      this.listeners[name] = listener;
    },
  };
}

test("both adapters ship the same branded block page resources", () => {
  const firefox = join(root, "firefox");
  const chromium = join(root, "chromium");
  for (const name of ["blocked.html", "blocked.css", "blocked.js"]) {
    assert.equal(
      readFileSync(join(firefox, name), "utf8"),
      readFileSync(join(chromium, name), "utf8"),
      `${name} differs between adapters`,
    );
  }
  for (const target of [firefox, chromium]) {
    const page = readFileSync(join(target, "blocked.html"), "utf8");
    assert.match(page, /src="icons\/icon128\.png"/);
    assert.match(page, /Distraction Blocker prevented this page from loading/);
  }
  const firefox_manifest = JSON.parse(
    readFileSync(join(firefox, "manifest.json"), "utf8"),
  );
  assert.ok(firefox_manifest.web_accessible_resources?.includes("blocked.html"));
});

test("block page displays allowance budget, rolling reset, and timer state", async () => {
  const fields = new Map([
    ["rule-name", element()],
    ["requested", element()],
    ["back", element()],
    ["allowance-status", element()],
  ]);
  const result = {
    rule_name: "Social Media Evenings",
    active: true,
    remaining_seconds: 420,
    period_budget_seconds: 600,
    period_remaining_seconds: 420,
    window_seconds: 3600,
    window_end_utc: new Date(Date.now() + 1800_000).toISOString(),
    daily_cap_seconds: 3600,
    daily_remaining_seconds: 3000,
    lease_remaining_seconds: 20,
  };
  let went_back = false;
  const context = vm.createContext({
    document: { getElementById: (id) => fields.get(id) },
    history: { back() { went_back = true; } },
    window: { location: { search: "?rule=Evenings&url=https%3A%2F%2Fx.com%2F" } },
    URLSearchParams,
    Date,
    browser: {
      runtime: {
        sendMessage: () => Promise.resolve({ ok: true, result }),
      },
    },
  });
  const source = readFileSync(join(root, "firefox", "blocked.js"), "utf8");
  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(fields.get("rule-name").textContent, "Evenings");
  assert.equal(fields.get("requested").textContent, "Requested page: https://x.com/");
  fields.get("back").listeners.click();
  assert.equal(went_back, true);
  assert.match(fields.get("allowance-status").textContent, /7m remaining/);
  assert.match(fields.get("allowance-status").textContent, /Rolling window: 10m per 60m/);
  assert.match(fields.get("allowance-status").textContent, /Daily cap: 50m/);
  assert.match(fields.get("allowance-status").textContent, /Usage timer: running/);
});
