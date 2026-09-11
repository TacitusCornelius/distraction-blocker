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
});

test("block page displays rule name and requested URL as text", () => {
  const fields = new Map([
    ["rule-name", element()],
    ["requested", element()],
    ["back", element()],
  ]);
  let went_back = false;
  const document = {
    getElementById(id) {
      return fields.get(id);
    },
  };
  const window = {
    location: {
      search:
        "?rule=Focus%20%3CWork%3E&url=https%3A%2F%2Fx.com%2Fhome%3Ftab%3D1",
    },
  };
  const history = { back() { went_back = true; } };
  const context = vm.createContext({ document, history, window, URLSearchParams });
  const source = readFileSync(join(root, "firefox", "blocked.js"), "utf8");
  vm.runInContext(source, context);

  assert.equal(fields.get("rule-name").textContent, "Focus <Work>");
  assert.equal(
    fields.get("requested").textContent,
    "Requested page: https://x.com/home?tab=1",
  );
  assert.equal(fields.get("requested").hidden, false);
  fields.get("back").listeners.click();
  assert.equal(went_back, true);
});
