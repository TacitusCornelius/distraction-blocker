import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");


test("both adapters ship the same branded popup presentation", () => {
  const firefox = join(root, "firefox");
  const chromium = join(root, "chromium");
  for (const name of ["status.html", "status.css"]) {
    assert.equal(
      readFileSync(join(firefox, name), "utf8"),
      readFileSync(join(chromium, name), "utf8"),
      `${name} differs between adapters`,
    );
  }
  const page = readFileSync(join(firefox, "status.html"), "utf8");
  for (const required of [
    "icons/icon48.png",
    "id=\"state\"",
    "id=\"refresh\"",
    "id=\"denial-count\"",
    "id=\"denials\"",
    "id=\"block_inactive\"",
    "Technical details",
  ]) {
    assert.match(page, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

function popup_fixture() {
  const elements = new Map();
  for (const id of [
    "state",
    "refresh",
    "denial-count",
    "denials",
    "block_inactive",
    "inactive_state",
    "recorded",
  ]) {
    elements.set(id, {
      textContent: "",
      className: "",
      checked: false,
      children: [],
      listeners: {},
      addEventListener(name, listener) {
        this.listeners[name] = listener;
      },
      replaceChildren(...children) {
        this.children = children;
      },
      append(...children) {
        this.children.push(...children);
      },
    });
  }
  return {
    elements,
    document: {
      createElement() {
        return {
          textContent: "",
          className: "",
          children: [],
          append(...children) {
            this.children.push(...children);
          },
        };
      },
      getElementById(id) {
        return elements.get(id);
      },
    },
  };
}

test("popup renders status, denial totals, and inactive-tab state", async () => {
  const status = {
    policy_ok: true,
    last_error: null,
    last_refresh_ms: 0,
    block_inactive: false,
    inactive_ok: true,
    inactive_error: null,
    denials: {
      "Test extension rule": 3,
      "Another rule": 2,
    },
  };
  for (const target of ["firefox", "chromium"]) {
    const fixture = popup_fixture();
    const stored = {
      denials: status.denials,
      block_inactive: false,
    };
    const api = {
      runtime: {
        sendMessage() {
          return Promise.resolve(status);
        },
      },
      storage: {
        local: {
          get() {
            return Promise.resolve(stored);
          },
          set(values) {
            Object.assign(stored, values);
            return Promise.resolve();
          },
        },
        onChanged: { addListener() {} },
      },
    };
    const source = readFileSync(
      join(root, target, "status.js"),
      "utf8",
    );
    vm.runInNewContext(source, {
      browser: api,
      chrome: api,
      document: fixture.document,
      Promise,
      Date,
      JSON,
      setTimeout,
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    assert.equal(fixture.elements.get("state").textContent,
      "Enforcing rules from the service.");
    assert.equal(fixture.elements.get("denial-count").textContent, "5");
    assert.equal(fixture.elements.get("denials").children.length, 2);
    assert.equal(
      fixture.elements.get("inactive_state").textContent,
      "Background-tab loads are permitted.",
    );
  }
});
