"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { AllowanceTracker } from "../core/allowance.js";
import { partition_rules } from "../core/usage.js";

test("timed rules are permitted until the service marks them exhausted", () => {
  const { enforced, allowance } = partition_rules([
    { id: "timed", enabled: true, allowance_time: { periods: [] } },
    { id: "spent", enabled: true, allowance_time: { periods: [] }, budget_exhausted: true },
  ]);
  assert.deepEqual(allowance.map((rule) => rule.id), ["timed"]);
  assert.deepEqual(enforced.map((rule) => rule.id), ["spent"]);
});

test("tracker leases only focused, non-idle active-tab time", async () => {
  let now = 1000;
  const leases = [];
  const reports = [];
  const tracker = new AllowanceTracker({
    now: () => now,
    request_lease: async (rule_id) => {
      leases.push(rule_id);
      return {
        ok: true,
        result: {
          rule_id,
          lease_id: "11111111-1111-4111-8111-111111111111",
          start_utc: "1970-01-01T00:00:01.000Z",
          end_utc: "1970-01-01T00:00:04.000Z",
          seconds: 3,
        },
      };
    },
    report_usage: async (report) => {
      reports.push(report);
      return { ok: true };
    },
  });

  await tracker.set_focused(true);
  await tracker.set_idle(false);
  await tracker.set_active_tab(7, { rule_id: "timed" });
  assert.deepEqual(leases, ["timed"]);

  now = 2500;
  await tracker.pulse();
  assert.equal(reports.length, 1);
  assert.equal(reports[0].rule_id, "timed");
  assert.equal(reports[0].lease_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(reports[0].start_utc, "1970-01-01T00:00:01.000Z");
  assert.equal(reports[0].end_utc, "1970-01-01T00:00:02.500Z");
  now = 3000;
  await tracker.set_idle(true);
  assert.equal(reports.length, 2);
  assert.equal(reports[1].lease_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(reports[1].end_utc, "1970-01-01T00:00:03.000Z");
  now = 9000;
  await tracker.pulse();
  assert.equal(leases.length, 1);
});

test("tracker retains a report when the native host refuses it", async () => {
  let now = 1000;
  let refused = true;
  const tracker = new AllowanceTracker({
    now: () => now,
    request_lease: async (rule_id) => ({
      ok: true,
      result: {
        rule_id,
        lease_id: "22222222-2222-4222-8222-222222222222",
        start_utc: "1970-01-01T00:00:01.000Z",
        end_utc: "1970-01-01T00:00:04.000Z",
        seconds: 3,
      },
    }),
    report_usage: async () => {
      if (refused) return { ok: false };
      return { ok: true };
    },
  });
  await tracker.set_focused(true);
  await tracker.set_idle(false);
  await tracker.set_active_tab(1, { rule_id: "timed" });
  now = 2000;
  await tracker.pulse();
  assert.equal(tracker.pending_count, 1);
  refused = false;
  await tracker.pulse(2500);
  assert.equal(tracker.pending_count, 0);
});

test("tracker drops reports whose service lease was lost", async () => {
  let report_calls = 0;
  let lease_calls = 0;
  const tracker = new AllowanceTracker({
    request_lease: async (rule_id) => {
      lease_calls += 1;
      return {
        ok: true,
        result: {
          rule_id,
          lease_id: "66666666-6666-4666-8666-666666666666",
          start_utc: "1970-01-01T00:00:01.000Z",
          end_utc: "1970-01-01T00:00:04.000Z",
          seconds: 3,
        },
      };
    },
    report_usage: async () => {
      report_calls += 1;
      return {
        ok: false,
        error: {
          code: "not_found",
          message: "allowance lease was not found",
        },
      };
    },
  });
  tracker.restore_pending([{
    report_id: "77777777-7777-4777-8777-777777777777",
    rule_id: "timed",
    lease_id: "88888888-8888-4888-8888-888888888888",
    start_utc: "1970-01-01T00:00:01.000Z",
    end_utc: "1970-01-01T00:00:02.000Z",
  }]);

  await tracker.set_focused(true);
  await tracker.set_idle(false);
  await tracker.set_active_tab(3, { rule_id: "timed" });

  assert.equal(report_calls, 1);
  assert.equal(lease_calls, 1);
  assert.equal(tracker.pending_count, 0);
  assert.equal(tracker.has_lease("timed"), true);
});


test("tracker rejects a lease response for a rule that is no longer active", async () => {
  let resolve_lease;
  const unavailable = [];
  const tracker = new AllowanceTracker({
    request_lease: () => new Promise((resolve) => {
      resolve_lease = resolve;
    }),
    report_usage: async () => ({ ok: true }),
    on_unavailable: (rule_id) => unavailable.push(rule_id),
  });
  await tracker.set_focused(true);
  await tracker.set_idle(false);
  const first = tracker.set_active_tab(1, { rule_id: "old" });
  await Promise.resolve();
  await tracker.set_tab_match(1, { rule_id: "new" });
  resolve_lease({
    ok: true,
    result: {
      rule_id: "old",
      lease_id: "33333333-3333-4333-8333-333333333333",
      start_utc: "1970-01-01T00:00:01.000Z",
      end_utc: "1970-01-01T00:00:04.000Z",
    },
  });
  await first;
  assert.equal(tracker.has_lease("old"), false);
  assert.deepEqual(unavailable, ["old"]);
});

test("tracker rejects a lease response when the active match changes within the same rule", async () => {
  let resolve_lease;
  const unavailable = [];
  const tracker = new AllowanceTracker({
    request_lease: () => new Promise((resolve) => {
      resolve_lease = resolve;
    }),
    report_usage: async () => ({ ok: true }),
    on_unavailable: (rule_id) => unavailable.push(rule_id),
  });
  await tracker.set_focused(true);
  await tracker.set_idle(false);
  const first = tracker.set_active_tab(1, {
    rule_id: "timed",
    kind: "website",
    value: "first.example",
    name: "Timed",
  });
  await Promise.resolve();
  await tracker.set_tab_match(1, {
    rule_id: "timed",
    kind: "website",
    value: "second.example",
    name: "Timed",
  });
  resolve_lease({
    ok: true,
    result: {
      rule_id: "timed",
      lease_id: "55555555-5555-4555-8555-555555555555",
      start_utc: "1970-01-01T00:00:01.000Z",
      end_utc: "1970-01-01T00:00:04.000Z",
    },
  });
  await first;
  assert.equal(tracker.has_lease("timed"), false);
  assert.deepEqual(unavailable, ["timed"]);
});


test("tracker reports queued usage changes for durable persistence", async () => {
  let now = 1000;
  let snapshot = [];
  const tracker = new AllowanceTracker({
    now: () => now,
    request_lease: async (rule_id) => ({
      ok: true,
      result: {
        rule_id,
        lease_id: "44444444-4444-4444-8444-444444444444",
        start_utc: "1970-01-01T00:00:01.000Z",
        end_utc: "1970-01-01T00:00:04.000Z",
      },
    }),
    report_usage: async () => ({ ok: false }),
    on_pending_changed: (reports) => {
      snapshot = reports.map((report) => ({ ...report }));
    },
  });
  await tracker.set_focused(true);
  await tracker.set_idle(false);
  await tracker.set_active_tab(2, { rule_id: "timed" });
  now = 2000;
  await tracker.pulse();
  assert.equal(snapshot.length, 1);
  let sent_report;
  const restored = new AllowanceTracker({
    now: () => now,
    request_lease: async (rule_id) => ({
      ok: true,
      result: {
        rule_id,
        lease_id: "55555555-5555-4555-8555-555555555555",
        start_utc: "1970-01-01T00:00:01.000Z",
        end_utc: "1970-01-01T00:00:04.000Z",
      },
    }),
    report_usage: async (report) => {
      sent_report = report;
      return { ok: true };
    },
  });
  restored.restore_pending(snapshot);
  await restored.set_focused(true);
  await restored.set_idle(false);
  await restored.set_active_tab(2, { rule_id: "timed" });
  assert.equal(sent_report.report_id, snapshot[0].report_id);
  assert.equal(sent_report.lease_id, "44444444-4444-4444-8444-444444444444");
});

test("tracker discards reports from versions without persisted lease IDs", () => {
  let cleared = null;
  const tracker = new AllowanceTracker({
    request_lease: async () => ({ ok: false }),
    report_usage: async () => ({ ok: true }),
    on_pending_changed: (reports) => {
      cleared = reports;
    },
  });
  tracker.restore_pending([{
    report_id: "99999999-9999-4999-8999-999999999999",
    rule_id: "timed",
    start_utc: "1970-01-01T00:00:01.000Z",
    end_utc: "1970-01-01T00:00:02.000Z",
  }]);
  assert.equal(tracker.pending_count, 0);
  assert.deepEqual(cleared, []);
});
