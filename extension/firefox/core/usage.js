/**
 * Shared counters for website starts and browser denials.
 *
 * The browser adapters use these functions for one key format and restore
 * path. Counts use safe integer limits. Bounded maps evict old keys first.
 */
"use strict";

/** True when a rule can still permit counted starts. */
function is_allowance_rule(rule) {
  const starts = rule?.allowance_starts;
  return (
    typeof starts === "number" &&
    Number.isInteger(starts) &&
    starts >= 1 &&
    rule?.budget_exhausted !== true
  );
}

/**
 * Split service rules into two enforcement groups.
 * `enforced` rules block as before. `allowance` rules permit counted starts.
 * The downstream compilers filter disabled rules.
 */
function partition_rules(rules) {
  const enforced = [];
  const allowance = [];
  for (const rule of rules ?? []) {
    (is_allowance_rule(rule) ? allowance : enforced).push(rule);
  }
  return { enforced, allowance };
}
/** Maximum exact value for one counter. */
const COUNTER_MAX = Number.MAX_SAFE_INTEGER;
const USAGE_KINDS = new Set([
  "url_path",
  "url_wildcard",
  "url_keyword",
  "youtube_video",
  "youtube_channel",
]);

/** Encode one (rule_id, value) counter key. */
function usage_key(rule_id, value) {
  return `${rule_id}\u0000${value}`;
}

/** Decode one counter key, or return null for malformed storage data. */
function decode_usage_key(key) {
  if (typeof key !== "string") {
    return null;
  }
  const cut = key.indexOf("\u0000");
  if (cut <= 0) {
    return null;
  }
  return {
    rule_id: key.slice(0, cut),
    value: key.slice(cut + 1),
  };
}

function saturated_add(current, n) {
  return Math.min(COUNTER_MAX, current + n);
}

/** Add n to one usage counter. */
function bump_usage(counts, rule_id, value, n = 1) {
  if (!Number.isInteger(n) || n <= 0) {
    return;
  }
  const key = usage_key(rule_id, value);
  counts.set(key, saturated_add(counts.get(key) ?? 0, n));
}

/**
 * Add n to a bounded map.
 *
 * New keys evict the oldest key when the map is full. Existing keys keep
 * their insertion order. Counts stop at COUNTER_MAX.
 */
function bump_bounded(counts, key, n = 1, limit = 256) {
  if (
    !Number.isInteger(n) ||
    n <= 0 ||
    !Number.isInteger(limit) ||
    limit < 1
  ) {
    return;
  }
  if (!counts.has(key)) {
    while (counts.size >= limit) {
      counts.delete(counts.keys().next().value);
    }
    counts.set(key, Math.min(COUNTER_MAX, n));
    return;
  }
  counts.set(key, saturated_add(counts.get(key) ?? 0, n));
}

/**
 * Build report entries from the counter map, oldest insertion first,
 * capped at `limit` so one message stays far below the native messaging
 * frame limit. Unsent counters past the cap stay in the map untouched.
 */
function usage_entries(counts, limit = 128) {
  const entries = [];
  for (const [key, count] of counts) {
    if (entries.length >= limit) {
      break;
    }
    const decoded = decode_usage_key(key);
    if (decoded === null) {
      continue;
    }
    entries.push({ ...decoded, count });
  }
  return entries;
}

/** Convert encoded counters to the labels used by adapter status storage. */
function usage_snapshot(counts) {
  const out = {};
  for (const [key, count] of counts) {
    const decoded = decode_usage_key(key);
    if (decoded !== null && Number.isInteger(count) && count > 0) {
      out[`${decoded.rule_id} → ${decoded.value}`] = count;
    }
  }
  return out;
}

/** Subtract reported counts from the map, dropping counters that reach 0. */
function retire_usage(counts, entries) {
  for (const entry of entries) {
    const key = usage_key(entry.rule_id, entry.value);
    const remaining = (counts.get(key) ?? 0) - entry.count;
    if (remaining > 0) {
      counts.set(key, remaining);
    } else {
      counts.delete(key);
    }
  }
}

/**
 * Merge display-labelled counters (exactly what record_state snapshots
 * write: "rule_id -> value" keys with a pending count) back into a counter
 * map. Labels whose rule id starts with one of `blocked_prefixes` are
 * skipped - local-only counters such as inactive-tab counts must never
 * become reportable again through a restore.
 */
function merge_labels(counts, labels, blocked_prefixes = []) {
  if (!labels || typeof labels !== "object") {
    return;
  }
  for (const [label, count] of Object.entries(labels)) {
    const cut = label.indexOf(" \u2192 ");
    if (cut <= 0 || !Number.isInteger(count) || count <= 0) {
      continue;
    }
    const rule_id = label.slice(0, cut);
    if (blocked_prefixes.some((prefix) => rule_id.startsWith(prefix))) {
      continue;
    }
    bump_usage(counts, rule_id, label.slice(cut + 3), count);
  }
}

/** Drop queued usage rows that are not targets in an active allowance rule. */
function prune_usage(counts, rules) {
  const allowed = new Set();
  for (const rule of rules ?? []) {
    if (!is_allowance_rule(rule) || !Array.isArray(rule.targets)) {
      continue;
    }
    for (const target of rule.targets) {
      if (
        target &&
        USAGE_KINDS.has(target.kind) &&
        typeof target.value === "string"
      ) {
        allowed.add(usage_key(rule.id, target.value));
      }
    }
  }
  for (const key of counts.keys()) {
    if (!allowed.has(key)) {
      counts.delete(key);
    }
  }
}

/** Merge report-shaped entries back into the map (retry/restore paths). */
function merge_usage(counts, entries) {
  for (const entry of entries) {
    if (Number.isInteger(entry.count) && entry.count > 0) {
      bump_usage(counts, entry.rule_id, entry.value, entry.count);
    }
  }
}

/**
 * Restore encoded counters from storage.
 *
 * Invalid rows do not enter the map. Repeated keys add together and use the
 * same saturated counter as live updates.
 */
function restore_usage(counts, stored) {
  if (!Array.isArray(stored)) {
    return;
  }
  for (const row of stored) {
    if (!Array.isArray(row) || row.length !== 2) {
      continue;
    }
    const decoded = decode_usage_key(row[0]);
    if (decoded === null || !Number.isInteger(row[1]) || row[1] <= 0) {
      continue;
    }
    bump_usage(counts, decoded.rule_id, decoded.value, row[1]);
  }
}
