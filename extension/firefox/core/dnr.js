/**
 * Compile service policies into declarativeNetRequest rules.
 *
 * This module is browser-agnostic by rule: it transforms the service blob
 * into plain data (JSON-safe DNR rule objects). The Chromium adapter submits
 * them through declarativeNetRequest.updateDynamicRules; tests evaluate the
 * emitted regular expressions directly against fixture URLs so both
 * adapters provably enforce identical semantics.
 *
 * Matching contract mirrors ../firefox behavior:
 * - url_path:        hostname exact, path exact (case-sensitive path).
 * - url_wildcard:    hostname exact, path starts with the stored prefix
 *                    (exactly one trailing star in the stored value).
 * - url_keyword:     keyword occurs anywhere in the full URL
 *                    (case-insensitive).
 * - youtube_video:   video ID equal on any YouTube host form (case-sensitive).
 * - youtube_channel: @handle or UC channel reference in the URL path.
 */
"use strict";

// Breadcrumb: single source of truth lives in engine.js; both adapters
// load this file as an ES module next to its vendored engine.js copy,
// so the relative specifier resolves in every context that runs it.

const YOUTUBE_HOST_PATTERN =
  "(?:www\\.|m\\.|music\\.)?(?:youtube\\.com|youtube-nocookie\\.com)";

// Breadcrumb: DNR omits main_frame from its default resource types. Keep
// this complete HTTP request set shared by policy and inactive-tab rules.
const NETWORK_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "xmlhttprequest",
  "script",
  "stylesheet",
  "image",
  "media",
  "font",
  "object",
  "ping",
  "csp_report",
  "websocket",
  "webtransport",
  "webbundle",
  "other",
];

function escape_regex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function case_insensitive_host(host) {
  // Breadcrumb: DNR case-sensitivity is per-rule, but the matching
  // contract needs insensitive hosts with sensitive paths; spelling the
  // host as dual-case classes gives exactly that.
  return [...host]
    .map((char) =>
      /[a-z]/.test(char)
        ? `[${char}${char.toUpperCase()}]`
        : escape_regex(char),
    )
    .join("");
}

/** Build the anchored DNR regexFilter body for one target, or null. */
function target_pattern(target) {
  const anchor = "^https?://";
  if (target.kind === "website") {
    return (
      anchor +
      case_insensitive_host(target.value) +
      "(?::[0-9]+)?(?:[/?#].*)?$"
    );
  }
  if (target.kind === "url_path" || target.kind === "url_wildcard") {
    const parts = split_target(target.value);
    if (parts === null) {
      return null;
    }
    const wildcard = target.kind === "url_wildcard";
    const raw_path = wildcard ? parts.path.slice(0, -1) : parts.path;
    return (
      anchor +
      case_insensitive_host(parts.host) +
      "(?::[0-9]+)?" +
      escape_regex(raw_path) +
      (wildcard ? ".*" : "") +
      "(?:[?#].*)?$"
    );
  }
  if (target.kind === "youtube_video") {
    return (
      anchor + YOUTUBE_HOST_PATTERN +
      "/(?:watch\\?(?:[^#]*&)?v=|shorts/|embed/|live/)" +
      escape_regex(target.value) +
      "(?:$|[&#])"
    );
  }
  if (target.kind === "youtube_channel") {
    const reference = target.value.startsWith("@")
      ? "@" + escape_regex(target.value.slice(1))
      : "channel/" + escape_regex(target.value);
    return (
      anchor +
      // Breadcrumb: same host set as engine.js YOUTUBE_HOSTS.
      "(?:www\\.|m\\.|music\\.)?youtube(?:-nocookie)?\\.com/" +
      reference + "(?:$|/)"
    );
  }
  if (target.kind === "url_keyword") {
    // Breadcrumb: keywords are lowercase ASCII by model validation, and the
    // emitted rule runs case-insensitively, matching the Firefox matcher.
    return escape_regex(target.value);
  }
  return null;
}

function case_sensitive(kind) {
  // Paths and YouTube video IDs are case-sensitive on their source
  // services; keywords and YouTube channel forms are compared loosely,
  // exactly like the Firefox matcher.
  return (
    kind === "url_path" ||
    kind === "url_wildcard" ||
    kind === "youtube_video"
  );
}

/**
 * Compile service rules into deterministic DNR rule objects.
 * Returns [{ rule, rule_id, kind, value }] sorted by rule_id then value,
 * ids assigned 1..N so dynamic-rule replacement is stable across restarts.
 */
function compile_dnr(rules) {
  const active = (rules ?? []).filter(
    (rule) => rule.enabled && Array.isArray(rule.targets),
  );
  const entries = [];
  for (const rule of active) {
    for (const target of rule.targets) {
      const pattern = target_pattern(target);
      if (pattern !== null) {
        entries.push({
          rule_id: rule.id,
          kind: target.kind,
          value: target.value,
          pattern,
          exception: false,
        });
      }
    }
    for (const target of Array.isArray(rule.exceptions) ? rule.exceptions : []) {
      const pattern = target_pattern(target);
      if (pattern !== null) {
        entries.push({
          rule_id: rule.id,
          kind: target.kind,
          value: target.value,
          pattern,
          exception: true,
        });
      }
    }
  }
  if (entries.length > 5000) {
    throw new Error("browser rule capacity cannot hold the complete policy");
  }
  entries.sort((a, b) =>
    a.exception - b.exception ||
    (a.rule_id < b.rule_id ? -1 :
      a.rule_id > b.rule_id ? 1 :
      a.value < b.value ? -1 :
      a.value > b.value ? 1 : 0),
  );
  return entries.map((entry, index) => ({
    rule_id: entry.rule_id,
    kind: entry.kind,
    value: entry.value,
    rule: {
      id: index + 1,
      priority: entry.exception ? 2 : 1,
      action: { type: entry.exception ? "allow" : "block" },
      condition: {
        regexFilter: entry.pattern,
        isUrlFilterCaseSensitive: case_sensitive(entry.kind),
        resourceTypes: NETWORK_RESOURCE_TYPES,
      },
    },
  }));
}

/**
 * Build one session rule that blocks HTTP loads from the selected tabs.
 * A null result removes the rule when no inactive tabs exist.
 */
function compile_inactive_tab_rule(tab_ids, rule_id) {
  const ids = [...new Set((tab_ids ?? []).filter(
    (tab_id) => Number.isInteger(tab_id) && tab_id >= 0,
  ))].sort((left, right) => left - right);
  if (ids.length === 0) {
    return null;
  }
  return {
    id: rule_id,
    priority: 1,
    action: { type: "block" },
    condition: {
      regexFilter: "^https?://",
      isUrlFilterCaseSensitive: false,
      resourceTypes: NETWORK_RESOURCE_TYPES,
      tabIds: ids,
    },
  };
}

/** Build a live RegExp from one compiled rule (for tests and tooling). */
function rule_to_regexp(rule) {
  return new RegExp(
    rule.condition.regexFilter,
    rule.condition.isUrlFilterCaseSensitive ? "" : "i",
  );
}
