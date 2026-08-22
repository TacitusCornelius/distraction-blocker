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
 * - youtube_video:   video ID equal on any YouTube host form.
 * - youtube_channel: @handle or UC channel reference in the URL path.
 */
"use strict";

const YOUTUBE_HOST_PATTERN =
  "(?:www\\.|m\\.|music\\.)?(?:youtube\\.com|youtube-nocookie\\.com)";

function escape_regex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function split_target(value) {
  const cut = value.indexOf("/");
  if (cut < 0) {
    return null;
  }
  return {
    host: value.slice(0, cut).toLowerCase(),
    path: value.slice(cut),
  };
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
export function target_pattern(target) {
  const anchor = "^https?://" ;
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
      anchor + "(?:www\\.)?youtube\\.com/" + reference + "(?:$|/)"
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
  // Paths are case-sensitive on real servers; keywords and YouTube forms
  // are compared loosely, exactly like the Firefox matcher.
  return kind === "url_path" || kind === "url_wildcard";
}

/**
 * Compile service rules into deterministic DNR rule objects.
 * Returns [{ rule, rule_id, kind, value }] sorted by rule_id then value,
 * ids assigned 1..N so dynamic-rule replacement is stable across restarts.
 */
export function compile_dnr(rules) {
  const active = (rules ?? []).filter(
    (rule) => rule.enabled && Array.isArray(rule.targets),
  );
  const entries = [];
  for (const rule of active) {
    for (const target of rule.targets) {
      const pattern = target_pattern(target);
      if (pattern === null) {
        continue;
      }
      entries.push({
        rule_id: rule.id,
        kind: target.kind,
        value: target.value,
        pattern,
      });
    }
  }
  entries.sort((a, b) =>
    a.rule_id < b.rule_id ? -1 :
    a.rule_id > b.rule_id ? 1 :
    a.value < b.value ? -1 :
    a.value > b.value ? 1 : 0,
  );
  return entries.map((entry, index) => ({
    rule_id: entry.rule_id,
    kind: entry.kind,
    value: entry.value,
    rule: {
      id: index + 1,
      priority: 1,
      action: { type: "block" },
      condition: {
        regexFilter: entry.pattern,
        isUrlFilterCaseSensitive: case_sensitive(entry.kind),
      },
    },
  }));
}

/** Build a live RegExp from one compiled rule (for tests and tooling). */
export function rule_to_regexp(rule) {
  return new RegExp(
    rule.condition.regexFilter,
    rule.condition.isUrlFilterCaseSensitive ? "" : "i",
  );
}
