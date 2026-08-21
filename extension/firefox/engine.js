/**
 * Pure rule compiler for Distraction Blocker URL targets.
 *
 * Input is the `targets` array of service rules; output is a matcher that
 * returns the first matching target description or null. No browser or
 * service APIs appear here, so the matching contract is unit testable with
 * `node --test`.
 *
 * Matching contract (mirrors distraction_blocker.model validation):
 * - url_path:    hostname equal (case-insensitive) AND path exactly equal.
 * - url_wildcard: hostname equal AND path starts with the stored prefix.
 * - url_keyword:  keyword occurs anywhere in the full lowercase URL.
 */
"use strict";

/** Split a stored `host/path` value into its lowercase host and path. */
export function split_target(value) {
  const cut = value.indexOf("/");
  if (cut < 0) {
    return null;
  }
  return {
    host: value.slice(0, cut).toLowerCase(),
    path: value.slice(cut),
  };
}

/** Normalize a request URL into the fields matchers compare against. */
export function describe_url(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  return {
    host: parsed.hostname.toLowerCase(),
    path: parsed.pathname,
    href: parsed.href.toLowerCase(),
  };
}

function matches(target, url) {
  const parts = split_target(target.value);
  if (parts === null || parts.host !== url.host) {
    return false;
  }
  if (target.kind === "url_path") {
    return url.path === parts.path;
  }
  // url_wildcard validation guarantees exactly one trailing star.
  return url.path.startsWith(parts.path.slice(0, -1));
}

/**
 * Compile service rules into a matcher.
 * `rules` is a list of { id, enabled, targets: [{kind, value}] }.
 */
export function compile(rules) {
  const active = (rules ?? []).filter(
    (rule) => rule.enabled && Array.isArray(rule.targets),
  );
  /** Return { rule_id, kind, value } for the first match, or null. */
  return function match(raw_url) {
    const url = describe_url(raw_url);
    if (url === null) {
      return null;
    }
    for (const rule of active) {
      for (const target of rule.targets) {
        if (target.kind === "url_keyword") {
          if (url.href.includes(target.value)) {
            return { rule_id: rule.id, kind: target.kind, value: target.value };
          }
          continue;
        }
        if (target.kind !== "url_path" && target.kind !== "url_wildcard") {
          continue;
        }
        if (matches(target, url)) {
          return { rule_id: rule.id, kind: target.kind, value: target.value };
        }
      }
    }
    return null;
  };
}
