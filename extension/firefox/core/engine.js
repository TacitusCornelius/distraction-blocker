/**
 * Pure rule compiler for Distraction Blocker URL targets.
 *
 * Input is the `targets` array of service rules; output is a matcher that
 * returns the first matching target description or null. No browser or
 * service APIs appear here, so the matching contract is unit testable with
 * `node --test`.
 *
 * Matching contract (mirrors distraction_blocker.model validation):
 * - url_path:       hostname equal (case-insensitive) AND path exactly equal.
 * - url_wildcard:   hostname equal AND path starts with the stored prefix.
 * - url_keyword:    keyword occurs anywhere in the full lowercase URL.
 * - youtube_video:  video ID equal on any YouTube host (watch, shorts,
 *                   embed, live).
 * - youtube_channel: @handle or UC channel ID in the URL path.
 */
"use strict";

/** Split a stored `host/path` value into its lowercase host and path. */
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

const YOUTUBE_HOSTS = new Set([
  "youtube.com",
  "www.youtube.com",
  "m.youtube.com",
  "music.youtube.com",
  "youtube-nocookie.com",
  "www.youtube-nocookie.com",
]);
/**
 * Extract a video ID or channel reference from a YouTube URL.
 * Handles watch?v=, /shorts/, /embed/, /live/, /@handle and /channel/UC….
 */
function youtube_fields(parsed) {
  const host = parsed.hostname.toLowerCase();
  if (!YOUTUBE_HOSTS.has(host)) {
    return null;
  }
  const segments = parsed.pathname.split("/").filter(Boolean);
  let youtube_video = parsed.searchParams.get("v");
  if (
    !youtube_video &&
    (segments[0] === "shorts" ||
      segments[0] === "embed" ||
      segments[0] === "live")
  ) {
    youtube_video = segments[1] ?? null;
  }
  let youtube_channel = null;
  if (segments[0] === "channel") {
    youtube_channel = segments[1] ?? null;
  } else if (segments[0]?.startsWith("@")) {
    youtube_channel = segments[0];
  }
  return {
    host,
    path: parsed.pathname,
    href: parsed.href.toLowerCase(),
    youtube_video:
      youtube_video && /^[A-Za-z0-9_-]{11}$/.test(youtube_video)
        ? youtube_video
        : null,
    youtube_channel: youtube_channel ? youtube_channel.toLowerCase() : null,
  };
}

/** Normalize a request URL into the fields matchers compare against. */
function describe_url(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  return (
    youtube_fields(parsed) ?? {
      host: parsed.hostname.toLowerCase(),
      path: parsed.pathname,
      href: parsed.href.toLowerCase(),
      youtube_video: null,
      youtube_channel: null,
    }
  );
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
function compile(rules) {
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
        if (target.kind === "youtube_video") {
          if (url.youtube_video !== null && url.youtube_video === target.value) {
            return { rule_id: rule.id, kind: target.kind, value: target.value };
          }
          continue;
        }
        if (target.kind === "youtube_channel") {
          if (
            url.youtube_channel !== null &&
            url.youtube_channel === target.value.toLowerCase()
          ) {
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
