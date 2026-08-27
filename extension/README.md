# Distraction Blocker browser extension

This subfolder holds the browser extension planned in
`docs/FUTURE-VERSIONS.md` under "Browser extension version".

## Product boundary

The root service stays the final policy authority. The extension enforces
URL-level rules that `/etc/hosts` cannot express:

- URL-path rules.
- Wildcard URL rules.
- Search-keyword rules.
- Website exceptions under a broad rule.
- YouTube channel or video rules.
- Embedded-content blocking: rules match loads in any frame, so
  iframe/embedded content is blocked like a top-level navigation.
- Inactive-tab blocking.
- Browser-extension protection.
- Each URL-level rule can have a daily website allowance. The extension
  permits starts until the allowance ends. The service then enforces the
  rule all day. The allowance resets at local midnight for the rule.

## Status

Implemented: the shared policy engine, Firefox and Chromium adapters,
denial attribution, the native host, installer wiring, and unit checks.
The two adapters block inactive-tab loads. Policy projections include an
explicit schema version.

The desktop application does not trust the extension. Policy flows from
the root service to the extension. The extension sends observational
statistics to the service.
