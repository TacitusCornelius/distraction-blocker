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
- Embedded-content blocking.
- Inactive-tab blocking.
- Browser-extension protection.
- Website usage statistics.
- Website allowance accounting.

The desktop application never trusts the extension. Policy flows one way,
from the signed service to the extension. Statistics flow back as plain
observational data.

## Status

Design phase. No code yet.
