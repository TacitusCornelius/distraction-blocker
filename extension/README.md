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
The two adapters block inactive-tab loads. URL-level exceptions are
browser-only allows: an exception matching a URL takes precedence over
URL blocks, while the root service continues enforcing its own targets.
Policy projections include an explicit schema version.

The desktop application does not trust the extension. Policy flows from
the root service to the extension. The extension sends observational
statistics to the service.

## Reproduce the Firefox AMO build

The Firefox XPI is built from this source tree on a Linux, macOS, or Windows
system with Python 3.9 or newer. The build uses only the Python standard
library; Node.js, npm, webpack, and other third-party tools are not required.

From the source archive root, run:

```text
python3 extension/build.py
python3 scripts/package_firefox_extension.py \
  --output /tmp/distraction-blocker-firefox-rebuilt.xpi
```

`extension/build.py` generates the Firefox classic-script copies from the
browser-agnostic modules in `extension/core/`. The packaging command verifies
those copies, then writes an XPI with `manifest.json` at its root. The archive
is deterministic and contains the same Firefox adapter sources and assets as
the submitted add-on. The generated `extension/firefox/core/` directory is
intentionally omitted from the source archive and is recreated by the first
command.
