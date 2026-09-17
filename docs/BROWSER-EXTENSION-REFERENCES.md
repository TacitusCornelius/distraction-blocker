# Browser extension references

## Chrome: Build extensions with coding agents

- Official guide: <https://developer.chrome.com/docs/extensions/ai/build-with-ai>
- Related Modern Web Guidance: <https://developer.chrome.com/docs/modern-web-guidance>
- Chrome DevTools for agents: <https://developer.chrome.com/docs/devtools/agents>

The Chrome guide recommends giving coding agents current extension-specific
skills and validating changes against a real browser through Chrome DevTools.
The documented Modern Web Guidance installer is:

```bash
npx modern-web-guidance@latest install --choose
```

When using Chrome DevTools for agent-assisted work, enable the extensions tool
category (`--categoryExtensions`) and, when needed, automatic connection to an
existing Chrome profile (`--autoConnect`). The extension tooling can inspect
and operate on installed extensions, popups, side panels, service workers, and
other extension surfaces.

The guide also describes maintaining `CHROMEWEBSTORE.md` when preparing an
extension for Chrome Web Store publication. That file records permission
justifications and store-readiness information; it is relevant to publication
work, not runtime enforcement.

## Firefox and LibreWolf: signing and distribution

- Mozilla signing and distribution overview: <https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/>
- Mozilla self-distribution: <https://extensionworkshop.com/documentation/publish/self-distribution/>
- Mozilla packaging: <https://extensionworkshop.com/documentation/publish/package-your-extension/>
- AMO Developer Hub: <https://addons.mozilla.org/developers/>

Production Firefox and LibreWolf installs use the AMO-signed XPI. The
repository's unsigned XPI is only an AMO submission artifact; the acceptance
harness may sideload an unsigned copy only inside its marked disposable VM.
The release procedure and stable Gecko ID are recorded in
`FIREFOXADDONS.md`.

## Application to this repository

Use these references for Chromium adapter API choices, real-browser smoke
checks, service-worker lifecycle behavior, accessibility, and publication
preparation. They do not replace this repository's governing constraints:

- The root service remains the policy authority.
- Firefox and LibreWolf remain supported alongside Chromium.
- Native messaging, policy projection, and fail-closed behavior remain part of
  a single trust boundary.
- Shared browser-agnostic core modules must not contain browser APIs.
- Browser changes require extension conformance tests and a real-surface smoke
  check when the runtime is available.
