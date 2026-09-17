# Chrome Web Store release

This repository ships a Chromium Manifest V3 adapter in `extension/chromium/`.
The Chrome Web Store package is an installation channel for that adapter; the
Ubuntu root service and native-messaging host remain required for enforcement.

The Web Store release is **Version 1.9.0**. The Firefox and Chromium adapter
manifests share this version so the extension build contract remains strict.

## Distribution decision

Use **Unlisted** for the first production release. Unlisted items do not appear
in Chrome Web Store search, but anyone with the direct item URL can install
one. Use **Private** instead when installation must be limited to named trusted
testers, Google Groups, or an eligible managed organization. These are Chrome
Web Store visibility settings, not manifest fields.

The repository cannot create the publisher account, complete identity or
payment verification, provide a privacy-policy URL, or submit an item for
review. Those are operator actions in the Chrome Developer Dashboard.

## Current publication status

Version 1.9.0 has been submitted to the Chrome Web Store for review. The
publisher contact email is verified, and the public HTTPS privacy-policy URL
is available at:

<https://tacituscornelius.github.io/distraction-blocker/privacy-policy/>

The submission now awaits the Chrome Web Store review outcome. No source or
ZIP change is required while review is pending. If Google requests changes,
record the review feedback here before preparing a new submission.

## Build the upload archive

Run from the repository root:

```bash
python3 extension/build.py
python3 scripts/package_chromium_extension.py
```

The package script runs `extension/build.py --check`, validates the MV3
manifest, requires the service worker and popup entry points, omits Python
caches and platform metadata, removes the development-only manifest `key`
field, and writes a reproducible ZIP with `manifest.json` at its root. The
archive is generated under ignored `dist/`; it is not a source artifact to
commit.

Upload only the generated ZIP. Do not zip the `extension/` directory itself,
which would put `manifest.json` below an extra directory level.

## Extension identity and native messaging

The source manifest pins a public key for local development. It produces this
local/unpacked extension ID:

```text
kcoacponjklfkboekihkibdlnpdijnmn
```

Chrome Web Store rejects the `key` field in an uploaded manifest. The package
script therefore removes that field only in the upload ZIP; it remains in the
source manifest so local development and acceptance profiles retain a stable
ID.

The Web Store assigns the production Item ID during the first upload. Do not
assume it is the local ID above. Before publishing or installing the Web Store
item, update `packaging/org.distraction_blocker.chromium.json` so both native
messaging allowlists contain the Dashboard Item ID. Update the corresponding
identity test in the same change and run the full extension/build checks. A
different or unreconciled ID makes native messaging fail closed because the
host will reject the browser origin.

Keep the source `key` unchanged for local development unless the Dashboard
public key is deliberately adopted as a versioned identity change. Never
publish a package whose Web Store Item ID and installed native-host allowlist
disagree.

## Dashboard checklist

1. Register or select the Chrome Web Store developer account.
2. Choose **Add new item** and upload the generated ZIP.
3. On the Package tab, verify the version and Item ID.
4. Complete the Store Listing tab.
5. Complete the Privacy tab using the declarations below and the public
   privacy-policy URL.
6. On Distribution, select **Unlisted** for link-only installation, or
   **Private** and add the intended testers, group, or managed organization.
7. Submit for review. Publish immediately or defer publication according to
   the release plan.

### Publisher contact email

The contact-email errors cannot be fixed in the ZIP or repository. In the
Developer Dashboard, open **Settings**, enter the publisher contact email,
save it, and start verification. Complete the verification link delivered to
that mailbox. Return to the item only after the Dashboard shows the address as
verified.

Chrome Web Store references:

- [Prepare your extension](https://developer.chrome.com/docs/webstore/prepare)
- [Publish in the Chrome Web Store](https://developer.chrome.com/docs/webstore/publish)
- [Set up distribution](https://developer.chrome.com/docs/webstore/cws-dashboard-distribution)
- [Keep a consistent extension ID](https://developer.chrome.com/docs/extensions/reference/manifest/key)

## Listing copy

**Name:** Distraction Blocker

**Single-purpose description:** Distraction Blocker enforces the user's
browser website policy from the locally installed Distraction Blocker service.
It blocks configured browser targets, applies browser exceptions, and reports
local enforcement status.

The extension is not a general content reader, advertising tool, analytics
product, or remote policy service. The root service is the policy authority;
the extension holds and enforces a browser projection of that local policy.

## Permission justifications

Use these explanations in the Dashboard permission disclosures and review
notes:

- **`nativeMessaging`:** Connects to the locally installed
  `org.distraction_blocker.extension` native host. The host forwards policy
  requests and browser usage observations to the root-owned Distraction Blocker
  service over its owner-checked local Unix socket. No remote endpoint is used.
- **`storage`:** Persists the extension's local policy snapshot, status, denial
  counters, allowance bookkeeping, and worker-restart recovery state. This is
  required because Manifest V3 service workers stop and restart.
- **`declarativeNetRequest`:** Compiles the active browser policy into dynamic
  blocking and allow rules. Session rules also enforce inactive-tab and timed
  allowance behavior. This is the Chromium MV3 enforcement API.
- **`alarms`:** Schedules policy refreshes, lease heartbeats, and usage-accounting
  work while the service worker is not continuously running.
- **`webRequest`:** Observes browser requests for local attribution, denial
  status, and timed-allowance accounting. It does not perform the blocking;
  the blocking rules are installed through `declarativeNetRequest`.
- **`tabs`:** Identifies the active and inactive tab set so inactive-tab rules,
  focused-tab allowance accounting, and the block page can be applied to the
  correct tabs.
- **`idle`:** Distinguishes active use from idle time so timed browser
  allowances count only foreground activity while the user is not idle.
- **Host permission `<all_urls>`:** The user's policy can name any website.
  The extension must inspect and enforce requests across all HTTP(S) hosts,
  not only a fixed catalog. Raw URL observations remain local and are not sent
  to a remote server.

The Web Store may ask for a narrower justification or a separate data-use
selection. The declarations above describe the implementation, not a request
to add broader access.

### Paste-ready Privacy practices values

The Dashboard requires a separate non-empty justification for every declared
permission. Paste the matching value into each field:

- **`alarms`:** Schedules policy refreshes, native-service heartbeats, and
  timed-allowance accounting while the Manifest V3 service worker is stopped
  between events.
- **`declarativeNetRequest`:** Installs the user's active browser policy as
  dynamic blocking and allow rules, including session rules for inactive tabs
  and timed allowances. This is the Chromium MV3 enforcement API.
- **Host permission `<all_urls>`:** The user may configure any HTTP or HTTPS
  hostname. Access across all hosts is required to compare requests with that
  policy and enforce its blocks; the extension does not send raw URLs to a
  remote server.
- **`idle`:** Detects whether the user is idle so timed browser allowances
  count only foreground activity and do not consume budget while the user is
  away.
- **`nativeMessaging`:** Communicates with the locally installed
  `org.distraction_blocker.extension` host, which forwards policy requests and
  bounded usage observations to the local Distraction Blocker service. No
  remote service is contacted.
- **`storage`:** Stores the local policy snapshot, enforcement status, denial
  counters, allowance state, and pending reports so service-worker restarts do
  not lose state.
- **`tabs`:** Identifies active, inactive, and focused tabs so inactive-tab
  rules, focused-tab allowance accounting, and the local block page apply to
  the correct tab.
- **`webRequest`:** Observes requests for local policy attribution, denial
  status, and timed-allowance accounting. Blocking is performed by
  `declarativeNetRequest`, not by this observer.
- **Remote code:** Select **No, I am not using remote code**. All JavaScript,
  HTML, CSS, images, and shared policy code are packaged in the upload ZIP.
  The extension does not download, evaluate, or execute code from a server.

For data-use disclosures, declare that the extension handles web-browsing
activity and policy/enforcement state solely to enforce the user's local
Distraction Blocker policy. It does not sell data, use it for advertising,
transfer it to a remote server, or use it for unrelated purposes. The native
host and root service are local components on the user's Ubuntu machine.

### Data usage selections

Select these two data categories:

- **Web history**, because the extension observes requested URLs in order to
  match the user's browser policy and retain local denial status.
- **User activity**, because timed allowances use the focused tab, active
  window, and idle state to measure foreground usage. The extension does not
  record clicks, mouse position, scrolls, or keystrokes.

Do not select personally identifiable information, health information,
financial and payment information, authentication information, personal
communications, location, or website content. The extension does not read page
text, images, audio, video, or hyperlinks as content.

Check all three certification statements:

- I do not sell or transfer user data to third parties, outside of the approved
  use cases.
- I do not use or transfer user data for purposes unrelated to this item's
  single purpose.
- I do not use or transfer user data to determine creditworthiness or for
  lending purposes.


## Privacy and data-use statement

The extension handles web-browsing activity because it must compare requested
URLs with the user's local blocking policy. It also handles policy state,
allowance state, and enforcement status. The extension stores this state in
Chrome extension storage and sends policy requests plus bounded usage
observations only to the locally installed native host and root service. The
service stores its policy and statistics on the local Ubuntu system.

The extension does not sell data, use data for advertising, transfer data to a
remote server, execute remotely hosted code, or use browsing data for a purpose
unrelated to enforcing the user's Distraction Blocker policy. Denial URLs are
kept as local status data; they are not uploaded as analytics.

The repository draft privacy policy is [`docs/PRIVACY-POLICY.md`](docs/PRIVACY-POLICY.md).
Publish that document at a stable, publicly accessible HTTPS URL before
submitting the item, then paste that URL into the Dashboard's Privacy policy
field. A local filesystem path or a private repository URL will not satisfy
the Web Store requirement. Keep the hosted policy synchronized with the
extension's actual behavior.

## Production installation after publication

Installing the Web Store item does not install the native host. On the Ubuntu
machine that owns the protected desktop user, install the service and host
first:

```bash
sudo python3 scripts/install.py --confirm --owner-uid "$(id -u)"
```

Then install the extension from its Chrome Web Store item URL. Do not use
**Load unpacked** for production users. The installer places the Chrome native
host manifest in the system and per-user Chrome locations; those manifests
must continue to allow the verified Web Store Item ID.

For a new release, increment `extension/chromium/manifest.json`'s version,
run the build and package commands again, upload the new ZIP to the existing
Dashboard item, and submit the update for review. Never create a second item
for an update: the existing item ID is part of the native-messaging trust
boundary.

## Removal

Remove the Chrome Web Store extension through `chrome://extensions` or the
browser's Extensions page. Remove the local service and native host separately
when the machine should no longer enforce policy:

```bash
sudo python3 scripts/uninstall.py --confirm
```
