# Distraction Blocker Privacy Policy

**Applies to:** Distraction Blocker Chrome extension, Version 1.9.0

Distraction Blocker is a local browser-policy enforcement extension. It works
with the Distraction Blocker service and native-messaging host installed on the
user's Ubuntu computer. This policy describes the data the extension handles
and how it is used.

## Data handled

### Web browsing activity

The extension observes requested HTTP and HTTPS URLs so it can compare each
request with the user's configured browser policy and enforce matching blocks.
It may retain bounded local denial status containing a requested URL for the
user's status view. It does not read or collect page text, images, audio, video,
hyperlinks as page content, form data, passwords, cookies, or personal
communications.

### User activity and policy state

For timed browser allowances, the extension handles the currently focused tab,
active window state, tab lifecycle, and Chrome's idle/active state. It uses
those signals to count foreground usage and does not record clicks, mouse
position, scrolling, or keystrokes.

The extension also handles the policy and enforcement state needed to perform
its user-facing function: configured browser targets, rule identifiers,
schedules, allowance state, bounded denial counters, and enforcement status.

## How data is used

Data is used only to enforce and display the user's Distraction Blocker policy,
including browser blocks, browser exceptions, inactive-tab protection, and
timed browser allowances. The extension does not use browsing activity for
advertising, profiling, analytics, creditworthiness, or any unrelated purpose.

The extension sends policy requests and bounded rule/usage observations only to
the locally installed `org.distraction_blocker.extension` native host. That
host communicates with the local Distraction Blocker service over its
owner-checked Unix socket. Raw browsing requests are not sent to a developer
server or other remote service.

## Storage and retention

The extension stores its policy snapshot, status, bounded counters, allowance
bookkeeping, and restart-recovery state using Chrome extension storage. The
local Distraction Blocker service stores the signed policy and local statistics
on the Ubuntu computer.

Persistent extension data remains until the user clears the extension data or
removes the extension; transient session state may be cleared by Chrome. Local
service statistics and policy data remain until the user removes them through
the application's controls or uninstall procedure. The application can
preserve signed policy data during an ordinary uninstall; removing that data
is an explicit separate action.

The user can remove the extension through Chrome's Extensions page and remove
the local service and its owned runtime data using the application's uninstall
procedure.

## Security

The extension communicates with the native host using Chrome native messaging.
The host runs as the configured desktop user and forwards requests through the
local service's owner-checked socket. Root-owned installation files and the
local service enforce the trust boundary. No remote code is downloaded or
executed by the extension.

## Permissions

The extension requests permissions only for its current function:

- `nativeMessaging` connects to the local policy service.
- `storage` preserves local policy and worker-restart state.
- `declarativeNetRequest` installs browser blocking and allow rules.
- `alarms` schedules refresh and allowance work for the service worker.
- `webRequest` observes requests for local attribution and status; it does not
  perform the blocking.
- `tabs` tracks the tab and window state needed for enforcement and allowances.
- `idle` distinguishes foreground use from idle time.
- `<all_urls>` allows a user-configured policy to apply to any website.

## Changes and contact

This policy applies to Version 1.9.0 and later releases unless a later policy
is published. Privacy questions should be sent using the publisher contact
email displayed for the Distraction Blocker item in the Chrome Web Store.
