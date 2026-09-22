# Future Version Roadmap

This document records approved features for Distraction Blocker after version 1.0.

## Product boundary

The root service remains the policy authority. The GUI sends requests to the service.

Website rules currently use `/etc/hosts`. They apply only to clients that use the Ubuntu system hosts lookup.

Application rules use Linux fanotify. They apply to exact resolved executable paths.

Root, recovery boot, another operating system, and kernel failure remain outside the protection boundary.

## Version 1.1

Version 1.1 adds local usability and data-portability features.

### Themes

The GUI provides three theme choices:

- System
- Light
- Dark

The GUI stores the theme in the user configuration directory. The root service does not read this preference.

### One-time date and time selection

One-time rules use calendar panes for the start and end dates. Each pane includes hour and minute selectors.

New rules start at the next five-minute boundary. The default end is one hour after the start.

The service continues to store UTC start and end values. This GUI change does not change the policy file contract.

### Plain domain import

The importer accepts these local UTF-8 text formats:

- One domain on each line.
- Blank lines and lines that start with `#`.
- Hosts rows that start with `0.0.0.0`, `127.0.0.1`, or `::`.
- HaGeZi `onlydomains` files.

The importer validates each domain through the application data model. It rejects URL paths, wildcards, IP addresses, and invalid hostnames.

The preview shows these counts:

- Accepted domains.
- Duplicate domains.
- Invalid or unsupported rows.
- Ignored blank lines and comments.

The user can apply accepted domains to a new rule or an inactive rule. An import cannot weaken an active finite rule.

### Export

A plain domain export contains one normalized domain on each line. The file uses UTF-8 and alphabetical order.

A native JSON export contains all rule fields and a schema version. It does not contain the HMAC key, policy signature, clock state, or socket data.

Native JSON import validates the complete file before it changes policy. The service applies the replacement as one atomic policy update.

### Rule management

The GUI can duplicate a rule. The copy gets a new UUID, a new name, and a disabled state.

The GUI can search rule names and targets. It can filter rules by all, active, inactive, enabled, or disabled state.

## Local Block List export

The Block List importer accepts the JSON block mapping used by `.blocklist.json`
exports. It strictly parses the JSON and never repairs truncated or malformed
files. Its current compatibility contract is defined in
[Version 1.5](#version-15--block-list-import-fidelity) below.

The importer creates disabled Distraction Blocker rules from representable
targets and weekly schedules. The import time zone is explicit because these
exports do not carry an IANA time-zone name. Unsupported or ambiguous
URL forms, user targeting, window-title rules, unmapped applications, lock and
break settings, and unrepresentable schedule periods remain visible as
categorized preview issues rather than being silently discarded.

The importer never infers Linux paths, user scope, or lock strength. Whole
internet imports require the separately installed network controls, and
application or lock/break mappings require explicit user-supplied files.


## Version 1.2

Version 1.2 is built. It adds managed lists and schedule improvements.

### Managed large lists

Large lists do not use normal rule targets. A rule stores one managed-list UUID reference.

The root service stores each list once in the signed policy. It expands list targets only during enforcement.

The implementation has these limits:

- 64 managed lists in one policy.
- 50,000 domains in one managed list.
- 4 MiB of normalized managed domains in one policy.
- 200 domains in one service import chunk.
- 65,536 bytes in one normal RPC message.
- 8 MiB in one native backup import.

Normal service responses contain list metadata and domain counts. They do not contain managed domains.

Each summary shows the source, data version, license note, import time, and domain count.

The service stages imports in memory. It commits a complete list in one signed policy update.

An update cannot remove domains from a list that an active rule uses. A referenced list cannot be deleted.

HaGeZi publishes its lists under GNU GPL version 3. A user who imports one must keep its source and license information.

A local DNS service remains a possible long-term design. Large `/etc/hosts` sections can reduce resolver performance.

### Other version 1.2 features

- Seven small offline starter categories, including Video and YouTube.
- Up to 16 weekly periods for one rule.
- Quick focus timers that copy existing rule targets.
- Per-rule notification controls for rule-state and upcoming-change alerts.

Notifications report only the categories selected on each rule. They never
control enforcement.

## Version 1.3

Version 1.3 is built. It adds stricter sessions and observational activity data.

### Rule locks

The root service enforces weekly schedule, timed, friction, and password locks.

- A schedule lock is effective automatically during active periods of a weekly rule.
- A timed lock can last up to 366 days.
- An untrusted clock keeps a timed lock effective.
- A friction challenge uses 12 service-generated characters.
- A password uses a root-owned scrypt hash, stored with its own parameter values.
- Failed password attempts add a persisted delay of up to 64 seconds.
- Friction and password grants are memory-only, single-use, and valid for 60 seconds.

Random text adds friction. It is not a security boundary. Root remains outside the lock boundary.

### Pomodoro

A Pomodoro rule stores one UTC anchor. It supports 1 to 180 work minutes, 1 to 60 break minutes, and 1 to 20 cycles.

The service derives each phase from trusted UTC. GUI exit and reboot do not reset it.

### Application denial statistics

Fanotify reports a denial only after it sends `FAN_DENY`. A bounded queue moves observational work to the service thread.

The signed statistics file stores at most 256 application paths. The whole
state also stays under a total byte budget, so every legal state fits the file.
The queue holds at most 1,024 pending events.

Statistics count denied starts. They do not measure foreground use or time spent.

### Public command-line client

The installed `distraction-blocker` command uses the existing owner-checked Unix socket. Password input is hidden and never enters an argument.

### Multi-user policy research

The multi-user policy research record remains local-only. Version 1.3 does not add multi-user enforcement.

## Browser extension version

A browser extension is necessary for these features:

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

Deferred by owner decision: browser-extension protection.

Website allowance accounting is built. Each URL-level rule can have an
optional daily start budget. The service enforces the rule after the
budget ends. The budget resets at local midnight for the rule.

The next feature cycle is built:

- Chromium inactive-tab blocking uses a session DNR rule with inactive tab
  IDs. Tab events replace the rule.
- Policy projections include `schema_version: 5` and `revision`. Firefox,
  Chromium, the GUI, and the CLI reject an unsupported projection.

The root service must remain the final policy authority.

## Privileged network version

The protected-user firewall and SafeSearch subset is implemented behind
separate installation approval:

- Whole-internet protected-user output blocking.
- Alternate DNS and DNS-over-TLS port restrictions.
- Protected-user SafeSearch DNS mappings for Google, Bing, and YouTube.

The first narrow encrypted-DNS control is implemented behind the same
approval:

- Known DoH endpoint blocking for a versioned static catalog of documented
  Cloudflare, Google, and Quad9 resolver addresses.

The DoH catalog blocks protected-user TCP and UDP port 443 traffic by exact
destination address. It does not inspect hostnames, SNI, HTTP paths, or
payloads. A provider address rotation can remain uncovered until a package
catalog update, and shared resolver addresses can block unrelated HTTPS.
Arbitrary DoH, alternate ports, unrecognized proxy/VPN transports, and root or
other-UID traffic remain outside the claim.

The implementation uses one owned nftables table, a dedicated dnsmasq
instance, an early-boot fence, drift repair, and offline recovery. It does
not modify the global resolver configuration or unrelated firewall state.

The proxy and VPN endpoint controls are implemented behind the same explicit
installation approval:

- Common proxy listener port blocking for protected-user TCP and UDP output.
- Common VPN transport port blocking for protected-user TCP and UDP output.
- GRE and ESP packet blocking for protected-user output.

These are versioned transport catalogs, not proxy or VPN identification. They
do not inspect payloads, discover arbitrary ports, or cover local proxy/VPN
processes, tunnels using ordinary web traffic, root, or other UIDs. Common
ports and protocols can be shared with unrelated services and may cause
collateral blocking.

The SafeSearch-over-arbitrary-encrypted-paths review is complete. No network
implementation is approved under the current architecture:

- Encrypted DNS over arbitrary HTTPS is indistinguishable from ordinary
  HTTPS using the available UID, address, port, and protocol metadata.
- A VPN or tunnel hides the inner DNS query and search destination from the
  host output filter.
- Blocking all remote HTTPS or all tunnel-capable traffic would either make
  SafeSearch unusable or cause unacceptable collateral blocking.
- Browser-level URL rewriting would cover only supported browsers and remains
  disableable; it cannot establish a protected-user network guarantee.

SafeSearch therefore remains explicitly limited to the owned local resolver
path. The existing known-DoH, common-proxy, and common-VPN controls are
best-effort bypass reduction, not a solution for arbitrary encrypted paths.

## Current feature cycle

The following lower-priority application features are now implemented:

- Lock, log out, or shut down the workstation on a separately persisted schedule.
- GNOME notification suppression with restoration of the prior state.
- Advanced five-minute rule-boundary warning notifications while the GUI runs.
- Deterministic application and website statistics export.
- Optional system tray controls through Ayatana AppIndicator.

The tray launcher requires Ubuntu's
`gir1.2-ayatanaappindicator3-0.1` package because GTK 4 does not provide a
cross-desktop system tray API. Scheduled shutdown remains separate from normal
blocking rules because it can cause data loss.

## Version 1.4

Version 1.4 adds timed allowances and Delay locks as separate controls.
Timed allowances govern automatic permitted browsing time inside an active rule
period. Delay is an explicit, temporary pause requested by the user. Delay does
not change the saved policy.



### Timed allowances

The first implementation supports elapsed-time allowances only for
browser-enforced URL targets:

- `url_path`
- `url_wildcard`
- `url_keyword`
- YouTube video and channel targets

Application, `/etc/hosts` website, network, and mixed-target rules do not
receive timed allowances until the corresponding enforcement layer can provide
a trustworthy foreground-time signal. Existing daily start allowances remain
unchanged and are not reinterpreted as elapsed time.

For a weekly schedule, each concrete period occurrence receives its own
allowance. A period that lists several weekdays therefore has an independent
budget on each weekday. A period with no allowance is strict: it blocks for
the entire active period. Unused time never carries forward.

The initial allowance modes are:

- strict;
- one total duration per period occurrence;
- a rolling refill window, such as 10 minutes in each 60-minute window,
  anchored when matching use begins after the previous window expires.

Rolling windows are scoped to each weekly period occurrence. A rule-level
daily cap is supported as a hard ceiling across all allowance-enabled periods.
It resets at local midnight in the rule's schedule time zone, and the effective
remaining time is the smaller of the applicable period budget and the
remaining daily cap.

Timed allowances reject overlapping weekly periods because the existing
continuous-block behavior cannot identify which independent budget should
consume overlapping time. Allowance usage is measured in elapsed UTC seconds,
while period occurrences and daily reset boundaries are derived from the
schedule's IANA time zone. DST transitions and cross-midnight periods must
remain deterministic.
The Phase 2 pure engine resolves allowance boundaries on the UTC timeline.
Ambiguous local boundary times use their earlier UTC occurrence. A nonexistent
local boundary moves forward through the DST gap to the first representable
local time. Usage reports are half-open intervals; overlapping or retried
reports count once, and time reported after the evaluation instant is ignored.
Budget consumption is rounded up to whole seconds so sub-second reports cannot
grant extra time.


The root service owns the budget. Browser adapters count only the focused
window's active tab while the user is non-idle and the URL matches the
allowance rule. They use short-lived service-issued leases and retry-safe
reports so multiple browser clients cannot independently spend the same
remaining budget. Browser-extension tampering remains outside the existing
extension protection boundary.
The Phase 3 service ledger stores accepted usage intervals in a separate
signed state file. Browser adapters request leases of up to 30 seconds and
must report an interval inside the issued lease. The service reserves live
leases across all clients, accepts each report ID at most once, persists a
report before re-projecting enforcement, and rejects reports that would
exceed either the active period budget or the daily cap. Expired leases do
not consume budget.


### Delay

A Delay lock has two configured durations:

- a wait duration for the countdown;
- a fixed break duration from 1 minute through 1440 minutes.

The user can request a break only while the locked rule is active. The root
service records the request, keeps the rule enforced during the countdown,
and starts the fixed-duration break automatically when the countdown ends.
Repeated requests return the existing countdown; they cannot reset or shorten
it. Canceling a pending request is allowed because it strengthens
enforcement.

Pending and active break state is root-owned and persisted, so closing the GUI
or restarting the service cannot bypass the Delay. Countdown and expiry use
the trusted-clock behavior already required by finite schedules and timed
locks; an untrusted clock fails closed.

A break applies to the requested rule only. Other rules that match the same
target continue to enforce. A break is a separate manual pause: it does not
refill or modify automatic allowance budgets and is reported separately.
Global breaks are not part of this contract.

Both features are additive policy changes. The existing `allowance_starts`
field and behavior remain compatible. New policy and protected-runtime-state
schema versions must be introduced only with strict migration and capability
checks for browser adapters that understand timed allowances and break
overrides.

These contracts define the Version 1.4 behavior. Any change to target scope,
overlap handling, break scope, clock behavior, or allowance accounting requires
updating this contract before source changes.


## Version 1.5 — Block List import fidelity

Version 1.5 expands Block List migration without silently weakening the
imported policy. The importer remains capability-based and loss-aware: every
source entry ends in exactly one of these outcomes:

- an equivalent Distraction Blocker target or rule;
- an explicit unsupported issue; or
- an explicit user-supplied mapping.

No parser path may silently discard a source setting.

### Import contract

`BlockListIssue` and the preview contract gain stable issue categories:

- `format`;
- `target`;
- `schedule`;
- `lock`;
- `break`;
- `application`;
- `user_scope`; and
- `policy_capability`.

Each issue retains the source JSON path and source text. The CLI preview
reports accepted, transformed, unsupported, and duplicate counts. `--apply`
validates and stages the complete import atomically. Imported rules remain
disabled unless `--enable` is supplied.

The importer reuses `Target.from_dict` and `Rule` validation; it does not
introduce a parallel target schema. The compatibility matrix is:

| Block List entry | Automatic result |
| --- | --- |
| Exact hostname | `website` target |
| Exact `host/path` | `url_path` target |
| Importer's bounded trailing-star form | `url_wildcard` target |
| Recognized keyword form | `url_keyword` target |
| Recognized YouTube video or channel form | Existing YouTube target kind |
| URL exceptions | `Rule.exceptions`, only when every exception is URL-level |
| Canonical whole-internet entry | Closed `network` target value `whole_internet`, subject to capability check |
| Any other wildcard, path, exception, application, lock, break, user, or unknown form | Explicit issue retaining its source path and text |

The canonical whole-internet entry is recognized only as the closed `network`
target value `whole_internet`. The preview marks it as requiring separately
installed network controls, and application is refused with a specific
`policy_capability` issue when the protected-user network opt-in is
unavailable. An arbitrary wildcard is never translated into whole-internet
blocking.

### Exact schedules and assisted migration

Schedule conversion remains exact. Continuous schedules and representable
weekly periods continue to require an explicit IANA time zone. New parser
branches and fixtures are added only for verified Block List schedule
encodings. A source period may be split only when the resulting weekly
periods are provably equivalent; otherwise the source path is retained as an
unrepresentable-schedule issue rather than shortening, extending, or guessing
the period.

Settings that cannot be inferred safely use a second, explicitly assisted
migration phase. A user-provided mapping file maps Block List application
identifiers to absolute Linux executable paths. Missing, invalid, duplicate,
or conflicting mappings remain preview issues. Linux paths, user scope, and
lock strength are never inferred from names. Lock and break settings enter
the review flow and map only to an existing equivalent lock or allowance
contract.

Block List user targeting remains outside automatic import while the
one-owner policy boundary and unresolved multi-user decisions remain in force.
The preview states that such entries were not imported. The compatibility
examples remain part of this contract.

## Version 1.6 — Local DNS hostname backend

Version 1.6 implements an opt-in local DNS backend for protected-user
hostname enforcement. `local_dns` is a new closed network-control token, not
an arbitrary firewall or resolver-configuration input. It uses the existing
installer risk acknowledgement and is not required for existing `/etc/hosts`
operation.

### Resolver ownership and semantics

The dedicated resolver is generalized rather than duplicated. It reuses
`NetworkEnforcer`'s owned `dnsmasq` unit, resolver-configuration ownership
marker, loopback listeners (`127.0.0.54` and `::1` on port `1053`), upstream
`127.0.0.53`, SafeSearch mappings, resolver health probes, drift repair, and
fail-closed fence behavior.

The resolver projection has these exact semantics:

- Active exact `website` targets and expanded managed-list domains are locally
  authoritative and return the same deterministic sink result for A and AAAA
  lookups.
- Non-blocked names forward through the trusted systemd-resolved stub.
- SafeSearch source names continue to return only their enforced A records;
  unfiltered AAAA, SVCB, and HTTPS answers are not exposed.
- URL paths, keywords, browser exceptions, and application paths remain
  outside DNS and continue through their existing enforcement layers.

Selecting `local_dns` contributes both loopback port-53 redirection to the
owned resolver and non-local TCP/UDP port-53 and 853 restrictions. Known-DoH,
proxy, and VPN controls remain additive and independently selectable.
Arbitrary encrypted DNS and tunnels remain outside the guarantee.

### Reconciliation, rollback, and product integration

The service reconciliation boundary supplies the active website and
managed-list projection to the resolver before installing a new redirect. It
generates the complete owned configuration atomically, validates it with the
installed `dnsmasq`, restarts only the owned unit after a changed
configuration, and health-probes blocked, allowed, SafeSearch, A, AAAA, SVCB,
and HTTPS behavior before reporting healthy. A generation or health failure
leaves the stronger existing state in place or installs the protected-user
whole-internet fence; it never exposes a partially generated blocklist.

`/etc/hosts` remains the default backend and rollback path until disposable-VM
acceptance proves parity for exact-hostname blocks, managed-list updates,
schedule transitions, resolver cache and TTL behavior, service restart,
boot-fence recovery, and uninstall. The implementation does not modify
`/etc/resolv.conf`, global `systemd-resolved` configuration, foreign nftables
tables, or foreign resolver assets.

When the backend is enabled, the GUI, CLI status and validation, native policy
schema migration, installer dependency checks, packaging ownership markers,
uninstall/recovery, and network acceptance documentation are updated as one
clean cutover. Network targets remain rejected unless the network opt-in is
available; owned assets are removed only after successful recovery.

**Protected-UID boundary:** enforcement is for the configured protected UID.
Root, other UIDs, applications that bypass the configured resolver path,
cached answers, arbitrary DoH, proxies, VPNs, and direct-address traffic are
not covered. This contract promises neither machine-wide DNS enforcement nor
exhaustive SafeSearch.

## Version 1.8 — Browser and system-level website enforcement

Version 1.8 changes website enforcement to be browser-level by default.
Browser website blocks and browser-expanded managed-list domains are enforced
by the installed browser adapters and show the branded block page for
top-level navigations. Existing `website` and `managed_list` rule targets are
migrated to this browser-level behavior.

System-level website enforcement becomes explicit and opt-in per rule through
the **System-level blocks** section in the rule editor. The system-level
section is disabled while its toggle is off, but its configured entries remain
stored so toggling the section does not delete policy.

### Policy scope and precedence

The normal block-target box contains browser-level targets:

- exact website hostnames, matching every path on that exact hostname;
- managed-list contents expanded into browser website targets;
- URL paths and bounded URL wildcards;
- URL keywords; and
- YouTube video and channel targets.

The rule editor adds a **System-level blocks** box below **Application
Blocks**. Its toggle controls whether the rule's `system_targets` contribute
to root enforcement. `system_targets` are restricted to:

- exact website hostnames; and
- managed-list references.

URL paths, keywords, YouTube targets, browser exceptions, and applications
cannot be represented by the existing system hosts layer. Applications remain
system-level independently of this toggle.

When the system toggle is off, only browser-level targets apply. When it is
on, active `system_targets` are projected through the root service's existing
system enforcement. A system-level block takes precedence over a browser
block because hostname resolution or system enforcement can prevent the
browser request from reaching the extension. A browser exception can never
override an active system-level block.

The system-level explainer must state that system blocks normally produce a
DNS or connection failure rather than the branded browser page. Browser-only
mode is the default; it does not provide coverage when the extension is
disabled, absent, or bypassed.

### Browser block exceptions

The editor section currently named **Block exceptions** is renamed
**Browser Block exceptions**. Its entries remain URL-level, browser-only
allows. They may allow a URL inside a browser-level website or URL block, but
they do not weaken `system_targets`, application enforcement, or network
controls.

### Managed-list import behavior

Managed lists are imported into the target box as their normalized contents,
not as a visible `[Managed List] Name` target row. Selecting a list adds each
website/domain in that list as an individual browser-level domain entry.
Deselecting the list removes the domains contributed by that list from the
box. Entries shared by another selected source remain because the target box
represents a deduplicated union; provenance is retained so removal is
deterministic.

The visible editor representation is flattened, while policy storage may
retain compact list provenance and a canonical expansion so large lists do
not duplicate their full source data in every rule. The browser projection
must build and install the complete effective domain set atomically. It must
never silently drop entries, partially apply a list, or fall back to
system-level enforcement when an adapter cannot accept the complete
projection.

Managed-list selection is an explicit import operation. Editing a managed
list does not silently mutate an already saved rule; refreshing a rule's
contents requires an explicit reimport or refresh action. A refresh replaces
the list-owned contribution atomically and preserves separately authored
browser targets.

Expanded managed-list domains are browser targets and may participate in the
same elapsed-time allowance contract as other browser website/URL targets.
The allowance is shared by the rule's matching browser targets unless a later
contract defines per-domain budgets. System-level targets, applications, and
network controls remain ineligible for elapsed-time allowances.

### Migration and schema

The policy schema gains explicit `system_targets` and the per-rule system
blocking state. Existing `website` and `managed_list` targets migrate to the
browser target collection, and existing root hosts entries are removed by
normal reconciliation. New rules default to browser-only with no
`system_targets`.

Native import/export, GUI editing, CLI summaries, browser projections, and
statistics retain one strict schema contract. Migration must preserve target
names, schedules, locks, and browser exceptions while making the website
scope change explicit in preview and status output. A system toggle change is
atomic with the rule update; failure must not leave a stale system block
active or partially install a new one.

These rules define the Version 1.8 scope. Any change to target placement,
managed-list refresh behavior, system precedence, allowance eligibility, or
browser capacity handling requires updating this contract before source
changes.

## Dependency and release order

The two tracks share a strict release order:

1. Land Block List URL-target mappings only after the existing model, service
   projection, native-messaging/browser adapters, and both browser conformance
   suites remain on one schema contract. The extension's existing
   `url_path`, `url_wildcard`, `url_keyword`, YouTube, and exception support is
   the reusable implementation seam.
2. Land whole-internet import recognition only after the `whole_internet`
   network target can be capability-checked through the service and the
   installer's explicit network opt-in. Import must not create a policy the
   host cannot enforce.
3. Version 1.6's local DNS backend is implemented behind the existing
   SafeSearch resolver and nftables ownership/recovery contract. Keep
   `/etc/hosts` through the full disposable-VM matrix; only after it passes
   may local DNS become the recommended backend for large managed lists.

Timed elapsed allowances remain browser-only. They are not attached to DNS or
mixed-target rules unless a later contract defines a trustworthy DNS usage
signal. Multi-user private-policy work remains blocked on the written design
decisions.

## Sources

- HaGeZi DNS block lists: https://github.com/hagezi/dns-blocklists
