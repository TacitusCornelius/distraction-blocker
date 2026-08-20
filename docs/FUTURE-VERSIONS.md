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

The file at `/home/tacitus/Documents/blocklists/qwit-starter-blocklist.txt` contains Block List JSON data. It is not a plain domain list.

The inspected file lacks its final outer `}` character. A strict parser must refuse it. The application must not repair malformed input without an explicit user action.

A temporary in-memory inspection found:

- 13 blocks.
- 153 website entries.
- 118 exact hostname candidates.
- 35 wildcard or URL-path entries.
- 10 Windows executable or window-title entries.
- 1 scheduled block.

A future Block List importer can accept exact hostnames. It must report every unsupported entry.

The current service cannot reproduce these Block List features:

- URL-path rules.
- Wildcard URL rules.
- Whole-internet rules.
- Website exceptions.
- Windows application identifiers.
- Window-title rules.
- Allowances, breaks, and delay locks.

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

- Five small offline starter categories.
- Up to 16 weekly periods for one rule.
- Quick focus timers that copy existing rule targets.
- Start and end notifications while the GUI runs.
- A daily schedule overview in the system time zone.

Notifications only report observed state. They never control enforcement.

## Version 1.3

Version 1.3 can add stricter sessions and activity features.

- Timed edit locks.
- Password locks with root-owned password hashes.
- Random-text friction locks.
- Pomodoro work and break periods.
- Application denial statistics.
- Public command-line client.
- Multi-user policy research.

Random text adds friction. It is not a security boundary.

Usage-based allowances need foreground activity data. A fixed manual timer does not prove that the user viewed a blocked item.

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

The root service must remain the final policy authority.

## Privileged network version

These features need a separate security review and explicit installation approval:

- Whole-internet blocking.
- Alternate DNS resolver blocking.
- DNS-over-HTTPS blocking.
- Proxy and VPN endpoint blocking.
- Safe-search enforcement.

These controls can break unrelated network access. They require privileged DNS or firewall changes.

## Other Block List features

These features remain possible but have lower priority:

- Lock, log out, or shut down the workstation on a schedule.
- Block notifications and advanced warning notifications.
- System tray controls.
- Statistics export.

Scheduled shutdown can cause data loss. It must remain separate from normal blocking rules.

GTK 4 does not provide a cross-desktop system tray API. A tray feature can require an additional Ubuntu package.

## Sources

- Block List user guide: https://
- HaGeZi DNS block lists: https://github.com/hagezi/dns-blocklists
