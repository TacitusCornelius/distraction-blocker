# Distraction Blocker

Distraction Blocker is an Ubuntu desktop application. It blocks exact website hostnames and application executable paths.

The application uses a native GTK 4 interface. A root-owned systemd service applies each active rule.

## Functions

Each rule supports website, application, and managed-list targets. Each rule uses one schedule type:

- One time: The rule has one UTC start and end.
- Weekly: The rule has up to 16 local weekly periods and one IANA time zone.
- Pomodoro: The rule alternates work blocks with permitted breaks.
- Indefinite: The rule stays active until the user disables it.

A weekly period can cross midnight. Overlapping periods act as one continuous block.

An active finite rule cannot lose targets or shorten its schedule. An active
unlocked rule can be disabled manually; an effective lock prevents weakening
changes until its condition is satisfied.

The service continues after the GUI closes. The service starts during the Ubuntu boot process.

## Current release

The current root service and Ubuntu application release is **Version 1.8
(v1.8.0)**. Version 1.8 makes browser-level website enforcement the default
and adds explicit, per-rule opt-in system-level website blocks.

The Chrome and Firefox/LibreWolf browser adapters are packaged as **Version
1.9**. They require the root service and native-messaging host described in
[Install](#install).


## Version 1.4

Version 1.4 adds timed allowances and Delay locks for URL-level browser
rules:

- Daily or period-based elapsed-time allowances with service-owned budgets.
- Short-lived service leases and retry-safe browser usage reports.
- Delay locks with persisted countdowns and fixed temporary breaks.

Allowance accounting and Delay state remain outside portable policy exports.
The root service remains the final policy authority.


## Version 1.3

Version 1.3 adds these functions:

- Timed rule locks.
- Random-text friction locks.
- Password locks with root-owned scrypt hashes.
- Persisted password attempt delays.
- Pomodoro work and break schedules.
- Bounded application denial statistics.
- A public socket-only command-line client.
- A multi-user policy research record.

The current feature cycle also adds separately persisted scheduled workstation
actions (lock, log out, and shut down), GNOME notification suppression with
state restoration, advanced rule-boundary warnings, statistics export, and an
optional Ayatana system tray client. Scheduled actions remain separate from
normal blocking rules because shutdown can cause data loss.

Locks and statistics stay outside portable policy exports. The root service remains the policy authority.

### Protected-user network controls

The optional network controls apply only to outbound sockets owned by the
configured protected desktop UID. They are not machine-wide and do not control
root, system daemons, containers, or virtual machines.

The supported controls are:

- **Whole internet:** drops the protected UID's non-loopback IPv4 and IPv6
  output.
- **Alternate DNS:** denies non-local DNS and DNS-over-TLS ports 53 and 853.
- **Local DNS:** redirects the protected UID's DNS through an owned dnsmasq
  resolver. Active website and managed-list hostnames resolve to deterministic
  sink addresses while other names forward through systemd-resolved; remote
  DNS and DNS-over-TLS are denied.
- **SafeSearch:** redirects the protected UID's local DNS port 53 traffic to an
  owned resolver and applies documented Google, Bing, and YouTube mappings.
- **Known DoH endpoints:** denies protected-UID TCP and UDP port 443 traffic
  to the installed static catalog of documented Cloudflare, Google, and Quad9
  public resolver addresses.
- **Common proxy endpoints:** denies protected-UID TCP and UDP traffic to the
  common proxy listener ports 1080, 3128, 8000, 8080, 8118, 8888, 9050, and
  9150.
- **Common VPN endpoints:** denies protected-UID TCP and UDP traffic to common
  VPN transport ports 500, 1194, 1701, 1723, 4500, and 51820, plus GRE and
  ESP packets.

The proxy and VPN controls are transport catalogs, not proxy or VPN
identification. They do not inspect payloads, detect arbitrary ports, or
prevent a local proxy/VPN process from tunnelling under another identity.
Common listener ports and VPN transports can be shared with unrelated
services, so enabling them may cause collateral blocking.

SafeSearch is a resolver-path control. It can enforce the documented mappings
when the protected user's DNS reaches the owned local resolver, but it cannot
distinguish DNS carried inside arbitrary HTTPS, a proxy, or a VPN tunnel from
ordinary traffic at the nftables layer. No exhaustive SafeSearch guarantee is
made for those paths.

Known DoH enforcement is address-based. It does not inspect hostnames, SNI,
HTTP paths, or encrypted payloads. Because resolver addresses can be shared
with ordinary HTTPS, enabling it can block unrelated traffic to those
addresses. The catalog is release-fresh only; provider address changes are
covered after a catalog update and package release.

SafeSearch does not modify `/etc/resolv.conf` or the global
`systemd-resolved` configuration. Arbitrary DoH endpoints, DoH on other ports,
arbitrary proxies, VPN tunnels, cached answers, and traffic owned by other
UIDs remain outside this scope. These controls are best-effort network policy,
not a guarantee against an administrator or a process using another identity.

Network controls require both explicit installer flags:

```bash
sudo python3 scripts/install.py --confirm --owner-uid 1000 \
  --enable-network-controls --accept-network-risk
```

The installer never installs packages automatically. It requires working
`nftables`, `dnsmasq` 2.86 or newer, and `systemd-resolved`. Installation
creates an early-boot protected-user fence and keeps unrelated nftables tables
and resolver files untouched.

If the service cannot start, recover the owned network state from the VM or
host console:

```bash
sudo python3 scripts/recover_network.py --confirm
```

Recovery removes only the owned nftables table and local DNS/SafeSearch
resolver, disables the boot fence, and removes the network opt-in marker after
cleanup succeeds. The signed policy is preserved.



## Version 1.2

Version 1.2 adds these functions:

- Managed domain lists with bounded, staged service imports.
- Seven offline starter categories, including Video and YouTube.
- Up to 16 weekly periods in one rule.
- Quick focus timers that copy targets from an existing rule.
- A daily schedule overview in the system time zone.
- Per-rule notification controls for rule-state and upcoming-change alerts.
- Native backup version 2 with managed-list data.

The service stores managed-list entries once. Normal service responses show metadata and counts, not the domain entries.

The future-version roadmap is in `docs/FUTURE-VERSIONS.md`.


## Version 1.1

Version 1.1 adds these functions:

- System, light, and dark GUI themes.
- Calendar and time selectors for one-time rules.
- UTF-8 domain-list import with a validation preview.
- Plain domain export.
- Versioned native JSON backup import and export.
- Rule duplication.
- Rule search and state filters.

Version 1.1 remains the first usability and data-portability update.


## Limits

Website rules block exact hostnames through `/etc/hosts`. They apply only to clients that use the Ubuntu system hosts lookup.
A client can bypass this block with another DNS resolver, a proxy, or a direct address. URL paths and unlisted subdomains are not blocked.

Application rules block the resolved executable path through Linux fanotify. A copied executable has a different path and needs a separate target.

Script targets and interpreter data files have Linux enforcement limits. Select the interpreter executable when that target is correct.

The protection boundary is the configured normal user. Root can stop the service, replace files, change policy state, or boot another system.

The service detects wall-clock jumps while it runs. A detected jump sets a persistent latch and activates all enabled finite rules.

Root recovery must correct the clock and protected state. An offline RTC change before service startup is outside the protection boundary.

A fanotify listener failure or queue overflow can permit an execution. The service reports this state as unhealthy and rejects policy changes.

Application denial statistics count denied starts. They do not measure foreground use or time spent in an application.

Random-text entry adds friction only. It is not a security boundary.

## Requirements

Use Ubuntu with systemd, Python 3, GTK 4, `python3-gi`, and a kernel that supports fanotify permission events.

The application has no Python package manifest. It uses the Python standard library and the Ubuntu GTK binding.

## Automated tests

Run the offline unit tests:

```bash
python3 -m unittest discover -s tests
```

These tests do not need root access. They do not change the real hosts file, clock, or systemd state.

## License

Distraction Blocker is released under the Apache License, Version 2.0.
See [`LICENSE`](LICENSE).

## Install

CAUTION: Get approval before you run these commands. Installation uses root access and changes `/etc/hosts` during active website rules.

Run the installer from the repository. Replace `1000` with the UID from `id -u` for the protected desktop user.

```bash
sudo python3 scripts/install.py --confirm --owner-uid 1000
```

The installer copies root-owned code to `/usr/lib/distraction-blocker`. It installs and starts `distraction-blocker.service`.

### Chrome Web Store extension (Version 1.9)

The Chromium adapter is published separately as an unlisted Chrome Web Store
item. The root service and native-messaging host are still required; the
browser extension alone is not a complete installation. Build the Version 1.9
upload archive from the repository root:

```bash
python3 extension/build.py
python3 scripts/package_chromium_extension.py
```

Upload the generated ZIP from `dist/` through the Chrome Developer Dashboard,
choose **Unlisted** for link-only distribution, and install the resulting Web
Store item URL in Chrome. Verify the Dashboard Item ID matches the ID
documented in `CHROMEWEBSTORE.md` before publishing. The full permission,
privacy, identity, and update procedure is in `CHROMEWEBSTORE.md`.

The native host is installed with the normal service installer:

```bash
sudo python3 scripts/install.py --confirm --owner-uid "$(id -u)"
```

Do not use **Load unpacked** as the production installation method.

### Firefox / LibreWolf extension (Version 1.9)

Build the Firefox submission archive from the repository root:

```bash
python3 extension/build.py
python3 scripts/package_firefox_extension.py
```

Submit `dist/distraction-blocker-firefox-1.9.0.xpi` to Mozilla's AMO
self-distribution channel, download the resulting signed XPI, and install that
signed file through the Firefox or LibreWolf Add-ons page. The root service and
native-messaging host are still required; install them with the command above.
The complete AMO, LibreWolf, stable-ID, and update procedure is in
`FIREFOXADDONS.md`.



Open **Distraction Blocker** from the Ubuntu application menu. You can also run the installed GUI directly:

```bash
/usr/bin/python3 -I /usr/lib/distraction-blocker/gui_entry.py gui
```

The installer also adds the public client at `/usr/local/bin/distraction-blocker`.

Run a command:


```bash
distraction-blocker status
distraction-blocker rules
distraction-blocker managed-lists
distraction-blocker managed-lists create --name "My list" \
  --file ~/Downloads/domains.txt
distraction-blocker managed-lists edit LIST_ID \
  --add extra.example --remove old.example
distraction-blocker today
distraction-blocker focus RULE_ID 30
distraction-blocker stats
distraction-blocker stats --export ~/distraction-statistics.json
distraction-blocker actions list
distraction-blocker actions add --kind lock --at "2026-01-01 22:00"
distraction-blocker actions disable ACTION_ID
distraction-blocker notifications block
distraction-blocker import-block-list ~/Downloads/focus.blocklist.json
distraction-blocker import-block-list \
  ~/Downloads/focus.blocklist.json --timezone Europe/London --apply
```

The Block List command first previews accepted exact hostnames and every
unsupported entry. Imported rules are disabled by default; `--apply` stages
the complete import and commits it atomically through the root service, while
`--enable` explicitly enables them.

Scheduled actions accept one-time timestamps or weekly local-time windows.
Use `actions enable ACTION_ID` or `actions disable ACTION_ID` to pause one
without deleting it; `actions remove ACTION_ID` deletes one. In addition to
lock, logout, and shutdown, `--kind notifications` blocks GNOME banners and
lock-screen notifications for the scheduled window and restores the prior
values when the window ends. Shutdown actions require the explicit
`--confirm-shutdown` option.

The optional **Distraction Blocker Tray** launcher provides quick access to the
GUI, per-rule controls, scheduled-action controls, and notification controls.
The installer also registers it for desktop-session autostart. It requires
Ubuntu's `gir1.2-ayatanaappindicator3-0.1` package in addition to
`python3-gi`.


Rule commands are `enable`, `disable`, and `delete`.

Lock commands are `lock-schedule`, `lock-timed`, `lock-delay`, `lock-friction`, `lock-password`, `clear-lock`, `delay-break`, `cancel-delay-break`, and `authorize`.

`lock-delay RULE_ID WAIT_MINUTES BREAK_MINUTES` configures an explicit Delay
countdown and temporary break. `delay-break RULE_ID` requests the break while
the rule is active; `cancel-delay-break RULE_ID` cancels its pending countdown.
The root service persists Delay state and keeps enforcement active during the
countdown.

The password commands read hidden terminal input. A password never appears in a command argument or output.

Add `--json` for one deterministic JSON result:

```bash
distraction-blocker --json status
```

The client returns a nonzero status when validation or the service refuses a request.

## Use

1. Select **Add rule**.
2. Enter a rule name.
3. Enter each exact website hostname on a separate line.
4. Select each application executable.
5. Select a schedule type.
6. Select dates, times, weekly periods, or Pomodoro values.
7. Optionally select **Configure a lock after saving**. The lock setup opens
   immediately after the new rule is saved.
8. Select **Save rule**.

An active rule can be disabled when it is not locked. A locked rule cannot be
disabled until its schedule period ends, its timed lock expires, or its
friction/password authorization is completed. Disable a rule before deleting it.

### One-time date and time selection

Select the start button to open its calendar and time pane. Select a date, hour, and minute.

Select **Apply** to keep the selection. Use the same procedure for the end date and time.

New rules start at the next five-minute boundary. The default end is one hour later.

### Themes

Use the theme selector in the title bar. Select **System**, **Light**, or **Dark**.

The GUI stores this choice in `~/.config/distraction-blocker/preferences.json`.

### Import domains

Select **Import domains** to create a rule from a UTF-8 text file. The importer accepts these rows:

- One domain on each line.
- Blank lines.
- Lines that start with `#`.
- Hosts rows that start with `0.0.0.0`, `127.0.0.1`, or `::`.

Review the accepted, duplicate, ignored, and invalid counts. Then select **Continue** to configure the new rule.

Select **Edit** and **Import domains** to add a file to an existing rule. The service refuses a change that weakens an active rule.

### Managed lists and starter categories

Select **Managed lists** to import a large domain file, create a custom list,
edit an existing roster, or install a starter category.

Each list shows its source, data version, license note, import time, and domain count.
The GUI's **New custom list** and **Edit roster** actions accept one hostname per
line. Saves replace the complete roster atomically through the root service; a
change that weakens an active rule is refused.

The command line has equivalent operations:

```bash
distraction-blocker managed-lists create --name "My list" --file domains.txt
distraction-blocker managed-lists edit LIST_ID \
  --add extra.example --remove old.example
```

The service receives list entries in chunks of 200 domains. It commits the complete list in one signed policy update.

Select a managed list in the rule editor to use it as a rule target. A list can be the rule's only target.


The rule list has separate state and sort controls. Sort options are **Most
recent** (newest policy entries first), **Alphabetical A-Z**, and
**Alphabetical Z-A**.
The starter categories cover social media, games, shopping, streaming media,
Video, YouTube, and adult content. Video and YouTube intentionally overlap.

These are small starter sets. Website blocking remains exact-hostname blocking.


### Multiple weekly periods

Select **Weekly**, then select **Add period** for each additional period.

Each period has its own weekdays, start time, and end time. One rule can contain up to 16 periods.

### Timed allowances

Timed allowances are configured in the **Weekly** section of the rule editor,
directly below the weekly period rows. Select **Enable elapsed-time allowance
for these periods**, then choose a mode for each period:

- **No allowance** keeps that period fully blocked.
- **Total minutes** permits one elapsed-time quota for each period occurrence.
- **Fixed refill window** permits a quota within each repeating window.

You can also set an optional daily timed-allowance ceiling. Timed allowances
require URL-level targets and non-overlapping weekly periods. They cannot be
combined with the separate **Daily start allowance** control above the
schedule.

### Rule locks

Select **Lock** on an existing rule, or select **Configure a lock after
saving** while creating a rule. Choose a schedule, timed, friction, or
password lock. A schedule lock is valid for weekly rules and automatically
protects the rule during each active weekly period.

Locks protect weakening changes: disabling a rule, removing targets, shortening
a schedule, increasing an allowance, or deleting the rule. An active rule that
has no effective lock can be disabled manually.

A schedule lock is effective only while its weekly rule is active. It cannot
be removed or weakened during that active period.

A timed lock cannot be shortened or removed before its UTC expiry. An untrusted
clock keeps it effective.

A friction lock shows random text. Select **Authorize**, then type that text
exactly to authorize one weakening change.

A password lock stores only a root-owned scrypt hash. Select **Authorize**, then
enter the hidden password to authorize one weakening change.

### Per-rule notifications

Each rule can turn notifications on or off independently. When notifications
are on, choose either or both categories:

- **Rule starts and ends** — notify when the observed rule state changes.
- **Upcoming schedule changes** — notify five minutes before the next boundary.

These notifications are generated by the GUI while it is running. They never
control enforcement.


Version 4 backups include the protected-user DoH target in addition to the
network target rules, managed-list metadata, and managed-list domains. Native
backup files have an 8 MiB limit.

Native backups exclude locks, password hashes, attempt state, denial
statistics, the HMAC key, policy signature, clock state, and socket data.

Root remains outside the lock boundary and can recover protected state.

### Pomodoro schedules

Select **Pomodoro** in the rule editor. Set the start, work minutes, break minutes, and cycle count.

The service blocks during work and permits each break. The UTC start keeps the phase stable after GUI exit and reboot.

### Application denial statistics

Select **Denial statistics** to see blocked application starts.

Each row shows the path, count, first time, last time, and applicable rule IDs.

The service stores at most 256 paths. A bounded queue reports events that it must drop.

Select **Clear statistics** only when you no longer need this observational data.

### Duplicate, search, and filter

Select **Duplicate** to create a disabled copy of a rule. The copy gets a
new identity and the name suffix `copy`.

Use the search box to find text in rule names and targets.

Use the state selector to show all, active, inactive, enabled, or disabled
rules.

## Ubuntu virtual-machine acceptance

WARNING: Run these procedures only in a disposable Ubuntu virtual machine.
The scripts install a root service and change firewall, resolver, hosts, and
policy state inside that VM.

Create the test marker. Replace `1000` with the UID of the test desktop user.

```bash
printf '{"purpose":"distraction-blocker-acceptance","owner_uid":1000}\n' | sudo install -o root -g root -m 0600 /dev/stdin /etc/distraction-blocker-test-vm
```

Run the existing policy/browser acceptance:

```bash
sudo python3 scripts/ubuntu_acceptance.py
```

For the opt-in protected-user firewall and local DNS/SafeSearch acceptance,
use:

```bash
sudo python3 scripts/network_acceptance.py
```

The network procedure requires `nftables`, `dnsmasq-base` (version 2.86 or
newer), and active `systemd-resolved`; it refuses to install packages. It
checks IPv4/IPv6 output, existing-flow denial, UID scope, local DNS projection
and forwarding, SafeSearch transitions, resolver metadata records, drift
repair, reboot fence behavior, offline recovery, uninstall, and preservation
of foreign firewall state.




## Clock recovery

Correct the Ubuntu clock before you clear a clock-tamper latch. Make sure that systemd reports synchronized time.

Run the root recovery command:

```bash
sudo python3 scripts/recover_clock.py --confirm
```

The service refuses recovery when wall time does not match its boot-time clock.


## Remove

CAUTION: Get approval before you run this command. Removal stops the service and removes its managed hosts section.

Preserve the signed policy by default:

```bash
sudo python3 scripts/uninstall.py --confirm
```

Remove the signed policy and HMAC key only when that data is no longer needed:

```bash
sudo python3 scripts/uninstall.py --confirm --remove-policy
```
