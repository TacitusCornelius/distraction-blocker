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

An active finite rule cannot lose targets, stop early, or become disabled.

The service continues after the GUI closes. The service starts during the Ubuntu boot process.

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

Locks and statistics stay outside portable policy exports. The root service remains the policy authority.


## Version 1.2

Version 1.2 adds these functions:

- Managed domain lists with bounded, staged service imports.
- Five offline starter categories.
- Up to 16 weekly periods in one rule.
- Quick focus timers that copy targets from an existing rule.
- A daily schedule overview in the system time zone.
- Start and end notifications while the GUI runs.
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

## Install

CAUTION: Get approval before you run these commands. Installation uses root access and changes `/etc/hosts` during active website rules.

Run the installer from the repository. Replace `1000` with the UID from `id -u` for the protected desktop user.

```bash
sudo python3 scripts/install.py --confirm --owner-uid 1000
```

The installer copies root-owned code to `/usr/lib/distraction-blocker`. It installs and starts `distraction-blocker.service`.

Open **Distraction Blocker** from the Ubuntu application menu. You can also run the installed GUI directly:

```bash
/usr/bin/python3 -I /usr/lib/distraction-blocker/gui_entry.py gui
```

The installer also adds the public client at `/usr/local/bin/distraction-blocker`.

### Command-line client

The client uses the same owner-checked Unix socket as the GUI. It never reads protected files.

Run a command:

```bash
distraction-blocker status
distraction-blocker rules
distraction-blocker managed-lists
distraction-blocker today
distraction-blocker focus RULE_ID 30
distraction-blocker stats
```

Rule commands are `enable`, `disable`, and `delete`.

Lock commands are `lock-timed`, `lock-friction`, `lock-password`, `clear-lock`, and `authorize`.

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
7. Select **Save rule**.

Disable an indefinite rule before you delete it. Wait for an active finite rule to end before you weaken or delete it.

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

Each direct domain import file has a 4 MiB limit. Normal service messages keep the 65,536-byte limit.

Use a managed list for a large HaGeZi file.

### Managed lists and starter categories

Select **Managed lists** to import a large domain file or install a starter category.

Each list shows its source, data version, license note, import time, and domain count.

The service receives list entries in chunks of 200 domains. It commits the complete list in one signed policy update.

Select a managed list in the rule editor to use it as a rule target. A list can be the rule's only target.

The starter categories cover social media, games, shopping, streaming media, and adult content.

These are small starter sets. Website blocking remains exact-hostname blocking.

### Multiple weekly periods

Select **Weekly**, then select **Add period** for each additional period.

Each period has its own weekdays, start time, and end time. One rule can contain up to 16 periods.

### Quick focus

Select **Quick focus**. Select a source rule and a duration.

The GUI copies the source targets into an immediate one-time rule. The available durations are 15, 30, 60, and 120 minutes.

You can also enter a custom number of minutes.

### Rule locks

Select **Lock** on a rule. Select a timed, friction, or password lock.

A timed lock cannot be shortened before its UTC expiry. An untrusted clock keeps it effective.

A friction lock shows random text. Select **Authorize**, then type that text exactly.

A password lock stores only a root-owned scrypt hash. Select **Authorize**, then enter the hidden password.

Friction and password authorization permit one weakening change for 60 seconds. The grant is memory-only and single-use.

Failed password attempts add a persisted delay. The delay increases to a maximum of 64 seconds.

Root remains outside the lock boundary and can recover protected state.

### Pomodoro schedules

Select **Pomodoro** in the rule editor. Set the start, work minutes, break minutes, and cycle count.

The service blocks during work and permits each break. The UTC start keeps the phase stable after GUI exit and reboot.

### Application denial statistics

Select **Denial statistics** to see blocked application starts.

Each row shows the path, count, first time, last time, and applicable rule IDs.

The service stores at most 256 paths. A bounded queue reports events that it must drop.

Select **Clear statistics** only when you no longer need this observational data.

### Daily overview and notifications

Select **Daily overview** to see today's enabled intervals in the system time zone.

While the GUI runs, it checks the service every 15 seconds. It sends a desktop notification when it observes a rule start or end.

Notification failure does not change enforcement.

### Export domains

Select **Export domains** to export all rule domains. Select **Export** on one rule to export only that rule.

The output uses UTF-8. It contains one normalized domain on each line in alphabetical order.

### Native backup

Select **Export backup** to write the complete policy to a versioned JSON file.

Select **Import backup** to replace inactive policy state from that file. The service validates the complete file before one signed update.

The service refuses a native import that removes or weakens an active rule or active managed list.

Version 2 backups include rules, managed-list metadata, and managed-list domains. Native backup files have an 8 MiB limit.

Native backups exclude locks, password hashes, attempt state, denial statistics, the HMAC key, policy signature, clock state, and socket data.

### Duplicate, search, and filter

Select **Duplicate** to create a disabled copy of a rule. The copy gets a new identity and the name suffix `copy`.

Use the search box to find text in rule names and targets.

Use the state selector to show all, active, inactive, enabled, or disabled rules.


## Clock recovery

Correct the Ubuntu clock before you clear a clock-tamper latch. Make sure that systemd reports synchronized time.

Run the root recovery command:

```bash
sudo python3 scripts/recover_clock.py --confirm
```

The service refuses recovery when wall time does not match its boot-time clock.

## Ubuntu virtual-machine acceptance

WARNING: Run this procedure only in a disposable Ubuntu virtual machine. The script installs a root service, changes time, changes `/etc/hosts`, and restarts the machine.

Create the test marker. Replace `1000` with the UID of the test desktop user.

```bash
printf '{"purpose":"distraction-blocker-acceptance","owner_uid":1000}\n' | sudo install -o root -g root -m 0600 /dev/stdin /etc/distraction-blocker-test-vm
```

Run the acceptance script as root:

```bash
sudo python3 scripts/ubuntu_acceptance.py
```

The first phase checks direct and managed website blocks, multiple weekly periods, executable blocking, GUI exit, time tampering, policy tampering, and service restart.

The virtual machine then restarts. Run the same command again to check boot persistence and remove the test installation.

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
