# Distraction Blocker

Distraction Blocker is an Ubuntu desktop application. It blocks exact website hostnames and application executable paths.

The application uses a native GTK 4 interface. A root-owned systemd service applies each active rule.

## Functions

Each rule supports one or more website and application targets. Each rule uses one schedule type:

- One time: The rule has one UTC start and end.
- Weekly: The rule uses weekdays, local times, and one IANA time zone.
- Indefinite: The rule stays active until the user disables it.

A weekly period can cross midnight. An active finite rule cannot lose targets, stop early, or become disabled.

The service continues after the GUI closes. The service starts during the Ubuntu boot process.

## Limits

Website rules block exact hostnames through `/etc/hosts`. They apply only to clients that use the Ubuntu system hosts lookup.
A client can bypass this block with another DNS resolver, a proxy, or a direct address. URL paths and unlisted subdomains are not blocked.

Application rules block the resolved executable path through Linux fanotify. A copied executable has a different path and needs a separate target.

Script targets and interpreter data files have Linux enforcement limits. Select the interpreter executable when that target is correct.

The protection boundary is the configured normal user. Root can stop the service, replace files, change policy state, or boot another system.

The service detects wall-clock jumps while it runs. A detected jump sets a persistent latch and activates all enabled finite rules.

Root recovery must correct the clock and protected state. An offline RTC change before service startup is outside the protection boundary.

A fanotify listener failure or queue overflow can permit an execution. The service reports this state as unhealthy and rejects policy changes.

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

## Use

1. Select **Add rule**.
2. Enter a rule name.
3. Enter each exact website hostname on a separate line.
4. Select each application executable.
5. Select a schedule type.
6. Enter the schedule values.
7. Select **Save rule**.

Disable an indefinite rule before you delete it. Wait for an active finite rule to end before you weaken or delete it.

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

The first phase checks website and executable blocks. It also checks GUI exit, time tampering, policy tampering, and service restart.

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
