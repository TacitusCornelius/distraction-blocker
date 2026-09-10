#!/usr/bin/python3
"""Run the installed network enforcement CLI from its fixed root-owned path.

Invoked as ``python3 -I /usr/lib/distraction-blocker/network_entry.py`` with
one subcommand:

- ``boot-fence``: install the emergency deny for the protected UID whenever
  the persisted policy carries an active network control.
- ``recover``: stop enforcement, remove only owned network resources, and
  disable the boot fence.

The subcommand reads the protected owner UID from the state directory
itself. Exit status is 0 on success and nonzero on any refusal.
"""

from __future__ import annotations

import sys

INSTALL_ROOT = "/usr/lib/distraction-blocker"
sys.path.insert(0, INSTALL_ROOT)

from distraction_blocker.network_enforcement import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
