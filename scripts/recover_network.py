#!/usr/bin/env python3
"""Recover Distraction Blocker network state offline.

Use this when the installed service is stuck or cannot start. The
recovery, in order:

1. stops the policy service (a no-op when it is already stopped),
2. removes only the owned nftables table and the dedicated resolver and
   its configuration,
3. disables the boot fence, last, only after every cleanup step succeeded.

The signed policy is preserved, but network enablement is removed after
successful cleanup. The policy service remains stopped. Explicitly opt in
again to resume network enforcement, or uninstall to remove the policy.

Run as root:

    python3 scripts/recover_network.py --confirm
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import NoReturn


def fail(message: str) -> NoReturn:
    print(f"Recovery refused: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recover Distraction Blocker network state offline"
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm network recovery on this host",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        fail("run as root")
    if not args.confirm:
        fail("pass --confirm; this default protects the current host")
    source_root = Path(__file__).resolve().parent.parent
    if source_root == Path("/") or not (source_root / "distraction_blocker").is_dir():
        fail("the source package is missing")
    sys.path.insert(0, str(source_root))
    from distraction_blocker.network_enforcement import main as network_main

    try:
        return network_main(["recover"])
    except OSError as exc:
        fail(f"recovery failed: {exc.strerror or exc}")


if __name__ == "__main__":
    raise SystemExit(main())
