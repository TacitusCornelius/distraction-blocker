#!/usr/bin/env python3
"""Clear the clock-tamper latch after root corrects system time."""

from __future__ import annotations

import argparse
import os
import sys

INSTALL_ROOT = "/usr/lib/distraction-blocker"


def main() -> int:
    parser = argparse.ArgumentParser(description="Clear the Distraction Blocker clock latch")
    parser.add_argument("--confirm", action="store_true", help="confirm clock recovery")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Clock recovery refused: run as root.", file=sys.stderr)
        return 2
    if not args.confirm:
        print("Clock recovery refused: pass --confirm.", file=sys.stderr)
        return 2
    sys.path.insert(0, INSTALL_ROOT)
    try:
        from distraction_blocker.rpc import Client, RpcError

        result = Client().request("clear_clock_latch")
    except (ImportError, RpcError) as error:
        print(f"Clock recovery refused: {error}", file=sys.stderr)
        return 2
    print(f"Clock trust restored at {result['time_utc']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
