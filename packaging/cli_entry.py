#!/usr/bin/python3
"""Run the installed socket-only CLI from its fixed root-owned path."""

# distraction-blocker-owned-wrapper-v1
from __future__ import annotations

import sys

INSTALL_ROOT = "/usr/lib/distraction-blocker"
sys.path.insert(0, INSTALL_ROOT)

from distraction_blocker.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
