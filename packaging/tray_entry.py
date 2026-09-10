#!/usr/bin/python3
"""Run the optional system tray client from its fixed root-owned path."""

from __future__ import annotations

import sys

INSTALL_ROOT = "/usr/lib/distraction-blocker"
sys.path.insert(0, INSTALL_ROOT)

from distraction_blocker.__main__ import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["tray"]))
