"""Command entry points for Distraction Blocker."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m distraction_blocker")
    parser.add_argument("command", choices=("gui", "service"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected package command."""
    arguments = _parser().parse_args(argv)

    # Breadcrumb for reviewers: Keep each import in its command branch. The
    # service must start on systems that do not have the optional GTK binding.
    if arguments.command == "service":
        from .service import main as service_main

        return service_main(argv=[])

    from .gui import GtkUnavailableError, run_gui

    try:
        return run_gui()
    except GtkUnavailableError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
