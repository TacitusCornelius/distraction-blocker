"""Command entry points for Distraction Blocker."""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Run GUI, service, or the public socket-only CLI."""
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "service":
        # Breadcrumb for reviewers: Keep optional imports in their command
        # branch. The service path does not import GTK or the CLI.
        from .service import main as service_main

        return service_main(argv=values[1:])
    if values and values[0] == "gui":
        from .gui import GtkUnavailableError, run_gui

        try:
            return run_gui()
        except GtkUnavailableError as error:
            print(str(error), file=sys.stderr)
            return 1

    from .cli import main as cli_main

    return cli_main(values)

if __name__ == "__main__":
    raise SystemExit(main())
