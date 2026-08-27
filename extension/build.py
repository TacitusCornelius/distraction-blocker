#!/usr/bin/env python3
"""Sync the shared extension core into each browser adapter directory.

Browser extensions cannot reference files outside their own root, so the
core module is copied into every adapter. The copies must match:

- Chromium keeps ES modules verbatim; its service worker imports them.
- Firefox ships an MV2 persistent background (Gecko does not start MV3
  event pages reliably), so its copies are compiled to classic scripts:
  ``import`` lines are dropped and ``export`` markers are stripped. The
  manifest lists the files before ``background.js``, and classic scripts
  share one scope, so the names resolve as globals.

tests/test_extension_build.py asserts both contracts, making drift a
build failure instead of a review hope.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
CORE_FILES = sorted((ROOT / "core").glob("*.js"))
TARGETS = ("firefox", "chromium")


def to_classic(source_text: str) -> str:
    """Compile one ES module to a classic shared-scope script."""
    lines = []
    for line in source_text.splitlines():
        if line.startswith("import "):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        lines.append(line)
    return "\n".join(lines) + "\n"


def expected_text(target: str, source_path: Path) -> str:
    source_text = source_path.read_text()
    if target == "firefox":
        return to_classic(source_text)
    return source_text


def sync(target: str) -> None:
    destination = ROOT / target / "core"
    destination.mkdir(parents=True, exist_ok=True)
    for source in CORE_FILES:
        (destination / source.name).write_text(expected_text(target, source))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail instead of writing when copies are stale")
    args = parser.parse_args()

    failures = []
    synced = []
    for target in TARGETS:
        if not (ROOT / target / "manifest.json").is_file():
            continue  # adapter not started yet; nothing to keep in sync
        for source in CORE_FILES:
            destination = ROOT / target / "core" / source.name
            if args.check:
                if (not destination.exists()
                        or destination.read_text() != expected_text(target, source)):
                    failures.append(f"{target}/core/{source.name} is stale")
            else:
                sync(target)
        synced.append(target)

    if args.check and failures:
        for failure in failures:
            print(f"STALE: {failure}")
        print("Run: python3 extension/build.py")
        return 1
    print("core synced:", ", ".join(synced))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
