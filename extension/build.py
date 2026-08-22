#!/usr/bin/env python3
"""Sync the shared extension core into each browser adapter directory.

Browser extensions cannot reference files outside their own root, so the
core module is copied into every target. The copy must be byte-identical;
tests/test_extension_build.py asserts that, making core drift a build
failure instead of a review hope.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
CORE_FILES = sorted((ROOT / "core").glob("*.js"))
TARGETS = ("firefox", "chromium")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync(target: str) -> None:
    destination = ROOT / target / "core"
    destination.mkdir(parents=True, exist_ok=True)
    for source in CORE_FILES:
        shutil.copyfile(source, destination / source.name)


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
                if not destination.exists() or digest(destination) != digest(source):
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
