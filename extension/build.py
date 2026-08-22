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
CORE = ROOT / "core" / "engine.js"
TARGETS = ("firefox", "chromium")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync(target: str) -> Path:
    destination = ROOT / target / "core"
    destination.mkdir(parents=True, exist_ok=True)
    copied = destination / "engine.js"
    shutil.copyfile(CORE, copied)
    return copied


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
        destination = ROOT / target / "core" / "engine.js"
        if args.check:
            if not destination.exists() or digest(destination) != digest(CORE):
                failures.append(f"{target}/core/engine.js is stale")
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
