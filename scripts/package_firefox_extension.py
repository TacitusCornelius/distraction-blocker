#!/usr/bin/env python3
"""Build a deterministic Firefox XPI for AMO signing or self-distribution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "extension" / "firefox"


def read_manifest(source: Path) -> dict:
    manifest_path = source / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot read {manifest_path}: {error}") from error
    if not isinstance(manifest, dict):
        raise RuntimeError("Firefox manifest must be a JSON object")
    browser_specific = manifest.get("browser_specific_settings", {})
    gecko = (
        browser_specific.get("gecko", {})
        if isinstance(browser_specific, dict)
        else {}
    )
    if (
        manifest.get("manifest_version") not in (2, 3)
        or not isinstance(manifest.get("name"), str)
        or not isinstance(manifest.get("version"), str)
        or not isinstance(gecko, dict)
        or not isinstance(gecko.get("id"), str)
        or not gecko["id"]
    ):
        raise RuntimeError(
            "Firefox manifest must declare a valid MV2/MV3 name, version, and Gecko ID"
        )
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", manifest["version"]):
        raise RuntimeError("Firefox manifest version is not numeric")
    return manifest


def package(source: Path, output: Path) -> None:
    source = source.resolve()
    output = output.resolve()
    manifest = read_manifest(source)
    build_check = subprocess.run(
        [sys.executable, str(source.parent / "build.py"), "--check"],
        cwd=ROOT,
        check=False,
    )
    if build_check.returncode:
        raise RuntimeError("extension core copies are stale")
    if not source.is_dir():
        raise RuntimeError(f"extension source is not a directory: {source}")
    if output.is_relative_to(source):
        raise RuntimeError("output archive must be outside the extension source")
    files = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"extension contains a symlink: {path}")
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.name == ".DS_Store":
            continue
        files.append(path)
    names = {path.relative_to(source).as_posix() for path in files}
    required = {"manifest.json", "background.js", "status.html"}
    if not required <= names:
        raise RuntimeError(
            "extension archive is missing: "
            + ", ".join(sorted(required - names))
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in files:
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    print(
        f"created {output} ({manifest['name']} {manifest['version']}); "
        f"Gecko ID {manifest['browser_specific_settings']['gecko']['id']}; "
        "unsigned XPI for AMO submission"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=EXTENSION,
        help="Firefox extension directory (default: extension/firefox)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="XPI path (default: dist/distraction-blocker-firefox-VERSION.xpi)",
    )
    args = parser.parse_args()
    source = args.source.resolve()
    manifest = read_manifest(source)
    output = args.output
    if output is None:
        output = ROOT / "dist" / (
            f"distraction-blocker-firefox-{manifest['version']}.xpi"
        )
    try:
        package(source, output)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
