#!/usr/bin/env python3
"""Build a deterministic Chromium extension archive for Web Store upload."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "extension" / "chromium"


def read_manifest(source: Path) -> dict:
    manifest_path = source / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot read {manifest_path}: {error}") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("manifest_version") != 3
        or not isinstance(manifest.get("name"), str)
        or not isinstance(manifest.get("version"), str)
        or not isinstance(manifest.get("key"), str)
    ):
        raise RuntimeError(
            "Chromium manifest must be MV3 with name, version, and key"
        )
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", manifest["version"]):
        raise RuntimeError("Chromium manifest version is not numeric")
    return manifest

def extension_id(manifest: dict) -> str:
    try:
        public_key = base64.b64decode(manifest["key"], validate=True)
    except (ValueError, TypeError) as error:
        raise RuntimeError("Chromium manifest key is not valid base64") from error
    if not public_key:
        raise RuntimeError("Chromium manifest key is empty")
    digest = hashlib.sha256(public_key).hexdigest()[:32]
    return "".join(chr(ord("a") + int(digit, 16)) for digit in digest)



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
            contents = path.read_bytes()
            if relative == "manifest.json":
                upload_manifest = dict(manifest)
                upload_manifest.pop("key")
                contents = (
                    json.dumps(upload_manifest, indent=2, ensure_ascii=False) + "\n"
                ).encode("utf-8")
            archive.writestr(info, contents)
    print(
        f"created {output} ({manifest['name']} {manifest['version']}); "
        f"local development extension id {extension_id(manifest)}; "
        "manifest key omitted for Web Store upload"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=EXTENSION,
        help="Chromium extension directory (default: extension/chromium)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="archive path (default: dist/distraction-blocker-chromium-VERSION.zip)",
    )
    args = parser.parse_args()
    source = args.source.resolve()
    manifest = read_manifest(source)
    output = args.output
    if output is None:
        output = ROOT / "dist" / (
            f"distraction-blocker-chromium-{manifest['version']}.zip"
        )
    try:
        package(source, output)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
