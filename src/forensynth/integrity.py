"""Verify locally generated run manifests without following unsafe paths."""

import json
import re
from pathlib import Path

from .evidence import sha256


def verify_run(directory):
    root = Path(directory).resolve(strict=True)
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Manifest must be a regular local file")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("Manifest must contain file hashes")
    failures = []
    for name, expected in manifest.items():
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            or ":" in name
        ):
            raise ValueError("Unsafe path in manifest")
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("Invalid SHA-256 checksum in manifest")
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
            failures.append(name)
        elif sha256(path) != expected:
            failures.append(name)
    if failures:
        raise ValueError("Checksum mismatch or missing file: " + ", ".join(failures))
    return len(manifest)
