"""Create/verify SHA-256 checksums for a desktop build using only Python stdlib."""

import argparse
import hashlib
import re
from pathlib import Path, PurePosixPath


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def checksums(root, verify=False):
    root = Path(root).resolve(strict=True)
    manifest = root / "SHA256SUMS"
    if verify:
        if manifest.is_symlink():
            raise ValueError("Checksum manifest cannot be a symlink")
        seen = set()
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
            if not match:
                raise ValueError("Malformed checksum entry")
            expected, name = match.groups()
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or ":" in name or "\\" in name:
                raise ValueError("Unsafe path in checksum entry")
            path = root.joinpath(*relative.parts)
            if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
                raise ValueError(f"Unsafe or missing build file: {name}")
            if digest(path) != expected:
                raise ValueError(f"Checksum mismatch: {name}")
            if name in seen:
                raise ValueError("Duplicate checksum entry")
            seen.add(name)
        actual = {
            p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p != manifest
        }
        if not seen or seen != actual:
            raise ValueError("Checksum manifest does not cover all build files")
        return len(seen)
    paths = sorted(p for p in root.rglob("*") if p.is_file() and p != manifest)
    if not paths:
        raise ValueError("Build directory contains no files")
    if any(p.is_symlink() for p in paths):
        raise ValueError("Build files cannot be symlinks")
    manifest.write_text(
        "".join(f"{digest(p)}  {p.relative_to(root).as_posix()}\n" for p in paths), encoding="utf-8"
    )
    return len(paths)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    print(f"Files checked: {checksums(args.directory, args.verify)}")
