#!/usr/bin/env python3
"""Stage previously approved endpoint vendor binaries for the local Docker lab.

No downloads, automatic SHA approvals, or security-key changes. Use only after
independently verifying publisher signatures and obtaining approved hash pins.
The manifest is published last so incomplete copies fail the gateway checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

REQUIRED = {
    "windows": ("TuranSec-Agent-Setup.exe", "ClamAV.zip", "Sysmon64.exe"),
    "linux": ("TuranSec-Agent-Setup", "ClamAV.deb", "SysmonForLinux.deb"),
}
MAX_SIZE = 300 * 1024 * 1024
MAX_MANIFEST = 16 * 1024
CHUNK = 1024 * 1024


def regular(path: Path, limit: int) -> os.stat_result:
    entry = path.lstat()
    if not stat.S_ISREG(entry.st_mode) or not 0 < entry.st_size <= limit:
        raise ValueError(f"Not a regular approved file or invalid size: {path.name}")
    return entry


def source_manifest(path: Path, platform: str) -> tuple[bytes, dict[str, str]]:
    regular(path, MAX_MANIFEST)
    with path.open("rb") as source:
        raw = source.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ValueError("Approval manifest is oversized")
    data = json.loads(raw)
    records = data.get("files") if isinstance(data, dict) else None
    names = REQUIRED[platform]
    if not isinstance(records, list) or len(records) != len(names):
        raise ValueError("Approval manifest must contain exactly three file hashes")
    pins: dict[str, str] = {}
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("Malformed approval record")
        name, digest = item.get("name"), item.get("sha256")
        if name not in names or name in pins or not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("Missing, duplicate, or invalid approved SHA-256")
        pins[name] = digest.lower()
    if set(pins) != set(names):
        raise ValueError("Approval manifest is missing a required component")
    output = json.dumps({"files": [{"name":name, "sha256":pins[name]} for name in names]},
                        separators=(",", ":")).encode() + b"\n"
    return output, pins


def verified_copy(source: Path, dest: Path, expected_sha: str) -> None:
    entry = regular(source, MAX_SIZE)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(source, flags)
    try:
        opened = os.fstat(fd)
        if not os.path.samestat(entry, opened):
            raise ValueError(f"Source changed during verification: {source.name}")
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(fd, "rb", closefd=False) as incoming, dest.open("xb") as out:
            os.chmod(dest, 0o600)
            while True:
                block = incoming.read(CHUNK)
                if not block:
                    break
                count += len(block)
                if count > MAX_SIZE:
                    raise ValueError("Payload size exceeded while streaming")
                digest.update(block)
                out.write(block)
        if count != entry.st_size or digest.hexdigest() != expected_sha:
            raise ValueError(f"Approved SHA-256 mismatch: {source.name}")
    finally:
        os.close(fd)


def stage(platform: str, source_dir: Path, manifest_path: Path, replace: bool) -> None:
    cwd = Path.cwd()
    runtime = cwd / ".docker-local" / "runtime" / "edrd.json"
    if not runtime.is_file() or runtime.is_symlink() or runtime.stat().st_uid != os.geteuid():
        raise ValueError("Run as the owner of an initialized TuranSec lab (without sudo)")
    source_dir = source_dir.absolute()
    manifest_path = manifest_path.absolute()
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise ValueError("A regular approved source directory is required")
    canonical_manifest, pins = source_manifest(manifest_path, platform)
    payload_root = cwd / ".docker-local" / "payloads"
    target = payload_root / platform
    if not payload_root.is_dir() or payload_root.is_symlink():
        raise ValueError("Lab payload root missing or a symbolic link")
    if target.is_symlink():
        raise ValueError("Refusing symbolic-linked destination directory")
    target.mkdir(mode=0o700, exist_ok=True)
    if target.stat().st_uid != os.geteuid():
        raise ValueError("Destination owned by another user")
    destination_paths = [target / name for name in (*REQUIRED[platform], "approved.json")]
    if not replace and any(path.exists() or path.is_symlink() for path in destination_paths):
        raise ValueError("Approved files already present; explicit --replace required")
    staged = Path(tempfile.mkdtemp(prefix=".staging-", dir=payload_root))
    try:
        for name in REQUIRED[platform]:
            verified_copy(source_dir / name, staged / name, pins[name])
        approved = staged / "approved.json"
        with approved.open("xb") as out:
            out.write(canonical_manifest)
        os.chmod(approved, 0o600)
        # Publish manifest LAST. The generator rejects partially staged sets.
        for name in REQUIRED[platform]:
            os.replace(staged / name, target / name)
        os.replace(approved, target / "approved.json")
    finally:
        shutil.rmtree(staged)
    print(f"Verified {platform} component hashes and staged them as the lab owner.")
    print("In the admin dashboard, click Recheck files, then Download complete 3-in-1 agent.")
    print("SHA-256 matching does not replace independent publisher signature verification.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=sorted(REQUIRED), required=True)
    parser.add_argument("--source-dir", type=Path, required=True,
                        help="Absolute directory with three independently approved vendor files")
    parser.add_argument("--manifest", type=Path, required=True,
                        help="Absolute JSON file with independently verified SHA-256 approvals")
    parser.add_argument("--replace", action="store_true", help="Replace previously staged binaries")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run as the lab owner, not root")
    if not args.source_dir.is_absolute() or not args.manifest.is_absolute():
        parser.error("--source-dir and --manifest must be absolute paths")
    try:
        stage(args.platform, args.source_dir, args.manifest, args.replace)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"Staging refused: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
