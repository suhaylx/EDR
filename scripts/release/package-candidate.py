#!/usr/bin/env python3
"""Build portable candidate bundles and verify detached release signatures.

Unsigned staging is explicit. Release signing requires an external signer and
an independently provisioned public key; no key is generated or self-trusted.
This tool does not install a service or authorize deployment.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checked_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("A full 40-character candidate commit SHA is required")
    return value


def run(command: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    if os.name == "nt" and command[0] == "npm":
        command = [shutil.which("npm.cmd") or "npm.cmd", *command[1:]]
    subprocess.run(command, cwd=cwd, env=env, check=True)


def verify(archive: Path, manifest: Path, signature: Path, trusted_key: Path, expected_sha: str) -> dict:
    checked_sha(expected_sha)
    if not signature.is_file() or signature.stat().st_size == 0:
        raise ValueError("A detached signature from the release signer is required")
    # The caller provisions the trust root independently of the downloaded
    # package. Never discover a public key from the archive or manifest.
    subprocess.run([
        "openssl", "dgst", "-sha256", "-verify", str(trusted_key.resolve()),
        "-signature", str(signature.resolve()), str(manifest.resolve()),
    ], check=True, stdout=subprocess.DEVNULL)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("source_sha") != expected_sha:
        raise ValueError("Release manifest schema or candidate SHA mismatch")
    item = data.get("archive", {})
    if item.get("name") != archive.name or item.get("size") != archive.stat().st_size:
        raise ValueError("Archive name/size differs from the signed manifest")
    if item.get("sha256") != digest(archive):
        raise ValueError("Archive digest differs from the signed manifest")
    public_der = subprocess.check_output([
        "openssl", "pkey", "-pubin", "-in", str(trusted_key.resolve()), "-outform", "DER",
    ])
    return {
        "result": "signature-and-archive-verified",
        "source_sha": expected_sha,
        "archive_sha256": item["sha256"],
        "trusted_public_key_sha256": hashlib.sha256(public_der).hexdigest(),
        "target": data["target"],
        "deployment_authorization": "not-granted-by-package-verification",
    }


def deterministic_archive(stage: Path, archive: Path, windows: bool) -> None:
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    if windows:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path in files:
                member = zipfile.ZipInfo(path.relative_to(stage).as_posix(), (1980, 1, 1, 0, 0, 0))
                member.compress_type = zipfile.ZIP_DEFLATED
                member.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
                output.writestr(member, path.read_bytes())
    else:
        with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as output:
                for path in files:
                    member = output.gettarinfo(str(path), arcname=path.relative_to(stage).as_posix())
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = 0
                    with path.open("rb") as contents:
                        output.addfile(member, contents)


def verify_windows_signature(binary: Path, thumbprint: str) -> None:
    if not re.fullmatch(r"[0-9A-Fa-f]{40,64}", thumbprint):
        raise ValueError("An approved Windows signing-certificate thumbprint is required")
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        raise ValueError("Native Windows Authenticode verification is unavailable")
    env = os.environ.copy()
    env["EDR_SIGN_CHECK_FILE"] = str(binary.resolve())
    env["EDR_EXPECTED_SIGNER"] = thumbprint.upper()
    subprocess.run([
        shell, "-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; "
        "$s=Get-AuthenticodeSignature -LiteralPath $env:EDR_SIGN_CHECK_FILE; "
        "if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $env:EDR_EXPECTED_SIGNER)"
        "{throw 'Authenticode signature or approved publisher mismatch'}",
    ], env=env, check=True)


def build(args: argparse.Namespace) -> dict:
    sha = checked_sha(args.candidate_sha)
    windows = args.target == "windows-x86_64"
    expected_os = "Windows" if windows else "Linux"
    if platform.system() != expected_os or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError(f"Build {args.target} on a native {expected_os} x86_64 runner")
    if not args.stage_only and (not args.signer_hook or not args.trusted_key):
        raise ValueError("Signed builds require --signer-hook and --trusted-key; use --stage-only for unsigned lab staging")
    if windows and not args.stage_only and (not args.authenticode_hook or not args.windows_signer_thumbprint):
        raise ValueError("Windows signed builds also require an approved Authenticode signer and publisher thumbprint")
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("Place package output outside the source repository")
    output.mkdir(parents=True, exist_ok=True)
    stem = f"turansec-edr-{sha[:12]}-{args.target}"
    if args.stage_only:
        stem += "-unsigned"
    archive = output / f"{stem}.{'zip' if windows else 'tar.gz'}"
    manifest = output / f"{stem}.manifest.json"
    signature = output / f"{stem}.manifest.sig"
    if any(path.exists() for path in (archive, manifest, signature)):
        raise ValueError("Refusing to overwrite existing release output")

    with tempfile.TemporaryDirectory(prefix="edr-package-") as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        source_archive = work / "source.tar"
        # Export the committed tree. Ignored files, local edits, credentials,
        # previously built binaries and dependency folders cannot enter it.
        run(["git", "archive", "--format=tar", f"--output={source_archive}", sha], ROOT)
        with tarfile.open(source_archive) as tree:
            tree.extractall(source, filter="data")
        for name in ("backend/go.sum", "agent/Cargo.lock", "frontend/package-lock.json", "docs/INSTALLATION.md"):
            if not (source / name).is_file():
                raise ValueError(f"Required committed packaging input missing: {name}")
        stage = work / "bundle"
        (stage / "bin").mkdir(parents=True)
        suffix = ".exe" if windows else ""
        server = stage / "bin" / f"edrd{suffix}"
        agent = stage / "bin" / f"turansec-edr-agent{suffix}"
        run(["go", "build", "-trimpath", "-mod=readonly", "-ldflags", f"-X main.sourceSHA={sha} -X main.version=0.1.0-candidate", "-o", str(server), "./cmd/edrd"], source / "backend")
        build_env = os.environ.copy()
        build_env["TURANSEC_BUILD_SHA"] = sha
        run(["cargo", "build", "--release", "--locked"], source / "agent", env=build_env)
        shutil.copy2(source / "agent" / "target" / "release" / f"turansec-edr-agent{suffix}", agent)
        run(["npm", "ci"], source / "frontend")
        run(["npm", "run", "build"], source / "frontend")
        shutil.copytree(source / "frontend" / "dist", stage / "web")
        shutil.copytree(source / "backend" / "migrations", stage / "backend" / "migrations")
        shutil.copytree(source / "backend" / "bootstrap", stage / "backend" / "bootstrap")
        (stage / "config").mkdir()
        shutil.copy2(source / "config" / "edrd.example.json", stage / "config" / "edrd.example.json")
        (stage / "docs" / "backend").mkdir(parents=True)
        shutil.copy2(source / "docs" / "INSTALLATION.md", stage / "docs" / "INSTALLATION.md")
        shutil.copy2(source / "docs" / "HOST_ACCEPTANCE.md", stage / "docs" / "HOST_ACCEPTANCE.md")
        shutil.copy2(source / "docs" / "backend" / "RUNTIME_DATABASE_ROLES.md", stage / "docs" / "backend" / "RUNTIME_DATABASE_ROLES.md")
        (stage / "INSTALLATION.md").write_text("# TuranSec engineering candidate\n\nRead [the complete installation and rollback manual](docs/INSTALLATION.md).\n\nThis portable archive does not install services or grant deployment authorization.\n", encoding="utf-8")
        (stage / "scripts" / "release").mkdir(parents=True)
        for name in ("collect-host-acceptance.py", "collect-sysmon-acceptance.ps1"):
            shutil.copy2(source / "scripts" / name, stage / "scripts" / name)
        for name in ("package-candidate.py", "release_switch.py"):
            shutil.copy2(source / "scripts" / "release" / name, stage / "scripts" / "release" / name)
        if windows and not args.stage_only:
            for binary in (server, agent):
                run([str(args.authenticode_hook.resolve()), str(binary)])
                verify_windows_signature(binary, args.windows_signer_thumbprint)
        for path in stage.rglob("*"):
            if path.is_symlink():
                raise ValueError("Bundle inputs must not contain symbolic links")
        if not windows:
            server.chmod(0o755)
            agent.chmod(0o755)
        files = [{
            "path": path.relative_to(stage).as_posix(),
            "sha256": digest(path),
            "size": path.stat().st_size,
        } for path in sorted(stage.rglob("*")) if path.is_file()]
        deterministic_archive(stage, archive, windows)
        data = {
            "schema": 1,
            "kind": "portable-engineering-candidate",
            "source_sha": sha,
            "target": args.target,
            "archive": {"name": archive.name, "sha256": digest(archive), "size": archive.stat().st_size},
            "files": files,
            "signature_scheme": "detached-openssl-sha256",
            "windows_authenticode": "verified" if windows and not args.stage_only else "not-established",
            "windows_publisher_thumbprint": args.windows_signer_thumbprint if windows and not args.stage_only else None,
            "host_acceptance": "separate-evidence-required",
            "deployment_authorization": "separate-approval-required",
        }
        manifest.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    if args.stage_only:
        return {"result": "unsigned-lab-candidate-staged", "archive": str(archive), "manifest": str(manifest),
                "source_sha": sha, "deployment_authorization": "not-granted"}
    # Signer hook contract: argv[1] manifest, argv[2] output raw signature.
    # It may use a hardware/remote signing service. This tool never provisions
    # credentials or replaces an organizational signer with an ephemeral key.
    run([str(args.signer_hook.resolve()), str(manifest), str(signature)])
    result = verify(archive, manifest, signature, args.trusted_key, sha)
    result.update(archive=str(archive), manifest=str(manifest), signature=str(signature))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--candidate-sha", required=True)
    build_parser.add_argument("--target", choices=("linux-x86_64", "windows-x86_64"), required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--stage-only", action="store_true")
    build_parser.add_argument("--signer-hook", type=Path)
    build_parser.add_argument("--trusted-key", type=Path)
    build_parser.add_argument("--authenticode-hook", type=Path)
    build_parser.add_argument("--windows-signer-thumbprint")
    verify_parser = sub.add_parser("verify")
    for option in ("archive", "manifest", "signature", "trusted-key"):
        verify_parser.add_argument(f"--{option}", type=Path, required=True)
    verify_parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    try:
        result = build(args) if args.operation == "build" else verify(
            args.archive, args.manifest, args.signature, args.trusted_key, args.expected_sha
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Package operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
