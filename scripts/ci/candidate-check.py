#!/usr/bin/env python3
"""Run a mandatory candidate check and save its exact source/run provenance.

The ledger records executed commands and exit codes. It does not constitute
InfoSec approval, independent QA signoff, signing, or host acceptance.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / ".quality-evidence"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def verify_source() -> str:
    expected = os.environ.get("EDR_CANDIDATE_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise RuntimeError("EDR_CANDIDATE_SHA must be the full candidate commit SHA")
    if git_output("rev-parse", "HEAD") != expected:
        raise RuntimeError("Checkout is not the requested candidate commit")
    if git_output("status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("Source files differ from the candidate commit or untracked inputs are present")
    return expected


def require_tracked(*paths: str) -> None:
    for relative in paths:
        if not (ROOT / relative).is_file():
            raise RuntimeError(f"Required candidate file missing: {relative}")
        subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative],
            cwd=ROOT, stdout=subprocess.DEVNULL, check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=(
        "backend", "rust", "frontend", "postgres", "postgres-seed",
        "postgres-verify", "integration", "release-tools",
    ))
    args = parser.parse_args()
    EVIDENCE.mkdir(exist_ok=True)
    stem = f"{args.component}-{platform.system().lower()}"
    ledger_path = EVIDENCE / f"{stem}.json"
    ledger = {
        "schema": 1,
        "scope": "candidate-engineering-checks",
        "component": args.component,
        "started_at": utc_now(),
        "os": platform.platform(),
        "candidate_sha": os.environ.get("EDR_CANDIDATE_SHA"),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"),
        "run_url": (
            f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
            f"{os.environ['GITHUB_RUN_ID']}"
            if os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID")
            else None
        ),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "commands": [],
        "result": "failed",
        "host_acceptance": "not-established-by-this-ledger",
        "deployment_authorization": "not-granted",
    }
    log_path = EVIDENCE / f"{stem}.log"
    log_path.write_text(
        f"Candidate: {ledger['candidate_sha']}\nStarted: {ledger['started_at']}\n",
        encoding="utf-8",
    )

    def save() -> None:
        ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    def run(label: str, command: list[str], directory: str = ".") -> None:
        record = {"label": label, "argv": command, "cwd": directory,
                  "started_at": utc_now(), "exit_code": None}
        ledger["commands"].append(record)
        save()
        print(f"\n=== {label} ===", flush=True)
        try:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n=== {label} ===\n")
                with subprocess.Popen(
                    command, cwd=ROOT / directory,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                ) as process:
                    assert process.stdout is not None
                    for line in process.stdout:
                        print(line, end="", flush=True)
                        log.write(line)
                    record["exit_code"] = process.wait()
        finally:
            record["finished_at"] = utc_now()
            save()
        if record["exit_code"] != 0:
            raise RuntimeError(f"Required check failed: {label}")

    try:
        ledger["candidate_sha"] = verify_source()
        if args.component == "backend":
            require_tracked("backend/go.mod", "backend/go.sum", "backend/cmd/edrd/main.go")
            run("Go toolchain", ["go", "version"])
            run("Go build", ["go", "build", "./..."], "backend")
            run("Go tests", ["go", "test", "-count=1", "./..."], "backend")
            run("Go race tests", ["go", "test", "-race", "-count=1", "./..."], "backend")
            run("Go vet", ["go", "vet", "./..."], "backend")
        elif args.component == "rust":
            require_tracked("agent/Cargo.toml", "agent/Cargo.lock", "agent/rust-toolchain.toml")
            run("Rust toolchain", ["rustc", "--version"])
            run("Cargo toolchain", ["cargo", "--version"])
            run("Rust build", ["cargo", "build", "--locked", "--all-targets"], "agent")
            run("Rust native tests", ["cargo", "test", "--locked", "--all-targets"], "agent")
            run("Rust check", ["cargo", "check", "--locked", "--all-targets"], "agent")
            if os.name == "nt":
                run("Native PowerShell host collector syntax", [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'scripts/collect-sysmon-acceptance.ps1'),[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){throw 'Host collector syntax failed'}"
                ])
        elif args.component == "frontend":
            require_tracked("frontend/package.json", "frontend/package-lock.json")
            run("Node toolchain", ["node", "--version"])
            run("Locked frontend dependencies", ["npm", "ci"], "frontend")
            run("React typecheck", ["npm", "run", "typecheck"], "frontend")
            run("React tests", ["npm", "test"], "frontend")
            run("React production build", ["npm", "run", "build"], "frontend")
            run("Install locked Playwright browser", [
                "node", "node_modules/playwright/cli.js", "install", "--with-deps", "chromium"
            ], "frontend")
            run("Browser accessibility/auth/unknown-state tests", [
                "npm", "run", "test:browser"
            ], "frontend")
        elif args.component.startswith("postgres"):
            require_tracked("scripts/ci/candidate-postgres.sh")
            phase = {"postgres": "test", "postgres-seed": "seed", "postgres-verify": "verify"}[args.component]
            run(f"PostgreSQL candidate {phase}", ["bash", "scripts/ci/candidate-postgres.sh", phase])
        elif args.component == "integration":
            require_tracked(
                "backend/go.sum", "backend/cmd/edrd/main.go", "agent/Cargo.lock",
                "frontend/package-lock.json", "scripts/test-integrated-candidate.sh",
            )
            run("Build authenticated Go service", ["go", "build", "./cmd/edrd"], "backend")
            run("Build one Rust endpoint agent", ["cargo", "build", "--locked"], "agent")
            run("Locked integrated frontend dependencies", ["npm", "ci"], "frontend")
            run("Build integrated React UI", ["npm", "run", "build"], "frontend")
            run("Actual Go/PostgreSQL/Rust/React candidate", [
                "bash", "scripts/test-integrated-candidate.sh"
            ])
        elif args.component == "release-tools":
            require_tracked(
                "scripts/release/package-candidate.py", "scripts/release/release_switch.py",
                "scripts/release/test_release_tools.py", "scripts/release/prepare-release.py",
                "scripts/release/test_prepare_release.py",
            )
            run("Signature tamper rejection and filesystem rollback regressions", [
                sys.executable, "scripts/release/test_release_tools.py"
            ])
            run("Host evidence attribution and signature regressions", [
                sys.executable, "scripts/test-host-acceptance.py"
            ])
            run("Release record source, artifact and path integrity", [
                sys.executable, "scripts/release/test_prepare_release.py"
            ])
            if platform.system() == "Linux":
                require_tracked(
                    "scripts/release/linux_service.py", "scripts/release/systemd_launcher.py",
                    "scripts/release/test_linux_service.py",
                )
                run("Linux installer, activation recovery and authenticated health", [
                    sys.executable, "scripts/release/test_linux_service.py"
                ])
        verify_source()
        ledger["result"] = "passed"
        return 0
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        ledger["error"] = str(exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        ledger["finished_at"] = utc_now()
        save()


if __name__ == "__main__":
    raise SystemExit(main())
