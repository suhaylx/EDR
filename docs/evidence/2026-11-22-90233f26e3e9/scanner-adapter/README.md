# Host execution and real scanner evidence

Candidate: `fb0891f98919fd0a166ff10427088f195d208225`.

## Actual result

On 2026-11-21 at 20:11 UTC, the unchanged candidate `clamav.rs` adapter and its unchanged `scan_jobs.rs` text validator were compiled in a separate acceptance probe. The probe connected over loopback TCP to the real vendor ClamAV 1.5.5 daemon. The daemon loaded genuine `daily.cvd` and `bytecode.cvd` databases; both detached signatures verified as `ClamAV_datafiles_release`.

The harmless text fixture returned `clean_by_signature`. The official 68-byte EICAR fixture returned `malicious` with `Eicar-Test-Signature`. After the actual daemon stopped, the same probe failed with `ConnectionRefused`, producing no clean verdict. No malware was executed. No broad host scan was performed. The daemon was stopped and temporary fixture/configuration files were removed.

The real result is **PASS_WITH_SCOPE_LIMITS**. This establishes actual Rust protocol-adapter to real daemon behavior. The product's Linux scan transport uses Unix sockets, which this executor prohibits, so the full product command and the Go/PostgreSQL/UI pipeline were not exercised by this probe. Windows uses loopback TCP in the product but no authorized Windows execution session was available. No production TCP configuration was added.

`main.cvd` remains absent after the earlier vendor CDN rate limit; no retry or alternate-mirror bypass was attempted. Two verified databases and a successful EICAR detection do not establish complete signature-database health.

## Remaining execution blockers

The approved Ubuntu lab SSH endpoint and Windows lab SSH/RDP endpoints still return network-unreachable errno 101. The visible native surface is a Linux desktop with no remote Windows client/session. No PowerShell, Wine, Docker, Podman or QEMU execution environment is available. Local TCP is permitted; Unix socket creation fails with EPERM. Processes participating in a local TCP test must start inside one executor command, because distinct commands use distinct network namespaces.

The exact-head [candidate CI run](https://github.com/suhaylx/EDR/actions/runs/44943696845) failed before execution. All eight jobs have `runner_id=0`, empty runner names and no steps. This is not evidence that application tests failed. The managed GitHub connector does not expose the runner/permissions/annotation administration routes required to establish the account-level cause, so billing or policy is not asserted as the cause. Runner registration, billing, organization policy and repository settings were not changed.

## Evidence files

- `real-clamd-adapter-result.json`: scoped result, binary/database hashes, checks and exclusions.
- `adapter-source-identity.json`: full candidate SHA, Git blob IDs and SHA-256 hashes of unchanged source and dependency-lock files.
- `rust-real-clamd-probe.log`, `rust-clamd-unavailable.log`: actual probe outputs.
- `clamd-tcp-runtime.log`: real daemon startup, actual EICAR detection and stop.
- `daily.cvd.verify.log`, `bytecode.cvd.verify.log`: detached vendor signature verification.
- `availability-recheck.json`: actual loopback/Unix and remote lab reachability observations.
- `exact-head-runner-evidence.json`: raw selected fields for all eight exact-head CI jobs.
- `execution-surfaces.json`: available execution surfaces and access limitations.

The vendor package verification included as `clamav-pgp-verification.log` used the ClamAV release public-key fingerprint `5BADCA2665EF59DCF8A23D8B707F0DB480836771`, obtained from the official vendor download page. The package SHA-256 is included in the result. This vendor signature is not a TuranSec release signature or deployment authorization.

## Reproduction

The external test harness is included as `real_clamd_probe.rs`; in the execution workspace it was `candidate-adapter/agent/src/bin/real_clamd_probe.rs`. Its two imported source modules came from `git archive` of the SHA above and are unchanged. It was compiled with `cargo build --locked --offline --bin real_clamd_probe` using the recorded candidate Cargo manifest and lockfile, with the output isolated to `adapter-target`. Build succeeded with unused-code warnings from importing the complete wire-contract module.

`run-real-clamd-probe.py` orchestrates this particular workspace's verified vendor binary, existing signature databases, exact EICAR fixture and compiled probe. It verifies fixture/archive hashes, verifies both database signatures, binds the daemon only to loopback, runs the two scans, stops the daemon and verifies the connection-error outcome. It does not download or update databases. The script is workspace-specific; review and provision the stated inputs before reproducing elsewhere.

Native Ubuntu/Windows installed-service acceptance, the complete authenticated scanner-to-SOC flow, genuine Sysmon Event 7 versus Event 11 evidence, host rollback/reboot evidence, organizational release signing, exact-head GitHub CI success, independent release approval and deployment authorization remain required. This evidence does not change the deployment **NO-GO**.
