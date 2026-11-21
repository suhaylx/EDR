# TuranSec Windows Server 2022 canary lab (operator-run)

**Status:** Preparatory / NOT DEPLOYED. Never mistake an open RDP port for permission or proof of a connected remote session. The code in this branch cannot deploy or inspect Windows hosts by itself. Current Rust `--lease-and-scan` is a **single-shot lab client**, not a Windows service or live Sysmon collector. No malware execution, kernel self-protection, production TLS, tenant authentication, auto-quarantine, or persistence is implemented.

## Security gates first

1. Dedicated, authorized Windows Server 2022 test host, **not** a domain controller or production server. Take a restorable snapshot and record the OS build. Do not disable Microsoft Defender/other protection to force scanner results.
2. **Rotate the Windows administrator password if shared in chat or tickets.** Never paste a password, token, private key, recovery key, or credential into a PR, CI or an issue.
3. Restrict inbound RDP at the cloud/provider security group and Windows Firewall to the administrator's actual trusted IP or VPN. Use NLA, account lockout and MFA/Remote Desktop Gateway where supported; do not use broad 0.0.0.0/0 ingress. User-approved access doesn't imply a remote execution channel is available to this assistant.
4. Use signed, verified official Sysmon and ClamAV distributions; record installed publisher, version, signature DB health, and test evidence. Keep local `clamd` TCP listener bound to **127.0.0.1:3310** only. Keep development Go API on Linux **127.0.0.1:8080** only. Neither port is publicly reachable.
5. For the 8 GB Ubuntu backend, start only the Go API and lab UI; defer ClickHouse/Kafka and performance sampling. In-memory events disappear on restart.

## Preflight (no administrator credentials required)

On Windows in a PowerShell terminal, clone the **authorized** private repo from an approved read-only GitHub key or obtain a signed/reviewed archive. Use the `feat/windows-server-2022-lab-preflight-20261121` feature branch and run:

```powershell
Set-Location C:\TuranSecLab\EDR
powershell.exe -NoProfile -File .\scripts\windows-lab-preflight.ps1
powershell.exe -NoProfile -File .\scripts\windows-lab-preflight.ps1 -Json
```

The script **does not change** service state, install packages, create users, read tokens, run test binaries, or open firewall rules. It evaluates basic OS, disk, memory, Sysmon event channel and Event ID 1 presence, loopback ClamAV socket reachability, Cargo, OpenSSH, and the Windows-side SSH-tunneled local Go health endpoint. `PASS` for a socket/command is *not* ClamAV signature or endpoint identity verification. `NOT_RUN` is not a test failure. `production_ready` is intentionally `BLOCKED`.

## Manual prerequisites and safe integration

- Linux backend: in a private administrative console verify `systemctl is-active turansec-edr-lab`, `curl -fsS http://127.0.0.1:8080/api/health`, `ss -ltnp | grep ':8080'`. If Linux SSH TCP/22 is closed, have the owner enable **authenticated, key-based SSH** in the admin-only security group. Do not expose the Go bearer-token API on a public interface.
- Windows host from its local RDP PowerShell: `Test-NetConnection <LINUX_SSH_REACHABLE_ADDRESS> -Port 22`. Set up a secure outbound SSH tunnel only after verifying the Linux host key: `ssh -o ExitOnForwardFailure=yes -N -L 127.0.0.1:8080:127.0.0.1:8080 <LINUX_USER>@<LINUX_SSH_REACHABLE_ADDRESS>`. Do not disable host-key checking. Windows can reach the Go backend at `http://127.0.0.1:8080` *through the encrypted tunnel*.
- Install Windows Sysmon using the original Microsoft package and test service/operational log and a benign ProcessCreate Event 1. The current TuranSec agent **does not subscribe** to Sysmon; event replay in the Go console is synthetic.
- Install official ClamAV with `freshclam` signatures and run a locally bound daemon at TCP 127.0.0.1:3310. Check ClamAV service and signature/database freshness separately; use EICAR **only in the isolated lab** and record whether ClamAV itself returned the signature, not merely other protection software.
- Build/test Rust `agent/` from dependent draft PR #16: `cargo test`; install MSVC tools as needed. Set a lab root such as `C:\TuranSecLab\scan` and use only path scans within this directory. Quick/full are intentionally `unscanned`.
- Register a test-only `windows` agent in Go and create a `path` job through the locally tunneled API; run `cargo run -- --lease-and-scan <LAB_AGENT_ID>` one time, then inspect `GET /api/scan-jobs` for the exact verdict and lease result. The same temporary **dev token** is required in both Windows session and Linux backend; transfer securely out of band, do not print or commit it. This is *not* mTLS and cannot be advertised as enrolled protection.
- Clear development token and test file after QA. Never automatically quarantine, delete, disable AV, or open network services. Stop on failure and preserve redacted logs.

## Acceptance evidence

| Gate | Verification | Claim permitted |
| --- | --- | --- |
| Windows host | Local preflight OS/build and resource output | Server 2022 lab preflight executed |
| Sysmon | Actual local Event ID 1 / timestamp | Real Sysmon events observed **locally** |
| ClamAV | Real daemon, signatures and safe test fixture | Real local signature scanner tested |
| Backend | Linux-local health and loopback listener | Lab API operational on Linux |
| Tunnel | Windows-local HTTP health + SSH tunnel evidence | Lab agent-to-Go transport demonstrated (not device mTLS) |
| Rust worker | `cargo test`, real path job and accepted result | One-shot ClamAV scan job completed in lab |
| SOC graph | Source/event provenance test | Graph renders stored events; NOT live Windows collection |

**Never report** successful deployment or working endpoint protection without recorded host-level service, Sysmon, clamd, Rust job, Go API, and QA evidence. Required production work remains: device mTLS, signed commands, tenant isolation, durable queue, tamper controls, safe file descriptor handling, auto collection, audited response, Windows/Linux packaging and canary tests.
