# ClamAV upstream architecture review — TuranSec EDR

Reviewed: 2026-11-21. Status: upstream source inspection, **not** a working scanner.

**Pinned baseline:** [ClamAV 1.5.5](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.5); re-evaluate official updates and security advisories before production.

**Official upstream:** https://github.com/Cisco-Talos/clamav (GPL-2.0; some bundled dependencies have their own notices). Source obtained for inspection through the authorized GitHub connector. A full `git clone` was attempted but is not possible from the current build container because its DNS/network connection is disabled. `scripts/fetch-clamav.sh` downloads the full upstream source on a development machine that can reach GitHub. Do not silently copy the whole source into TuranSec's proprietary repository.

## Modules examined and boundaries

| Upstream module | Function | TuranSec integration |
| --- | --- | --- |
| `clamd/clamd.c`, `clamd/session.c`, `clamd/scanner.c` | Long-running scanner daemon; framed commands; scan worker logic | Rust unified endpoint agent supervises a restricted local `clamd` worker; keep failures separate from the agent core |
| `libclamav/clamav.h` | Native scanning library / scan verdicts | Possible later direct integration after legal license and ABI/OS review, **not** the first implementation |
| `clamdscan/clamdscan.c` | ClamAV CLI client for the daemon | Reference for caller semantics; avoid launching a shell for user-controlled paths |
| `freshclam/freshclam.c` | Official signature update workflow | Supervise official freshclam updates, record database version and health, rate-limit changes and support offline paths |
| `COPYING.txt`, `README.md` | GPL-2.0 distribution terms and component notices | Preserve upstream license/notice/source obligations and review redistribution/commercial use with counsel |

## Recommended integration (implemented backend contract, endpoint scanner still pending)

The single TuranSec **Rust** agent owns the scan-job state machine and manages ClamAV/Sysmon as contained modules. ClamAV runs as a vendor daemon or worker, not a second TuranSec-registered agent. The Rust core must keep local telemetry buffering and heartbeat working if ClamAV or Sysmon stops.

On Linux, use a file-permission-restricted Unix socket to clamd (not a network-exposed TCP listener). On Windows, research appropriate supported local ClamAV daemon transport/service packaging, isolate it and restrict connections; ClamAV's TCP protocol is **not authenticated or encrypted**, so never expose it to LAN or Internet. Do not assume an official native Windows Unix socket is available.

Clamd protocol (upstream documentation: https://docs.clamav.net/manual/Usage/ClamdProtocol.html):

- Health command: bytes `zPING\0` and NUL-terminated `PONG` reply.
- Scan request: `zINSTREAM\0`, then repeated 4-byte big-endian chunk lengths and chunk bytes, followed by four zero bytes. Enforce a max file/chunk/total size and deadlines; match ClamAV `StreamMaxLength` configuration.
- A `FOUND` verdict means a matching signature; `OK` means **nothing matched by this engine**, **not** that the file is safe. Timeouts, size-limit rejections, disabled modules or unreadable files are `error` or `unscanned`, never silently treated as clean.
- Avoid path-based scan commands for a client-supplied untrusted path if possible; prefer a locally opened file with bounded `INSTREAM` to reduce clamd daemon filesystem access. Local file TOCTOU still needs identity/hash and safe permissions.
- Do not treat Sysmon logs as actual file execution prevention. Windows DLL Event 11 (creation) and Event 7 (module load) remain distinct.

## Backend implementation in this change

`backend/internal/edr/scans.go` adds a **development-only control-plane scan-job contract**:

1. `POST /api/scan-jobs`: authorized *lab shared-token* operator requests quick/full/path scan for an enrolled device. Includes a per-device idempotency `request_id` and validated local path shape. The server creates a queued job; **nothing is scanned yet**.
2. `POST /api/agents/{id}/scan-lease`: an agent picks up a job, with 60-second rotating lease ID and 30-minute job TTL; another endpoint cannot lease its job by ID within the store's logic.
3. `POST /api/scan-jobs/{id}/result`: endpoint reports `agent_id`, `lease_id`, engine (`clamav`), verdict, optional signature/engine/db version, threat name and detail. The store rejects an incorrect lease ID, cross-agent completion or unsupported verdict. `GET /api/scan-jobs` lists jobs with lease capability hidden.

**IMPORTANT SECURITY LIMITATION**: this is a localhost **lab** workflow only, using a shared bearer token and in-memory state. An attacker with that token can impersonate endpoints and forge results. No actual ClamAV scan, real signed device identity, mTLS, tenant RBAC, persistent queue, signed result/evidence or durable deduplication exists yet. Do not deploy on production endpoints.

## Next technical tasks

- Agent 2: implement the Rust ClamAV supervisor and bounded `INSTREAM` client, configure local-only transport, expose scan health and real scan results, ensure worker crash does not stop the agent core.
- Agent 2: implement device-scoped mTLS enrollment, persisted PostgreSQL scan-job storage and signed/replay-resistant commands before replacing the lab shared token; bind result origin to the authenticated device, not a JSON field.
- Agent 1: define ClamAV scanning policy (scan caps/exclusions/stream limits/signature updates), independent static PE/DLL analysis, and threat verdict mapping without clean->safe conflation.
- Agent 3: run real clamd protocol compatibility and EICAR fixture tests in isolated Windows/Linux VMs; test timeout and size limits, ClamAV service outage, duplicate leases and forged/stale results.
- Agent 5: render `queued`, `leased`, `completed`, `failed`, `expired` scan states, explicitly stating when a scan has not yet run.

## Licensing

ClamAV is published under GPLv2. Redistributing binaries, modifications, and certain combined works may carry source-disclosure and notice obligations. The separation of a local daemon process is an engineering boundary, **not a legal conclusion** about derivative-work classification. Obtain appropriate legal/license review before distributing the commercial TuranSec endpoint agent with ClamAV. Prefer official signed packages and retain upstream component licenses. This review includes no copied vendor source code.
