# Frontend and release QA — 22 November 2026

## Verdict and source

**The focused FIFO rejection fix passes the exercised release-tool QA scope.**
The React source passes type checking, all 374 unit tests and a production build.
New local browser/accessibility execution is **BLOCKED**, because the locked
Chromium download is denied by the execution environment. Full installed-system
acceptance and release/deployment approval remain **NOT APPROVED**.

This review starts from merged commit
`f00cab502cf04ee92fed1210fb7ba295d92e9c36` and includes the accompanying changes
to `linux_service.py`, `systemd_launcher.py` and their regression tests. An
additional assigned integration change makes service/bootstrap startup require
the new enrollment wall-clock capability, as described below.
The baseline source tree and blobs were verified against GitHub. The report is
an independent agent engineering assessment; it does not impersonate an
original role owner or constitute a formal GitHub approval. A combined follow-up
commit containing other agents' changes requires its own CI evidence.

## Confirmed and corrected finding: FIFO inputs can hang before validation

**Severity: P2 availability defect.** Both
`scripts/release/linux_service.py::copy_bounded` and
`scripts/release/systemd_launcher.py::regular_file` opened inputs using blocking
`os.open(..., O_RDONLY)` before checking the descriptor with `fstat`. A FIFO with
no writer therefore blocked indefinitely before the code could reject it as a
non-regular file. This could stall a package staging invocation or a credential
preflight when an operator selected such an input. No remote privilege
escalation or arbitrary-file-write impact is claimed.

The reproduction used an owner-only temporary directory, a mode-0600 FIFO, and
separate Python child processes with a two-second deadline. Both readers on the
baseline required termination at the deadline. The implementation blobs matched:

| File | Baseline Git blob |
|---|---|
| `scripts/release/linux_service.py` | `c113f51cdb22eb10066af6f21b0e31f41d294c87` |
| `scripts/release/systemd_launcher.py` | `e60fae88b9a10410a4d8f40c707bbb944393bf69` |

The fix adds `O_NONBLOCK` to the existing `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`
flags, allowing `fstat` to reject a FIFO without waiting for a writer. It retains
the descriptor-based type, size and private-permission checks. Ordinary file
contents and limits, directory/device rejection and symlink rejection remain
covered by executable tests.

The new regression was run against the unchanged implementation first: both
FIFO subcases failed at their five-second child deadlines. After the fix, the
same regression and the complete release suite passed. The bounded child
processes ensure that reintroducing this bug cannot hang the entire test suite.

## Enrollment capability integration

The service now requires version 1 of both `scan_lease_wallclock` and
`enrollment_wallclock` before opening either HTTP listener. It closes the
database handle on failure and emits a bounded diagnostic naming only the
hardcoded capability, with no DSN or database-error contents. Runtime bootstrap
requires the same capabilities and checks that all three enrollment functions
contain the wall-clock correction. The privilege catalog regression checks the
new capability while preserving the existing read-only grants and operation
allowlist.

Installation and database-role instructions now distinguish upgrades from 0012
(apply 0013, then 0014) from upgrades already at 0013 (apply only 0014). Both
paths retain the approved backup, drained serving processes, authorized
maintenance window, existing dedicated logins and compatibility requirements.

The backend QA agent owns actual integrated startup tests for a missing and a
version-2 `enrollment_wallclock` record, followed by restored version-1 startup.
They must run against the final combined source. This environment does not have
a working Go compiler or `gofmt`, so no local Go compilation is claimed for this
additional change. Hosted backend and integrated CI remain required.

## Executed checks

Commands ran on the local Linux execution environment. Package signatures used
temporary test keys only, and lifecycle tests used the explicit test service
manager. No production or installed-host services were operated.

| Command or check | Observed result |
|---|---|
| Baseline `python3 -B -m unittest discover -s scripts/release -p 'test_*.py' -v` | 56 passed |
| New `BoundedFileInputTests` against baseline | Three tests passed; FIFO test produced two timeout errors, one for each reader |
| Same release discovery command after the fix | **60 passed, zero failures** |
| `python3 -B scripts/test-host-acceptance.py` | **8 passed, zero failures** |
| `git diff --check` | Passed |
| `npm ci --no-audit --no-fund` | Installed the committed dependency set successfully |
| `npm run typecheck` | Passed |
| `npm test` | **374 passed, zero failed, skipped or cancelled** |
| `npm run build` | Passed; React production assets generated |
| `npm audit --omit=dev --json` | Exit 0; **zero reported production dependency advisories** at all severities |
| `npm run test:browser` | Blocked before any browser scenario: required Chromium executable absent |
| `node node_modules/playwright/cli.js install chromium` | Blocked by HTTP 403 from the locked browser download endpoint |

The 68 release/host-evidence tests exercise actual filesystem operations,
cryptographic signature verification and tamper rejection, loopback mTLS health
checks, the systemd unit parser, archive validation and rollback state machines.
They do **not** demonstrate installed systemd/Windows Service lifecycle or
database-restore acceptance. The host-evidence collector tests validate evidence
boundaries; they do not collect real endpoint acceptance on their own.

The production dependency audit completed within its 30-second deadline and
reported zero informational, low, moderate, high or critical vulnerabilities.
Its metadata lists four production dependency entries. Development dependencies
were excluded. Raw JSON, stderr and execution status were retained in
`.quality-evidence/frontend-production-npm-audit*`. No packages were updated.

## Frontend and packaging review observations

The reviewed SOC mutation path refreshes identity and target state before the
write, submits one POST, distinguishes an accepted write with failed refresh
from an unknown outcome, and does not automatically retry a mutation. Unit tests
exercise authorization changes, stale selections, malformed responses, late
responses and explicit unknown outcomes. No new frontend defect was confirmed
in this bounded review of `soc-api.ts`, `OperatorSOC.tsx` and `SOCControls.tsx`.

The package installer snapshots verification inputs, validates the full archive
inventory and member hashes, rejects links/traversal/duplicate members, checks
installed file ownership and contents, and retains explicit failed or pending
rollback journals. The tests exercise signed-manifest tampering, wrong trust
roots, artifact/source mismatches, unknown outcomes and restoration failures.
Passing checksum or fixture-signature tests does not establish an approved
publisher identity for the actual release archives.

The existing browser harness preserves incomplete mobile accessibility results
and performs a separate unclipped desktop scan. Prior candidate evidence reported
incomplete contrast measurements in three mobile table scans. Those results have
not been replaced by a new local browser run in this pass. The new follow-up CI
must execute the unchanged locked browser suite, and manual mobile/screen-reader
acceptance remains open.

## Remaining acceptance requirements

- Successful browser and integrated candidate CI for the final combined change.
- Actual authorized Ubuntu and Windows Server 2022 endpoint records, genuine
  ClamAV/EICAR and Sysmon evidence, and installed service restart/offline recovery.
- Native Windows service/installer and privileged local IPC acceptance where
  required by the product scope.
- Approved publisher signatures for the exact release packages.
- Live installed-service and database rollback rehearsal on the authorized hosts.
- Manual accessibility follow-up and explicit original role-owner acceptance.
- Deployment-owner authorization for the exact packages, hosts and window.

These requirements follow the repository's
[installation acceptance gates](../INSTALLATION.md),
[host acceptance manual](../HOST_ACCEPTANCE.md), and
[release-file guidance](../release/BUILD_RELEASE_FILES.md).
