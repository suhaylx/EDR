# Remaining Days 4–7 — seven-day TuranSec sprint

The owner clarified that the original sprint is seven days, the first three
days form the existing baseline, and four days of work remain. This checklist
continues that scope. It tracks deliverables and evidence, rather than treating
a document, draft PR or elapsed time as acceptance.

The original [seven-day authorization](../PM_MANUAL.md) permits meaningful
feature-branch development in private `suhaylx/EDR`; it does not grant unreviewed
merges, main-branch pushes, infrastructure-policy changes or production rollout.

## Day 4 — complete the integrated trust and persistence path

- One runnable Go/PostgreSQL/Rust/React candidate with separate operator/device
  trust, restricted database identities and live revocation checks.
- Same-transaction certificate authorization and operational mutations; no
  successful response before commit.
- Fresh lease deadlines after lock waits, an upgrade for existing databases,
  and refusal to start with incomplete schema/capability state.
- Actual SQL lifecycle/concurrency/restart and integrated transport/storage
  execution with exact source identity.

The preceding integrated candidate `fb0891f98919fd0a166ff10427088f195d208225`
has local execution and fresh independent engineering reviews for these changes.
Its GitHub CI did not execute, and those local results do not establish the
current follow-up head until source attribution and relevant checks are recorded.

## Day 5 — complete existing SOC and detection workflows

- Connect the secure React controls to the backend's implemented path-scan and
  case-management APIs, including permission checks, stale-state handling and
  explicit uncertain mutation outcomes.
- Preserve unknown, unscanned, failed, expired and degraded states; no optimistic
  protection claim or automatic mutation retry after an ambiguous response.
- Exercise real benign/EICAR/scanner-unavailable behavior where the environment
  permits, preserving vendor provenance and exact adapter identity.
- Require genuine Windows Sysmon provider/channel/record evidence and the actual
  integrated scanner path for host acceptance. Synthetic fixtures remain labelled.

The endpoint specialist has demonstrated the unchanged Rust scanner adapter
against real ClamAV over isolated TCP. The Linux product transport and approved
native hosts remain separate unexecuted gates. Native Sysmon evidence is still
required; FileCreate is not evidence of a DLL ImageLoad.

## Day 6 — installation, operation and recovery

- Package runtime binaries, UI assets, schema/bootstrap, configuration examples
  and precise installation guidance in one versioned release directory.
- Add Linux backend service and bounded endpoint scheduling with explicit
  credential delivery, restricted identities and no automatic infrastructure
  provisioning or privileged file deletion.
- Validate package extraction/identity, failed activation and rollback behavior;
  retain credentials, data and previous releases during removal/recovery.
- Execute native Linux and Windows install/start/stop/restart/offline/resource
  tests and database recovery on the approved hosts before acceptance.

Filesystem or systemd syntax tests provide implementation evidence. They do not
replace an installed-systemd/Windows-Service rehearsal. The current execution
container is not either designated deployment host.

## Day 7 — reviewed release files and authorization

- Freeze the candidate; build native packages from its committed tree and record
  binary versions, archive/file hashes and dependency-lock identity.
- Retain real exact-head CI, independent InfoSec/QA verdicts and host evidence.
- Produce signed packages with the approved organizational signer; Windows
  executables also require approved native Authenticode verification.
- Rehearse installed-service/database rollback and obtain the named deployment
  owner's approval for exact signed files, targets, canary and window.

An unsigned archive may be supplied for engineering review and controlled
staging. It is not an approved signed release. Draft release creation never
grants deployment authorization or completes all four original owner assignments.

## External gates that still need evidence

GitHub runner allocation currently fails before jobs receive a runner. The
authorized Windows/Ubuntu hosts are unreachable from the provided environment.
The browser surface cannot access the local test origin through an approved
route, and no organizational signing identity is available here. These remain
explicit blockers until the corresponding execution/access is provided; source
changes cannot manufacture those results.
