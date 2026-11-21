# Linux service installation and upgrade

This guide installs the authenticated Go/PostgreSQL service and the existing
bounded Rust endpoint commands as systemd services from a verified release
package.

**Current release gates still apply:** use the exact reviewed commit, successful
CI and independent review records, approved package identity, the designated
host acceptance results and an authorized installation window. See
[INSTALLATION.md](INSTALLATION.md) and [HOST_ACCEPTANCE.md](HOST_ACCEPTANCE.md).
Building or extracting an archive does not install, start or enable a service.

## What is installed

| Component | Behavior |
| --- | --- |
| `turansec-edrd.service` | Runs the PostgreSQL-backed Go service and the same release's React assets on the configured numeric loopback mTLS listeners. |
| `turansec-agent.service` | Runs a heartbeat, ClamAV liveness check and `--scan-batch-mtls` with the configured limit of 1–20 jobs. It is a bounded oneshot service. |
| `turansec-agent.timer` | Runs another batch 30 seconds after the previous invocation becomes inactive, with up to 5 seconds of jitter. There is no catch-up backlog or overlapping worker from this timer. |

Install the server, the endpoint, or both on an authorized host. The endpoint
still depends on the approved ClamAV engine/signature installation and existing
enrollment. Timer-driven signature scans do not provide tamper protection,
quarantine, a native tray application, full system monitoring or a prevention
verdict. ClamAV PONG proves liveness, not signature freshness.

## Prerequisites

The target baseline is Ubuntu 24.04 x86_64. The installer requires Python 3.11
or newer, OpenSSL, systemd 249 or newer, and root for service registration,
activation and removal. The package is built on a native Linux x86_64 runner;
confirm binary/library compatibility on the actual target host.

Prepare PostgreSQL 16, the reviewed migrations and restricted-role bootstrap
before service activation. The installer never runs migrations, creates
database accounts, enrolls identities or restores a database. An upgrade that
changes schema needs its own reviewed compatibility and backup/restore plan.

Use `/opt/turansec` for the installation prefix. Keep it and its ancestors
administrator owned, without symlinks or group/world write permission. Do not
place runtime binaries under `/home`, `/root`, `/run/user`, `/tmp` or `/var/tmp`;
the service sandbox hides or replaces these locations.

The service units use `DynamicUser=yes`. Do not create static accounts or
groups named `turansec-edrd` or `turansec-agent`: registration rejects existing
identities instead of inheriting their privileges. Resolve a conflicting old
installation with its owner; the installer does not remove unrelated accounts.

## 1. Verify and stage a complete release

Run the installer from the reviewed source checkout or an independently
authenticated copy. Do not execute code from an unverified downloaded archive
to establish that archive's trust. Verify its detached signature using a
separately provisioned publisher public key first, as described in the main
manual.

Set the reviewed full commit and package paths; none of these variables contains
a credential:

```bash
export EDR_CANDIDATE_SHA=FULL_REVIEWED_40_CHARACTER_COMMIT
export EDR_ARCHIVE=/staging/turansec-candidate.tar.gz
export EDR_MANIFEST=/staging/turansec-candidate.manifest.json
```

For a signed package, inspect the staging result before writing files:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec stage \
  --archive "$EDR_ARCHIVE" --manifest "$EDR_MANIFEST" \
  --expected-sha "$EDR_CANDIDATE_SHA" \
  --signature /staging/turansec-candidate.manifest.sig \
  --trusted-key /approved/trust/release-publisher.pem --dry-run
```

Remove only `--dry-run` to stage the same reviewed package. Staging snapshots
the input bytes into a private temporary directory, verifies the signature,
archive digest, full file catalog and expected commit, and rejects unexpected
files, traversal paths, links, special files and elevated permission bits.
The complete version is placed under `/opt/turansec/releases/FULL_SHA/` with a
receipt. Staging does not change the current version or touch systemd.

An unsigned engineering candidate is limited to an explicitly approved lab.
It requires an independently recorded manifest digest:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec stage \
  --archive "$EDR_ARCHIVE" --manifest "$EDR_MANIFEST" \
  --expected-sha "$EDR_CANDIDATE_SHA" \
  --unsigned-lab --manifest-sha256 EXPECTED_MANIFEST_SHA256_FROM_REVIEWED_RECORD \
  --dry-run
```

Remove `--dry-run` only for that authorized lab staging. The receipt remains
marked unsigned. A digest calculated solely from the same untrusted download
does not establish an independent trust decision; checksums do not replace
publisher authentication. This option does not generate a signing key or make
the package suitable for production.

## 2. Provision existing identities outside the package

Keep `/etc/turansec` administrator owned with mode `0700`. Configuration,
private keys, DSN files and health configuration require root ownership and
owner-only permissions (`0600` or `0400`). Public certificates/CA files may use
`0644` inside the protected directory. No file may be a symlink, and credential
ancestors must not be group/world writable.

### Server

Use `config/edrd.example.json` as a template for `/etc/turansec/edrd.json`.
Supply the approved server certificate/key, separate agent and operator CA
bundles, and the two different restricted PostgreSQL DSN files. Keep
`ui_dir` equal to `/opt/turansec/current/web`. Configure distinct unprivileged
ports on numeric loopback addresses; defaults are `127.0.0.1:9443` and
`127.0.0.1:9444`.

The unit loads the configuration and credential files with systemd
`LoadCredential=`. The launcher uses the read-only copies exposed to the
dynamic service identity and writes a private, transient configuration under
systemd's runtime directory. It pins the UI and binary to the resolved release
directory. Private PEM/DSN contents are not command-line arguments or
environment-variable values, and inherited PG/proxy/UI override variables are
not propagated to the application. The source files retain their root ownership
and are never rewritten by installation or upgrade.

### Endpoint

Use `config/agent.example.json` as a template for
`/etc/turansec/endpoint/agent.json`. Provision the enrolled agent certificate,
key, server CA, tenant and agent IDs. Its HTTPS origin must be numeric loopback;
remote approved servers require an existing reviewed encrypted tunnel. Keep
certificate hostname verification enabled and match the client-facing URL.

Configure the existing ClamAV Unix socket and a narrowly scoped scan root.
The root must be administrator controlled and not group/world writable. All
descendants to be scanned need read access for the approved scan group. For
example, after the group and policy have been reviewed:

```bash
sudo install -d -o root -g turansec-scan -m 2750 /var/lib/turansec/scan-root
```

`read_groups` must exactly match the non-root group IDs of the scan root and
the ClamAV socket. The root needs group read/search permission; the socket
needs group connect (write) permission and no world access, normally mode
`0660`. The installer grants no additional groups. Confirm these
groups carry no unrelated host privileges; group names and a short denylist
cannot prove that. The example expects dedicated `turansec-scan` access and the
ClamAV package's `clamav` group. The installer does not create groups, broaden
file permissions, install ClamAV or open its socket publicly.

The endpoint remains non-root with no capabilities. Its service sandbox makes
the system read-only, hides home directories and provides a private temporary
directory. Select an approved scan root outside those hidden paths. A failed
heartbeat or scanner liveness check prevents a batch from starting. Missing
scanner readiness must be reported as degraded/unknown, not protected.

## 3. Register services without starting them

For both components:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec register \
  --sha "$EDR_CANDIDATE_SHA" \
  --server-config /etc/turansec/edrd.json \
  --agent-config /etc/turansec/endpoint/agent.json --dry-run
```

Remove `--agent-config` for a server-only host; remove `--server-config` for an
endpoint-only host. Remove `--dry-run` to register the reviewed units. This
validates staged bytes and credential permissions, writes only the named units,
sets the initial `current` symlink and reloads systemd. It does **not** start a
service or enable boot startup. Existing/unmanaged units and local overrides
are not silently adopted or overwritten.

The three generated units can also be inspected with:

```bash
sudo systemd-analyze verify /etc/systemd/system/turansec-edrd.service \
  /etc/systemd/system/turansec-agent.service /etc/systemd/system/turansec-agent.timer
```

Include only units that were registered. Parsing units is not host acceptance.

## 4. Activate in the approved installation window

For a server, provision a dedicated enrolled **viewer** health identity and
`/etc/turansec/health.json` using `config/service-health.example.json`. Its
operator origin must match the configured SOC listener. The file references
the approved server CA, viewer certificate/key and expected tenant/operator.
It stays outside the application package and is used by the administrator's
activation check, not passed to the daemon.

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec activate \
  --sha "$EDR_CANDIDATE_SHA" --health-config /etc/turansec/health.json --dry-run
```

Remove `--dry-run` only when the package and host change are authorized.
Endpoint-only hosts omit `--health-config`. Activation starts the server and
requires a direct TLS 1.3 operator session with verified server identity and
matching enrolled principal. Redirects and proxy environment settings are not
used. It also requires the systemd main process to be running from the selected
release's `edrd` binary; another process answering the port is insufficient.

For an endpoint it executes the bounded heartbeat, scanner-liveness and batch
sequence successfully before starting the timer. These checks establish the
requested operations, not the full security/host acceptance verdict.

Inspect and collect the approved host evidence:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec status
sudo systemctl status turansec-edrd.service turansec-agent.timer
sudo systemctl show turansec-agent.service -p Result -p ExecMainStatus
```

Select only installed units. Once startup, acceptance and reboot behavior have
been approved, enable the desired boot units explicitly:

```bash
sudo systemctl enable turansec-edrd.service
sudo systemctl enable turansec-agent.timer
```

The installer never silently enables boot persistence. Do not enable the oneshot
agent service itself; its timer schedules it. The installer's `status` reports
the last recorded installation operation; use systemd and authenticated probes
for current process health.

## 5. Upgrade and rollback

First stage the new approved complete release. Preserve the previous directory,
receipt, credentials and database recovery plan. Drain or account for queued
work before the maintenance window; stopping an active bounded worker may leave
a lease to expire/recover, so verify durable queue state during acceptance.

Run `activate --sha NEW_FULL_SHA` with the same health configuration. There is
no second registration step. The installer serializes changes, verifies both
release trees, stops the timer/worker, atomically selects the new complete
binary/UI tree, refreshes its managed units and starts the components. It does
not migrate the database or change credentials.

If restart or health validation fails, it restores the previous release and
units, restarts them, and requires their health checks to pass. Exit status `3`
means the candidate failed and the prior release was restored and healthy.
Exit status `4` means rollback itself failed and operator recovery is required.
An initial installation with no previous running version stops its services
on failure and records `initial_start_failed`; it does not claim a rollback.

To deliberately select a previously verified compatible release:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec rollback \
  --sha PREVIOUS_FULL_SHA --health-config /etc/turansec/health.json --dry-run
```

Review the dry run, then remove `--dry-run` within the authorized window.
Database compatibility is an external prerequisite. Never apply reverse SQL
merely because binary rollback is available.

`activation.json` and `.service-installation.json` record the selected version
and operation state. A pending/interrupted or failed recovery state is a stop
condition. Preserve the records, stop managed units, inspect the actual
`current` target and unit hashes, and have the deployment owner approve a
recovery plan. Do not delete the journal merely to bypass the guard.

## 6. Uninstall without deleting data or credentials

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec uninstall --dry-run
```

Remove `--dry-run` for the approved removal. Uninstall stops/disables only the
managed units, removes their unchanged unit files and reloads systemd. It
preserves configuration, private keys, database contents, releases, receipts
and the installation record. The dynamic service identity disappears when its
unit stops. Credential retirement and package/data retention are separate
administrator actions; there is no purge option.

## Validation scope and limitations

`python3 scripts/release/test_linux_service.py` verifies archive/path checks,
filesystem staging, credential mapping, real systemd unit parsing, registration,
bounded timer sequencing, process-health requirements, failed-upgrade recovery,
secret preservation and uninstall behavior. Service operations in those
filesystem tests use an explicit test implementation. Native systemd startup,
boot persistence, Linux scanner/queue behavior under the real service identity
and actual service rollback still require the authorized host.

The same test command also makes real TLS 1.3 loopback connections using
ephemeral test-only CA and client identities. It verifies the probe's expected
tenant/operator match, forbidden-session handling, proxy bypass and refusal to
follow redirects. The TLS fixture is not the EDR service and does not grant
an integrated or native-host acceptance result.

Publisher signing, Windows installation/Authenticode, both host acceptance
records, independent InfoSec/QA approval and deployment authorization remain
separate release gates. Neither the installer nor a passing fixture test grants
them.

The credential and timer behavior follows the primary
[systemd execution documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html)
and [systemd timer documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html).
