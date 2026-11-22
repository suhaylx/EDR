# TuranSec EDR Installation Manual

Dashboard and Windows and Linux Agents

Edition 1 • 22 November 2026 • Asia/Tashkent

This manual explains how an administrator prepares and verifies the TuranSec
engineering candidate: the Go and PostgreSQL backend with the React dashboard,
the Linux endpoint service and timer, and the Windows portable endpoint client.
Start with package preparation, install the dashboard, enroll each endpoint,
and follow the relevant operating-system chapter. Commands include expected
results and recovery checks so an installation can be reviewed before use.

**Source status.** The corrective code is merged to `main` through
[pull request 182](https://github.com/suhaylx/EDR/pull/182). The installation
examples are pinned to the immutable implementation commit
`eedfc0595e3f42983a18c64be86846a288da78b3`. Its tree is identical to the reviewed
and tested corrective head `fffd5bda9397a68b91f3c141b0d459eff5b9e70d`.
The full [candidate CI on the merged commit](https://github.com/suhaylx/EDR/actions/runs/44976030713)
and [starter CI](https://github.com/suhaylx/EDR/actions/runs/44976030763) passed.
This manual is a later documentation update; its publication does not change
the identity of an already built binary or archive.

**Installation scope.** These procedures describe the current controlled lab
candidate. The source has passed engineering checks. Actual Ubuntu 24.04 and
Windows Server 2022 installed-host acceptance, approved package signatures,
live service and database rollback, and deployment approval are separate
remaining requirements. The Windows workflow currently runs bounded commands;
it does not provide an accepted persistent Windows service or MSI installer.
No hosts were installed or configured while preparing this manual.

## Installation map

| Component | Current installation path | Primary interface |
| --- | --- | --- |
| Dashboard and backend | Complete Linux package, PostgreSQL 16, enrolled operator certificate, systemd service | `https://127.0.0.1:9444/` |
| Linux endpoint | Complete Linux package, enrolled agent certificate, local ClamAV, bounded systemd service and timer | Agent mTLS on local port 9443 |
| Windows endpoint | Source-built or verified packaged EXE, enrolled agent certificate, local ClamAV, explicit PowerShell commands | Agent mTLS on local port 9443 |
| Database | Dedicated local database, migration administrator and two distinct restricted serving logins | Numeric loopback PostgreSQL address |
| Remote lab access | Existing approved SSH access with an explicit local forward and end-to-end mTLS | Local 9444 for analysts or 9443 for endpoints |

### Installation order

1. Obtain the exact source and prepare or independently verify a fresh package.
2. Prepare the backend database, apply migrations through 0014, provision PKI
   and register the health and human operator identities.
3. Configure and activate the dashboard service, then verify the authenticated
   session and open the React SOC.
4. Complete the issuer-controlled enrollment procedure for each Linux or
   Windows endpoint. Provision that endpoint's own certificate and private key.
5. Install the relevant endpoint workflow, verify heartbeat and scanner state,
   and request one harmless bounded path scan from a scanner-role SOC account.
6. Record installed-host acceptance and rehearse the supported rollback before
   requesting a deployment decision.

For a combined server and Linux endpoint under one `/opt/turansec` prefix,
finish database and PKI preparation, endpoint enrollment and Linux prerequisites
before initial registration. Register both configurations together, then
activate with the server health configuration. The server-only sequence above
must be adjusted for that combined installation.

Read the **Package preparation** chapter first. Then use **Dashboard and backend
installation**, **Endpoint enrollment**, and either **Linux endpoint installation**
or **Windows endpoint installation**. The final operational chapters cover
rollback, evidence and acceptance. The repository copy is the easiest format
for copying long shell and PowerShell commands without layout wrapping.

### Command conventions

Run Bash commands on the named Linux build or installation host and PowerShell
commands on the named Windows endpoint. Do not run the whole document as one
script. Commands that change services or the database are for the administrator
of the intended installation. A `--dry-run` is a preview; it does not establish
root permissions, native systemd behavior, successful TLS health or host
acceptance. Review it, then perform the same operation without `--dry-run` when
that installation step is authorized.

Uppercase values such as `ENROLLED_TENANT`, `APPROVED_EDR_HOST` and
`REPLACE_WITH_APPROVED_64_HEX_DIGEST` are placeholders. Replace them with the
approved identifiers or paths before running a command. Paths containing real
secrets must remain outside the repository, package and evidence directory.
Example identifiers are not credentials and are not automatically created by
the application. Keep source SHA, archive manifest and executable `--version`
identity together in the installation record.

### Evidence behind this edition

The corrective PR passed all 20 GitHub check runs across 11 workflows. Its
required pipeline recorded Go build, tests, race and vet; 60 Linux and 48 Windows
Rust tests; 374 frontend unit tests and 14 real Chromium scenarios; 68 release
tool tests; 11 integrated checks; and PostgreSQL authorization, concurrency and
actual restart checks. All eight required jobs also passed after the merge.
See the [reviewed PR candidate run](https://github.com/suhaylx/EDR/actions/runs/44974711982/attempts/1)
and the merged-commit run linked above. These results establish the exercised
engineering behavior and do not replace native installation or release evidence.

## Package preparation

The installation source for this manual is commit **`eedfc0595e3f42983a18c64be86846a288da78b3`** on `main`, produced by merging PR #182. Its code tree is the same as tested PR head `fffd5bda9397a68b91f3c141b0d459eff5b9e70d`. The full [candidate workflow on merged main, run 44976030713](https://github.com/suhaylx/EDR/actions/runs/44976030713), and [starter workflow, run 44976030763](https://github.com/suhaylx/EDR/actions/runs/44976030763), passed. The package commands below embed the merged commit in the binaries and manifest.

The existing `v0.1.0-rc.2` packages were built from `65702cbc1cde6750304d9e438bb27bc0537c2d45`. They lack migration `0014_enrollment_wallclock.up.sql` and the corresponding service startup guard. **Build a new complete package from the merged commit, or obtain a separately verified new package for that exact commit.** Copying a new migration beside an old binary does not produce the corrected complete release.

This chapter supplies operator procedures; it does not record a completed installation. The hosted Linux jobs ran on Ubuntu 26.04. For the Ubuntu 24.04 target, build the Linux package natively on Ubuntu 24.04 x86_64, or independently establish compatibility of the package's linked libraries on that target before installation acceptance. A binary built on a newer distribution must not be assumed compatible with an older one.

### Obtain the exact source and build a fresh package

On the build machine, use Git, Python 3.12 or newer, OpenSSL, a native compiler/linker, Go 1.25 or newer, the repository's pinned Rust 1.100.0 toolchain, and Node 22.12 or newer with npm. Use the committed Go, Cargo and npm lockfiles; the packaging command does so automatically. PostgreSQL is needed for database tests and the server, but is not invoked by this package build. The installed endpoint does not need Go, Rust or Node. These requirements follow the [packager](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/package-candidate.py), [Go module](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/go.mod), and [Rust toolchain file](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/rust-toolchain.toml).

```bash
set -euo pipefail
export EDR_CANDIDATE_SHA=eedfc0595e3f42983a18c64be86846a288da78b3
git clone https://github.com/suhaylx/EDR.git turansec-edr-source
cd turansec-edr-source
git checkout --detach "$EDR_CANDIDATE_SHA"
test "$(git rev-parse HEAD)" = "$EDR_CANDIDATE_SHA"
export EDR_SOURCE_DIR="$PWD"
export EDR_PACKAGE_DIR="$HOME/turansec-release-eedfc0595e3f"
```

The output directory must be outside the source repository. The helper exports committed files with `git archive`; it refuses to overwrite existing package output. Keep this reviewed source checkout available for verification and installation tools. When running a helper as root, use an administrator-controlled copy of that reviewed code.

For a signed Linux package, set the next two paths to the organization's existing signing hook and independently provisioned publisher public key. The signing hook receives the manifest pathname and the output signature pathname as its two arguments. The helper does not create or trust a new signing key.

```bash
export EDR_SIGNER_HOOK=/approved/release/sign-manifest
export EDR_TRUSTED_KEY=/approved/trust/release-publisher.pem
python3 "$EDR_SOURCE_DIR/scripts/release/package-candidate.py" build \
  --candidate-sha "$EDR_CANDIDATE_SHA" --target linux-x86_64 \
  --output "$EDR_PACKAGE_DIR" \
  --signer-hook "$EDR_SIGNER_HOOK" --trusted-key "$EDR_TRUSTED_KEY"
```

The resulting signed filenames are:

| File | Purpose |
| --- | --- |
| `turansec-edr-eedfc0595e3f-linux-x86_64.tar.gz` | Complete server, endpoint, web assets, migrations, configuration examples and installation tools |
| `turansec-edr-eedfc0595e3f-linux-x86_64.manifest.json` | Source commit, archive identity and individual file inventory |
| `turansec-edr-eedfc0595e3f-linux-x86_64.manifest.sig` | Detached manifest signature |

For an explicitly authorized unsigned engineering lab, use a different output directory and `--stage-only` instead of signing arguments:

```bash
python3 "$EDR_SOURCE_DIR/scripts/release/package-candidate.py" build \
  --candidate-sha "$EDR_CANDIDATE_SHA" --target linux-x86_64 \
  --output "$HOME/turansec-lab-eedfc0595e3f" --stage-only
```

That archive and manifest have `-unsigned` before their extensions; no signature is produced. This is an engineering candidate, with its unsigned status retained in the installation receipt. It cannot supply publisher-signature evidence.

### Verify before executing a downloaded package

Transfer the complete package and sidecars through the approved artifact channel. Set the paths below to their actual locations. `/staging` and `/approved` are examples that must be replaced where necessary. Provision the publisher public key independently of the downloaded package.

```bash
export EDR_ARCHIVE=/staging/turansec-edr-eedfc0595e3f-linux-x86_64.tar.gz
export EDR_MANIFEST=/staging/turansec-edr-eedfc0595e3f-linux-x86_64.manifest.json
export EDR_SIGNATURE=/staging/turansec-edr-eedfc0595e3f-linux-x86_64.manifest.sig
export EDR_TRUSTED_KEY=/approved/trust/release-publisher.pem

python3 "$EDR_SOURCE_DIR/scripts/release/package-candidate.py" verify \
  --archive "$EDR_ARCHIVE" --manifest "$EDR_MANIFEST" \
  --signature "$EDR_SIGNATURE" --trusted-key "$EDR_TRUSTED_KEY" \
  --expected-sha "$EDR_CANDIDATE_SHA"
```

Require successful signature verification, the expected full source SHA, and the approved publisher-key fingerprint. Save the verification result with the build and host records. Run this verifier from the reviewed checkout, rather than executing a helper from an archive whose trust has not yet been established.

Stage the verified complete release with the Linux installer:

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec stage \
  --archive "$EDR_ARCHIVE" --manifest "$EDR_MANIFEST" \
  --expected-sha "$EDR_CANDIDATE_SHA" \
  --signature "$EDR_SIGNATURE" --trusted-key "$EDR_TRUSTED_KEY" --dry-run
```

Review the dry run, then repeat that command without `--dry-run` to stage it. A dry run previews the operation; it does not prove actual root permissions, systemd behavior or authenticated health. Staging verifies the full file inventory and rejects path traversal, symlinks, special files, unexpected files and unsafe permission bits. It creates `/opt/turansec/releases/FULL_SHA/` and a corresponding receipt under `/opt/turansec/receipts/`; it does not start services or select a new running release. Keep `/opt/turansec` and its ancestors administrator owned, without symlinks or group/world write permission. Runtime files cannot be placed under `/home`, `/root`, `/run/user`, `/tmp` or `/var/tmp`, which the service sandbox hides or replaces. See the [installer implementation](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/linux_service.py).

For the unsigned lab alternative, point `EDR_ARCHIVE` and `EDR_MANIFEST` at the `-unsigned` files and replace the two signing arguments with:

```text
--unsigned-lab --manifest-sha256 EXPECTED_MANIFEST_SHA256_FROM_REVIEWED_RECORD
```

The expected manifest digest must come from an independent reviewed build record. Calculating a digest from the same untrusted download does not establish trust. The standalone `verify` command requires a signature; unsigned inspection is performed by `stage` with these explicit lab arguments.

## Dashboard and backend installation

### Supported installation and source identity

The authenticated dashboard is the built React application served by `edrd`,
the Go/PostgreSQL service. Its default browser address is
**`https://127.0.0.1:9444/`**; `/soc/` serves the same application. The endpoint
listener is separate at **`127.0.0.1:9443`**. Both listeners require mutual TLS.
The service rejects non-loopback listener addresses. Port 8080 and the Vite
development server belong to older development demonstrations and are not this
installation path. A separate Node/Vite process is not needed on a packaged
dashboard host. [D1, D2]

Use the merged source commit:

```bash
export EDR_CANDIDATE_SHA=eedfc0595e3f42983a18c64be86846a288da78b3
```

Its source tree matches tested corrective commit
`fffd5bda9397a68b91f3c141b0d459eff5b9e70d`. A package newly built from the merged
commit must identify `eedfc0595e3f42983a18c64be86846a288da78b3` in its manifest
and executable version output. Earlier archives naming `65702cbc1cde...` do not
contain these corrections. Follow the common package verification/staging
section before running any installer.

The supported candidate is a controlled loopback installation. Remote analysts
or endpoints need an existing approved encrypted tunnel with end-to-end TLS
verification. Public binding, a remote PostgreSQL topology, an SSO gateway or
an enterprise reverse-proxy deployment needs a separately reviewed design.
Passing CI and merging source do not establish those deployment capabilities.

### D1 Prepare the dashboard host

| Item | Required preparation |
|---|---|
| Target host | Authorized Ubuntu x86_64 host; the installation guide targets Ubuntu 24.04. Confirm actual binary/library compatibility and installed-host acceptance. |
| Service installer | Python 3.11+, OpenSSL 3, curl, systemd 249+, root for service registration and activation. |
| Database | PostgreSQL 16 client (`psql`) and a dedicated PostgreSQL 16 database on an explicit numeric-loopback address; controlled migration administrator plus two separate unprivileged serving logins. |
| Release | Complete verified package containing `bin/edrd`, `web/`, migrations, bootstrap, service tooling and templates. |
| Server identity | Approved server certificate/private key and server CA trust chain. |
| Client trust | Separate agent and operator CA bundles with no shared CA signing keys. |
| Health identity | An enrolled viewer operator certificate/private key, used only for activation checks. |
| Human operator | A separate approved operator client identity imported into the analyst's browser profile. |

Install `curl` and, on the host initiating a remote forward, `openssh-client` through the approved Ubuntu package process. Verify `curl`, `ssh`, `openssl`, `python3` and the PostgreSQL 16 `psql` command are available for the steps that use them.

If building the package from source, the common build procedure needs Go
1.25.0+, Rust/Cargo, Node 22.12+ with npm and the committed dependency lockfiles.
The packaged host does not need these build toolchains merely to run `edrd`.
Do not create static Linux identities named `turansec-edrd` or
`turansec-agent`; the supplied units use systemd dynamic identities and reject
conflicting pre-existing accounts. [D1, D3, D4]

### D2 Provision the dedicated PostgreSQL database

Install PostgreSQL 16 through the approved Ubuntu package or database-management process. Have the database administrator provision an empty dedicated database, such as
`edr`, owned by the approved migration administrator. The bootstrap executor needs DBA authority to create the dedicated group roles, grant memberships and change function owners; database ownership alone is insufficient. This authority is temporary administrative context and must never be assigned to either serving login. Neither serving login may own the
database, schemas, tables or privileged functions. The runtime and registry
logins must be distinct `LOGIN INHERIT` identities without superuser, role
creation, database creation, replication or RLS-bypass attributes, and without
unrelated memberships. Example role definitions in the administrator's
interactive `psql` session are:

```sql
CREATE ROLE edr_service_runtime LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE edr_service_registry LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
```

Provision authentication through the approved secret-management/database
procedure. Interactive `psql` supports `\password edr_service_runtime` and
`\password edr_service_registry` when an approved password workflow is used;
do not embed actual passwords in SQL files, shell history or this manual.

The following commands assume an administrator-maintained PostgreSQL service
entry named `edr_migration_admin` that points to the intended dedicated `edr`
database. Confirm the service entry names the intended numeric-loopback host, port, database and approved administrator before using it. Keep authentication material in the protected database secret mechanism. Run from the reviewed repository root. **Use the complete migration
loop only for a new empty database.** [D5]

```bash
set -euo pipefail
for migration in backend/migrations/*.up.sql; do
  psql 'service=edr_migration_admin' -X -v ON_ERROR_STOP=1 -f "$migration"
done
psql 'service=edr_migration_admin' -X -v ON_ERROR_STOP=1 \
  -v runtime_login=edr_service_runtime \
  -v registry_login=edr_service_registry \
  -v dedicated_edr_database=true \
  -f backend/bootstrap/runtime_privileges.sql
```

At this commit, the ordered migration chain is 0001–0014. Bootstrap grants
the runtime login only the reviewed operational authority and the separate
registry login read-only identity access. It refuses unsafe role reuse and
requires both clock-correction capabilities. Verify:

```sql
SELECT capability, version
FROM public.edr_schema_capabilities
WHERE capability IN ('scan_lease_wallclock', 'enrollment_wallclock')
ORDER BY capability;
```

Expected: exactly these two capability records, each at version **1**. `edrd`
refuses to open either listener if a required capability is missing or
incompatible. A database already at 0012 needs 0013 followed by 0014; a database
already at 0013 needs only 0014. For either upgrade, take and verify the approved
backup, drain serving processes in the authorized maintenance window, apply
the required upgrades as migration administrator and reapply bootstrap with
the existing serving logins. Check schema/application compatibility before
restart. [D1, D5]

Provision `/etc/turansec/runtime.dsn` and `/etc/turansec/registry.dsn` through
the approved secret mechanism. Each contains one PostgreSQL URI. Both must
name the same explicit numeric-loopback host, port and database, with different
login names. For example, the **shape**, with a placeholder rather than a real
password, is:

```text
postgresql://edr_service_runtime:ENCODED_SECRET@127.0.0.1:5432/edr?sslmode=disable
postgresql://edr_service_registry:ENCODED_SECRET@127.0.0.1:5432/edr?sslmode=disable
```

Put each URI in its corresponding file, never both in one file. Encode reserved
URI characters in credentials correctly. `sslmode=disable` is permitted only
within this candidate's controlled loopback database boundary; this example
does not authorize a remote plaintext database. Keep both files root-owned,
mode 0600 or 0400, with no symlinks or writable ancestors. [D1, D5]

### D3 Provision TLS identities and enroll operators

Use the organization's approved CA and issuance workflow. The repository does
not supply a production issuer CLI or an initial administrator password.

| Identity | Certificate requirements |
|---|---|
| Server | Valid non-CA leaf; matching private key; digital-signature usage and ServerAuth EKU; SAN matching the client-facing address. Access through `https://127.0.0.1:9444` needs IP SAN `127.0.0.1`. |
| SOC operator | Valid non-CA leaf; digital-signature usage and ClientAuth EKU; exactly one URI SAN: `spiffe://turansec.local/tenants/TENANT/operators/OPERATOR`. |
| Endpoint | Uses the separate agent CA and an `/agents/AGENT` URI SAN; an agent certificate cannot be used as a dashboard operator identity. |

Tenant and operator identifiers must use 1–96 letters, digits, dots,
underscores or hyphens, excluding `.` and `..`. The server checks the actual
leaf validity period and matches its DER SHA-256 fingerprint to the operator
registry on every request. The role comes from that registry, not from a
browser field or request header. [D1, D6]

Obtain the approved operator leaf's fingerprint without reading its private key:

```bash
openssl x509 -in /approved/pki/operator.pem -outform DER |
  openssl dgst -sha256
```

Use the resulting 64 hexadecimal digest characters for registration. The
fingerprint is over the DER certificate bytes, not the PEM text or public key.
Verify the leaf/chain, tenant, operator, validity and approved role before
registration. [D6]

If the tenant does not exist, a migration administrator may create the approved
new tenant and record its creation in one transaction:

```sql
BEGIN;
INSERT INTO public.edr_tenants(tenant_id, display_name)
VALUES ('tenantA', 'Approved tenant display name');
INSERT INTO public.edr_enrollment_audit(tenant_id, event_type, actor_id)
VALUES ('tenantA', 'tenant_created', current_user);
COMMIT;
```

Use this only for a new tenant. Do not reactivate a disabled tenant or replace
existing registrations as an installation shortcut.

For a new operator in an existing active tenant, use an administrator `psql`
session with `ON_ERROR_STOP` and substitute the reviewed identifiers/digest:

```sql
\set ON_ERROR_STOP on
\set tenant_id 'tenantA'
\set operator_id 'viewer01'
\set operator_fp 'REPLACE_WITH_APPROVED_64_HEX_DIGEST'
BEGIN;
INSERT INTO public.edr_soc_operators
  (tenant_id, operator_id, fingerprint_sha256, role)
SELECT tenant_id, :'operator_id', decode(:'operator_fp', 'hex'), 'viewer'
FROM public.edr_tenants
WHERE tenant_id=:'tenant_id' AND disabled_at IS NULL
RETURNING tenant_id, operator_id, role;
COMMIT;
```

Expected: one returned row and `INSERT 0 1`. Zero rows means the tenant was
absent or disabled; a duplicate-key error means the identity already exists.
Investigate either outcome rather than overwriting a registration. Use
`scanner` only for an operator explicitly authorized to request/cancel scans
and change analyst case state. `viewer` is read-only. Register a separate
viewer identity for the service health check. Preserve the approved
registration decision in the change record: this schema has no dedicated
operator-provisioning audit event type. [D6, D7]

### D4 Configure the packaged server

Keep `/etc/turansec` and its health subdirectory administrator owned:

```bash
sudo install -d -o root -g root -m 0700 /etc/turansec /etc/turansec/health
```

Provision the approved files at the paths below and create
`/etc/turansec/edrd.json` from `config/edrd.example.json`:

```json
{
  "agent_listen": "127.0.0.1:9443",
  "soc_listen": "127.0.0.1:9444",
  "server_cert_file": "/etc/turansec/server.pem",
  "server_key_file": "/etc/turansec/server.key",
  "agent_ca_file": "/etc/turansec/agent-ca.pem",
  "operator_ca_file": "/etc/turansec/operator-ca.pem",
  "registry_dsn_file": "/etc/turansec/registry.dsn",
  "runtime_dsn_file": "/etc/turansec/runtime.dsn",
  "ui_dir": "/opt/turansec/current/web"
}
```

Configuration, private keys, DSNs and the health configuration require root
ownership and mode 0600 or 0400. Public CA/certificate files can be 0644 inside
the protected directory. Files must be regular, non-symlink files, and paths
must be absolute. Preserve `/opt/turansec/current/web` for the managed service;
the launcher pins its binary and UI to the same selected release. [D1, D3]

Provision `/etc/turansec/health.json` from
`config/service-health.example.json`, with these fields:

```json
{
  "origin": "https://127.0.0.1:9444",
  "server_ca_file": "/etc/turansec/health/server-ca.pem",
  "operator_cert_file": "/etc/turansec/health/viewer.pem",
  "operator_key_file": "/etc/turansec/health/viewer.key",
  "expected_tenant_id": "tenantA",
  "expected_operator_id": "health-viewer"
}
```

The health-viewer certificate must have that exact enrolled tenant/operator
identity. The server CA in this file authenticates the server; it is not a
substitute for the separate operator CA that issued the viewer leaf.

### D5 Register and activate the dashboard service

After the verified complete package is staged, run the server-only
registration preview from the reviewed checkout:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec register \
  --sha "$EDR_CANDIDATE_SHA" \
  --server-config /etc/turansec/edrd.json --dry-run
```

Review the result, then repeat without `--dry-run` for the authorized
registration. Omit `--agent-config` for this server-only host. If this fresh host will also run the Linux endpoint under the same prefix, finish its prerequisites first and register both configurations together as described in the Linux chapter; do not register a server-only installation and assume a later registration adds the agent. Registration
writes `turansec-edrd.service` and selects the initial release but reports
`services_started: false` and `autostart_enabled: false`.

Preview activation, then remove `--dry-run` during the approved installation
window:

```bash
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec activate \
  --sha "$EDR_CANDIDATE_SHA" \
  --health-config /etc/turansec/health.json --dry-run
```

Successful actual activation reports `result: "active-and-health-checked"` and
the selected `source_sha`. It verifies the authenticated operator session and
that systemd's main process runs the selected `edrd` executable. Another
process merely answering port 9444 cannot satisfy this check. [D3, D8]

For an approved direct diagnostic session, the actual daemon interfaces are:

```bash
/opt/turansec/current/bin/edrd --version
/opt/turansec/current/bin/edrd --config /absolute/private/edrd.json
```

Direct execution requires a dedicated unprivileged identity with permission to
read its provisioned configuration/credentials; it does not use root-only
source files through systemd credential delivery. Prefer the managed service
for the installation above. Version output is `edrd VERSION source=FULL_SHA`.
The startup log identifies `transport=mTLS database=PostgreSQL status=candidate`.
There is no `edrd install`, public HTTP health endpoint or password-login flag.
[D1]

### D6 Verify the service and open the dashboard

On the dashboard host:

```bash
sudo systemctl status turansec-edrd.service
sudo python3 scripts/release/linux_service.py --prefix /opt/turansec status
sudo curl --fail --show-error --silent --noproxy '*' --tlsv1.3 \
  --cacert /etc/turansec/health/server-ca.pem \
  --cert /etc/turansec/health/viewer.pem \
  --key /etc/turansec/health/viewer.key \
  https://127.0.0.1:9444/soc/v1/session
```

Expected: systemd reports the service active, the installation record names the
selected SHA, and the session endpoint returns HTTP 200 with:

```json
{
  "tenant_id": "tenantA",
  "operator_id": "health-viewer",
  "role": "viewer",
  "server_time": "CURRENT_SERVER_UTC_TIMESTAMP"
}
```

The installer's status records its last operation; use systemd and the
authenticated probe to establish current service health. Do not use `curl -k`
or disable hostname verification to get a successful result. Missing operator
client credentials normally fail the TLS handshake; an unregistered, revoked,
expired or mismatched operator identity is denied. [D1, D2, D8]

For the human analyst, import the approved server CA chain into the managed
browser/OS trust store and the analyst's own client certificate/private-key
bundle into the personal/client-certificate store. Use the organization's
browser enrollment process; the backend offers no browser certificate-download
or account-registration UI. Keep the operator private key on its intended
workstation and do not reuse the automated health identity for analysts.

Browse to `https://127.0.0.1:9444/` on the service host or through an approved
local forward, select the proper client certificate when requested, and choose
**Connect** in the SOC. The session must show the approved tenant/operator/role.
Viewer access stays read-only; scanner-role controls can request one bounded
path scan, cancel an owned pending request, and manage supported alert/case
workflow. A new installation with no enrolled endpoints should show empty or
unknown inventory, not a protected fleet. [D2, D6]

For an approved remote analyst workstation, an example existing SSH access path
is:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:9444:127.0.0.1:9444 APPROVED_USER@APPROVED_EDR_HOST
```

Then browse to the same local HTTPS address on that workstation. Keep the
forward bound to `127.0.0.1`, verify the SSH host through the approved process,
and retain end-to-end operator mTLS and server certificate verification. This
is an operator-managed transport example, not an installed TuranSec gateway.
Opening public port 9444 or trusting forwarded identity headers is not an
equivalent deployment. Endpoint tunnelling uses the separately approved agent
port 9443 path described in the endpoint section. [D1, D6]

After installed-host startup, acceptance and reboot behavior are approved,
enable server boot startup explicitly:

```bash
sudo systemctl enable turansec-edrd.service
```

### D7 Recognize the supported failure and recovery states

| Symptom | Check |
|---|---|
| Required clock capability unavailable/incompatible | Confirm migrations through 0014, both capability versions equal 1, and the restricted-role bootstrap; do not bypass the startup check. |
| Database/least-privilege preflight fails | Confirm both DSN files name the same numeric-loopback host/port/database, different approved logins, correct permissions and required role membership. |
| TLS handshake fails | Check server CA/SAN, client CA chain, ClientAuth/ServerAuth purpose, validity, private-key match and TLS 1.3 support. |
| HTTP 401 | Check the operator URI identity, leaf fingerprint, active tenant, operator revocation and certificate validity. |
| HTTP 403 | Check the enrolled role/tenant and same-origin browser request; do not inject identity headers. |
| HTTP 503 | Registry/service data is unavailable; the UI clears current records rather than treating old data as authoritative. |
| `/lab/` or `/api/` is 404 on port 9444 | Expected: these development routes are not mounted on the secure operator listener. |
| A mutation outcome is unknown | Reconnect and inspect authoritative current state before another action; no automatic retry should occur. |

Use the common complete-package rollback procedure for binary/UI rollback and
the separately approved database recovery plan for schema/data restoration.
Reversing SQL migrations or replacing only the dashboard assets does not
constitute a verified rollback. [D2, D3, D5]

### Dashboard source references

- **D1:** [Daemon flags, configuration, database capability checks and listeners](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/cmd/edrd/main.go).
- **D2:** [Authenticated React serving and session endpoint](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/internal/edr/soc_application.go), [SOC client behavior](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/frontend/src/soc-api.ts).
- **D3:** [Linux service installation guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/LINUX_SERVICE_INSTALLATION.md).
- **D4:** [Complete installation prerequisites](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/INSTALLATION.md), [Go module](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/go.mod), [frontend scripts](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/frontend/package.json).
- **D5:** [Restricted database bootstrap](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/bootstrap/runtime_privileges.sql), [role and upgrade guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/backend/RUNTIME_DATABASE_ROLES.md).
- **D6:** [Operator certificate verification and registry lookup](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/internal/edr/soc_operator_mtls.go).
- **D7:** [Operator registry schema](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/migrations/0010_soc_operator_scan_jobs.up.sql), [tenant and enrollment-audit schema](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/migrations/0001_agent_enrollment.up.sql).
- **D8:** [Service activation and authenticated health implementation](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/linux_service.py), [credential launcher](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/systemd_launcher.py).

## Endpoint enrollment

Complete this procedure before starting a Windows or Linux endpoint with its
new identity. It applies to merged source
**`eedfc0595e3f42983a18c64be86846a288da78b3`**, after migrations 0001–0014 and
the restricted-role bootstrap.

### What this release supplies

The repository supplies certificate-validation library functions and an atomic
PostgreSQL registration function. It has **no self-enrollment CLI, public
enrollment endpoint, production certificate issuer or automatic first-device
wizard**. The organization must supply an authenticated issuance procedure that
authorizes the tenant/device and binds a fresh, single-use challenge to the
device's signed certificate request. The database function cannot establish
those facts on its own. If that issuance procedure is unavailable, fresh
endpoint enrollment remains an unmet installation prerequisite. [E1, E2]

Use the approved migration/enrollment administrator for the database steps.
The two serving logins must remain restricted: the bootstrap deliberately
excludes challenge consumption, enrollment and certificate rotation from their
execution grants. Keep the issuer's authorization record, certificate identity
and administrative change record together. Never place a private key or the
raw challenge secret in SQL, a manifest or shared acceptance evidence. [E1, E3]

### 1 Authorize the device and record its challenge

Start with an active tenant already created by the dashboard administrator.
Choose a new agent ID and the actual platform, `windows` or `linux`. Tenant and
agent IDs use 1–96 letters, digits, dots, underscores or hyphens, excluding `.`
and `..`. An existing agent, including a revoked one, cannot be enrolled again
through this initial-enrollment function. [E1]

The authorized issuer supplies a fresh challenge UUID, a cryptographically
random challenge secret, its 32-byte SHA-256 digest and a short expiration
approved by the issuance policy. Deliver and validate the challenge only
through that issuer's authenticated workflow. Its record must bind the
challenge to the approved tenant, agent and certificate request; the SQL table
stores the tenant/agent binding and digest, but has no CSR field. Do not reuse
a demonstration challenge or invent a different proof protocol for this
installation. [E2, E4]

Prepare `/approved/enrollment/record-challenge.sql` from the following `psql`
template, substituting the issuer's actual reviewed metadata. Keep this file
administrator controlled. The uppercase values are placeholders and must be
replaced. The
challenge digest is exactly 64 hexadecimal characters, without separators.
Use an explicit UTC expiration, such as the format
`YYYY-MM-DD HH:MM:SS+00`; do not extend an already expired challenge.

```sql
\set ON_ERROR_STOP on
\set tenant_id 'tenantA'
\set agent_id 'linux01'
\set platform 'linux'
\set challenge_id 'REPLACE_WITH_FRESH_CHALLENGE_UUID'
\set challenge_digest 'REPLACE_WITH_64_HEX_SHA256_OF_CHALLENGE_SECRET'
\set challenge_expires 'REPLACE_WITH_APPROVED_UTC_EXPIRATION'

WITH inserted AS (
  INSERT INTO public.edr_enrollment_challenges
    (challenge_id, tenant_id, agent_id, challenge_digest,
     created_at, expires_at)
  SELECT :'challenge_id'::uuid, t.tenant_id, :'agent_id',
         decode(:'challenge_digest', 'hex'), clock_timestamp(),
         :'challenge_expires'::timestamptz
  FROM public.edr_tenants AS t
  WHERE t.tenant_id = :'tenant_id' AND t.disabled_at IS NULL
    AND :'challenge_expires'::timestamptz > clock_timestamp()
    AND NOT EXISTS (
      SELECT 1 FROM public.edr_agents AS a
      WHERE a.tenant_id = t.tenant_id AND a.agent_id = :'agent_id'
    )
  RETURNING challenge_id
)
SELECT count(*) = 1 AS challenge_recorded FROM inserted
\gset
\if :challenge_recorded
  \echo 'Challenge recorded; continue with the approved issuer proof workflow.'
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'Challenge not recorded: check tenant, agent and expiry';
  END $$;
\endif
```

Run that reviewed file against the intended dedicated database:

```bash
psql 'service=edr_migration_admin' -X -v ON_ERROR_STOP=1 \
  -f /approved/enrollment/record-challenge.sql
```

This statement stores only the digest. It does not consume the challenge or
authorize certificate issuance. Duplicate challenge UUIDs/digests and other
database errors stop execution. The final enrollment function independently
rechecks tenant/device eligibility and the challenge deadline. [E1, E4]

### 2 Validate the signed CSR and issued agent certificate

The approved issuer must authenticate the requester and verify its challenge
response before approving registration. A signed CSR proves possession of its
key when the request was signed; the CSR signature alone does not establish a
fresh challenge response or authority to join a tenant. The endpoint private
key stays in its intended protected key location. [E2]

Require all of these checks:

- The CSR signature verifies and its only SAN is
  `spiffe://turansec.local/tenants/TENANT/agents/AGENT`, with the approved IDs.
  No DNS, email or IP SANs are permitted by the enrollment validator.
- The issued leaf is a current non-CA certificate with digital-signature key
  usage, ClientAuth EKU and that same single agent URI SAN. Its public key is
  identical to the signed CSR's public key.
- The leaf chain verifies for client authentication against the controlled
  agent CA, including approved intermediates where needed. The operator CA and
  general OS root store are not substitutes for the approved agent trust pool.
- The issuer has completed its separate challenge/requester authorization and
  has approved this exact leaf for this exact platform and device. [E2]

The Go library helper `ValidateTrustedIssuedCertificateForCSR` implements CSR
signature, identity, key-binding, leaf-validity and controlled-chain checks.
It is a library function for an authenticated issuer integration, **not an
installed command**, and still requires that integration's challenge and
requester authorization. [E2]

For an administrator reviewing already issued public artifacts, these OpenSSL
3 commands inspect the CSR, certificate and trust chain. They do not create a
key or issue a certificate:

```bash
set -euo pipefail
openssl req -in /approved/enrollment/agent.csr -verify -noout -text
openssl x509 -in /approved/enrollment/agent.pem -noout -text
openssl verify -purpose sslclient \
  -CAfile /approved/pki/agent-ca.pem -no-CApath -no-CAstore \
  /approved/enrollment/agent.pem
```

When required by the approved chain, add
`-untrusted /approved/pki/agent-intermediates.pem` to `openssl verify`.
Require a valid chain and inspect the SAN, basic constraints and key usages
against the requirements above. These inspection commands support the issuer
review; they do not replace its authorization or challenge proof. [E2, E5]

Compare the following two public-key digests; they must be identical:

```bash
openssl req -in /approved/enrollment/agent.csr -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
openssl x509 -in /approved/enrollment/agent.pem -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
```

Obtain the leaf's exact certificate fingerprint and dates separately:

```bash
openssl x509 -in /approved/enrollment/agent.pem -outform DER |
  openssl dgst -sha256
openssl x509 -in /approved/enrollment/agent.pem \
  -noout -dates -dateopt iso_8601
```

The enrollment fingerprint is the SHA-256 digest of the **whole DER leaf**,
not either public-key digest. Copy its 64 hexadecimal characters and the exact
`notBefore`/`notAfter` values into the next step. Retain their UTC timezone.
Do not substitute a planned issuance window or the CA's validity dates. [E1,
E2, E5]

### 3 Complete registration atomically and require a true result

After all issuer checks have passed, prepare the administrator-controlled file
`/approved/enrollment/complete-enrollment.sql`. Copy the identical approved
challenge/tenant/agent/platform values from step 1 and supply the exact leaf
metadata derived above:

```sql
\set ON_ERROR_STOP on
\set tenant_id 'tenantA'
\set agent_id 'linux01'
\set platform 'linux'
\set challenge_id 'REPLACE_WITH_SAME_CHALLENGE_UUID'
\set challenge_digest 'REPLACE_WITH_SAME_64_HEX_CHALLENGE_DIGEST'
\set leaf_der_sha256 'REPLACE_WITH_64_HEX_SHA256_OF_DER_LEAF'
\set not_before 'REPLACE_WITH_EXACT_LEAF_NOT_BEFORE_UTC'
\set not_after 'REPLACE_WITH_EXACT_LEAF_NOT_AFTER_UTC'

SELECT public.edr_complete_agent_enrollment(
  :'challenge_id'::uuid,
  :'tenant_id',
  :'agent_id',
  decode(:'challenge_digest', 'hex'),
  :'platform',
  decode(:'leaf_der_sha256', 'hex'),
  :'not_before'::timestamptz,
  :'not_after'::timestamptz,
  current_user::text
) AS enrolled
\gset
\if :enrolled
  \echo 'Initial enrollment committed.'
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'Enrollment denied: investigate issuer and registry state';
  END $$;
\endif
```

Execute the reviewed file as the administrator:

```bash
psql 'service=edr_migration_admin' -X -v ON_ERROR_STOP=1 \
  -f /approved/enrollment/complete-enrollment.sql
```

Use this as a single autocommitted function statement; do not pre-consume the
challenge. The function atomically consumes the valid challenge, creates the
agent and certificate rows, and appends both `agent_enrolled` and
`certificate_enrolled` audit records. It checks the real clock after acquiring
the relevant locks. Expired or already consumed challenges, an ineligible
tenant/device, an invalid platform or invalid certificate dates deny
registration. Invalid certificate dates leave the challenge unconsumed. [E1]

The boolean guard matters: `SELECT ...` returning `false` is valid SQL and can
otherwise leave `psql` with exit status zero. These templates raise a SQL error
on denial; `psql -f` with `ON_ERROR_STOP=1` then exits with status 3. Do not add
a semicolon before either `\gset`: `\gset` sends the pending query once and
captures its result. [E7] A successful prior registration
must not be blindly replayed. Investigate a lost/ambiguous response by reading
the exact stored identity and audit records. An expired challenge requires a
fresh authorized issuance attempt; rotation and recovery of existing devices
are separate administrator procedures. Never bypass a denial by directly
inserting an agent/certificate or changing the challenge deadline. [E1, E3]

### 4 Verify the registration then install the endpoint files

Read the new registry state through the administrator connection. Set
`tenant_id` and `agent_id` to the approved values in that session:

```sql
\set tenant_id 'tenantA'
\set agent_id 'linux01'

SELECT a.tenant_id, a.agent_id, a.platform,
       encode(c.fingerprint_sha256, 'hex') AS leaf_der_sha256,
       c.not_before, c.not_after
FROM public.edr_agents AS a
JOIN public.edr_agent_certificates AS c
  ON c.tenant_id = a.tenant_id AND c.agent_id = a.agent_id
WHERE a.tenant_id = :'tenant_id' AND a.agent_id = :'agent_id'
  AND a.revoked_at IS NULL AND c.revoked_at IS NULL;

SELECT event_type, actor_id, occurred_at
FROM public.edr_enrollment_audit
WHERE tenant_id = :'tenant_id' AND agent_id = :'agent_id'
  AND event_type IN ('agent_enrolled', 'certificate_enrolled')
ORDER BY audit_id DESC LIMIT 2;
```

Require one active certificate row with the approved platform, exact DER
fingerprint and leaf dates, plus the two expected audit events. Provision the
approved client leaf/chain, protected private key, server trust CA and matching
tenant/agent IDs using the Windows or Linux chapter. A subsequent authenticated
heartbeat confirms the endpoint can use that enrolled identity. It does not
enroll the endpoint or prove full host acceptance. [E1, E6]

### Enrollment source references

- **E1:** [Corrected atomic initial-enrollment function](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/migrations/0014_enrollment_wallclock.up.sql), [registry and audit schema](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/migrations/0001_agent_enrollment.up.sql).
- **E2:** [CSR, leaf, key-binding and controlled-CA validation helpers](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/internal/edr/agent_certificate_validation.go), [explicit external enrollment authorization boundary](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/internal/edr/agent_enrollment_postgres.go).
- **E3:** [Restricted runtime bootstrap](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/bootstrap/runtime_privileges.sql), [database role guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/backend/RUNTIME_DATABASE_ROLES.md).
- **E4:** [Challenge table and issuer prerequisites](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/migrations/0004_enrollment_challenges.up.sql); migration 0014 replaces the historical consume implementation.
- **E5:** OpenSSL 3 documentation for [CSR verification](https://docs.openssl.org/3.0/man1/openssl-req/), [certificate inspection](https://docs.openssl.org/3.0/man1/openssl-x509/), [public-key conversion](https://docs.openssl.org/3.0/man1/openssl-pkey/) and [chain verification](https://docs.openssl.org/3.0/man1/openssl-verify/).
- **E6:** [Live agent certificate verification](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/backend/internal/edr/agent_identity.go), [supported endpoint commands](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/main.rs).
- **E7:** [PostgreSQL 16 psql: conditional commands, query-result variables and exit status](https://www.postgresql.org/docs/16/app-psql.html).

## Linux endpoint installation

### L1 Prepare Ubuntu 24 04 and ClamAV

The Linux endpoint target is **Ubuntu 24.04 x86_64**, with Python 3.11+, OpenSSL and systemd 249+. Ubuntu 24.04 supplies Python 3.12. Install runtime dependencies from the approved Ubuntu repositories; do not replace the system Python or assume Ubuntu's default Go package meets the separate build requirement. Package availability is documented by Ubuntu for [Python](https://packages.ubuntu.com/noble/python3), [ClamAV daemon](https://packages.ubuntu.com/noble/clamav-daemon), and [FreshClam](https://packages.ubuntu.com/noble/clamav-freshclam).

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  python3 openssl ca-certificates clamav clamav-daemon clamav-freshclam
uname -m
python3 --version
systemctl --version
```

The authenticated endpoint expects a local Unix socket. Ubuntu packages include both `clamav-daemon.service` and `clamav-daemon.socket`; socket activation can create the socket independently of `clamd.conf`. Inspect the installed units before changing them:

```bash
sudo systemctl cat clamav-daemon.service clamav-daemon.socket
```

During initial setup or the agreed scanner maintenance window, stop the daemon, its socket and the updater before changing their configuration:

```bash
sudo systemctl stop clamav-daemon.service clamav-daemon.socket clamav-freshclam.service
sudoedit /etc/clamav/clamd.conf
```

Merge these values into the existing daemon configuration, keeping its other reviewed settings. Leave `TCPSocket` disabled. Use the canonical `/run` path in the endpoint configuration so no `/var/run` symlink is traversed.

```text
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 660
```

Also set the socket unit's effective listener, group and permissions. Inspect and preserve any existing local overrides; use `sudo systemctl edit clamav-daemon.socket` and merge this configuration:

```ini
[Socket]
ListenStream=
ListenStream=/run/clamav/clamd.ctl
SocketUser=clamav
SocketGroup=clamav
SocketMode=0660
```

The empty `ListenStream=` clears inherited listeners before selecting the Unix socket. The live socket must grant the approved group access and no access to other users. These settings are supported by the [Ubuntu ClamAV manual](https://manpages.ubuntu.com/manpages/noble/man5/clamd.conf.5.html) and [systemd socket documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.socket.html); Ubuntu's [package file list](https://packages.ubuntu.com/en/noble/amd64/clamav-daemon/filelist) confirms the unit names. A one-time `chmod` on the live socket is insufficient because service restart recreates it.

Download and verify official signature databases before starting the engine. Keep the packaged `freshclam.conf`, database directory and vendor certificate-directory settings consistent; where policy requires customization, record the actual directories. FreshClam needs an operational configuration and obtains the official databases, as described in [ClamAV signature management](https://docs.clamav.net/manual/Usage/SignatureManagement.html).

```bash
sudo freshclam
sudo systemctl daemon-reload
sudo systemctl enable --now clamav-freshclam.service
sudo systemctl enable --now clamav-daemon.socket
sudo systemctl enable --now clamav-daemon.service
sudo systemctl status clamav-freshclam.service clamav-daemon.service clamav-daemon.socket
sudo stat -Lc '%F %U %G %a %n' /run/clamav/clamd.ctl
sudo journalctl -u clamav-daemon.service -u clamav-freshclam.service \
  --since '15 minutes ago' --no-pager
```

Proceed only after the initial update and daemon startup succeed and the live socket is a Unix socket with group `clamav` and mode `660`. Record the engine and database versions and freshness from the actual host. A ClamAV `PONG` proves only that the daemon answers; it does not attest to fresh signatures. Review ClamAV stream, file and archive-size limits against the scanning policy. The agent itself accepts regular files of at most 128 MiB, but a smaller daemon limit can reject a stream and archive limits can constrain inspection.

### L2 Provision the enrolled identity and a narrow scan root

Complete the server, tenant and agent enrollment procedures first. This installer does not issue certificates, enroll an identity or create database accounts. Provision the enrolled agent's certificate/key and the server CA through the approved PKI process. The configured tenant and agent IDs must match that enrollment.

Use root-owned directories and files. In the following example, replace the three `/approved/pki/` input paths with the already provisioned files:

```bash
sudo install -d -o root -g root -m 0700 /etc/turansec /etc/turansec/endpoint
sudo install -o root -g root -m 0644 /approved/pki/server-ca.pem \
  /etc/turansec/endpoint/server-ca.pem
sudo install -o root -g root -m 0644 /approved/pki/agent.pem \
  /etc/turansec/endpoint/agent.pem
sudo install -o root -g root -m 0600 /approved/pki/agent.key \
  /etc/turansec/endpoint/agent.key
sudo install -o root -g root -m 0600 \
  "$EDR_SOURCE_DIR/config/agent.example.json" /etc/turansec/endpoint/agent.json
sudoedit /etc/turansec/endpoint/agent.json
```

For an existing installation, preserve its current configuration and identity rather than copying the example over them. Configuration and private keys must remain root owned, mode `0600` or `0400`, with no symlinks or writable ancestors. Public CA/certificate files may be `0644` inside the protected directory. The systemd launcher passes protected `LoadCredential` copies to a dynamic identity; do not grant it direct ownership of the original key.

Select a dedicated group for read access to the approved scan root. Inspect `getent group turansec-scan`; if the dedicated group does not exist, create it with `sudo groupadd --system turansec-scan`. Review an existing group's privileges before reusing it. Then create the example root:

```bash
sudo install -d -o root -g root -m 0755 /var/lib/turansec
sudo install -d -o root -g turansec-scan -m 2750 /var/lib/turansec/scan-root
```

The directory and its ancestors must remain administrator controlled and not group/world writable. Approved files need group read access, for example root ownership, group `turansec-scan` and mode `0640`. The example does not authorize scanning the entire filesystem or user homes.

The exact endpoint configuration shape is:

```json
{
  "origin": "https://127.0.0.1:9443",
  "tenant_id": "ENROLLED_TENANT",
  "agent_id": "ENROLLED_AGENT",
  "ca_file": "/etc/turansec/endpoint/server-ca.pem",
  "cert_file": "/etc/turansec/endpoint/agent.pem",
  "key_file": "/etc/turansec/endpoint/agent.key",
  "scan_root": "/var/lib/turansec/scan-root",
  "clamd_socket": "/run/clamav/clamd.ctl",
  "max_jobs": 1,
  "read_groups": ["clamav", "turansec-scan"]
}
```

Replace both enrollment placeholders. Use a bare numeric loopback HTTPS origin with an explicit unprivileged port. A remote backend requires an existing approved encrypted local tunnel; the installer does not create one. Use the port 9443 SSH forwarding procedure in the Windows chapter from the Linux endpoint as well; the SSH command has the same flags in Bash, with a backslash for line continuation. Keep that tunnel available for every timer run. The server certificate must verify for the client-facing address. Do not substitute a remote hostname, public bind, disabled certificate checking or proxy-header identity.

`read_groups` must exactly match the non-root group IDs of the scan root and ClamAV socket. The scan root needs group read/search permission, and the socket needs group write/connect permission. The installer grants no additional groups. Both runtime service identities use `DynamicUser=yes`; **do not create static users or groups named `turansec-agent` or `turansec-edrd`**. Registration rejects existing identities with those names. The [configuration example](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/config/agent.example.json), [launcher](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/systemd_launcher.py) and [installer](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/linux_service.py) define these restrictions.

### L3 Register activate and inspect the Linux agent

For an endpoint-only host:

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec register --sha "$EDR_CANDIDATE_SHA" \
  --agent-config /etc/turansec/endpoint/agent.json --dry-run
```

Review the output, then repeat without `--dry-run`. Registration validates the staged release, configuration, credentials, scan root, groups and live socket. It writes `turansec-agent.service` and `turansec-agent.timer`, selects the initial `current` symlink and reloads systemd. It does not start or enable them, and it refuses to overwrite unmanaged units or overrides.

If installing both server and agent into this prefix on a fresh host, pass both `--server-config /etc/turansec/edrd.json` and `--agent-config /etc/turansec/endpoint/agent.json` in that initial registration. Follow the dashboard chapter for database preparation and the server health identity. Do not use registration as a routine upgrade command or silently change an existing installation's component set.

Inspect the units and binary identity:

```bash
sudo systemd-analyze verify /etc/systemd/system/turansec-agent.service \
  /etc/systemd/system/turansec-agent.timer
"/opt/turansec/releases/$EDR_CANDIDATE_SHA/bin/turansec-edr-agent" --version
```

The agent version output must report `source=eedfc0595e3f42983a18c64be86846a288da78b3`. Activate the endpoint:

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec activate --sha "$EDR_CANDIDATE_SHA" --dry-run
```

Review, then repeat without `--dry-run`. An installation that also contains the server must additionally pass `--health-config /etc/turansec/health.json`; endpoint-only activation omits it. Activation requires the initial heartbeat, ClamAV liveness check and bounded scan batch commands to succeed before starting the timer. A scan batch can exit successfully after persisting a scanner `error` verdict; inspect the stored verdict as well as service exit status.

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec status
sudo systemctl status turansec-agent.timer
sudo systemctl show turansec-agent.service -p Result -p ExecMainStatus
sudo systemctl list-timers --all turansec-agent.timer
sudo journalctl -u turansec-agent.service -u turansec-agent.timer \
  --since '15 minutes ago' --no-pager
```

The installer status is the last recorded installation operation; systemd and authenticated fleet observations establish current operation. It is normal for the oneshot service to be inactive between successful runs. Check its result and exit status, the next timer event, the fleet's last heartbeat, scanner readiness and scan evidence together. For one additional bounded run, use `sudo systemctl start turansec-agent.service`.

Once startup and the host's reboot behavior have been accepted, enable the timer explicitly:

```bash
sudo systemctl enable turansec-agent.timer
```

Do not enable the oneshot agent service itself. To stop scheduled and currently running work during maintenance, use `sudo systemctl stop turansec-agent.timer turansec-agent.service` and account for any interrupted leased job.

#### Understand actual worker behavior

The [service unit](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/packaging/linux/turansec-agent.service.in) executes `--heartbeat-mtls`, `--clamav-health`, then `--scan-batch-mtls N`, where `max_jobs` is an integer from 1 through 20. Jobs run sequentially and the batch ends if no work is available. A failed heartbeat or liveness command prevents the batch from starting. The [timer](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/packaging/linux/turansec-agent.timer.in) schedules another run 30 seconds after the previous invocation becomes inactive, with up to five seconds of jitter; it does not create overlapping workers or a catch-up queue.

The service has a 15-minute start timeout, a 20-second stop timeout, a 512 MiB memory ceiling and no Linux capabilities. The separate ClamAV daemon needs its own capacity planning. Read-only system access, hidden home directories, a private temporary directory and loopback-only IP access are deliberate constraints.

Each queued path scan targets a single regular file inside the configured root, even though the API field is named `scan_root`. It is not a recursive directory scan. Linux path opening rejects unsafe traversal, symlinks and mount crossings; it fails closed if the required kernel operation is unsupported. The supported authenticated commands are defined in the [Rust entry point](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/main.rs). Legacy telemetry and local lab modes do not supply the authenticated installed service's evidence.

### L4 Verify on the actual host and preserve evidence

After installation, use a scanner-role operator in the authenticated dashboard to queue an approved benign file under the scan root. Confirm the enrolled endpoint, exact file target, completed job and `clean_by_signature` result in the same tenant. This result describes a signature scan, not a guarantee of safety.

On the designated isolated acceptance host, also run the approved official 68-byte EICAR fixture through the same Rust → ClamAV → backend → dashboard path and retain the observed malicious result. Never execute the fixture. Confirm an invalid or unreadable target becomes an error, and that an unavailable scanner remains degraded/unknown. A controlled scanner-outage test must account for both `clamav-daemon.service` and `clamav-daemon.socket`; leaving the socket active can restart the daemon. Restore scanner operation before ending the test. Direct `clamscan` output alone does not prove the queue integration.

Record the source SHA, signed manifest and archive digests, publisher-key fingerprint, OS/kernel, installed engine/signature versions, protected configuration paths, live socket permissions, effective unit definitions, service/timer results and authenticated queue observations. Keep private keys, DSNs and raw sensitive telemetry out of shared evidence. Record baseline, candidate and restored states for the rollback rehearsal.

The repository provides a read-only collector for package identity and service snapshots:

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/collect-host-acceptance.py" \
  --candidate-sha "$EDR_CANDIDATE_SHA" \
  --package-root "/opt/turansec/releases/$EDR_CANDIDATE_SHA" \
  --manifest "$EDR_MANIFEST" --manifest-signature "$EDR_SIGNATURE" \
  --trusted-release-key "$EDR_TRUSTED_KEY" \
  --service turansec-agent.service --phase candidate \
  --output /secure/evidence/linux-candidate.json
```

Choose a protected output path that does not already exist. This endpoint-only invocation intentionally leaves the collector's optional operator and active scanner checks `NOT_RUN`, so it returns exit status `2`; retain the JSON and complete the separate host checks. It does not certify acceptance. A service snapshot is recorded as `OBSERVED`, including the expected inactive state between batches. The [host acceptance guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/HOST_ACCEPTANCE.md) and [collector](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/collect-host-acceptance.py) describe optional operator and isolated scanner checks, including actual database/certificate-directory arguments.

Passing CI and installation fixture tests does not establish native startup, reboot behavior, real signature detection, long-running resource behavior or successful host rollback. This candidate implements bounded authenticated signature scanning; it does not provide quarantine/restore, tamper protection, full system monitoring, a native tray application or a prevention verdict.

## Windows endpoint installation

This section installs the current portable Rust agent on an authorized isolated
Windows Server 2022 x64 host and connects it to the authenticated Go backend.
Use source `eedfc0595e3f42983a18c64be86846a288da78b3`, the merged source containing
the reviewed fixes. Fresh packages must identify this source. Earlier rc.2
packages built from `65702cbc1cde...` do not contain this correction.

The supported Windows workflow is an explicit heartbeat, status read or bounded
path-scan batch. There is no accepted TuranSec Windows persistent service,
MSI installer or privileged local IPC in this candidate. The commands below
do not establish continuous protection, quarantine/restore or tamper protection.
This section supersedes the legacy Windows quickstarts using a shared bearer
token, port 8080 and the old `TuranSec-EDR-Lab-Agent.exe` artifact name.

### W1 Prepare the authorized Windows host

Use a dedicated lab VM with a restorable snapshot. Keep Defender, SmartScreen
and enterprise execution policy in effect. An unsigned local build needs the
organization's permitted lab execution path; do not disable controls to run it.
Run builds and the portable agent under the approved account rather than
assuming that it needs a permanent administrator session.

Make the approved OpenSSH client, Python launcher (`py`), OpenSSL and Git available in the shell. Both acquisition routes use Git to obtain the reviewed verifier; Rust/rustup and MSVC are needed only for the source-build route. Open PowerShell and record the actual host and clock state:

```powershell
$ErrorActionPreference = 'Stop'
Get-Command ssh, py, openssl -ErrorAction Stop | Select-Object Name, Source
$SourceSha = 'eedfc0595e3f42983a18c64be86846a288da78b3'
$Source = 'C:\TuranSecLab\EDR'
$Evidence = 'C:\TuranSecLab\evidence'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption, Version, BuildNumber, OSArchitecture
Get-Date
w32tm /query /status
```

For a source build, install Git, Rust/rustup and the MSVC C++ build tools with a
Windows SDK through the approved software process. The repository pins Rust
**1.100.0** in `agent/rust-toolchain.toml`; run Cargo from the `agent` directory
so rustup selects that toolchain. The official [Rust MSVC prerequisites](https://rust-lang.github.io/rustup/installation/windows-msvc.html)
explain the required linker and SDK. Python 3.12+ and an approved OpenSSL build
are sufficient for the packaging and evidence commands in this guide. A
portable prebuilt agent does not itself require the Rust build toolchain.

### W2 Choose a fresh source build or a verified package

**Source-build route.** Obtain the private repository using your already
authorized Git credentials. Never embed a token in the URL or script. Use a
new checkout:

```powershell
git clone https://github.com/suhaylx/EDR.git $Source
if ($LASTEXITCODE -ne 0) { throw 'Repository clone failed' }
Set-Location $Source
git checkout --detach $SourceSha
if ($LASTEXITCODE -ne 0) { throw 'Requested source is unavailable' }
$ActualSha = (git rev-parse HEAD).Trim()
if ($ActualSha -ne $SourceSha) { throw 'Source SHA mismatch' }
if (git status --porcelain) { throw 'Use a clean source checkout' }

$env:TURANSEC_BUILD_SHA = $SourceSha
Push-Location .\agent
try {
  rustup show active-toolchain
  if ($LASTEXITCODE -ne 0) { throw 'Pinned Rust toolchain unavailable' }
  cargo test --locked --all-targets
  if ($LASTEXITCODE -ne 0) { throw 'Windows Rust tests failed' }
  cargo build --release --locked
  if ($LASTEXITCODE -ne 0) { throw 'Windows Rust build failed' }
} finally {
  Pop-Location
  Remove-Item Env:TURANSEC_BUILD_SHA -ErrorAction SilentlyContinue
}
$Agent = Join-Path $Source 'agent\target\release\turansec-edr-agent.exe'
Get-FileHash -LiteralPath $Agent -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $Agent |
  Select-Object Status, SignerCertificate
```

This builds the exact committed agent and records its hash. It does not apply
an organizational publisher signature. Preserve that distinction in acceptance
records; a successful build is not signed-package acceptance.

**Signed-package route.** Obtain a newly built Windows x64 ZIP, its manifest and
detached signature for this same SHA. Obtain the trusted publisher public key
independently of the archive. Use the verifier from the reviewed source
checkout, not an unverified script extracted from a downloaded archive:

Perform the clone, detached-checkout and clean-source checks above to obtain
that verifier; the Cargo test/build block is unnecessary for this package route.

```powershell
$Incoming = 'C:\TuranSecLab\incoming'
$Stem = 'turansec-edr-eedfc0595e3f-windows-x86_64'
$Archive = Join-Path $Incoming ($Stem + '.zip')
$Manifest = Join-Path $Incoming ($Stem + '.manifest.json')
$Signature = Join-Path $Incoming ($Stem + '.manifest.sig')
$TrustedReleaseKey = 'C:\ProgramData\TuranSec\trust\release-publisher.pem'
$ApprovedWindowsPublisherThumbprint = 'REPLACE_WITH_APPROVED_THUMBPRINT'
$Release = Join-Path 'C:\TuranSecLab\releases' $SourceSha

if ($ApprovedWindowsPublisherThumbprint -notmatch '^[0-9A-Fa-f]{40,64}$') {
  throw 'Set the independently approved Windows publisher thumbprint'
}
py -3 "$Source\scripts\release\package-candidate.py" verify `
  --archive $Archive --manifest $Manifest --signature $Signature `
  --trusted-key $TrustedReleaseKey --expected-sha $SourceSha
if ($LASTEXITCODE -ne 0) { throw 'Signed package verification failed' }
$Package = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
if ($Package.target -ne 'windows-x86_64') { throw 'Wrong package target' }
if ($Package.windows_publisher_thumbprint -ne $ApprovedWindowsPublisherThumbprint) {
  throw 'Manifest publisher differs from the independently approved publisher'
}
if (Test-Path -LiteralPath $Release) { throw 'Use a new release directory' }
Expand-Archive -LiteralPath $Archive -DestinationPath $Release
$Agent = Join-Path $Release 'bin\turansec-edr-agent.exe'
$Entry = @($Package.files | Where-Object { $_.path -eq 'bin/turansec-edr-agent.exe' })
if ($Entry.Count -ne 1) { throw 'Agent manifest entry missing or ambiguous' }
if ((Get-FileHash -LiteralPath $Agent -Algorithm SHA256).Hash -ne $Entry[0].sha256) {
  throw 'Extracted agent digest differs from the verified manifest'
}
$Publisher = Get-AuthenticodeSignature -LiteralPath $Agent
if ($Publisher.Status -ne 'Valid' -or
    $Publisher.SignerCertificate.Thumbprint -ne $ApprovedWindowsPublisherThumbprint) {
  throw 'Windows publisher verification failed'
}
```

The signing authority and publisher thumbprint must be approved independently;
set `$ApprovedWindowsPublisherThumbprint` from that approved channel, not from
the manifest. The manifest does not choose the organization's trust policy.
The verifier has no `--allow-unsigned` option. If signed artifacts are unavailable, record that
gate as open and use only the separately authorized source-build lab route.
Do not substitute an older archive or a generated test signer.

For either route, check the executable's embedded identity before connecting:

```powershell
$VersionText = & $Agent --version
if ($LASTEXITCODE -ne 0 -or
    (($VersionText -join "`n") -notmatch [regex]::Escape("source=$SourceSha"))) {
  throw 'Executable source identity mismatch'
}
$VersionText
```

### W3 Provision the endpoint identity and private files

The issuer must already have provisioned this tenant and a `windows` device,
validated the CSR/issued leaf through its approved workflow, and registered
the exact leaf fingerprint. The portable client does not automatically enroll
a device. The new database must include migrations 0001–0014 and the restricted
runtime/registry bootstrap from the backend section.

| Endpoint input | Required meaning |
| --- | --- |
| `server-ca.pem` | Approved CA that authenticates the Go server; this is not a release-signing key. |
| `agent.pem` | Current client-authentication leaf and any required chain, with the exact single agent URI SAN defined in Endpoint enrollment. |
| `agent.key` | Matching private PEM key, provisioned locally through the approved process and protected by reviewed Windows ACLs. |
| Tenant/device IDs | Exact already enrolled identifiers matching the certificate SAN and backend registration. |
| Scan root | Administrator-controlled local directory with reviewed ancestors and no reparse-point traversal; never a whole volume or network share. |

Keep these files outside the source/archive and evidence directories. Agent and
operator issuance use separate trust policies and signing keys. Do not place an
operator key on an endpoint just to make its heartbeat work. No shared bearer
token or identity header substitutes for certificate registration.

Configure paths and identifiers in the current PowerShell process:

```powershell
$env:TURANSEC_MTLS_ORIGIN = 'https://127.0.0.1:9443'
$env:TURANSEC_MTLS_TENANT_ID = 'ENROLLED_TENANT'
$env:TURANSEC_MTLS_AGENT_ID = 'ENROLLED_AGENT'
$env:TURANSEC_MTLS_CA_PEM = 'C:\ProgramData\TuranSec\pki\server-ca.pem'
$env:TURANSEC_MTLS_CERT_PEM = 'C:\ProgramData\TuranSec\pki\agent.pem'
$env:TURANSEC_MTLS_KEY_PEM = 'C:\ProgramData\TuranSec\pki\agent.key'
$env:TURANSEC_LAB_SCAN_ROOT = 'C:\TuranSecLab\scan'

foreach ($Path in @($env:TURANSEC_MTLS_CA_PEM,
                    $env:TURANSEC_MTLS_CERT_PEM,
                    $env:TURANSEC_MTLS_KEY_PEM)) {
  $Item = Get-Item -LiteralPath $Path -Force
  if (-not [IO.Path]::IsPathRooted($Path) -or $Item.PSIsContainer -or
      ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      $Item.Length -lt 1 -or $Item.Length -gt 1048576) {
    throw 'Credential path is not a bounded regular local file'
  }
}
Get-Acl -LiteralPath 'C:\ProgramData\TuranSec\pki' | Format-List
Get-Acl -LiteralPath $env:TURANSEC_MTLS_KEY_PEM | Format-List
openssl x509 -in $env:TURANSEC_MTLS_CERT_PEM -noout `
  -dates -fingerprint -sha256 -ext 'subjectAltName,extendedKeyUsage,keyUsage'
if ($LASTEXITCODE -ne 0) { throw 'Client certificate inspection failed' }
```

Replace both enrolled-ID placeholders before running the client. Review the
public certificate output against the issuer's registration; never display the
private key. The host administrator must restrict key/configuration access to
the intended identity and approved administrators, including inherited access
and parent directories. The checks above inspect current files and ACLs; they
do not supply the missing application-enforced Windows ACL or race-safe
reparse-point guarantees.

The Rust executable does not accept `--config`, `--install-service` or `--help`.
`config/agent.example.json` is input for the separate Linux launcher, not a
Windows agent configuration file. Running the executable without a supported
mode prints usage and exits with code 2.

### W4 Connect through the approved lab tunnel

The current Go service binds only numeric loopback: agent mTLS on 9443 and
operator mTLS on 9444. PostgreSQL remains loopback, and Windows ClamAV remains
local on 3310. For a remote Windows lab host, keep this approved SSH forward
running in a separate terminal; use the enrolled server's actual SSH account
and host and verify its SSH host key through the approved channel:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 `
  -L 127.0.0.1:9443:127.0.0.1:9443 `
  BACKEND_SSH_USER@BACKEND_SSH_HOST
```

The HTTPS connection remains end-to-end mTLS through the tunnel. With the
example URL, the server certificate must contain IP SAN `127.0.0.1` and chain
to `server-ca.pem`. Never disable certificate/hostname verification to resolve
a mismatch. This tunnel is the current approved lab access pattern; it does
not establish acceptance of a production network topology. Do not expose
5432, 9443, 9444 or ClamAV 3310 publicly as a shortcut.

### W5 Configure ClamAV then exercise the supported modes

Install a supported, approved Windows ClamAV distribution from the
[official vendor source](https://docs.clamav.net/manual/Installing.html), verify
its publisher/source, and configure official signature updates. Use the
installed package's actual paths and [Windows configuration instructions](https://docs.clamav.net/manual/Usage/Configuration.html).
`freshclam.conf` and `clamd.conf` require actual database/log/trust paths; remove
the sample `Example` directive where present. The required daemon listener is:

```ini
TCPSocket 3310
TCPAddr 127.0.0.1
```

Use the vendor's approved service/start procedure. TuranSec does not install or
supervise that Windows daemon. Verify all configured databases and the update
result; a reachable socket or `PONG` alone does not prove signature freshness.

```powershell
Get-NetTCPConnection -LocalPort 3310 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, OwningProcess
& $Agent --clamav-health
if ($LASTEXITCODE -ne 0) { throw 'Local ClamAV is not ready' }
& $Agent --heartbeat-mtls
if ($LASTEXITCODE -ne 0) { throw 'Authenticated heartbeat failed' }
& $Agent --agent-status-mtls
if ($LASTEXITCODE -ne 0) { throw 'Authenticated status read failed' }
```

Expected successful output includes `clamav_health=alive`,
`agent_mtls_heartbeat=stored`, and `agent_mtls_status platform=windows ...`.
Heartbeat means the authenticated storage operation succeeded; it does not
attest the endpoint or prove prevention. If ClamAV is unavailable, the heartbeat
can still report `scan_ready=false`; preserve that degraded state.

Create the scan directory through the administrator-reviewed ACL process, then
prepare one harmless regular file there. Have a scanner-role SOC operator
schedule its exact path for this endpoint:

```powershell
New-Item -ItemType Directory -Force -Path $env:TURANSEC_LAB_SCAN_ROOT | Out-Null
$Benign = Join-Path $env:TURANSEC_LAB_SCAN_ROOT 'benign.txt'
Set-Content -LiteralPath $Benign -Value 'TuranSec harmless acceptance fixture' `
  -Encoding Ascii -NoNewline
& $Agent --scan-once-mtls
if ($LASTEXITCODE -ne 0) { throw 'Scan command failed; inspect authoritative SOC state' }

# On a later approved run process at most five queued path jobs
& $Agent --scan-batch-mtls 5
if ($LASTEXITCODE -ne 0) { throw 'Batch command failed; inspect authoritative SOC state' }
```

The batch limit is 1–20; it processes one job at a time and stops on no pending
work or a command, transport or lease failure. `agent_mtls_claim=no_job` means
no work was leased, not a completed scan. A durably stored `classification=error`
counts as a completed job. The batch can continue to the next job, and the
command may still exit successfully. Inspect the verdict as well as the exit
code. Expected benign outcome is `clean_by_signature`, which
is not proof of safety. The file-size cap is 128 MiB. Quick/full profiles and
automatic response actions are not supplied by these mTLS commands.

### W6 Collect host evidence without overstating coverage

Obtain the official exact 68-byte EICAR fixture without an added newline only for the approved isolated lab, never run
it, and retain detection attribution if another security product intercepts it.
The cross-platform collector performs direct benign/EICAR `clamscan` checks
and verifies the official `main`, `daily` and `bytecode` database files. Its
`--cvdcertsdir` option requires a compatible installed vendor tool version and
the actual vendor trust directory. Set the following paths to that verified
installation, then run from the reviewed source:

```powershell
$ClamBin = 'C:\Program Files\ClamAV'              # Actual installed tool directory
$ClamDb = 'C:\ProgramData\ClamAV\database'        # Actual configured database directory
$CvdCerts = 'C:\Program Files\ClamAV\certs'        # Actual vendor CVD trust directory
$Eicar = 'C:\TuranSecLab\scan\eicar.com'           # Official verified fixture
$ScannerId = [Guid]::NewGuid().ToString('N')
$ScannerEvidence = Join-Path $Evidence "windows-scanner-candidate-$ScannerId.json"
if (Test-Path -LiteralPath $ScannerEvidence) {
  throw 'Choose a new scanner evidence filename'
}
py -3 "$Source\scripts\collect-host-acceptance.py" `
  --candidate-sha $SourceSha --phase candidate `
  --exercise-scanner --lab-confirmation isolated-lab `
  --clamscan "$ClamBin\clamscan.exe" --sigtool "$ClamBin\sigtool.exe" `
  --database-dir $ClamDb --cvd-certs-dir $CvdCerts --eicar-file $Eicar `
  --output $ScannerEvidence
$CollectorExit = $LASTEXITCODE
if (-not (Test-Path -LiteralPath $ScannerEvidence -PathType Leaf)) {
  throw "Collector did not create new evidence (exit $CollectorExit)"
}
Get-Content -LiteralPath $ScannerEvidence -Raw |
  ConvertFrom-Json | Select-Object -ExpandProperty checks
Write-Output "Evidence file: $ScannerEvidence"
Write-Output "Collector exit code: $CollectorExit"
```

The example intentionally collects scanner evidence only. Omitted package,
operator-API and installed-service inputs remain `NOT_RUN`, and the collector
returns 2 for incomplete checks as well as failures: read each recorded status.
Each invocation chooses a fresh filename and reads it only after new output
exists; both collectors refuse to overwrite an existing evidence record.
For the signed-package route, add all four arguments below to the same collector invocation to measure package files and signing too. Use PowerShell continuation backticks if breaking the invocation across lines.

- `--package-root $Release`
- `--manifest $Manifest`
- `--manifest-signature $Signature`
- `--trusted-release-key $TrustedReleaseKey`

 Do not invent a TuranSec Windows service
name for `--service`. The report always keeps `host_acceptance_complete=false`.
A separate actual queued job is required to prove the Rust → daemon → mTLS →
PostgreSQL → SOC flow.

If Microsoft Sysmon is installed with an approved policy, use the bounded local
collector after approved benign activity:

```powershell
$SysmonId = [Guid]::NewGuid().ToString('N')
$SysmonEvidence = Join-Path $Evidence "windows-sysmon-candidate-$SysmonId.json"
if (Test-Path -LiteralPath $SysmonEvidence) {
  throw 'Choose a new Sysmon evidence filename'
}
powershell.exe -NoProfile -File "$Source\scripts\collect-sysmon-acceptance.ps1" `
  -CandidateSha $SourceSha -LookbackMinutes 15 -MaximumEvents 500 `
  -OutputPath $SysmonEvidence
$SysmonExit = $LASTEXITCODE
if (-not (Test-Path -LiteralPath $SysmonEvidence -PathType Leaf)) {
  throw "Sysmon collector did not create new evidence (exit $SysmonExit)"
}
Get-Content -LiteralPath $SysmonEvidence -Raw |
  ConvertFrom-Json | Select-Object status, counts, event7_observed, truncated
Write-Output "Evidence file: $SysmonEvidence"
Write-Output "Sysmon collector exit code: $SysmonExit"
```

The collector reads only the genuine provider/channel and Events 1, 7 and 11;
it does not install/reconfigure Sysmon or upload events to TuranSec. Event 11
is file creation, while actual Event 7 is required for module-load evidence,
consistent with [Microsoft's event definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Missing Event 7 produces an incomplete result and exit 2. Local observation
does not prove authenticated backend ingestion or a detection. Legacy
`--telemetry-once`/`--telemetry-loop` use the separate development API and are
not a substitute for this candidate's authenticated acceptance.

### W7 Stop retain evidence and plan upgrades

The bounded agent exits when its selected operation finishes. Do not register
this exiting CLI using `sc.exe create`, a generic service wrapper or a scheduled
task and call the result an accepted Windows EDR service. Stop an active lab
operation normally, inspect any unknown job outcome in the SOC, then close the
lab tunnel when no longer needed. Keep previous verified binaries and
credentials separate. Replacing a portable EXE is not an accepted installed
Windows service/database rollback.

Before enterprise rollout, close the native Windows service/installer and
local-IPC requirements, Windows key/config ACL and reparse-safe file access,
approved publisher signing, installed-host and rollback evidence, and designated
owner/deployment approvals. No successful heartbeat or installer-free file copy
closes those gates.

### Source references for this section

- [Supported CLI and embedded source identity](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/main.rs)
- [Pinned Rust toolchain](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/rust-toolchain.toml)
- [mTLS environment variables, trust and credential reads](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/scan_mtls.rs)
- [Bounded scanner/heartbeat behavior](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/scan_runner.rs)
- [Windows ClamAV endpoint and file restrictions](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/agent/src/scan_file.rs)
- [Package verification CLI](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/release/package-candidate.py)
- [Host-acceptance collector](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/collect-host-acceptance.py) and [Sysmon collector](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/scripts/collect-sysmon-acceptance.ps1)
- [Current installation and PKI requirements](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/INSTALLATION.md) and [native-host acceptance](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/HOST_ACCEPTANCE.md)

## Upgrade rollback and removal

### Upgrade

Stage the new complete, verified release first. Preserve the current release directory and receipt, protected credentials, installation records and the database backup/compatibility plan for any server sharing this prefix. Account for active jobs before stopping a worker. Use `activate --sha NEW_FULL_SHA` on the existing registration; a second `register` is not needed. Add `--health-config` if a server is installed.

The installer serializes changes, stops the agent timer/worker, switches the complete binary/web tree, refreshes its managed units and checks the restarted components. It does not apply database migrations or replace credentials. The dashboard chapter's migration and restricted-role bootstrap steps must be completed in their proper order.

### Rollback

Select a previously verified release that is compatible with the current schema and still meets the security requirements. The old `v0.1.0-rc.2` package is not an acceptable default recovery target for the enrollment-expiry correction. A previously available package is not automatically a safe fallback.

```bash
export EDR_PREVIOUS_SHA=PREVIOUS_COMPATIBLE_FULL_40_CHARACTER_SHA
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec rollback --sha "$EDR_PREVIOUS_SHA" --dry-run
```

For a prefix containing the server, also supply `--health-config /etc/turansec/health.json`. Review the dry run and repeat without it during the maintenance window. Check the restored version, authenticated health, durable queue/database state and service evidence. Binary rollback does not restore a database and does not justify running reverse SQL.

If candidate activation fails, the installer attempts to restore and health-check the prior release. Exit `3` means the candidate failed but the previous release was restored and healthy. Exit `4` means rollback failed and requires operator recovery. An initial installation with no prior running release stops its units and records `initial_start_failed`; it cannot claim a restored deployment. Preserve `activation.json` and `.service-installation.json`. A pending or failed recovery record must be resolved against the actual `current` target and unit files; deleting the journal to bypass its guard is not recovery.

### Uninstall

```bash
sudo python3 "$EDR_SOURCE_DIR/scripts/release/linux_service.py" \
  --prefix /opt/turansec uninstall --dry-run
```

Review the selected managed units, then repeat without `--dry-run`. The tool stops/disables and removes only its unchanged managed units, then reloads systemd. It preserves configuration, private keys, database contents, release directories, receipts and installation records. In a combined installation, this removes the managed server and agent units together. There is no purge option or agent-only switch for a combined registration. Retire or revoke the endpoint identity and handle retained data through the separate administrator process; do not remove an independently used ClamAV installation as a side effect. These behaviors are specified by the [Linux service guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/LINUX_SERVICE_INSTALLATION.md) and implementation.

## Installation verification and acceptance

### Record the installed result

For each host, record the full source SHA, package and manifest digest, approved
publisher identity where available, operating system build, installation time,
service state and authenticated tenant/device or operator identity. Keep
certificate fingerprints and public validity details, but exclude private keys,
passwords, DSNs, full lease tokens and unrelated host telemetry. Preserve an
actual failed or incomplete result rather than replacing it with a passing CI
result from another machine.

| Check | Successful installation evidence | Remaining limitation |
| --- | --- | --- |
| Dashboard | Active selected service; HTTP 200 from `/soc/v1/session`; correct tenant, operator and role; React SOC renders | Requires managed browser client identity and manual accessibility review |
| Linux agent | Correct source version; bounded service run succeeds; timer state recorded; authenticated heartbeat and endpoint status | Timer execution and heartbeat alone do not establish continuous protection |
| Windows agent | Correct source version; supported command output and exit state; authenticated heartbeat and endpoint status | Portable workflow has no accepted persistent TuranSec Windows service |
| Scanner | Approved engine and verified databases; harmless file outcome; separately approved EICAR observation and attribution | `PONG`, `scan_ready` and a signature-clean verdict have distinct meanings |
| Queued scan | Actual SOC request, Rust lease/scan/result, durable PostgreSQL result, matching SOC state | Direct `clamscan` or synthetic CI results do not prove this complete path |
| Recovery | Stop/start and network recovery observations; tested complete-package switch; compatible database restore plan | A file copy or rollback unit test is not an installed-host rehearsal |

### Exercise the current dashboard workflow

Use an enrolled scanner-role operator to schedule one exact regular-file path
inside the endpoint's configured scan root. Run the bounded endpoint operation
or let the approved Linux timer execute it. Confirm that the same job moves
through the supported states and that its final classification and any
error detail match the endpoint and stored result. Distinguish `no_job`,
`clean_by_signature`, `malicious`, `error` and `unscanned`.

Check read-only viewer behavior, cancellation of a pending job, permission or
certificate revocation, and reconnect behavior. An interrupted mutation can
have an unknown outcome even if the connection failed. Refresh authoritative
state before deciding whether another request is necessary. A successful
acknowledgement or case resolution records an analyst action; it does not
prove endpoint remediation.

For accessibility, verify keyboard navigation, focus, labels and the actual
browser at desktop and mobile widths. Automated tests reported zero axe
violations, but three mobile table scans retained incomplete color-contrast
measurements. Manual accessibility acceptance remains required.

### Close the remaining release gates

Before enterprise deployment, the release owner needs evidence from the actual
authorized Ubuntu 24.04 and Windows Server 2022 hosts, genuine ClamAV and Sysmon
observations, trusted publisher signing, installed-service and database recovery,
and the reviewed browser behavior. Windows additionally needs completion and
acceptance of its native service or installer, private-key ACL and safe
reparse-point handling, and privileged local IPC requirements.

The deployment record must identify the exact signed artifacts, target hosts,
canary scope, approved window and recovery plan, together with the designated
InfoSec, QA and deployment-owner decisions. The engineering review and this
manual do not grant approval for an unspecified production installation.

### Related operational references

- [Host acceptance procedure](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/HOST_ACCEPTANCE.md)
- [Linux service implementation guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/LINUX_SERVICE_INSTALLATION.md)
- [Database role and upgrade guide](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/backend/RUNTIME_DATABASE_ROLES.md)
- [Package build and signature workflow](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/release/BUILD_RELEASE_FILES.md)
- [Exact candidate CI](https://github.com/suhaylx/EDR/blob/eedfc0595e3f42983a18c64be86846a288da78b3/docs/qa/CANDIDATE_CI.md)
