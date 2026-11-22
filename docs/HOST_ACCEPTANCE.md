# Native host acceptance evidence

These collectors record evidence from the computer on which they execute. They do not install a service, change Sysmon policy, restart a daemon, alter a firewall, grant deployment authorization, or turn a portable CLI into an installed endpoint service.

Run on the approved isolated Ubuntu 24.04 and Windows Server 2022 hosts. A run in a container is container evidence. Preserve **PASS, FAIL, NOT_RUN and OBSERVED** separately. Archive the reports privately with the release review; do not commit credentials, private keys, raw events or production identifiers.

## 1. Candidate and native operating system

Use a full commit SHA and the exact archive/manifest from that SHA. Verify its detached signature with an independently provisioned organizational public key before installation. The supplied packager's `verify` operation checks the archive; the host collector compares installed artifact files to the manifest and independently checks its signature. A public key bundled inside an untrusted package is not a trust root.

Python 3.10+ and OpenSSL are required for the cross-platform collector. It writes one new JSON file and refuses to overwrite prior evidence.

```bash
python3 scripts/collect-host-acceptance.py \
  --candidate-sha FULL_40_CHARACTER_COMMIT_SHA \
  --package-root /opt/turansec/releases/CANDIDATE \
  --manifest /secure/review/candidate.manifest.json \
  --manifest-signature /secure/review/candidate.manifest.sig \
  --trusted-release-key /etc/turansec/trusted-release-public.pem \
  --service turansec-edrd \
  --phase candidate --output /secure/evidence/linux-candidate.json
```

On Windows use `py -3`, absolute Windows paths and the installed service name. Native Authenticode status and the approved publisher thumbprint in the signed manifest are checked for packaged executables. If the package is unsigned, signature acceptance remains **NOT_RUN**. Hash equality alone does not establish an approved publisher.

The current Rust executable remains an explicit one-shot/bounded-batch tool; do not invent a Windows service name or register its exiting CLI as persistent protection. A missing installed service is a release gap.

## 2. Authenticated operator API

Add `--soc-origin https://127.0.0.1:9444`, `--server-ca`, `--operator-cert` and `--operator-key` paths to protected, operator-provisioned files. Use the approved loopback tunnel if the backend is remote. The collector never disables TLS verification or reads a password from the command line.

It verifies the TLS 1.3 session, no-store response, forged-header resistance, wrong-tenant denial, cross-origin denial and missing-client-certificate rejection. These are read-only API requests. Additional persisted revocation, backend restart, Rust heartbeat/scan and UI browser tests are still required. Do not revoke the actual host identity casually to manufacture a negative test; use a separately provisioned test identity in an agreed acceptance window.

## 3. Real ClamAV and EICAR-only checks

Install a supported vendor package through the approved process. Verify the package's publisher signature using the current [official ClamAV downloads page](https://www.clamav.net/downloads). Do not substitute a generated signing key. Run official `freshclam` with the vendor CA directory and obtain `main`, `daily` and `bytecode` databases. For relocated ClamAV 1.5.x installations, configure both `CVDCertsDirectory` and `CVD_CERTS_DIR` so the updater and loaded engine use the correct trust directory.

Honor CDN cooldowns. An updater exit code alone is insufficient: a partial update can succeed while a required database is unavailable. The collector checks the presence and cryptographic validation of each database independently.

Download only the [official EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) into the isolated lab. The collector accepts the exact 68-byte file with SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`. If another installed antivirus intercepts it, record that product's result; do not disable controls to force ClamAV attribution. Never execute the EICAR file or use live malware.

Add these options to the collector:

```bash
--exercise-scanner --lab-confirmation isolated-lab \
--clamscan /usr/local/bin/clamscan --sigtool /usr/local/bin/sigtool \
--database-dir /var/lib/clamav --cvd-certs-dir /usr/local/etc/certs \
--eicar-file /secure/lab/eicar.com
```

The only scans are a generated harmless text fixture and the verified EICAR file. Expected `clamscan` exits are **0** for benign and **1** for EICAR. Exit 2 or an unexpected result is failure. This proves direct engine behavior, not the complete Rust→daemon→mTLS→PostgreSQL→SOC path. That path needs its own actual queued job, recorded result and UI evidence, including daemon-unavailable behavior. A signature-clean verdict is not proof of safety.

## 4. Genuine Sysmon creation versus module loading

On Windows run the read-only collector after approved benign activity under the reviewed Sysmon policy:

```powershell
.\scripts\collect-sysmon-acceptance.ps1 `
  -CandidateSha FULL_40_CHARACTER_COMMIT_SHA `
  -LookbackMinutes 15 -MaximumEvents 500 `
  -OutputPath C:\SecureEvidence\sysmon-candidate.json
```

It reads only the genuine `Microsoft-Windows-Sysmon` provider and `Microsoft-Windows-Sysmon/Operational` channel, bounded to Event IDs 1, 7 and 11. Record IDs, timestamps, boot time and hashed process/path relationships are retained; raw command lines and event XML are excluded. The report explicitly treats Event 11 as file creation only and requires actual Event 7 for observed module loading. Missing Event 7 remains **NOT_RUN/unknown**; it cannot become a load verdict from Event 11 alone.

Local channel observation does not prove authenticated delivery or detection in TuranSec. QA must correlate the actual observed records with tenant/device/boot/process identities in backend evidence and check the create-only negative scenario. Enabling broad Event 7 collection or altering Sysmon configuration requires a reviewed plan; this collector does neither.

## 5. Rollback and service acceptance

Collect separate `baseline`, `candidate` and `restored` reports around an approved manual canary/rollback window. Keep credentials, identity registration and PostgreSQL state outside versioned binary directories. Capture the actual service state, binary hashes, candidate SHA, authenticated health, backend persistence and continuity of agent heartbeat before and after each operation.

The collectors do not perform the switch and do not automatically declare rollback passed. Independently inspect the activation journal, restore the known-good binary/configuration combination, verify native service health and reboot behavior, and run the database-compatibility test. Validate failed activation, health failure, interrupted activation and failed rollback on disposable canaries. The current POSIX release-switch primitive and its unit tests are not a native Windows rollback implementation.

## Required review outcome

The collector deliberately leaves `host_acceptance_complete=false` and deployment authorization ungranted. Agent 3 must assemble all actual host, exact-head CI, full pipeline, resource/isolation, browser/accessibility and rollback evidence and issue an explicit independent verdict. Agent 1 must approve the trust/detection requirements. Signed packages and the deployment owner's explicit authorization remain separate gates.
