# TuranSec EDR v0.1.0-rc.1 — Linux release files

This directory contains an **unsigned engineering candidate** built from source
commit [`90233f26e3e93b2d777cf1e07ca6f2fd479f5b82`](https://github.com/suhaylx/EDR/commit/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82).
Both packaged native binaries report that complete commit ID. The source changes
are available in [integration PR #180](https://github.com/suhaylx/EDR/pull/180).

## Download and verify

- [Linux x86_64 archive](turansec-edr-90233f26e3e9-linux-x86_64-unsigned.tar.gz)
- [Complete package manifest](turansec-edr-90233f26e3e9-linux-x86_64-unsigned.manifest.json)
- [SHA256SUMS](SHA256SUMS)
- [Release metadata](release.json)
- [Release notes](RELEASE_NOTES.md)

Archive size: **10,741,228 bytes**. Archive SHA-256:

```text
f70c3fc435b2d2e7dc96346bed14ac6546335824b2d1a7b45598acfe051e3fcc
```

Independently recorded manifest SHA-256:

```text
f70aa9ae5e64f7a94acfe7abc3174c1ea5aaf267eaa717f64f318a13f0d43825
```

Download the archive, manifest and checksum file into one directory, then run
`sha256sum -c SHA256SUMS`. The manifest lists all 38 packaged files. Checksums
establish byte identity; they do not authenticate a publisher signature.

Read the committed [installation manual](https://github.com/suhaylx/EDR/blob/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82/docs/INSTALLATION.md)
and [Linux service guide](https://github.com/suhaylx/EDR/blob/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82/docs/LINUX_SERVICE_INSTALLATION.md)
before staging. PostgreSQL, approved PKI/enrollment, ClamAV and verified signature
databases are provisioned separately. The archive contains no private credentials.

## Acceptance state

**Deployment: NO-GO.** This package has no approved publisher signature, and no
Windows package is present. Actual Windows/Linux host acceptance, installed-service
and database recovery, browser acceptance, current independent InfoSec and original
owner approvals remain outstanding. The [exact-head GitHub candidate CI run](https://github.com/suhaylx/EDR/actions/runs/44946276402)
failed before runner assignment; its jobs executed no test steps. Successful local
functional checks and package validation do not replace those gates.

See PR #180 for the immutable execution evidence and scoped QA verdict. Building,
downloading or verifying these files does not authorize installation or deployment.
