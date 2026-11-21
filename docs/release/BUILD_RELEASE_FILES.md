# Build and review release files

A release file is a package built from one exact source commit. It does
not by itself grant native-host acceptance, trusted publisher identity or
deployment authorization. The current staging path produces explicitly unsigned
engineering candidates. Preserve the failed and not-run gates alongside them.

## Native local build

Check out the reviewed full SHA and use the committed dependency locks. Build a
Linux archive on native Linux x86_64 and a Windows ZIP on native Windows x86_64.
The packager exports the committed tree, excluding local credentials and build
outputs, and embeds the source SHA in both binaries.

```sh
export EDR_CANDIDATE_SHA="$(git rev-parse HEAD)"
python3 scripts/release/package-candidate.py build \
  --candidate-sha "$EDR_CANDIDATE_SHA" --target linux-x86_64 \
  --output /absolute/empty/release-files --stage-only
python3 scripts/release/prepare-release.py \
  --directory /absolute/empty/release-files --version v0.1.0-rc.1 \
  --source-sha "$EDR_CANDIDATE_SHA" --require-target linux-x86_64
```

On Windows, use the native Python invocation, a Windows absolute output path,
`--target windows-x86_64` and the corresponding PowerShell environment syntax.
No cross-compiled executable substitutes for native testing.

The output contains the archive, its manifest, `SHA256SUMS`, `release.json` and
`RELEASE_NOTES.md`. Release preparation verifies the source SHA, expected names,
archive size/hash and requested platform set. It refuses path escapes, linked
archives and existing metadata. A platform that was not built remains explicitly
listed as missing; the helper does not create a placeholder package.

The package includes the runtime binaries, React assets, database migrations,
restricted-role bootstrap, installation guidance and Linux service tooling when
building the Linux target. Provision PostgreSQL, approved PKI, endpoint identities,
ClamAV/signature databases and the service credentials separately. Do not include
private credentials in an archive, manifest or release attachment.

## GitHub workflow

`.github/workflows/release-candidate.yml` is a manual workflow. It captures the
selected ref's exact commit, executes backend and POSIX release-tool checks on
Ubuntu and Rust checks on both native Ubuntu and Windows runners. Both packages must succeed before the
combined release record is prepared. Its artifact upload also retains check
ledgers. This workflow must be available to GitHub Actions through the repository's
approved workflow process; committing it is not evidence that it has run.

By default it only uploads reviewable workflow artifacts. Selecting
`create_draft_release` additionally creates a **draft prerelease**, with the exact
target commit, unsigned label and files. It never publishes a stable release,
marks it latest, deploys, generates signing keys or overrides an existing release.
GitHub runner allocation must work before any of these jobs can execute.

The combined release job requests repository contents write permission only for
that draft operation. No signing secrets are used by the staging workflow.
Operational signing must use the independently approved publisher key or service
and the signed-build options described in the installation manual. Windows signed
packages additionally require valid Authenticode from the approved publisher.

## Promotion and rollback

Keep the source commit and package hashes fixed during review. Link successful
exact-head CI, native Windows/Linux acceptance, original role-owner verdicts,
publisher signature verification and actual service/database rollback results.
The deployment owner then approves the specific package, targets, canary, window
and rollback plan. A draft and an unsigned file remain engineering artifacts
until those requirements are satisfied.

References: [GitHub artifact transfer](https://docs.github.com/en/actions/tutorials/store-and-share-data)
and [GitHub CLI draft release options](https://cli.github.com/manual/gh_release_create).
