# TuranSec EDR v0.1.0-rc.1

Source commit: `90233f26e3e93b2d777cf1e07ca6f2fd479f5b82`.

These files are **unsigned engineering candidates**. They do not carry an
approved publisher signature or deployment authorization. A draft release or
successful package build does not prove CI, native host acceptance or rollback.

The bundle contains the Go/PostgreSQL mTLS service, the single Rust endpoint
binary, React SOC assets, schema migrations, configuration examples and
installation guidance. Linux service staging and operation are documented in
the included manual. PostgreSQL, approved PKI identities, ClamAV and its verified
signature databases must be provisioned separately. No private credentials are
included.

Verify `SHA256SUMS`, compare the source SHA to the reviewed commit, and read the
included installation manual before staging. Checksums establish byte identity;
publisher authentication requires the separately approved release signature.

The native platforms absent from this package set are listed in `release.json`.
The original InfoSec/QA approval, actual Windows/Linux acceptance, trusted signing,
service/database rollback and deployment authorization remain separate gates.
