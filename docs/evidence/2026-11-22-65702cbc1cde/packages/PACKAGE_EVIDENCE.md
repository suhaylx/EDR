# Native unsigned package delivery

**Result: PASS for unsigned engineering artifact delivery. Release/deployment: NO-GO.**

Candidate source: `65702cbc1cde6750304d9e438bb27bc0537c2d45`.

- [Draft prerelease v0.1.0-rc.2](https://github.com/suhaylx/EDR/releases/tag/untagged-82e4f1a402acda71ef9c), release ID 454032107. API state: draft=true, prerelease=true, published_at=null. All seven assets are uploaded.
- [Successful native build run 44956977201, attempt 1](https://github.com/suhaylx/EDR/actions/runs/44956977201/attempts/1).
- Delivery workflow: `c9b8f67347eb03c7df6c647a19dcf6bfde8898c3`, separate branch `release-build/65702cbc-rc2`. The jobs explicitly checked out the unchanged tested source `65702cbc1cde6750304d9e438bb27bc0537c2d45`.
- [Combined artifact 14728616168](https://github.com/suhaylx/EDR/actions/runs/44956977201/artifacts/14728616168), outer ZIP SHA-256 `2574b1bc7631203839c39b8f8ad222e997d000e567a1731c713097aa67baa4f8`.

| Native package | Bytes | Archive SHA-256 |
|---|---:|---|
| [turansec-edr-65702cbc1cde-linux-x86_64-unsigned.tar.gz](https://github.com/suhaylx/EDR/releases/download/untagged-82e4f1a402acda71ef9c/turansec-edr-65702cbc1cde-linux-x86_64-unsigned.tar.gz) | 9804534 | `b1c19f5dbc5556119d850da176dd5cc29075ff1d3c25b24c2be1a08c7ca3fa78` |
| [turansec-edr-65702cbc1cde-windows-x86_64-unsigned.zip](https://github.com/suhaylx/EDR/releases/download/untagged-82e4f1a402acda71ef9c/turansec-edr-65702cbc1cde-windows-x86_64-unsigned.zip) | 9595202 | `dfe1d44cbb2cc636485b110c87812be42d39ff8554e6e445c8f4a64347101ef9` |

Each native job validated the archive size/hash, all 38 packaged file sizes/hashes and both actual executable source identifiers. The backend reported `edrd 0.1.0-candidate`; the Rust agent reported version 0.1.0; both contained the full candidate SHA. [Linux job 137007158567](https://github.com/suhaylx/EDR/actions/runs/44956977201/job/137007158567) and [Windows job 137007158294](https://github.com/suhaylx/EDR/actions/runs/44956977201/job/137007158294) succeeded. Native prerequisite tests also succeeded.

The [prepare job 137008904505](https://github.com/suhaylx/EDR/actions/runs/44956977201/job/137008904505) required both platforms and verified their archive/manifest hashes before preparing SHA256SUMS, release.json and release notes. The independent CI reviewer read both native smoke logs, compared the preparation record and independently checked the draft release API. Root separately matched the uploaded archive sizes/digests and manifest digests to the preparation record.

See [release.json](release.json) for the exact preparation record and [delivery-record.json](delivery-record.json) for job and uploaded-asset metadata. The final package hashes differ from the transient local build because these are the actual native GitHub builds; the earlier local archive upload did not complete and is not presented as the delivered package.

## Scope and installation

These are unsigned portable engineering archives, not approved signed installers. Linux includes separately invoked service tooling. The Windows bundle does not implement or validate a Windows service installer or privileged local companion IPC. The archives contain installation, verification and rollback guidance from the exact source commit.

[Installation manual](https://github.com/suhaylx/EDR/blob/65702cbc1cde6750304d9e438bb27bc0537c2d45/docs/INSTALLATION.md). [Linux service guide](https://github.com/suhaylx/EDR/blob/65702cbc1cde6750304d9e438bb27bc0537c2d45/docs/LINUX_SERVICE_INSTALLATION.md).

No approved publisher signature or Windows Authenticode identity is established; native host acceptance, installed-service/database rollback, InfoSec/original-owner approvals and deployment-owner authorization remain outstanding. Draft creation did not publish a stable release, merge main, install services or deploy.
