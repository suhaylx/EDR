# TuranSec Agent 3 QA — Milestones M76–M100

**Date:** 21 November 2026. **Owner:** Agent 3, independent QA. **Ancestry:** M51–M75 QA PR #132, which builds on earlier QA PR #96. These 25 named test cases are committed in `backend/internal/edr/qa_sysmon_source_m76_m100_test.go` and exercise Go development event ingestion with synthetic metadata. They do NOT establish real Windows collection, production source authentication, mTLS, persistent storage, scanner performance or malware detection.

**Status semantics:** CODE COMMITTED = source exists; CI PASS = exact commit tests passed; QA ACCEPTED = independent review; HOST VERIFIED = real isolated Windows/Linux evidence. Never promote directly from committed to host verified.

| Case | Acceptance | Layer | Current result |
| --- | --- | --- | --- |
| M76 | EID1 process GUID, image and parent identity preserved | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M77 | EID3 network destination fields retained | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M78 | EID7 DLL module path retained as an observed load | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M79 | EID10 process access source and target metadata preserved | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M80 | EID13 registry target object accepted without raw registry value | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M81 | EID21 WMI binding accepted as observation | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M82 | EID22 DNS query metadata allowed | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M83 | EID24 metadata-only clipboard event accepted | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M84 | EID25 tampering recorded without action | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M85 | EID255 sensor health event never produces malware signal | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M86 | Unknown EID30 rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M87 | Numeric ID zero with nonempty fields rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M88 | Linux claim to Windows Sysmon denied | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M89 | Source ID/type mismatch rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M90 | EID1 missing process GUID rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M91 | EID1 missing image rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M92 | EID7 forged parent process GUID rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M93 | EID24 with clipboard file path rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M94 | EID24 with image content rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M95 | EID24 with process GUID rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M96 | EID24 with additional metadata rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M97 | Private command-line/token field rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M98 | Control characters in source field rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M99 | Oversized metadata field rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |
| M100 | Control characters in source record ID rejected | Go synthetic ingestion | CODE COMMITTED; CI PENDING |

## Additional P0 release gates outside this suite

- Agent mTLS and tenant/device identity; revoked cert, lease replay, cross-tenant denial, and PostgreSQL restart/concurrency (separate QA PRs; rerun at exact integrated SHA).
- Windows Server 2022: genuine Sysmon 1–29/255 as actually configured; RecordID/bookmark loss, privacy, provider/channel, clock skew and process lineage. **HOST NOT RUN**.
- Ubuntu 24.04: actual /proc snapshots, Linux audit/eBPF available/unavailable truth, resource limits, reboot and permission denial. **HOST NOT RUN**.
- Real ClamAV: signed signature database, benign file plus official EICAR-only, daemon offline, failure states and no false-clean verdict. **HOST NOT RUN**.
- Frontend: Windows/Linux source IDs, original source time versus server receipt, missing evidence warnings, keyboard accessibility and no public HTTP token entry.
- No signed installer, authenticated endpoint evidence, durable stream/rollback or independently accepted release yet. **Production NO-GO**.

## Run and report exact results

```bash
cd backend
go test ./internal/edr -run '^TestQAM76ToM100SysmonSourcePrivacyMatrix$' -count=1 -v
go test -race ./internal/edr -run '^TestQAM76ToM100SysmonSourcePrivacyMatrix$' -count=1
go test ./...
go vet ./...
```

Collect the exact GitHub commit SHA and separate PASS/FAIL/NOT RUN, with sanitized failures and QA reviewer. Do not merge to `main` or deploy hosts without approval.
