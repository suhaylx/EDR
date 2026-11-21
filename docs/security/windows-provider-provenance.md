# SEC-076 — Windows event provider/channel provenance (partial lab implementation)

## Security intent
Windows Event Log IDs are **namespaced by provider and channel**. `Microsoft-Windows-Sysmon/Operational` Event ID 1 is different from Windows Security 4688 process creation; a raw numeric ID alone cannot establish the provider. Sysmon 7 is a module load, not generic Windows Event Log 7. The current lab uses a shared development bearer token and sender-reported event metadata; none of these strings authenticates the Windows host or proves that Windows emitted the record.

## Implemented in this draft branch
- Rust Sysmon collector adds `source_provider="Microsoft-Windows-Sysmon"` and `source_channel="Microsoft-Windows-Sysmon/Operational"` to each sender-reported event.
- Go `Event` preserves `source_provider` and `source_channel` and accepts the pair only for `source=sysmon`, `platform=windows`, with the exact Sysmon names. Any partial pair or other provider/channel is rejected. This is input consistency validation, **not cryptographic attestation**.
- Legacy lab events lacking both fields remain accepted and explicitly retain an **unknown** provider/channel state for compatibility; do not treat this as secure production ingestion.
- React parser denies mismatched event-provider claims and displays reported provider/channel or `not reported (legacy)`.
- Go and frontend tests cover positive Sysmon record, forged Windows Security/PowerShell/System providers, mismatched or partial pair, Linux impersonation and legacy unknown cases; Rust CLI tests assert the explicit source labels.

## Gaps and blockers
- **No Windows Security/PowerShell/System collector**: IDs 4688, 4698, 4702, 4104 and 7045 remain NOT INSTRUMENTED. They are listed in upcoming SEC-077–080 as separate source adapters and must never be relabeled as Sysmon.
- The Go development listener has no per-device cert-bound identity or tenant isolation. The source tuple is attacker-controlled if the shared dev token leaks. Production source attestation requires the earlier SEC-051/052 mTLS identity program and signed/verified enrollment.
- Sysmon policy coverage and channel bookmark loss accounting remain future SEC-028/030 acceptance gates. No live Windows collector or forensic chain-of-custody proof is claimed.
- Add server-side capability reporting, durable event queue and independent Windows event log QA before promoting this to a pilot.

## Acceptance commands (for connected developer or GitHub CI)

```bash
cd backend && go test ./... && go vet ./...
cd ../agent && cargo test
cd ../frontend && npm ci && npm test && npm run build
```

**Status:** DRAFT CODE — CI/independent QA and Windows host verification pending. No merge to main, automatic deployment or product security certification.
