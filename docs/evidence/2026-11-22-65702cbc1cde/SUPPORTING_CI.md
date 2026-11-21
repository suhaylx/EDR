# Supporting CI — exact source 65702cbc

Source: `65702cbc1cde6750304d9e438bb27bc0537c2d45`.

All 15 supporting workflows completed successfully, attempt 1. This record was reconstructed from verified GitHub responses and the independent CI agent's final report after the execution workspace became unavailable; it does not claim the hash of the earlier local Markdown report.

| Workflow | Exact run | Result |
|---|---|---|
| postgres-certificate-rotation | [44951109326](https://github.com/suhaylx/EDR/actions/runs/44951109326) | SUCCESS |
| postgres-enrollment-challenges | [44951109439](https://github.com/suhaylx/EDR/actions/runs/44951109439) | SUCCESS |
| postgres-enrollment-integration | [44951109391](https://github.com/suhaylx/EDR/actions/runs/44951109391) | SUCCESS |
| postgres-revocation-integration | [44951109508](https://github.com/suhaylx/EDR/actions/runs/44951109508) | SUCCESS |
| ubuntu-go-backend-lab-build | [44951109399](https://github.com/suhaylx/EDR/actions/runs/44951109399) | SUCCESS |
| postgres-atomic-agent-enrollment | [44951109412](https://github.com/suhaylx/EDR/actions/runs/44951109412) | SUCCESS |
| postgres-migration-chain | [44951109334](https://github.com/suhaylx/EDR/actions/runs/44951109334) | SUCCESS |
| Windows lab preflight | [44951109461](https://github.com/suhaylx/EDR/actions/runs/44951109461) | SUCCESS |
| rust-agent-ci | [44951109474](https://github.com/suhaylx/EDR/actions/runs/44951109474) | SUCCESS |
| postgres-scan-job-queue | [44951109373](https://github.com/suhaylx/EDR/actions/runs/44951109373) | SUCCESS |
| starter-ci | [44951109351](https://github.com/suhaylx/EDR/actions/runs/44951109351) | SUCCESS |
| frontend-ui-checks | [44951109482](https://github.com/suhaylx/EDR/actions/runs/44951109482) | SUCCESS |
| p0-agent-mtls-scan-listener | [44951109462](https://github.com/suhaylx/EDR/actions/runs/44951109462) | SUCCESS |
| linux-lab-agent-build | [44951109317](https://github.com/suhaylx/EDR/actions/runs/44951109317) | SUCCESS |
| windows-lab-agent-build | [44951109354](https://github.com/suhaylx/EDR/actions/runs/44951109354) | SUCCESS |

## Native Windows Go evidence

[Job 136989002857](https://github.com/suhaylx/EDR/actions/runs/44951109462/job/136989002857) ran on Windows Server 2025 with Go 1.25.0 windows/amd64, checked out the full source SHA, executed `go test -count=1 ./...` with all three packages passing, and passed `go vet ./...`. The [Linux job 136989002627](https://github.com/suhaylx/EDR/actions/runs/44951109462/job/136989002627) passed race tests and vet.

These are native GitHub runner executions. They do not establish the required Windows Server 2022 or designated Ubuntu deployment-host installation, managed ClamAV/Sysmon acceptance, signed packages, live rollback, owner approvals, or deployment authorization.
