# TuranSec EDR — isolated GitHub Actions full CI

**GitHub repository:** `suhaylx/EDR` (private). **Primary approach:** GitHub-hosted `ubuntu-latest` creates its own fresh VM and the CI script builds disposable Docker test environments. **Fallback:** a dedicated ephemeral GitHub Actions self-hosted runner if GitHub-hosted runner assignment remains unavailable. This is **not GitLab**, not production deployment, and not a runner on a customer or live EDR host.

## What has been prepared

- **Primary GitHub-hosted workflow:** `.github/workflows/qa-full-github-hosted.yml`, `runs-on: ubuntu-latest`. No runner registration or VM provisioning is needed when GitHub-hosted capacity is available.
- **Fallback self-hosted workflow:** `.github/workflows/qa-full-self-hosted.yml`, label `turansec-edr-qa`, **one job** per ephemeral runner.
- Test orchestrator: `scripts/ci/run-github-full-ci.sh`. It uses fresh Docker containers for Go unit/race/vet, Rust Linux, Windows GNU cross-target compilation, Node tests and React checks.
- Disposable PostgreSQL 16: internal Docker network, unique CI container, **separate new database per suite** (migration chain 0001–0012, inventory SQL, queue/lease, enrollment, atomic challenge, revocation, certificate rotation), plus actual PostgreSQL container restart with committed marker verification.
- The runner checks the **exact GitHub SHA**, never reads production database URLs, never deploys endpoint services, and emits `qa-full-ci-results.txt` with individual PASS/FAIL and explicit NOT RUN. An upload-artifact step retains that report. **Missing integrated frontend is a BLOCKED release gate rather than a passing integrated build.**
- This SOC backend source branch does **not** contain the React frontend; the workflow separately checks out the prior integrated React lab at pinned commit `0466e7c47f098ffdb83f7818eb6571e0d941aebe`. This is separate source validation, **not** an integrated frontend/backend build. **The full-CI orchestration now deliberately marks the overall run FAILED if the React UI is absent from the current SOC backend SHA**, even when the separate historical React snapshot builds successfully, to prevent an unsupported enterprise-readiness PASS.

## Primary GitHub-hosted execution (no extra VM required)

The dedicated QA branch triggers `.github/workflows/qa-full-github-hosted.yml` automatically on push; the workflow requests a fresh GitHub-hosted `ubuntu-latest` VM and runs the same Docker-backed script. **Current obstacle:** GitHub-hosted jobs in this repository are failing before runner assignment (issues #148/#153), so this workflow cannot be considered PASS until a real job has a runner ID, executed steps and test logs. Once the workflow is reviewed and exists on the default branch, it is also available for manual `workflow_dispatch`. The self-hosted instructions below are only a fallback.

## Optional fallback: one-time setup by an authorized runner administrator

1. Provision a **new disposable Ubuntu Linux x64 VM** (suggest 8 vCPU, 16 GB RAM, 80 GB scratch disk) exclusively for QA. It needs outbound access to GitHub, the official runner release, Go/Rust/npm package registries, and container registries. **Firewall off access to production endpoints, the Ubuntu EDR backend, customer networks and domain controllers.** Do not use the active 89.126.* lab endpoints as a runner.
2. Install Docker Engine from the trusted Ubuntu/Docker packages. Verify `docker info`. Only allow a dedicated runner user to control Docker; Docker access is effectively root-equivalent, so this VM must contain **no sensitive credentials, SSH keys, persistent secrets or writable production mounts**.
3. Open the official repository at **Settings → Actions → Runners → New self-hosted runner** and select Linux x64. On the disposable VM, execute GitHub's official **download and SHA-256 verification** commands. Do **not** paste the GitHub registration token into ChatGPT, tickets or committed files.
4. From the verified official runner directory, use the reviewed `scripts/ci/bootstrap-github-ephemeral-runner.sh` helper on the **new disposable VM** (copy only this file from the reviewed commit; inspect it first). Set `EDR_QA_DISPOSABLE_VM=yes`; the helper refuses root, missing Docker, missing official `config.sh`/`run.sh`, and absent local registration credentials. The helper prompts locally for the token and registers an ephemeral runner. The equivalent direct GitHub invocation is:

   ```bash
   ./config.sh --url https://github.com/suhaylx/EDR \
     --token '<TOKEN_FROM_GITHUB_SETTINGS_ON_THIS_VM_ONLY>' \
     --unattended --ephemeral --labels turansec-edr-qa \
     --name turansec-edr-qa-disposable-01
   ./run.sh
   ```

   Run as a **non-root runner user**. This example uses a placeholder, not a real token. If GitHub Actions or the organization blocks runner registration, resolve [#153](https://github.com/suhaylx/EDR/issues/153); no workflow YAML can repair an unavailable or unregistered runner.
5. The runner accepts **one** matching queued GitHub Actions job and auto-deregisters. The optional self-hosted workflow triggers on a push to the dedicated `qa/github-actions-isolated-full-ci-20261121` branch. Once the workflow is reviewed and exists on the default branch, it can also be dispatched manually using **Actions → isolated-qa-full-ci → Run workflow**. Do **not** merge or run unreviewed production code merely to enable dispatch.
6. Read the resulting GitHub Actions job logs and the `turansec-edr-isolated-qa-ledger` artifact. Record exact SHA, runner ID, Go/Rust/Node/SQL outcomes, and any failed test output. Tear down the disposable VM after the job. Reprovision a clean VM and re-register a new ephemeral runner for the next full-CI attempt.

**Security:** The workflow only permits a trusted branch/manual trigger, requests `contents: read`, and checks out source with `persist-credentials: false`. Do not enable `pull_request_target`, untrusted fork execution, persistent runners, privileged test containers, or host Docker socket mounts inside the test containers. Preserve and securely ship ephemeral runner diagnostic logs outside the VM when needed.

## QA acceptance and honest test status

| Gate | What the runner will execute | Evidence until a runner runs |
| --- | --- | --- |
| Go backend | `go test ./...`, `go test -race -count=1 ./...`, `go vet ./...` | **NOT RUN** on this new workflow |
| Rust Linux | `cargo test --all-targets` and `cargo check` | **NOT RUN** |
| Rust Windows | Linux GNU cross-target `cargo check` only | **NOT RUN**; real Windows tests separately required |
| Node UI | `node --check` and existing Node-native backend/web tests | **NOT RUN** |
| React lab | `typecheck`, `test`, `build` on pinned historical commit | **NOT RUN**; frontend integration on current SOC head missing |
| PostgreSQL | 0001–0012 migrations, tenant inventory SQL, scan queue, enrollment, revocation, challenge and rotation | **NOT RUN** |
| Restart | Actual restart of **disposable** PostgreSQL container and committed marker check | **NOT RUN**; not full agent reboot |
| Host-specific | Real Sysmon Event 1/7, signed ClamAV EICAR, Windows/Linux heartbeat, browser accessibility, AD/LDAPS | **NOT RUN** and deliberately excluded |

**Release:** Production **NO-GO** until exact-head GitHub-hosted **or** self-hosted runner evidence, independent InfoSec review, and owner-led host tests are complete. Agent 2 owns deployment; Agent 3 owns the test evidence gate. Do not call the pipeline green just because GitHub accepts the YAML.

## CI failure investigation

Existing GitHub-hosted jobs have failed with **runner_id=0 and zero recorded steps**: [#148](https://github.com/suhaylx/EDR/issues/148), [#153](https://github.com/suhaylx/EDR/issues/153). The primary GitHub-hosted workflow cannot run until GitHub assigns workers; the self-hosted alternative remains a fallback, not a claim that the GitHub-hosted issue is resolved. If no self-hosted runner with all four labels is online, GitHub queues the job without executing its tests.

Official setup references: GitHub Docs **Self-hosted runners reference** and **Secure use of Actions**.
