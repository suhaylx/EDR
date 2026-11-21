# TuranSec EDR — Agent 5 code review with Backend / QA handoff

**21 Nov 2026, Asia/Tashkent.** Scope: private `suhaylx/EDR`,
review follow-up stacked on Agent 5 draft PR #151. Source-checked
Go `http.go`, `store.go`, `overview.go`, `scans.go`; React
`policy-readonly.ts`, `PolicyEvidenceReview.tsx`, `endpoint-inventory.ts`,
`main.tsx` and associated tests. This artifact does **not**
prove independent Agent 2/3 review or passing CI.

## Code review findings and changes

| ID | Priority | Evidence / risk | Corrective code | Verification |
|---|---|---|---|---|
| CR-01 | P1 | The React policy view requested Go `GET /api/policies`; its JSON contains the entire Sysmon XML document despite the screen needing only IDs, revisions, names and SHA256. Shared-token lab responses have no tenant-scoped authorization. | New `GET /api/policy-metadata` produces a Go `PolicyMetadata` DTO without XML; React requests it and rejects any XML-bearing legacy fallback. **Existing lab `/api/policies` still returns XML to legacy clients**; this is exposure reduction in the React flow, not authorization hardening. | `backend/internal/edr/policy_metadata_test.go`; `frontend/tests/policy-backend-contract.test.mjs`; SSR tests |
| CR-02 | P1 | Policy failure detail is an arbitrary endpoint-reported string. Both `PolicyEvidenceReview` and `policyEvidenceLabel` rendered it, potentially exposing user names, file paths or sender error text in the shared-token dashboard. | Present policy-error **presence**, never body, in review rows and inventory labels. React UI shows `detail withheld`. Raw backend overview still has `last_policy_error`, so backend should consider a role-scoped DTO for production. | `frontend/tests/policy-backend-contract.test.mjs`, `backend-aligned-sprint-render.test.mjs`, `endpoint-inventory.test.mjs` |
| CR-03 | P0 | [CI issue #153](https://github.com/suhaylx/EDR/issues/153) / [QA issue #148](https://github.com/suhaylx/EDR/issues/148): GitHub Actions reported failed jobs with runner_id=0/zero executed steps, log blob unavailable. Failure is not test evidence. | No workaround or bypass; PR stays draft. Agent 2 DevOps to establish runner assignment and rerun exact HEAD; Agent 3 to capture actual logs. | NOT EXECUTED until actual runner/build logs available |
| CR-04 | P0 | [Backend SOC PR #149](https://github.com/suhaylx/EDR/pull/149), [#150](https://github.com/suhaylx/EDR/pull/150), [#152](https://github.com/suhaylx/EDR/pull/152) are a **different, still-draft mTLS tenant-scoped SOC stack**. React PR #151 uses shared bearer token and in-memory lab responses. | **Do not wire React lab token to mTLS SOC APIs or imply production RBAC.** Agent 2 to publish operator-certificate browser/BFF architecture, tenant-scoped view schemas, exact JSON payloads, and access-control matrix first. | [QA #154](https://github.com/suhaylx/EDR/issues/154) negative cert/tenant/role tests; NO-GO pending Agent 1/2/3 |
| CR-05 | P1 | The earlier frontend filtered rolling N×24h; Go overview uses UTC calendar midnight boundaries and filters event `Time`, not `received_at`. | Already corrected on parent PR #151; **do not revert**. Go receipt time is provenance, not overview period membership. | `backend-calendar-window.test.mjs`, `evidence-snapshot-25.test.mjs`; require exact-head CI |

## QA reproducible acceptance

**Backend / Agent 2:** in a reviewed checkout of this exact PR head, execute:

```sh
cd backend
go test ./internal/edr -run 'TestPolicyMetadata' -count=1 -v
go test ./...
go vet ./...
```

Expected `GET /api/policy-metadata` response:
`[{id,name,platform,revision,sha256,created_at}]` and
**no `xml` property or Sysmon rule body**. A valid lab bearer is
required; HTTP 401 without it, `Cache-Control: no-store`;
POST to this new path has no mutation handler.
The legacy `GET /api/policies` remains unchanged.
**Backend owner review required** before merge for API naming,
compatibility and hardening.

**QA / Agent 3:** independently run (not simulated by this document):

```sh
cd frontend
npm ci
npm run typecheck
npm test
npm run build
```

Check (a) the metadata route is used, never `/api/policies`;
(b) a legacy response with `xml` fails closed; (c) raw
`last_policy_error` does not appear in either policy or
inventory HTML; (d) absent/invalid token produces no
cached/partial evidence; (e) duplicate IDs, metadata bounds,
XSS cases, UTC calendar boundaries, scan job lease redaction.
Then real Chromium/Firefox tab order, forced colors, 200% zoom,
NVDA/Orca. **SSR is not screen-reader QA.**

**Backend-to-Frontend dependencies:** The six-request
all-or-nothing React refresh now requires the additional
metadata-only Go route. Do **not** cherry-pick the React fetch
change without its backend companion. Conversely, this route
does not expose or authorize any production mTLS SOC operation.
No host scan/policy command or deployment is part of this patch.

## Release gates and outcome

- Code review fixes are **committed on a draft feature branch** only.
- Agent 1 approval of policy/error confidentiality is pending.
- Agent 2 Go API review + actual Go test execution is pending.
- Agent 3 strict TS/Node/browser QA + negative auth is pending.
- Agent 4 PM must reconcile stacked draft PR #151 and this review PR;
  protect main, avoid automatic merge.
- Production release: **NO-GO**. Exact-head CI **not yet verified**.

Proof of a commit does not prove passing tests, an independent reviewer
or a deployed endpoint.
