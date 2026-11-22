package edr

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

// M51-M75: executable negative API contracts on the tenant/device-scoped
// scan handler. This uses an injected verified principal to isolate HTTP
// authorization semantics; real certificate validation has separate tests.
// No PostgreSQL connection or real endpoint is needed. Any unexpected request
// to a storage adapter fails closed because the DB is not configured.
func TestQAHTTPAuthorizationAdversarialMatrixM51ToM75(t *testing.T) {
    principal := &AgentIdentity{TenantID:"tenantA", AgentID:"win01"}
    h := AgentScanQueueHandler(PostgresScanJobQueue{})
    cases := []struct {
        name string
        method string
        path string
        body string
        haveIdentity bool
        wantStatus int
    }{
        {"M51-no-identity-claim", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim", "", false, 401},
        {"M52-no-identity-completion", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}", false, 401},
        {"M53-cross-tenant-claim", "POST", "/agent/v1/tenants/tenantB/agents/win01/scan-jobs/claim", "", true, 403},
        {"M54-cross-agent-claim", "POST", "/agent/v1/tenants/tenantA/agents/other/scan-jobs/claim", "", true, 403},
        {"M55-cross-tenant-completion", "POST", "/agent/v1/tenants/tenantB/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}", true, 403},
        {"M56-cross-agent-completion", "POST", "/agent/v1/tenants/tenantA/agents/other/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}", true, 403},
        {"M57-claim-get-not-allowed", "GET", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim", "", true, 405},
        {"M58-claim-put-not-allowed", "PUT", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim", "", true, 405},
        {"M59-claim-delete-not-allowed", "DELETE", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim", "", true, 405},
        {"M60-complete-get-not-allowed", "GET", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "", true, 405},
        {"M61-complete-patch-not-allowed", "PATCH", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "", true, 405},
        {"M62-unknown-command-denied", "POST", "/agent/v1/tenants/tenantA/agents/win01/response/kill-process", "", true, 404},
        {"M63-claim-query-smuggling", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim?tenant_id=tenantB", "", true, 400},
        {"M64-completion-query-smuggling", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete?agent_id=other", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}", true, 400},
        {"M65-empty-completion-body", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "", true, 400},
        {"M66-malformed-completion-json", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{", true, 400},
        {"M67-array-instead-of-object", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "[]", true, 400},
        {"M68-null-completion-object", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "null", true, 400},
        {"M69-missing-required-success", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\"}", true, 400},
        {"M70-null-success", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":null}", true, 400},
        {"M71-string-success", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":\"true\"}", true, 400},
        {"M72-malformed-job-uuid", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"not-a-uuid\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}", true, 400},
        {"M73-malformed-lease-token", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"stolen\",\"success\":true}", true, 400},
        {"M74-extra-tenant-field", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true,\"tenant_id\":\"tenantB\"}", true, 400},
        {"M75-trailing-json-payload", "POST", "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete", "{\"job_id\":\"11111111-1111-4111-8111-111111111111\",\"lease_token\":\"22222222-2222-4222-8222-222222222222\",\"success\":true}{}", true, 400},
    }
    if len(cases) != 25 { t.Fatalf("adversarial matrix shrank to %d",len(cases)) }
    for _,tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            var as *AgentIdentity
            if tc.haveIdentity { as=principal }
            w:=httptest.NewRecorder()
            h.ServeHTTP(w,scanRequest(tc.method,tc.path,tc.body,as))
            if w.Code!=tc.wantStatus {
                t.Fatalf("%s %s status=%d want=%d response=%q",
                    tc.method,tc.path,w.Code,tc.wantStatus,w.Body.String())
            }
            if w.Header().Get("Cache-Control")!="no-store" {
                t.Fatal("agent API response may be cached")
            }
            if strings.Contains(w.Body.String(),"\"lease_token\"") ||
                strings.Contains(w.Body.String(),"\"scan_root\"") {
                t.Fatal("denied agent API returned a lease capability or scan path")
            }
            if tc.wantStatus==http.StatusMethodNotAllowed &&
                w.Header().Get("Allow")!="POST" {
                t.Fatal("method denial must advertise POST only")
            }
        })
    }
}
