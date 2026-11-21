package edr

import (
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestBE021To025RenewalIdentityBoundary(t *testing.T) {
 base := "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew"
 valid := &AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 cases := []struct{name,path string; principal *AgentIdentity; want int}{
  {"BE021 missing authenticated principal",base,nil,http.StatusUnauthorized},
  {"BE022 tenant substitution","/agent/v1/tenants/tenantB/agents/win01/scan-jobs/renew",valid,http.StatusForbidden},
  {"BE023 agent substitution","/agent/v1/tenants/tenantA/agents/win02/scan-jobs/renew",valid,http.StatusForbidden},
  {"BE024 malformed tenant route","/agent/v1/tenants/tenantA/agents/../scan-jobs/renew",valid,http.StatusForbidden},
  {"BE025 mismatched authenticated principal",base,&AgentIdentity{TenantID:"tenantA",AgentID:"win02"},http.StatusForbidden},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  w:=httptest.NewRecorder()
  AgentScanQueueHandler(PostgresScanJobQueue{}).ServeHTTP(w,scanRequest("POST",tc.path,"{}",tc.principal))
  if w.Code!=tc.want {t.Fatalf("status=%d want=%d",w.Code,tc.want)}
 })}
}
