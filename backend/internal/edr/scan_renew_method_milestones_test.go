package edr

import (
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestBE026To030RenewalMethodAndQuery(t *testing.T){
 base:="/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew"
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 cases:=[]struct{name,method,path string;want int}{
  {"BE026 GET denied","GET",base,405},
  {"BE027 PUT denied","PUT",base,405},
  {"BE028 DELETE denied","DELETE",base,405},
  {"BE029 query tenant override denied","POST",base+"?tenant_id=tenantB",400},
  {"BE030 query token override denied","POST",base+"?lease_token=ignored",400},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  w:=httptest.NewRecorder()
  AgentScanQueueHandler(PostgresScanJobQueue{}).ServeHTTP(w,scanRequest(tc.method,tc.path,"",principal))
  if w.Code!=tc.want {t.Fatalf("status=%d want=%d",w.Code,tc.want)}
  if tc.want==http.StatusMethodNotAllowed && w.Header().Get("Allow")!="POST" {t.Fatalf("missing POST Allow header")}
 })}
}
