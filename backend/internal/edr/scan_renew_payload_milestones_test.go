package edr

import (
 "net/http/httptest"
 "testing"
)

func TestBE031To035RenewalPayloadValidation(t *testing.T){
 base:="/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew"
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 cases:=[]struct{name,body string}{
  {"BE031 empty JSON object",`{}`},
  {"BE032 missing lease token",`{"job_id":"`+testUUID+`","lease_seconds":30}`},
  {"BE033 missing job identifier",`{"lease_token":"`+leaseUUID+`","lease_seconds":30}`},
  {"BE034 unknown identity field",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30,"agent_id":"win02"}`},
  {"BE035 multiple JSON documents",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}{}`},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  w:=httptest.NewRecorder()
  AgentScanQueueHandler(PostgresScanJobQueue{}).ServeHTTP(w,scanRequest("POST",base,tc.body,principal))
  if w.Code!=400 {t.Fatalf("status=%d want=400",w.Code)}
 })}
}
