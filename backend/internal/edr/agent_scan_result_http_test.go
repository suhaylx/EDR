package edr

import (
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestAgentScanResultStoredWithinAuthenticatedScope(t *testing.T){
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if !strings.Contains(query,"edr_complete_scan_job_with_result")||len(args)!=7||
   args[0].Value!="tenantA"||args[1].Value!="win01"||args[2].Value!=testUUID||
   args[3].Value!=leaseUUID||args[4].Value!="malicious"||args[5].Value!="Lab-Signature"{
   t.Fatalf("unscoped malware persistence: %q %#v",query,args)
  }
  return &scanRows{columns:[]string{"saved"},values:[][]driver.Value{{true}}},nil
 })
 h:=AgentScanQueueHandler(PostgresScanJobQueue{DB:db})
 body:=`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"malicious","threat_name":"Lab-Signature","detail":""}`
 w:=httptest.NewRecorder()
 h.ServeHTTP(w,scanRequest("POST","/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete-result",
 body,&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}))
 if w.Code!=204 {t.Fatalf("malware result status %d: %s",w.Code,w.Body.String())}
}
func TestAgentScanResultRejectsSpoofingAndMalformedVerdicts(t *testing.T){
 h:=AgentScanQueueHandler(PostgresScanJobQueue{})
 path:="/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete-result"
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 cases:=[]struct{name,path,body string;want int}{
  {"unknown verdict",path,`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"safe"}`,400},
  {"missing threat on malicious",path,`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"malicious"}`,400},
  {"injected tenant field",path,`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"error","tenant_id":"tenantB"}`,400},
  {"cross tenant route","/agent/v1/tenants/tenantB/agents/win01/scan-jobs/complete-result","{}",403},
  {"valid but database down",path,`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"error"}`,503},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,scanRequest("POST",tc.path,tc.body,principal))
  if w.Code!=tc.want {t.Fatalf("status %d expected %d",w.Code,tc.want)}
 })}
}

func TestScanResultRejectsControlCharacters(t *testing.T) {
  for _,tc:=range []struct{verdict,threat,detail string}{
    {"malicious","Lab\nSignature",""},
    {"malicious","Lab-Signature","line\rbreak"},
    {"error","","bad\tmessage"},
    {"clean_by_signature","unexpected-threat",""},
    {"unscanned","", "injected\x00null"},
  } {
    if validScanResult(tc.verdict,tc.threat,tc.detail) {
      t.Fatalf("unsafe result unexpectedly valid: %q",tc.verdict)
    }
  }
  if !validScanResult("malicious","Lab-Signature","") {
    t.Fatal("safe malware signature unexpectedly refused")
  }
}
