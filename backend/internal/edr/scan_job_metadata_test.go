package edr

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestScanJobMetadataRedactsSensitiveFields(t *testing.T) {
 now:=time.Date(2026,11,21,12,0,0,0,time.UTC)
 jobs:=[]ScanJob{{
  ID:"job-1",AgentID:"host-A",ScanType:"path",Status:"completed",
  RequestID:"SECRET_REQUEST",Path:`C:\Private\User\secret.bin`,
  LeaseID:"SECRET_LEASE",CreatedAt:now,ExpiresAt:now.Add(time.Hour),
  CompletedAt:&now,Engine:"clamav",Verdict:"malicious",
  ThreatName:"SECRET_SIGNATURE",Detail:"SECRET_WORKER_OUTPUT",
 }}
 response:=scanJobReviewMetadata(jobs)
 if len(response)!=1 || !response[0].SignatureReported ||
    response[0].Verdict!="malicious" || response[0].ID!="job-1" {
  t.Fatalf("metadata classification missing: %+v",response)
 }
 raw,err:=json.Marshal(response)
 if err!=nil{t.Fatal(err)}
 for _,s:=range []string{"SECRET_REQUEST","SECRET_LEASE","secret.bin","SECRET_SIGNATURE",
  "SECRET_WORKER_OUTPUT",`"request_id"`,`"path"`,`"lease_id"`,`"threat_name"`,`"detail"`} {
   if strings.Contains(string(raw),s){t.Fatalf("sensitive field in scan metadata: %s",s)}
 }
}

func TestScanJobMetadataEndpointBearerNoStoreReadOnly(t *testing.T){
 store:=NewStore()
 if _,err:=store.CheckIn(Agent{ID:"win1",Platform:"windows"});err!=nil{t.Fatal(err)}
 _,err:=store.CreateScan(ScanRequest{AgentID:"win1",RequestID:"PRIVATE_REQUEST",
  ScanType:"path",Path:`C:\Private\secret.exe`},time.Now().UTC())
 if err!=nil{t.Fatal(err)}
 h:=(&Server{Store:store,Token:"test-only-development-token",WebDir:"."}).Handler()
 for _,auth:=range []string{"","Bearer wrong"}{
  r:=httptest.NewRequest(http.MethodGet,"/api/scan-job-metadata",nil)
  if auth!=""{r.Header.Set("Authorization",auth)}
  w:=httptest.NewRecorder();h.ServeHTTP(w,r)
  if w.Code!=http.StatusUnauthorized{t.Fatalf("unauthorized scan status=%d",w.Code)}
 }
 r:=httptest.NewRequest(http.MethodGet,"/api/scan-job-metadata",nil)
 r.Header.Set("Authorization","Bearer test-only-development-token")
 w:=httptest.NewRecorder();h.ServeHTTP(w,r)
 if w.Code!=http.StatusOK{t.Fatalf("status=%d body=%s",w.Code,w.Body.String())}
 if w.Header().Get("Cache-Control")!="no-store"{t.Fatal("missing no-store")}
 for _,secret:=range []string{"PRIVATE_REQUEST","secret.exe",`"path"`,`"request_id"`,`"lease_id"`,`"detail"`,`"threat_name"`} {
  if strings.Contains(w.Body.String(),secret){t.Fatalf("leaked scan metadata: %s",secret)}
 }
 var got []ScanJobReview
 if err:=json.Unmarshal(w.Body.Bytes(),&got);err!=nil{t.Fatal(err)}
 if len(got)!=1||got[0].AgentID!="win1"||got[0].Status!="queued"{
  t.Fatalf("unexpected scan metadata: %#v",got)
 }
 r=httptest.NewRequest(http.MethodPost,"/api/scan-job-metadata",strings.NewReader("{}"))
 r.Header.Set("Authorization","Bearer test-only-development-token")
 w=httptest.NewRecorder();h.ServeHTTP(w,r)
 if w.Code!=http.StatusNotFound{t.Fatalf("unexpected scan write endpoint: %d",w.Code)}
 if len(store.ScanJobs())!=1{t.Fatal("scan metadata request mutated queue")}
}
