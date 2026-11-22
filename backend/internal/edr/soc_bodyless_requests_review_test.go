package edr

import (
 "context"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

type qaZeroThenData struct{
 first bool
 remaining []byte
}
func(r *qaZeroThenData)Read(dst []byte)(int,error){
 if !r.first{r.first=true;return 0,nil}
 if len(r.remaining)==0{return 0,io.EOF}
 n:=copy(dst,r.remaining)
 r.remaining=r.remaining[n:]
 return n,nil
}

func TestQAReviewBodylessReaderRejectsDelayedPayload(t *testing.T){
 for _,value:=range []string{"{}",`{"tenant_id":"other"}`,"x"}{
  r:=httptest.NewRequest("POST","/soc/v1/tenants/tenantA/alerts/"+testUUID+"/ack",nil)
  r.Body=io.NopCloser(&qaZeroThenData{remaining:[]byte(value)})
  w:=httptest.NewRecorder()
  if requestBodyIsEmpty(w,r){
   t.Fatalf("accepted delayed request payload %q",value)
  }
 }
 r:=httptest.NewRequest("POST","/soc/v1/tenants/tenantA/alerts/"+testUUID+"/ack",nil)
 w:=httptest.NewRecorder()
 if !requestBodyIsEmpty(w,r){t.Fatal("genuine empty body refused")}
}

func TestQAReviewNoBodyRoutesRejectZeroNilBeforeDatabase(t *testing.T){
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 h:=SOCScanHandler(PostgresScanJobQueue{})
 cases:=[]string{
  "/soc/v1/tenants/tenantA/alerts/"+testUUID+"/ack",
  "/soc/v1/tenants/tenantA/alerts/"+testUUID+"/reopen",
  "/soc/v1/tenants/tenantA/scan-jobs/"+testUUID+"/cancel",
 }
 for _,path:=range cases{t.Run(path,func(t *testing.T){
  r:=httptest.NewRequest(http.MethodPost,path,nil)
  r.Body=io.NopCloser(&qaZeroThenData{remaining:[]byte("{}")})
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},principal))
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,r)
  if w.Code!=http.StatusBadRequest{
   t.Fatalf("delayed payload allowed to reach DB: %d %s",w.Code,w.Body.String())
  }
 })}
}

func TestQAReviewAgentClaimRejectsDelayedPayload(t *testing.T){
 h:=AgentScanQueueHandler(PostgresScanJobQueue{})
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 r:=scanRequest(http.MethodPost,
  "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim","",principal)
 r.Body=io.NopCloser(&qaZeroThenData{remaining:[]byte(strings.Repeat("X",2))})
 w:=httptest.NewRecorder()
 h.ServeHTTP(w,r)
 if w.Code!=http.StatusBadRequest{
  t.Fatalf("agent claim accepted delayed body: %d %s",w.Code,w.Body.String())
 }
}
