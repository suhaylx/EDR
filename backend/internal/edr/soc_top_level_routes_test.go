package edr

import (
 "context"
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

// This exercises the *top-level* SOC router. Tests that invoke a child
// handler directly cannot catch accidental disconnection of live routes.
func TestSprintDay1SOCDispatchesAllOperatorFunctionalRoutes(t *testing.T) {
 now:=time.Now().UTC()
 calls:=map[string]int{}
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if len(args)==0 || args[0].Value!="tenantA" {
   t.Fatalf("SOC SQL escaped tenant: %q %#v",query,args)
  }
  switch {
  case strings.Contains(query,"edr_soc_change_alert_state"):
   calls["ack"]++
   if args[1].Value!="analyst" || args[3].Value!="ack" {
    t.Fatalf("alert transition lost verified principal: %#v",args)
   }
   return &scanRows{columns:[]string{"ok"},values:[][]driver.Value{{true}}},nil
  case strings.Contains(query,"count(*) FILTER") && strings.Contains(query,"edr_soc_alerts"):
   calls["alert-stats"]++
   return &scanRows{columns:[]string{"open","acknowledged","resolved"},
    values:[][]driver.Value{{int64(1),int64(0),int64(0)}}},nil
  case strings.Contains(query,"count(*) FILTER") && strings.Contains(query,"edr_scan_jobs"):
   calls["scan-stats"]++
   return &scanRows{columns:[]string{"total","pending","leased","succeeded","failed","cancelled"},
    values:[][]driver.Value{{int64(2),int64(0),int64(0),int64(2),int64(0),int64(0)}}},nil
  case strings.Contains(query,"SELECT count(*) FROM edr_scan_job_results"):
   return &scanRows{columns:[]string{"malicious"},values:[][]driver.Value{{int64(1)}}},nil
  case strings.Contains(query,"edr_enqueue_operator_scan_job"):
   calls["schedule"]++
   if args[1].Value!="analyst" || args[2].Value!="win01" {
    t.Fatalf("scan scheduling lost verified principal: %#v",args)
   }
   return &scanRows{columns:[]string{"job_id","created"},values:[][]driver.Value{{testUUID,true}}},nil
  case strings.Contains(query,"FROM edr_agents AS a"):
   return &scanRows{columns:[]string{"platform"},values:[][]driver.Value{{"windows"}}},nil
  case strings.Contains(query,"FROM edr_soc_alerts"):
   calls["alerts"]++
   return &scanRows{columns:[]string{"alert_id","job_id","agent_id","category",
    "severity","signature","state","created","updated","acked_by","resolved_by","note","assigned_to"},
    values:[][]driver.Value{{testUUID,leaseUUID,"win01","malware_signature",
    "high","Lab-Signature","open",now,now,"","","",""}}},nil
  default:
   t.Fatalf("unexpected top-level SOC SQL %q",query)
   return nil,nil
  }
 })
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 handler:=SOCScanHandler(PostgresScanJobQueue{DB:db})
 base:="/soc/v1/tenants/tenantA/"
 cases:=[]struct{method,path,body string;want int;contains string}{
  {"GET","scan-stats","",200,`"malicious":1`},
  {"GET","alerts?state=open","",200,`"signature_name":"Lab-Signature"`},
  {"GET","alert-stats","",200,`"open":1`},
  {"POST","scan-jobs",`{"agent_id":"win01","request_id":"day1-001","scan_root":"C:\\Lab\\sample"}`,201,`"created":true`},
  {"POST","alerts/"+testUUID+"/ack","",204,""},
 }
 for _,tc:=range cases {
  t.Run(tc.method+" "+tc.path,func(t *testing.T){
   r:=httptest.NewRequest(tc.method,base+tc.path,strings.NewReader(tc.body))
   r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},principal))
   w:=httptest.NewRecorder()
   handler.ServeHTTP(w,r)
   if w.Code!=tc.want || !strings.Contains(w.Body.String(),tc.contains) {
    t.Fatalf("%s %s: got %d body %q; expected %d and %q",
     tc.method,tc.path,w.Code,w.Body.String(),tc.want,tc.contains)
   }
   if w.Header().Get("Cache-Control")!="no-store" {
    t.Fatal("sensitive SOC response unexpectedly cacheable")
   }
  })
 }
 for _,operation:=range []string{"scan-stats","alerts","alert-stats","schedule","ack"}{
  if calls[operation]!=1 {t.Errorf("%s routed %d times (want 1)",operation,calls[operation])}
 }
}

func TestSprintDay1ViewerCannotUseSOCWrites(t *testing.T) {
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 h:=SOCScanHandler(PostgresScanJobQueue{})
 for _,path:=range []string{
  "/soc/v1/tenants/tenantA/scan-jobs",
  "/soc/v1/tenants/tenantA/alerts/"+testUUID+"/ack",
 } {
  r:=httptest.NewRequest("POST",path,strings.NewReader("{}"))
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},principal))
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,r)
  if w.Code!=403 {t.Errorf("viewer POST %s returned %d (want 403)",path,w.Code)}
 }
}
