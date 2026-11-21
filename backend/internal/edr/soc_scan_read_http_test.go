package edr

import(
 "context"
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)
func TestSOCReadAPIOffersTenantScopedHistory(t *testing.T){
 now:=time.Now().UTC()
 var reads int
 db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
  reads++
  if len(args)==0||args[0].Value!="tenantA"{
   t.Fatalf("SOC query is not tenant-scoped: %q %#v",q,args)
  }
  switch {
  case strings.Contains(q,"count(*) FILTER"):
   return &scanRows{columns:[]string{"total","pending","leased","succeeded","failed","cancelled"},
    values:[][]driver.Value{{int64(2),int64(0),int64(0),int64(2),int64(0),int64(0)}}},nil
  case strings.Contains(q,"SELECT count(*) FROM edr_scan_job_results"):
   return &scanRows{columns:[]string{"malicious"},values:[][]driver.Value{{int64(1)}}},nil
  case strings.Contains(q,"FROM edr_scan_job_results"):
   if strings.Contains(q,"LIMIT"){
    if args[1].Value!="win01"||args[2].Value!="malicious"{
     t.Fatalf("missing result filters %#v",args)
    }
   }
   return &scanRows{columns:[]string{"job_id","agent_id","engine","verdict","threat","detail","observed_at"},
    values:[][]driver.Value{{testUUID,"win01","clamav","malicious","Lab-Signature","",now}}},nil
  case strings.Contains(q,"FROM edr_scan_jobs"):
   return &scanRows{columns:[]string{"job_id","agent_id","root","state","attempts","created","updated"},
    values:[][]driver.Value{{testUUID,"win01","C:/Lab/file","succeeded",int64(1),now,now}}},nil
  default:
   t.Fatalf("unexpected read query: %s",q);return nil,nil
  }
 })
 q:=PostgresScanJobQueue{DB:db}
 handler:=SOCScanReadHandler(q)
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 base:="/soc/v1/tenants/tenantA/"
 paths:=[]struct{url,needle string}{
  {"scan-jobs?state=succeeded&limit=10&offset=0",`"state":"succeeded"`},
  {"scan-jobs/"+testUUID,`"job_id":"`+testUUID+`"`},
  {"scan-results?agent_id=win01&verdict=malicious&limit=5",`"verdict":"malicious"`},
  {"scan-results/"+testUUID,`"threat_name":"Lab-Signature"`},
  {"scan-stats",`"malicious":1`},
 }
 for _,tc:=range paths{t.Run(tc.url,func(t *testing.T){
  r:=httptest.NewRequest("GET",base+tc.url,nil)
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},principal))
  w:=httptest.NewRecorder()
  handler.ServeHTTP(w,r)
  if w.Code!=200||!strings.Contains(w.Body.String(),tc.needle){
   t.Fatalf("GET %s: status=%d body=%s",tc.url,w.Code,w.Body.String())
  }
  if strings.Contains(w.Body.String(),"lease_token")||strings.Contains(w.Body.String(),"lease_owner"){
   t.Fatal("scan lease capability leaked to SOC")
  }
 })}
 if reads!=6{t.Fatalf("expected 6 scoped reads, got %d",reads)}
}
func TestSOCReadsDoNotEscapeTenantOrUnboundLimit(t *testing.T){
 h:=SOCScanReadHandler(PostgresScanJobQueue{})
 viewer:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 for _,tc:=range []struct{route string;want int}{
  {"/soc/v1/tenants/tenantB/scan-jobs",403},
  {"/soc/v1/tenants/tenantA/scan-jobs?limit=9999",400},
  {"/soc/v1/tenants/tenantA/scan-results?verdict=unknown",503},
  {"/soc/v1/tenants/tenantA/scan-stats?tenant=other",400},
 }{
  r:=httptest.NewRequest("GET",tc.route,nil)
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},viewer))
  w:=httptest.NewRecorder();h.ServeHTTP(w,r)
  // Invalid verdict is validated by adapter before database access.
  want:=tc.want
  if strings.Contains(tc.route,"verdict=unknown"){want=400}
  if w.Code!=want{t.Fatalf("%s status=%d want=%d",tc.route,w.Code,want)}
 }
}
