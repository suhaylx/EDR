package edr

import (
 "context"
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestSprintDay2SOCEndpointInventoryAndTimeline(t *testing.T){
 now:=time.Now().UTC()
 observed:=map[string]int{}
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if len(args)==0||args[0].Value!="tenantA" {
   t.Fatalf("endpoint inventory escaped authenticated tenant: %q %#v",query,args)
  }
  if strings.Contains(query,"WITH inventory AS"){
   switch {
   case strings.Contains(query,"count(*)"):
    observed["summary"]++
    return &scanRows{columns:[]string{"total","windows","linux","online",
      "degraded","stale","unseen","revoked"},
      values:[][]driver.Value{{int64(4),int64(2),int64(2),
       int64(1),int64(1),int64(1),int64(1),int64(0)}}},nil
   case strings.Contains(query,"WHERE agent_id=$2"):
    observed["detail"]++
    if args[1].Value!="win01"{t.Fatalf("unscoped agent detail: %#v",args)}
   case strings.Contains(query,"LIMIT"):
    observed["list"]++
    if args[1].Value!="windows"||args[2].Value!="online"||
     args[3].Value!=int64(10)||args[4].Value!=int64(0) {
     t.Fatalf("incorrect filters/pagination: %#v",args)
    }
   default:t.Fatalf("unexpected inventory SQL: %q",query)
   }
   return &scanRows{columns:[]string{"agent","platform","version","clamav",
    "signature","ready","seen","count","health"},
    values:[][]driver.Value{{"win01","windows","0.1.0","1.5.5",
    "sig-2026",true,now,int64(4),"online"}}},nil
  }
  if strings.Contains(query,"FROM edr_scan_jobs AS j"){
   observed["timeline"]++
   if args[1].Value!="win01"||args[2].Value!=int64(5){
    t.Fatalf("timeline escaped agent scope: %#v",args)
   }
   return &scanRows{columns:[]string{"ref","agent","kind","state","detail","at"},
    values:[][]driver.Value{{testUUID,"win01","malware_alert","open",
      "Lab-Signature",now}}},nil
  }
  t.Fatalf("unexpected query: %s",query)
  return nil,nil
 })
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 handler:=SOCScanHandler(PostgresScanJobQueue{DB:db})
 base:="/soc/v1/tenants/tenantA/"
 cases:=[]struct{uri,needle string}{
  {"endpoints?platform=windows&health=online&limit=10&offset=0",
   `"agent_version":"0.1.0"`},
  {"endpoints/win01",`"health":"online"`},
  {"endpoint-stats",`"degraded":1`},
  {"endpoints/win01/timeline?limit=5",`"kind":"malware_alert"`},
 }
 for _,tc:=range cases {t.Run(tc.uri,func(t *testing.T){
  r:=httptest.NewRequest("GET",base+tc.uri,nil)
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p))
  w:=httptest.NewRecorder()
  handler.ServeHTTP(w,r)
  if w.Code!=200||!strings.Contains(w.Body.String(),tc.needle){
   t.Fatalf("GET %s code=%d body=%s",tc.uri,w.Code,w.Body.String())
  }
  for _,secret:=range []string{"lease_token","lease_owner","fingerprint_sha256"}{
   if strings.Contains(w.Body.String(),secret){t.Fatalf("SOC response leaked %s",secret)}
  }
 })}
 for _,kind:=range []string{"list","detail","summary","timeline"}{
  if observed[kind]!=1{t.Fatalf("missing SOC %s route: %v",kind,observed)}
 }
}

func TestSprintDay2SOCEndpointsRefuseCrossTenantAndInvalidInput(t *testing.T){
 h:=SOCEndpointHandler(PostgresScanJobQueue{})
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 cases:=[]struct{method,path string;want int}{
  {"GET","/soc/v1/tenants/tenantB/endpoints",403},
  {"POST","/soc/v1/tenants/tenantA/endpoints",405},
  {"GET","/soc/v1/tenants/tenantA/endpoints?platform=freebsd",400},
  {"GET","/soc/v1/tenants/tenantA/endpoints?health=active",400},
  {"GET","/soc/v1/tenants/tenantA/endpoints?limit=1000",400},
  {"GET","/soc/v1/tenants/tenantA/endpoint-stats?tenant=tenantB",400},
  {"GET","/soc/v1/tenants/tenantA/endpoints/win01/timeline?limit=101",400},
  {"GET","/soc/v1/tenants/tenantA/endpoints/win01/timeline?offset=500",400},
  {"GET","/soc/v1/tenants/tenantA/endpoints/win01",503},
 }
 for _,tc:=range cases {t.Run(tc.path,func(t *testing.T){
  r:=httptest.NewRequest(tc.method,tc.path,nil)
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p))
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,r)
  if w.Code!=tc.want{t.Fatalf("%s %s status=%d want=%d",
   tc.method,tc.path,w.Code,tc.want)}
 })}
}
