package edr

import (
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestMTLSHeartbeatRecordAndStatus(t *testing.T) {
 var writes int
 now:=time.Now().UTC()
 db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
  if strings.Contains(q,"edr_record_agent_heartbeat") {
   writes++
   if len(args)!=7 || args[0].Value!="tenantA" || args[1].Value!="win01" ||
      args[2].Value!="linux" || args[3].Value!="0.1.0" ||
      args[6].Value!=true {
    t.Fatalf("heartbeat unscoped: %q %#v",q,args)
   }
   return &scanRows{columns:[]string{"saved"},values:[][]driver.Value{{true}}},nil
  }
  if strings.Contains(q,"FROM edr_agent_heartbeats") {
   if len(args)!=2 || args[0].Value!="tenantA" || args[1].Value!="win01"{
    t.Fatalf("status lookup unscoped: %q %#v",q,args)
   }
   return &scanRows{columns:[]string{"platform","version","clamav","signature","ready","last_seen","count"},
       values:[][]driver.Value{{"linux","0.1.0","","",true,now,int64(2)}}},nil
  }
  t.Fatalf("unknown query %q",q)
  return nil,nil
 })
 h:=AgentScanQueueHandler(PostgresScanJobQueue{DB:db})
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 route:="/agent/v1/tenants/tenantA/agents/win01/heartbeat"
 w:=httptest.NewRecorder()
 h.ServeHTTP(w,scanRequest("POST",route,
  `{"platform":"linux","agent_version":"0.1.0","clamav_version":"","signature_version":"","scan_ready":true}`,principal))
 if w.Code!=204 || writes!=1 {t.Fatalf("heartbeat code=%d writes=%d",w.Code,writes)}
 w=httptest.NewRecorder()
 h.ServeHTTP(w,scanRequest("GET",route,"",principal))
 if w.Code!=200 || !strings.Contains(w.Body.String(),`"received_count":2`){
  t.Fatalf("heartbeat GET code %d body=%s",w.Code,w.Body.String())
 }
}
func TestHeartbeatCannotOverrideMTLSIdentity(t *testing.T){
 h:=AgentScanQueueHandler(PostgresScanJobQueue{})
 principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
 base:="/agent/v1/tenants/tenantA/agents/win01/heartbeat"
 good:=`{"platform":"linux","agent_version":"0.1.0","scan_ready":false}`
 cases:=[]struct{name,method,route,body string;want int}{
  {"wrong device","POST","/agent/v1/tenants/tenantA/agents/other/heartbeat",good,403},
  {"wrong tenant","GET","/agent/v1/tenants/other/agents/win01/heartbeat","",403},
  {"no identity","POST",base,good,401},
  {"unknown JSON","POST",base,`{"platform":"linux","agent_version":"0.1","tenant_id":"other"}`,400},
  {"invalid version","POST",base,`{"platform":"linux","agent_version":""}`,400},
  {"wrong verb","DELETE",base,"",405},
  {"DB offline","POST",base,good,503},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  p:=principal; if tc.name=="no identity"{p=nil}
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,scanRequest(tc.method,tc.route,tc.body,p))
  if w.Code!=tc.want{t.Fatalf("status %d want %d: %s",w.Code,tc.want,w.Body.String())}
 })}
}
