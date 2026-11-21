package edr

import (
 "context"
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestSprintDay3SOCAnalystCaseWorkflow(t *testing.T){
 now:=time.Now().UTC()
 calls:=map[string]int{}
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if len(args)==0||args[0].Value!="tenantA"{
   t.Fatalf("case SQL tenant scope missing: %q %#v",query,args)
  }
  switch{
  case strings.Contains(query,"edr_soc_assign_alert"):
   calls["assign"]++
   if args[1].Value!="lead"||args[2].Value!=testUUID||
    args[3].Value!="investigator"{t.Fatalf("unexpected case assignment: %#v",args)}
   return &scanRows{columns:[]string{"saved"},values:[][]driver.Value{{true}}},nil
  case strings.Contains(query,"edr_soc_add_alert_note"):
   calls["notes"]++
   if args[1].Value!="lead"||args[2].Value!=testUUID||
    args[3].Value!="Reviewed in SOC lab" {
    t.Fatalf("unscoped case note: %#v",args)
   }
   return &scanRows{columns:[]string{"activity_id"},
    values:[][]driver.Value{{leaseUUID}}},nil
  case strings.Contains(query,"FROM edr_soc_alert_activity"):
   calls["activity"]++
   if args[1].Value!=testUUID||args[2].Value!=int64(5)||
    args[3].Value!=int64(0){t.Fatalf("unscoped case activity: %#v",args)}
   return &scanRows{columns:[]string{"activity_id","actor_id","action","note","occurred_at"},
    values:[][]driver.Value{{leaseUUID,"lead","assigned","investigator",now}}},nil
  case strings.Contains(query,"FROM edr_soc_alerts")&&strings.Contains(query,"assigned_to=$2"):
   calls["my-alerts"]++
   if args[1].Value!="lead"{
    t.Fatalf("client-controlled assignment queue: %#v",args)
   }
   return &scanRows{columns:[]string{"alert_id","job_id","agent_id",
    "category","severity","signature_name","state","created_at","updated_at",
    "acknowledged_by","resolved_by","resolution_note","assigned_to"},
    values:[][]driver.Value{{testUUID,leaseUUID,"win01","malware_signature",
    "high","Lab-Signature","open",now,now,"","","","lead"}}},nil
  }
  t.Fatalf("unknown case SQL: %s",query)
  return nil,nil
 })
 handler:=SOCScanHandler(PostgresScanJobQueue{DB:db})
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"lead",Role:"scanner"}
 base:="/soc/v1/tenants/tenantA/"
 cases:=[]struct{method,path,body string;want int;contains string}{
  {"GET","my-alerts?limit=10","",200,`"assigned_to":"lead"`},
  {"POST","alerts/"+testUUID+"/assign",
   `{"operator_id":"investigator"}`,204,""},
  {"POST","alerts/"+testUUID+"/notes",
   `{"note":"Reviewed in SOC lab"}`,201,`"activity_id":"`+leaseUUID+`"`},
  {"GET","alerts/"+testUUID+"/activity?limit=5","",200,
   `"action":"assigned"`},
 }
 for _,tc:=range cases{
  t.Run(tc.method+" "+tc.path,func(t *testing.T){
   r:=httptest.NewRequest(tc.method,base+tc.path,strings.NewReader(tc.body))
   r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p))
   w:=httptest.NewRecorder()
   handler.ServeHTTP(w,r)
   if w.Code!=tc.want||!strings.Contains(w.Body.String(),tc.contains){
    t.Fatalf("%s %s: code=%d body=%s",tc.method,tc.path,w.Code,w.Body.String())
   }
   if w.Header().Get("Cache-Control")!="no-store"{
    t.Fatal("SOC case API cached a sensitive response")
   }
  })
 }
 for _,name:=range []string{"my-alerts","assign","notes","activity"}{
  if calls[name]!=1{t.Errorf("%s calls=%d want=1",name,calls[name])}
 }
}

func TestSprintDay3SOCViewerCanReadButCannotAlterCases(t *testing.T){
 q:=PostgresScanJobQueue{}
 h:=SOCScanHandler(q)
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 base:="/soc/v1/tenants/tenantA/alerts/"+testUUID+"/"
 cases:=[]struct{method,path,body string;want int}{
  {"POST",base+"assign",`{"operator_id":"analyst"}`,403},
  {"POST",base+"notes",`{"note":"not authorized"}`,403},
  {"GET","/soc/v1/tenants/tenantB/my-alerts","",403},
  {"POST",base+"assign",`{"operator_id":"../other"}`,403},
 }
 for _,tc:=range cases{
  r:=httptest.NewRequest(tc.method,tc.path,strings.NewReader(tc.body))
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p))
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,r)
  if w.Code!=tc.want{t.Errorf("%s %s: got=%d want=%d",
   tc.method,tc.path,w.Code,tc.want)}
 }
}

func TestSprintDay3CaseAdapterRejectsMalformedAndOversizedInput(t *testing.T){
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"lead",Role:"scanner"}
 q:=PostgresScanJobQueue{}
 for _,target:=range []string{"../analyst","..","user/other",strings.Repeat("x",97)}{
  _,err:=q.AssignSOCAlert(context.Background(),p,testUUID,target)
  if err!=ErrInvalidScanQueueRequest{t.Errorf("invalid assignee %q: %v",target,err)}
 }
 for _,note:=range []string{"","	",strings.Repeat("x",2049),"line\nbreak"}{
  _,err:=q.AddSOCAlertNote(context.Background(),p,testUUID,note)
  if err!=ErrInvalidScanQueueRequest{t.Errorf("invalid note: %v",err)}
 }
 _,err:=q.ListSOCAlertActivity(context.Background(),p,testUUID,101,0)
 if err!=ErrInvalidScanQueueRequest{t.Errorf("unbounded audit query: %v",err)}
}
