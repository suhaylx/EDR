package edr

import(
 "context"
 "database/sql/driver"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestSOCMalwareAlertsReadAndTriage(t *testing.T) {
 now:=time.Now().UTC()
 var changes []string
 db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
  if len(args)==0||args[0].Value!="tenantA" {
   t.Fatalf("SOC alert SQL escaped tenant: %q %#v",q,args)
  }
  switch {
  case strings.Contains(q,"edr_soc_change_alert_state"):
   if args[1].Value!="analyst"||args[2].Value!=testUUID{t.Fatalf("unscoped alert transition: %#v",args)}
   changes=append(changes,args[3].Value.(string))
   return &scanRows{columns:[]string{"ok"},values:[][]driver.Value{{true}}},nil
  case strings.Contains(q,"count(*) FILTER"):
   return &scanRows{columns:[]string{"open","acked","resolved"},
    values:[][]driver.Value{{int64(1),int64(0),int64(0)}}},nil
  case strings.Contains(q,"FROM edr_soc_alerts"):
   return &scanRows{columns:[]string{"alert_id","job_id","agent_id","category","severity",
     "signature_name","state","created_at","updated_at","acknowledged_by","resolved_by","note","assigned_to"},
    values:[][]driver.Value{{testUUID,leaseUUID,"win01","malware_signature",
      "high","Lab-Signature","open",now,now,"","","",""}}},nil
  }
  t.Fatalf("unknown alert SQL %s",q);return nil,nil
 })
 h:=SOCAlertHandler(PostgresScanJobQueue{DB:db})
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 base:="/soc/v1/tenants/tenantA/"
 send:=func(method,path,body string) *httptest.ResponseRecorder {
  r:=httptest.NewRequest(method,base+path,strings.NewReader(body))
  r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},principal))
  w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w
 }
 for _,tc:=range []struct{path,contains string}{
  {"alerts?state=open",`"signature_name":"Lab-Signature"`},
  {"alerts/"+testUUID,`"severity":"high"`},
  {"alert-stats",`"open":1`},
 }{
  w:=send("GET",tc.path,"")
  if w.Code!=200||!strings.Contains(w.Body.String(),tc.contains){
   t.Fatalf("GET %s: %d %s",tc.path,w.Code,w.Body.String())
  }
 }
 for _,tc:=range []struct{path,body string}{
  {"alerts/"+testUUID+"/ack",""},
  {"alerts/"+testUUID+"/resolve",`{"note":"Reviewed in SOC lab"}`},
  {"alerts/"+testUUID+"/reopen",""},
 }{
  w:=send("POST",tc.path,tc.body)
  if w.Code!=204 {t.Fatalf("POST %s status=%d body=%s",tc.path,w.Code,w.Body.String())}
 }
 if strings.Join(changes,",")!="ack,resolve,reopen"{t.Fatalf("transitions %v",changes)}
}
func TestSOCViewerCannotMutateAlert(t *testing.T){
 h:=SOCAlertHandler(PostgresScanJobQueue{})
 base:="/soc/v1/tenants/tenantA/alerts/"+testUUID+"/ack"
 p:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"viewer",Role:"viewer"}
 r:=httptest.NewRequest("POST",base,nil)
 r=r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p))
 w:=httptest.NewRecorder();h.ServeHTTP(w,r)
 if w.Code!=403{t.Fatalf("viewer modified alert: %d",w.Code)}
}
