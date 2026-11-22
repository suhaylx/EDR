package edr

import (
 "bytes"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "database/sql/driver"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)
func TestSOCMTLSOperatorSchedulesAndCancels(t *testing.T){
 now:=time.Now().UTC()
 leaf,cert,pool:=createTestAgentCertificate(t,now,
  []string{"spiffe://turansec.local/tenants/tenantA/operators/analyst"},
  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
 fingerprint:=sha256.Sum256(leaf.Raw)
 var created, cancelled int
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if strings.Contains(query,"FROM edr_soc_operators") {
   return &scanRows{columns:[]string{"fingerprint","role"},
     values:[][]driver.Value{{fingerprint[:],"scanner"}}},nil
  }
  if strings.Contains(query,"FROM edr_agents AS a") {
   if args[0].Value!="tenantA"||args[1].Value!="win01"{
    t.Fatalf("unscoped platform lookup: %#v",args)
   }
   return &scanRows{columns:[]string{"platform"},values:[][]driver.Value{{"windows"}}},nil
  }
  if strings.Contains(query,"edr_enqueue_operator_scan_job") {
   created++
   if args[0].Value!="tenantA"||args[1].Value!="analyst"||
     args[2].Value!="win01"||args[4].Value!="request-001"{
    t.Fatalf("unscoped SOC job: %#v",args)
   }
   return &scanRows{columns:[]string{"job_id","created"},
    values:[][]driver.Value{{testUUID,true}}},nil
  }
  if strings.Contains(query,"edr_cancel_operator_scan_job") {
   cancelled++
   if args[0].Value!="tenantA"||args[1].Value!="analyst"||
    args[2].Value!=testUUID {t.Fatalf("unscoped cancellation: %#v",args)}
   return &scanRows{columns:[]string{"cancelled"},values:[][]driver.Value{{true}}},nil
  }
  t.Fatalf("unexpected SOC SQL: %s",query);return nil,nil
 })
 server:=httptest.NewUnstartedServer(
  SOCOperatorHTTPGuard(db,SOCScanHandler(PostgresScanJobQueue{DB:db})))
 server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
  ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:pool}
 server.StartTLS();defer server.Close()
 base:="/soc/v1/tenants/tenantA/scan-jobs"
 noCert:=server.Client()
 resp,err:=noCert.Post(server.URL+base,"application/json",
  strings.NewReader(`{"agent_id":"win01","request_id":"request-001","scan_root":"C:\\Lab\\file"}`))
 if err==nil {resp.Body.Close();t.Fatalf("SOC listener accepted no cert: %d",resp.StatusCode)}
 client:=server.Client()
 transport:=client.Transport.(*http.Transport).Clone()
 transport.TLSClientConfig=transport.TLSClientConfig.Clone()
 transport.TLSClientConfig.Certificates=[]tls.Certificate{cert}
 client.Transport=transport;defer transport.CloseIdleConnections()
 post:=func(route string,body []byte)int{
  res,err:=client.Post(server.URL+route,"application/json",bytes.NewReader(body))
  if err!=nil{t.Fatal(err)}
  defer res.Body.Close()
  return res.StatusCode
 }
 if n:=post("/soc/v1/tenants/other/scan-jobs",nil);n!=403 {
  t.Fatalf("tenant route override status %d",n)
 }
 body:=[]byte(`{"agent_id":"win01","request_id":"request-001","scan_root":"C:\\Lab\\file"}`)
 if n:=post(base,body);n!=201 {t.Fatalf("schedule status %d",n)}
 if n:=post(base+"/"+testUUID+"/cancel",nil);n!=204 {t.Fatalf("cancel status %d",n)}
 if created!=1||cancelled!=1 {t.Fatalf("writes: %d/%d",created,cancelled)}
 // No operator bearer token, no agent API access or privilege from headers.
 req,_:=http.NewRequest("POST",server.URL+base,bytes.NewReader(body))
 req.Header.Set("X-Operator-Role","admin")
 req.Header.Set("Content-Type","application/json")
 res,err:=client.Do(req)
 if err!=nil{t.Fatal(err)}
 res.Body.Close()
 if res.StatusCode!=201 {t.Fatalf("valid cert was overridden by header: %d",res.StatusCode)}
}
