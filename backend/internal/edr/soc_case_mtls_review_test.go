package edr

import (
 "bytes"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "database/sql/driver"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

// QA P0: exercise the actual TLS handshake, fingerprint-backed operator
// guard and top-level SOC router. Handler-only tests are not a substitute
// for a real mTLS certificate boundary.
func TestQAReviewSOCAlertCaseOperationsRequireOperatorMTLS(t *testing.T) {
 now:=time.Now().UTC()
 leaf,operatorCert,pool:=createTestAgentCertificate(t,now,
  []string{"spiffe://turansec.local/tenants/tenantA/operators/analyst"},
  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
 fingerprint:=sha256.Sum256(leaf.Raw)
 var writes atomic.Int32
 var registryReads atomic.Int32
 db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
  if strings.Contains(query,"FROM edr_soc_operators AS o") {
   registryReads.Add(1)
   if len(args)!=2||args[0].Value!="tenantA"||args[1].Value!="analyst"{
    t.Errorf("registry escaped enrolled operator identity: %#v",args)
   }
   return &scanRows{columns:[]string{"fingerprint","role"},
    values:[][]driver.Value{{fingerprint[:],"scanner"}}},nil
  }
  if len(args)<3||args[0].Value!="tenantA"||
   args[1].Value!="analyst"||args[2].Value!=testUUID{
   t.Errorf("case operation escaped operator scope: %q %#v",query,args)
   return nil,io.ErrUnexpectedEOF
  }
  if strings.Contains(query,"edr_soc_assign_alert") {
   writes.Add(1)
   if len(args)!=4||args[3].Value!="investigator"{
    t.Errorf("assignee escaped approval: %#v",args)
   }
   return &scanRows{columns:[]string{"saved"},values:[][]driver.Value{{true}}},nil
  }
  if strings.Contains(query,"edr_soc_add_alert_note") {
   writes.Add(1)
   if len(args)!=4||args[3].Value!="Reviewed in QA isolated lab"{
    t.Errorf("case note changed: %#v",args)
   }
   return &scanRows{columns:[]string{"activity_id"},values:[][]driver.Value{{leaseUUID}}},nil
  }
  t.Errorf("unexpected SQL under operator guard: %q",query)
  return nil,io.ErrUnexpectedEOF
 })
 server:=httptest.NewUnstartedServer(
  SOCOperatorHTTPGuard(db,SOCScanHandler(PostgresScanJobQueue{DB:db})))
 server.TLS=&tls.Config{
  MinVersion:tls.VersionTLS13,
  ClientAuth:tls.RequireAndVerifyClientCert,
  ClientCAs:pool,
 }
 server.StartTLS()
 defer server.Close()
 path:="/soc/v1/tenants/tenantA/alerts/"+testUUID

 // A forged proxy header must not replace a missing mTLS client certificate.
 noCert:=server.Client()
 req,err:=http.NewRequest("POST",server.URL+path+"/assign",
  strings.NewReader(`{"operator_id":"investigator"}`))
 if err!=nil{t.Fatal(err)}
 req.Header.Set("X-Forwarded-Client-Cert","spiffe://turansec.local/tenants/tenantA/operators/analyst")
 resp,err:=noCert.Do(req)
 if err==nil{
  resp.Body.Close()
  t.Fatalf("SOC case accepted a request without a client certificate: %d",resp.StatusCode)
 }
 if writes.Load()!=0||registryReads.Load()!=0 {
  t.Fatal("unauthenticated TLS request reached registry or SQL mutation")
 }

 client:=server.Client()
 transport:=client.Transport.(*http.Transport).Clone()
 transport.TLSClientConfig=transport.TLSClientConfig.Clone()
 transport.TLSClientConfig.Certificates=[]tls.Certificate{operatorCert}
 client.Transport=transport
 defer transport.CloseIdleConnections()

 request:=func(route,body string)(int,http.Header){
  t.Helper()
  req,err:=http.NewRequest("POST",server.URL+route,bytes.NewBufferString(body))
  if err!=nil{t.Fatal(err)}
  req.Header.Set("Content-Type","application/json")
  // Spoofing these headers cannot override the authenticated principal.
  req.Header.Set("X-Tenant-ID","tenantB")
  req.Header.Set("X-Operator-Role","admin")
  req.Header.Set("X-Operator-ID","other")
  resp,err:=client.Do(req)
  if err!=nil{t.Fatal(err)}
  defer resp.Body.Close()
  _,_=io.Copy(io.Discard,resp.Body)
  return resp.StatusCode,resp.Header
 }

 t.Run("certificate-scoped assignment",func(t *testing.T){
  status,headers:=request(path+"/assign",`{"operator_id":"investigator"}`)
  if status!=204{t.Fatalf("valid mTLS assignment returned %d",status)}
  if headers.Get("Cache-Control")!="no-store"{
   t.Fatal("SOC case response must be no-store")
  }
 })
 t.Run("certificate-scoped audit note",func(t *testing.T){
  status,_:=request(path+"/notes",`{"note":"Reviewed in QA isolated lab"}`)
  if status!=201{t.Fatalf("valid mTLS note returned %d",status)}
 })
 t.Run("cross-tenant route refused before mutation",func(t *testing.T){
  before:=writes.Load()
  wrongPath:="/soc/v1/tenants/tenantB/alerts/"+testUUID+"/assign"
  status,_:=request(wrongPath,`{"operator_id":"investigator"}`)
  if status!=403 {t.Fatalf("cross-tenant assignment returned %d",status)}
  if writes.Load()!=before {t.Fatal("cross-tenant assignment reached SQL")}
 })
 t.Run("unknown fields refused before mutation",func(t *testing.T){
  before:=writes.Load()
  status,_:=request(path+"/notes",
   `{"note":"Reviewed in QA isolated lab","tenant_id":"tenantB"}`)
  if status!=400{t.Fatalf("injected JSON field returned %d",status)}
  if writes.Load()!=before {t.Fatal("malformed JSON reached SQL")}
 })
 if writes.Load()!=2{t.Fatalf("expected 2 authorized SOC writes; got %d",writes.Load())}
}
