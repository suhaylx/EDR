package edr

import (
 "bytes"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "database/sql/driver"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

// QA P0: a certificate signed by the trusted operator CA is not sufficient.
// The exact leaf fingerprint and an ACTIVE scanner role must be in the tenant
// roster on every request. No bearer/header fallback is allowed.
func TestQAReviewSOCCertificateRegistryFailureIsClosed(t *testing.T){
 now:=time.Now().UTC()
 leaf,cert,pool:=createTestAgentCertificate(t,now,
  []string{"spiffe://turansec.local/tenants/tenantA/operators/analyst"},
  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
 fingerprint:=sha256.Sum256(leaf.Raw)
 cases:=[]struct{name,role string;fingerprint []byte;offline bool;want int}{
  {"revoked or unregistered", "",nil,false,401},
  {"registry unavailable","",nil,true,503},
  {"unapproved operator role","admin",fingerprint[:],false,401},
  {"fingerprint mismatch","scanner",bytes.Repeat([]byte{0x42},32),false,401},
  {"viewer may not schedule scan","viewer",fingerprint[:],false,403},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  called:=0
  db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
   called++
   if !strings.Contains(query,"FROM edr_soc_operators AS o")||
    len(args)!=2||args[0].Value!="tenantA"||args[1].Value!="analyst"{
    t.Fatalf("unexpected SQL while authorizing operator: %q %#v",query,args)
   }
   if tc.offline{return nil,errors.New("test-only simulated private SQL outage")}
   if tc.role==""{
    return &scanRows{columns:[]string{"fingerprint","role"}},nil
   }
   return &scanRows{columns:[]string{"fingerprint","role"},
    values:[][]driver.Value{{tc.fingerprint,tc.role}}},nil
  })
  server:=httptest.NewUnstartedServer(
   SOCOperatorHTTPGuard(db,SOCScanHandler(PostgresScanJobQueue{DB:db})))
  server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
   ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:pool}
  server.StartTLS()
  defer server.Close()
  client:=server.Client()
  transport:=client.Transport.(*http.Transport).Clone()
  transport.TLSClientConfig=transport.TLSClientConfig.Clone()
  transport.TLSClientConfig.Certificates=[]tls.Certificate{cert}
  client.Transport=transport
  defer transport.CloseIdleConnections()
  req,err:=http.NewRequest("POST",
   server.URL+"/soc/v1/tenants/tenantA/scan-jobs",
   strings.NewReader(`{"agent_id":"win01","request_id":"qa-001","scan_root":"C:\\Lab\\sample"}`))
  if err!=nil{t.Fatal(err)}
  req.Header.Set("Content-Type","application/json")
  // A malicious role header must never create an operator principal.
  req.Header.Set("X-Operator-Role","scanner")
  res,err:=client.Do(req)
  if err!=nil{t.Fatal(err)}
  defer res.Body.Close()
  if res.StatusCode!=tc.want{
   t.Fatalf("%s returned %d want %d",tc.name,res.StatusCode,tc.want)
  }
  if called!=1{t.Fatalf("auth must query registered operator once, got %d",called)}
  if res.Header.Get("Cache-Control")!="no-store"{
   t.Fatal("operator response did not disable caching")
  }
 })}
}
