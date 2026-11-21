package edr

import (
 "crypto/tls"
 "crypto/x509"
 "database/sql"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"
)

func TestIndependentTLSLeafExpiryDuringSQLAuthorizationDenied(t *testing.T){
 sink:=&securitySink{header:make(http.Header)}
 state:=&securityTxState{allow:true,sink:sink,authDelay:40*time.Millisecond}
 db:=sql.OpenDB(securityConnector{state});defer db.Close()
 req:=httptest.NewRequest("POST","https://127.0.0.1/soc/v1/tenants/t/scan-jobs",nil)
 req.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{{
  Raw:[]byte("ephemeral-expiring-operator-leaf"),NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(20*time.Millisecond),
 }}}
 certificateTransaction(sink,req,db,"SELECT auth($1,$2,$3,$4)",[]any{"tenant","operator","scanner"},func(*sql.Tx)http.Handler{
  return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){state.next.Add(1);w.WriteHeader(204)})
 })
 if sink.status!=401||state.next.Load()!=0||state.commit.Load()!=0||state.rollback.Load()!=1{
  t.Fatalf("expired leaf reached mutation: status=%d next=%d commit=%d rollback=%d",sink.status,state.next.Load(),state.commit.Load(),state.rollback.Load())
 }
}
