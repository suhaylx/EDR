package edr

import (
    "crypto/tls"
    "crypto/x509"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestNewAgentMTLSServerRejectsIncompleteConfiguration(t *testing.T){
    pool:=x509.NewCertPool()
    cases:=[]struct{name,addr string;cert tls.Certificate;ca *x509.CertPool}{
        {"missing cert","127.0.0.1:9443",tls.Certificate{},pool},
        {"missing CA","127.0.0.1:9443",tls.Certificate{Certificate:[][]byte{{1}}},nil},
        {"wildcard ipv4","0.0.0.0:9443",tls.Certificate{Certificate:[][]byte{{1}}},pool},
        {"wildcard ipv6","[::]:9443",tls.Certificate{Certificate:[][]byte{{1}}},pool},
        {"no host",":9443",tls.Certificate{Certificate:[][]byte{{1}}},pool},
        {"malformed","not-a-listener",tls.Certificate{Certificate:[][]byte{{1}}},pool},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            if _,err:=NewAgentMTLSServer(tc.addr,nil,tc.cert,tc.ca);err==nil{
                t.Fatal("must reject missing database")
            }
        })
    }
}

func TestAgentScanQueueRequiresGuard(t *testing.T){
    // No TLS identity and no context principal: handler denies before SQL.
    h:=AgentHTTPGuard(PostgresAgentIdentityRegistry{},AgentScanQueueHandler(PostgresScanJobQueue{}))
    w:=httptest.NewRecorder()
    h.ServeHTTP(w,httptest.NewRequest(http.MethodPost,
        "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim",nil))
    if w.Code!=http.StatusUnauthorized{
        t.Fatalf("unauthenticated request status %d",w.Code)
    }
}
