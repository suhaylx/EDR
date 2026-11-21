package edr

import (
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

// Exercise certificate registration failures through the real TLS 1.3
// transport, not just a fabricated TLS connection state.
func TestAgentScanQueueRealTLSRejectsUnenrolledAndRevoked(t *testing.T){
    now:=time.Now().UTC()
    leaf,clientCert,caPool:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    id:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    good:=sha256.Sum256(leaf.Raw)
    wrong:=good
    wrong[0]^=0xff
    cases:=[]struct{
        name string
        record EnrolledAgentCertificate
        want int
    }{
        {"enrolled",EnrolledAgentCertificate{Identity:id,FingerprintSHA256:good},http.StatusServiceUnavailable},
        {"wrong-fingerprint",EnrolledAgentCertificate{Identity:id,FingerprintSHA256:wrong},http.StatusUnauthorized},
        {"revoked",EnrolledAgentCertificate{Identity:id,FingerprintSHA256:good,Revoked:true},http.StatusUnauthorized},
        {"wrong-tenant-registration",EnrolledAgentCertificate{Identity:AgentIdentity{TenantID:"tenantB",AgentID:"win01"},FingerprintSHA256:good},http.StatusUnauthorized},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            // No DB configured: only the correctly enrolled certificate
            // reaches the queue handler (which then returns 503).
            handler:=AgentHTTPGuard(testIdentityRegistry{record:tc.record},
                AgentScanQueueHandler(PostgresScanJobQueue{}))
            server:=httptest.NewUnstartedServer(handler)
            server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
                ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:caPool}
            server.StartTLS()
            defer server.Close()
            client:=server.Client()
            transport:=client.Transport.(*http.Transport).Clone()
            transport.TLSClientConfig=transport.TLSClientConfig.Clone()
            transport.TLSClientConfig.Certificates=[]tls.Certificate{clientCert}
            client.Transport=transport
            defer transport.CloseIdleConnections()
            resp,err:=client.Post(server.URL+
                "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim",
                "application/json",strings.NewReader(""))
            if err!=nil{t.Fatal(err)}
            defer resp.Body.Close()
            if resp.StatusCode!=tc.want{
                t.Fatalf("status %d want %d",resp.StatusCode,tc.want)
            }
        })
    }
}
